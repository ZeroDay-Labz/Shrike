//! Extension scanner bridge: runs each running extension's registered passive
//! scan checks (Montoya `ScanCheck` / legacy `IScannerCheck`) over completed
//! transactions and files the issues they raise as Findings, alongside Shrike's
//! native passive scanner.
//!
//! Like [`crate::scanner::PassiveScanner`], this is a [`TrafficSink`] whose work
//! runs on a dedicated worker thread fed by a bounded channel, so capture is
//! never blocked; under overload transactions are dropped rather than stalling
//! the bus. Each transaction is round-tripped to the extension's host over the
//! serve protocol (`@SCAN` / `@ISSUES`); a wedged extension only loses its own
//! scan (fail-open) and never blocks traffic.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde::Deserialize;
use tracing::warn;

use super::{RunningBapp, ServeHost, Target};
use crate::core::{TrafficEvent, TrafficSink, Transaction};
use crate::findings::{Confidence, NewFinding, Severity};
use crate::store::Store;

/// Bounded queue depth; beyond this the scanner drops (capture must not block).
const QUEUE_DEPTH: usize = 128;
/// Per-extension round-trip budget; a passive audit that overruns it is skipped.
const SCAN_TIMEOUT: Duration = Duration::from_secs(15);

/// One issue an extension's scan check raised, as serialized by the Java host.
#[derive(Debug, Clone, Deserialize)]
pub struct ExtIssue {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub confidence: String,
    #[serde(default)]
    pub url: String,
}

impl ExtIssue {
    /// Build the stored finding + dedup key for this issue, attributed to the
    /// extension `ext_name` (sha `sha`) at `host`/`path`, evidenced by `txn_id`.
    /// Severity/confidence are the extension's own labels (`HIGH`, `Firm`, …),
    /// parsed case-insensitively; unknown values fall back to Info / Tentative.
    fn into_finding(
        self,
        sha: &str,
        ext_name: &str,
        host: &str,
        path: &str,
        txn_id: u64,
    ) -> (NewFinding, String) {
        let title = if self.name.is_empty() {
            format!("{ext_name}: issue")
        } else {
            format!("{ext_name}: {}", self.name)
        };
        let mut detail = self.detail;
        if !self.url.is_empty() {
            if !detail.is_empty() {
                detail.push_str("\n\n");
            }
            detail.push_str("URL: ");
            detail.push_str(&self.url);
        }
        // The extension + issue name + location make a stable dedup key, so
        // re-observing the same issue collapses onto the one finding.
        let dedup_key = format!("ext:{sha}|{}|{host}|{path}", self.name);
        let finding = NewFinding {
            title,
            severity: Severity::parse(&self.severity),
            confidence: Confidence::parse(&self.confidence),
            detail,
            host: Some(host.to_string()),
            path: Some(path.to_string()),
            transaction_ids: vec![txn_id],
        };
        (finding, dedup_key)
    }
}

type Hosts = Arc<Mutex<HashMap<String, Arc<ServeHost>>>>;
type States = Arc<Mutex<HashMap<String, Arc<Mutex<RunningBapp>>>>>;

/// A [`TrafficSink`] that feeds completed transactions to the running
/// extensions' passive scan checks and files the issues they raise.
pub struct BappScanner {
    tx: SyncSender<Arc<Transaction>>,
    /// Shares the engine's "passive scanning" switch; off means no extension
    /// scanning either, matching the native passive scanner.
    enabled: Arc<AtomicBool>,
}

impl BappScanner {
    /// Spawn the worker and return a sink. `hosts`/`state` are the engine's live
    /// running-extension maps (shared), so the sink always reflects what is
    /// running right now; findings go to `store` and are announced on `bus`.
    pub fn new(
        store: Arc<Store>,
        bus: crate::core::EventBus,
        enabled: Arc<AtomicBool>,
        hosts: Hosts,
        state: States,
    ) -> Self {
        let (tx, rx) = sync_channel::<Arc<Transaction>>(QUEUE_DEPTH);
        thread::Builder::new()
            .name("shrike-ext-scan".into())
            .spawn(move || {
                while let Ok(txn) = rx.recv() {
                    scan_one(&txn, &store, &bus, &hosts, &state);
                }
            })
            .expect("spawning extension scanner worker");
        Self { tx, enabled }
    }
}

impl TrafficSink for BappScanner {
    fn handle(&mut self, event: &TrafficEvent) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        if let TrafficEvent::Completed(txn) = event {
            // Non-blocking: drop under backpressure so capture is never stalled.
            let _ = self.tx.try_send(Arc::clone(txn));
        }
    }
}

fn scan_one(
    txn: &Transaction,
    store: &Store,
    bus: &crate::core::EventBus,
    hosts: &Mutex<HashMap<String, Arc<ServeHost>>>,
    state: &Mutex<HashMap<String, Arc<Mutex<RunningBapp>>>>,
) {
    // Passive auditing needs the response; a failed transaction has nothing to scan.
    let Some(resp) = txn.response.as_ref() else {
        return;
    };
    // Snapshot the hosts that registered a scan check, then drop the locks before
    // the blocking round-trips so scanning never stalls live traffic.
    let targets: Vec<(String, String, Arc<ServeHost>)> = {
        let state = state.lock().expect("bapp state lock");
        let hosts = hosts.lock().expect("bapp hosts lock");
        let mut shas: Vec<&String> = hosts.keys().collect();
        shas.sort();
        shas.into_iter()
            .filter_map(|sha| {
                let meta = state.get(sha)?.lock().expect("running bapp lock");
                let has_scan = meta
                    .registered
                    .iter()
                    .any(|r| r == "registerScanCheck" || r == "registerScannerCheck");
                if !has_scan {
                    return None;
                }
                let name = meta.name.clone().unwrap_or_else(|| "Extension".to_string());
                let h = hosts.get(sha)?;
                Some((sha.clone(), name, Arc::clone(h)))
            })
            .collect()
    };
    if targets.is_empty() {
        return;
    }

    let host = txn.request.service.host.clone();
    let path = txn.request.path().to_string();
    let txn_id = txn.request.id;
    let target = Target {
        host: &host,
        port: txn.request.service.port,
        secure: txn.request.service.secure,
    };
    let req_raw = txn.request.to_raw();
    let resp_raw = resp.to_raw();

    for (sha, name, h) in targets {
        let json = match h.scan_passive(target, &req_raw, &resp_raw, SCAN_TIMEOUT) {
            Ok(j) => j,
            Err(e) => {
                warn!(error = %e, sha = %sha, "extension scan failed; skipping");
                continue;
            }
        };
        let issues: Vec<ExtIssue> = serde_json::from_str(&json).unwrap_or_default();
        for issue in issues {
            let (new, key) = issue.into_finding(&sha, &name, &host, &path, txn_id);
            match store.finding_create_deduped(new, &key) {
                Ok(Some(finding)) => bus.emit(TrafficEvent::FindingAdded(Arc::new(finding))),
                Ok(None) => {} // duplicate — already recorded
                Err(e) => warn!(error = %e, "extension finding insert failed"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_maps_to_finding_with_source_prefix_and_dedup_key() {
        let issue = ExtIssue {
            name: "SQL injection".to_string(),
            detail: "parameter id".to_string(),
            severity: "HIGH".to_string(),
            confidence: "Firm".to_string(),
            url: "https://t.example/item?id=1".to_string(),
        };
        let (finding, key) = issue.into_finding("abc123", "active-scan++", "t.example", "/item", 7);
        assert_eq!(finding.title, "active-scan++: SQL injection");
        assert_eq!(finding.severity, Severity::High);
        assert_eq!(finding.confidence, Confidence::Firm);
        assert_eq!(finding.host.as_deref(), Some("t.example"));
        assert_eq!(finding.path.as_deref(), Some("/item"));
        assert_eq!(finding.transaction_ids, vec![7]);
        assert!(finding.detail.contains("parameter id"));
        assert!(finding.detail.contains("URL: https://t.example/item?id=1"));
        assert_eq!(key, "ext:abc123|SQL injection|t.example|/item");
    }

    #[test]
    fn unknown_labels_fall_back_conservatively() {
        // Montoya's INFORMATION severity and a missing confidence land on the
        // safest values rather than erroring.
        let issue = ExtIssue {
            name: "Info leak".to_string(),
            detail: String::new(),
            severity: "INFORMATION".to_string(),
            confidence: String::new(),
            url: String::new(),
        };
        let (finding, _) = issue.into_finding("s", "ext", "h", "/p", 1);
        assert_eq!(finding.severity, Severity::Info);
        assert_eq!(finding.confidence, Confidence::Tentative);
        // No URL → detail stays empty (no dangling "URL:" line).
        assert!(finding.detail.is_empty());
    }
}
