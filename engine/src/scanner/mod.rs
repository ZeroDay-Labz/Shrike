//! Scanner: turns captured traffic into Findings.
//!
//! [`passive`] runs on the capture path (a `TrafficSink`) and raises issues
//! without sending any traffic of its own. The active scanner (insertion-point
//! driven) builds on the same Findings output and lands in an `active` module.

pub mod active;
pub mod js_libs;
pub mod jwt_scan;
pub mod passive;

pub use active::{ActiveScanConfig, ActiveScanEvent, run_active_scan};
pub use passive::PassiveScanner;

use crate::findings::{Confidence, NewFinding, Severity};

/// One passive/active check result, before it becomes a stored Finding. The
/// scanner turns it into a [`NewFinding`] plus a stable dedup key so repeated
/// observations of the same issue collapse to one finding.
#[derive(Debug, Clone)]
pub struct Hit {
    /// Stable check identifier, e.g. `missing-csp` — part of the dedup key.
    pub check_id: &'static str,
    pub title: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub detail: String,
    /// The affected parameter/cookie/header name, when the issue is tied to one.
    pub param: Option<String>,
}

impl Hit {
    /// The dedup key identifying this issue at this location:
    /// `check|host|path[|param]`.
    pub fn dedup_key(&self, host: &str, path: &str) -> String {
        match &self.param {
            Some(p) => format!("{}|{}|{}|{}", self.check_id, host, path, p),
            None => format!("{}|{}|{}", self.check_id, host, path),
        }
    }

    /// Build the stored finding for this hit at a location, evidenced by `txn_id`.
    pub fn into_finding(self, host: &str, path: &str, txn_id: u64) -> NewFinding {
        NewFinding {
            title: self.title,
            severity: self.severity,
            confidence: self.confidence,
            detail: self.detail,
            host: Some(host.to_string()),
            path: Some(path.to_string()),
            transaction_ids: vec![txn_id],
        }
    }
}

/// True for a media type we can scan as text.
pub(crate) fn is_texty(content_type: Option<&str>) -> bool {
    match content_type {
        Some(ct) => {
            let ct = ct.to_ascii_lowercase();
            ct.starts_with("text/")
                || ct.contains("json")
                || ct.contains("xml")
                || ct.contains("javascript")
                || ct.contains("html")
        }
        None => false,
    }
}
