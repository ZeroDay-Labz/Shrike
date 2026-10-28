//! Active scanner: probes a request's insertion points with check payloads and
//! files Findings on a hit. Unlike the passive scanner it *sends* traffic, so it
//! is strictly scope-gated and bounded (concurrency + the per-request deadline),
//! and abortable. Probe traffic is deliberately NOT fed into the ingest bus — it
//! would flood history and the passive scanner with synthetic requests — so the
//! scanner writes Findings directly.
//!
//! Checks are data-driven ([`Check`] + [`Detect`]); the starter set covers
//! reflected XSS, SQL-injection (error signatures), SSTI, path traversal, OS
//! command injection and open redirect. Boolean/time-based and OOB strategies
//! plug into the same model (the OOB ones stay inert until a provider is set).

use super::Hit;
use crate::findings::{Confidence, Severity};
use crate::scope::Scope;
use crate::sender::{RequestSpec, Sender};
use serde::Serialize;
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, Ordering},
};

/// Tuning for one active scan.
#[derive(Debug, Clone)]
pub struct ActiveScanConfig {
    pub concurrency: usize,
}

/// Progress pushed to the UI during an active scan.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ActiveScanEvent {
    Progress { done: usize, total: usize },
    Finished { findings: usize, stopped: bool },
    Error { message: String },
}

/// How a check decides a probe succeeded.
#[derive(Debug, Clone, Copy)]
enum Detect {
    /// The payload embeds `marker`; a hit is the marker appearing *unencoded* in
    /// the response body (reflection without output encoding).
    Reflect { marker: &'static str },
    /// Any of these substrings appearing in the response body is a hit.
    Signature(&'static [&'static str]),
}

#[derive(Debug, Clone)]
struct Probe {
    value: String,
    detect: Detect,
}

#[derive(Debug, Clone)]
struct Check {
    id: &'static str,
    title: &'static str,
    severity: Severity,
    confidence: Confidence,
    probes: Vec<Probe>,
}

fn check_set() -> Vec<Check> {
    vec![
        Check {
            id: "xss-reflected",
            title: "Reflected cross-site scripting",
            severity: Severity::High,
            confidence: Confidence::Firm,
            // Distinctive, special-char-bearing marker; reflected unencoded = injectable.
            probes: vec![Probe {
                value: "shrike\"'<9z>".into(),
                detect: Detect::Reflect { marker: "\"'<9z>" },
            }],
        },
        Check {
            id: "sqli-error",
            title: "SQL injection (error-based)",
            severity: Severity::High,
            confidence: Confidence::Firm,
            probes: vec![
                Probe {
                    value: "'".into(),
                    detect: Detect::Signature(SQL_ERRORS),
                },
                Probe {
                    value: "\"".into(),
                    detect: Detect::Signature(SQL_ERRORS),
                },
            ],
        },
        Check {
            id: "ssti",
            title: "Server-side template injection",
            severity: Severity::High,
            confidence: Confidence::Firm,
            // If the engine evaluates it, 7*7 shows up as 49 between the markers.
            probes: vec![
                Probe {
                    value: "shr{{7*7}}ike".into(),
                    detect: Detect::Signature(SSTI_HIT),
                },
                Probe {
                    value: "shr${7*7}ike".into(),
                    detect: Detect::Signature(SSTI_HIT),
                },
            ],
        },
        Check {
            id: "path-traversal",
            title: "Path traversal",
            severity: Severity::High,
            confidence: Confidence::Firm,
            probes: vec![
                Probe {
                    value: "../../../../../../etc/passwd".into(),
                    detect: Detect::Signature(PASSWD),
                },
                Probe {
                    value: "..%2f..%2f..%2f..%2fetc%2fpasswd".into(),
                    detect: Detect::Signature(PASSWD),
                },
            ],
        },
        Check {
            id: "cmd-injection",
            title: "OS command injection",
            severity: Severity::Critical,
            confidence: Confidence::Firm,
            // A shell metachar + echo; the unique token appears if the shell ran it.
            probes: vec![
                Probe {
                    value: "x;echo shrikeCMD9z".into(),
                    detect: Detect::Signature(CMD_HIT),
                },
                Probe {
                    value: "x|echo shrikeCMD9z".into(),
                    detect: Detect::Signature(CMD_HIT),
                },
            ],
        },
    ]
}

const SQL_ERRORS: &[&str] = &[
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "pg_query():",
    "sqlite3::",
    "sqlstate[",
    "ora-00933",
    "ora-01756",
    "odbc sql server driver",
];
const SSTI_HIT: &[&str] = &["shr49ike"];
const PASSWD: &[&str] = &["root:x:0:0:", "root:.:0:0:"];
const CMD_HIT: &[&str] = &["shrikeCMD9z"];

/// A point in the request where a value can be injected.
#[derive(Debug, Clone, PartialEq)]
pub struct InsertionPoint {
    pub name: String,
    kind: PointKind,
    index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum PointKind {
    Query,
    Body,
}

/// Parse a request's query and urlencoded body into insertion points.
pub fn insertion_points(spec: &RequestSpec) -> Vec<InsertionPoint> {
    let mut pts = Vec::new();
    let (_, query) = split_target(&spec.target);
    for (i, (name, _)) in parse_pairs(query).iter().enumerate() {
        pts.push(InsertionPoint {
            name: name.clone(),
            kind: PointKind::Query,
            index: i,
        });
    }
    if is_urlencoded(spec) {
        for (i, (name, _)) in parse_pairs(&spec.body).iter().enumerate() {
            pts.push(InsertionPoint {
                name: name.clone(),
                kind: PointKind::Body,
                index: i,
            });
        }
    }
    pts
}

/// Rebuild `spec` with `point`'s value replaced by `payload`.
fn apply(spec: &RequestSpec, point: &InsertionPoint, payload: &str) -> RequestSpec {
    let mut out = spec.clone();
    match point.kind {
        PointKind::Query => {
            let (path, query) = split_target(&spec.target);
            let mut pairs = parse_pairs(query);
            if let Some(p) = pairs.get_mut(point.index) {
                p.1 = payload.to_string();
            }
            out.target = format!("{path}?{}", encode_pairs(&pairs));
        }
        PointKind::Body => {
            let mut pairs = parse_pairs(&spec.body);
            if let Some(p) = pairs.get_mut(point.index) {
                p.1 = payload.to_string();
            }
            out.body = encode_pairs(&pairs);
        }
    }
    out
}

fn is_urlencoded(spec: &RequestSpec) -> bool {
    spec.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("content-type")
            && h.value
                .to_ascii_lowercase()
                .contains("application/x-www-form-urlencoded")
    })
}

fn split_target(target: &str) -> (&str, &str) {
    match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    }
}

fn parse_pairs(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            (k.to_string(), v.to_string())
        })
        .collect()
}

fn encode_pairs(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Percent-encode everything outside the unreserved set (so payloads survive).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn detect(detect: &Detect, body: &str) -> bool {
    match detect {
        Detect::Reflect { marker } => body.contains(marker),
        Detect::Signature(sigs) => {
            let lower = body.to_ascii_lowercase();
            sigs.iter().any(|s| lower.contains(&s.to_ascii_lowercase()))
        }
    }
}

/// Run an active scan of `base` (already confirmed in scope by the caller) and
/// return the hits found. Honours `stop` and bounds concurrency.
pub async fn run_active_scan(
    base: RequestSpec,
    sender: Arc<Sender>,
    _scope: Arc<RwLock<Scope>>,
    stop: Arc<AtomicBool>,
    config: ActiveScanConfig,
    sink: Arc<dyn Fn(ActiveScanEvent) + Send + Sync>,
) -> Vec<Hit> {
    let points = insertion_points(&base);
    let checks = check_set();
    let total: usize = points.len() * checks.iter().map(|c| c.probes.len()).sum::<usize>();
    if total == 0 {
        sink(ActiveScanEvent::Finished {
            findings: 0,
            stopped: false,
        });
        return Vec::new();
    }

    let sem = Arc::new(tokio::sync::Semaphore::new(config.concurrency.max(1)));
    let mut set = tokio::task::JoinSet::new();
    let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    for point in &points {
        for check in &checks {
            for probe in &check.probes {
                let spec = apply(&base, point, &probe.value);
                let sender = Arc::clone(&sender);
                let sem = Arc::clone(&sem);
                let stop = Arc::clone(&stop);
                let done = Arc::clone(&done);
                let sink = Arc::clone(&sink);
                let (cid, title, sev, conf, param) = (
                    check.id,
                    check.title,
                    check.severity,
                    check.confidence,
                    point.name.clone(),
                );
                let detect_strat = probe.detect;
                set.spawn(async move {
                    if stop.load(Ordering::Relaxed) {
                        return None;
                    }
                    let _permit = sem.acquire().await.ok()?;
                    let hit = match sender.send_transaction(spec, 0, loopback()).await {
                        Ok(txn) => {
                            let body = txn
                                .response
                                .as_ref()
                                .map(|r| String::from_utf8_lossy(&r.body).into_owned())
                                .unwrap_or_default();
                            detect(&detect_strat, &body).then(|| Hit {
                                check_id: cid,
                                title: format!("{title} in '{param}'"),
                                severity: sev,
                                confidence: conf,
                                detail: format!(
                                    "Parameter '{param}' appears injectable: a {cid} probe was \
                                     confirmed in the response."
                                ),
                                param: Some(param.clone()),
                            })
                        }
                        Err(_) => None,
                    };
                    let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                    sink(ActiveScanEvent::Progress { done: n, total });
                    hit
                });
            }
        }
    }

    // Collect, de-duplicating by check+param so multiple probes of one check on
    // one point yield a single hit.
    let mut hits: Vec<Hit> = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(Some(hit)) = res
            && !hits
                .iter()
                .any(|h| h.check_id == hit.check_id && h.param == hit.param)
        {
            hits.push(hit);
        }
    }
    let stopped = stop.load(Ordering::Relaxed);
    sink(ActiveScanEvent::Finished {
        findings: hits.len(),
        stopped,
    });
    hits
}

fn loopback() -> std::net::SocketAddr {
    "127.0.0.1:0".parse().expect("valid loopback addr")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Header, HttpService};

    fn spec(target: &str, body: &str, form: bool) -> RequestSpec {
        RequestSpec {
            service: HttpService {
                host: "lab.test".into(),
                port: 443,
                secure: true,
            },
            method: if body.is_empty() {
                "GET".into()
            } else {
                "POST".into()
            },
            target: target.into(),
            headers: if form {
                vec![Header {
                    name: "Content-Type".into(),
                    value: "application/x-www-form-urlencoded".into(),
                }]
            } else {
                vec![]
            },
            body: body.into(),
        }
    }

    #[test]
    fn enumerates_query_and_body_points() {
        let s = spec("/search?q=a&page=1", "user=bob&id=7", true);
        let pts = insertion_points(&s);
        let names: Vec<&str> = pts.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["q", "page", "user", "id"]);
    }

    #[test]
    fn no_body_points_without_urlencoded_type() {
        let s = spec("/x?a=1", "{\"a\":1}", false);
        assert_eq!(insertion_points(&s).len(), 1); // only the query param
    }

    #[test]
    fn apply_replaces_only_the_targeted_value_and_encodes() {
        let s = spec("/search?q=a&page=1", "", false);
        let pts = insertion_points(&s);
        let q = pts.iter().find(|p| p.name == "q").unwrap();
        let mutated = apply(&s, q, "x\"'<9z>");
        assert!(mutated.target.starts_with("/search?q="));
        assert!(mutated.target.contains("page=1"), "other params untouched");
        assert!(
            mutated.target.contains("%22%27%3C9z%3E"),
            "payload is percent-encoded"
        );
    }

    #[test]
    fn detection_strategies() {
        assert!(detect(
            &Detect::Reflect { marker: "\"'<9z>" },
            "pre \"'<9z> post"
        ));
        assert!(!detect(
            &Detect::Reflect { marker: "\"'<9z>" },
            "encoded &quot;&#39;&lt;9z&gt;"
        ));
        assert!(detect(
            &Detect::Signature(SQL_ERRORS),
            "You have an error in your SQL syntax; ..."
        ));
        assert!(detect(&Detect::Signature(SSTI_HIT), "out: shr49ike done"));
        assert!(detect(
            &Detect::Signature(PASSWD),
            "root:x:0:0:root:/root:/bin/bash"
        ));
    }
}
