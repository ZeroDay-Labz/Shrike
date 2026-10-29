//! Passive scanner: a [`TrafficSink`] that inspects each completed transaction
//! and files Findings, without sending any traffic. Work runs on a dedicated
//! worker thread (fed by a bounded channel) so the event bus is never blocked;
//! on overload it drops transactions rather than stall capture.

use super::{Hit, is_texty};
use crate::core::{TrafficEvent, TrafficSink, Transaction};
use crate::findings::{Confidence, Severity};
use crate::store::Store;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc::{SyncSender, sync_channel},
};
use std::thread;
use tracing::warn;

/// Bounded queue depth; beyond this the scanner drops (capture must not block).
const QUEUE_DEPTH: usize = 256;

/// A passive scanner registered as a sink on the ingest bus.
pub struct PassiveScanner {
    tx: SyncSender<Arc<Transaction>>,
    enabled: Arc<AtomicBool>,
}

impl PassiveScanner {
    /// Spawn the worker and return a sink. `enabled` is shared with the engine so
    /// the setting can be toggled live. Findings are written to `store`; new ones
    /// are announced on `bus` as [`TrafficEvent::FindingAdded`].
    pub fn new(store: Arc<Store>, bus: crate::core::EventBus, enabled: Arc<AtomicBool>) -> Self {
        let (tx, rx) = sync_channel::<Arc<Transaction>>(QUEUE_DEPTH);
        thread::Builder::new()
            .name("shrike-passive-scan".into())
            .spawn(move || {
                while let Ok(txn) = rx.recv() {
                    scan_one(&txn, &store, &bus);
                }
            })
            .expect("spawning passive scanner worker");
        Self { tx, enabled }
    }
}

impl TrafficSink for PassiveScanner {
    fn handle(&mut self, event: &TrafficEvent) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        if let TrafficEvent::Completed(txn) = event {
            // Non-blocking: drop under backpressure so capture is never stalled.
            if self.tx.try_send(Arc::clone(txn)).is_err() {
                // Full or closed; losing a passive scan is acceptable.
            }
        }
    }
}

fn scan_one(txn: &Transaction, store: &Store, bus: &crate::core::EventBus) {
    let host = txn.request.service.host.clone();
    let path = txn.request.path().to_string();
    let txn_id = txn.request.id;
    for hit in run_checks(txn) {
        let key = hit.dedup_key(&host, &path);
        let new = hit.into_finding(&host, &path, txn_id);
        match store.finding_create_deduped(new, &key) {
            Ok(Some(finding)) => bus.emit(TrafficEvent::FindingAdded(Arc::new(finding))),
            Ok(None) => {} // duplicate — already recorded
            Err(e) => warn!(error = %e, "passive finding insert failed"),
        }
    }
}

/// Run every passive check over a transaction.
/// Current Unix time in whole seconds (for JWT expiry checks); 0 if the clock
/// is before the epoch, which only makes the check more conservative.
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn run_checks(txn: &Transaction) -> Vec<Hit> {
    let mut hits = Vec::new();
    let Some(resp) = txn.response.as_ref() else {
        return hits;
    };
    let secure = txn.request.service.secure;
    let ctype = resp.content_type();
    let is_html = ctype.is_some_and(|c| c.contains("html"));
    let body = if is_texty(ctype) {
        String::from_utf8_lossy(&resp.body)
    } else {
        std::borrow::Cow::Borrowed("")
    };

    if is_html {
        hits.extend(security_header_hits(resp, secure));
    }
    hits.extend(cookie_flag_hits(resp, secure));
    hits.extend(reflected_input_hits(txn, &body, is_texty(ctype)));
    hits.extend(info_disclosure_hits(resp));
    hits.extend(error_signature_hits(&body));
    hits.extend(crate::scanner::jwt_scan::jwt_hits(txn, now_unix_secs()));
    if secure && is_html {
        hits.extend(mixed_content_hits(&body));
    }
    hits
}

fn has_header(resp: &crate::core::CapturedResponse, name: &str) -> bool {
    resp.headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case(name))
}

fn security_header_hits(resp: &crate::core::CapturedResponse, secure: bool) -> Vec<Hit> {
    let mut v = Vec::new();
    let csp = resp
        .headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case("content-security-policy"))
        .map(|h| h.value.clone());
    if csp.is_none() {
        v.push(Hit {
            check_id: "missing-csp",
            title: "Missing Content-Security-Policy".into(),
            severity: Severity::Low,
            confidence: Confidence::Firm,
            detail:
                "The response has no Content-Security-Policy header, so the browser applies no \
                     script/style source restrictions."
                    .into(),
            param: None,
        });
    }
    if secure && !has_header(resp, "strict-transport-security") {
        v.push(Hit {
            check_id: "missing-hsts",
            title: "Missing Strict-Transport-Security".into(),
            severity: Severity::Low,
            confidence: Confidence::Firm,
            detail: "HTTPS response without HSTS; clients may be downgraded to HTTP.".into(),
            param: None,
        });
    }
    if !has_header(resp, "x-content-type-options") {
        v.push(Hit {
            check_id: "missing-xcto",
            title: "Missing X-Content-Type-Options".into(),
            severity: Severity::Info,
            confidence: Confidence::Firm,
            detail: "No X-Content-Type-Options: nosniff; the browser may MIME-sniff the response."
                .into(),
            param: None,
        });
    }
    // Clickjacking protection: X-Frame-Options OR CSP frame-ancestors.
    let frame_ancestors = csp
        .as_deref()
        .is_some_and(|c| c.to_ascii_lowercase().contains("frame-ancestors"));
    if !has_header(resp, "x-frame-options") && !frame_ancestors {
        v.push(Hit {
            check_id: "missing-framing",
            title: "No clickjacking protection".into(),
            severity: Severity::Low,
            confidence: Confidence::Firm,
            detail:
                "Neither X-Frame-Options nor CSP frame-ancestors is set; the page can be framed."
                    .into(),
            param: None,
        });
    }
    v
}

fn cookie_flag_hits(resp: &crate::core::CapturedResponse, secure: bool) -> Vec<Hit> {
    let mut v = Vec::new();
    for h in resp
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("set-cookie"))
    {
        let lower = h.value.to_ascii_lowercase();
        let name = h
            .value
            .split('=')
            .next()
            .unwrap_or("cookie")
            .trim()
            .to_string();
        let mut missing: Vec<&str> = Vec::new();
        if secure && !lower.contains("secure") {
            missing.push("Secure");
        }
        if !lower.contains("httponly") {
            missing.push("HttpOnly");
        }
        if !lower.contains("samesite") {
            missing.push("SameSite");
        }
        if !missing.is_empty() {
            v.push(Hit {
                check_id: "cookie-flags",
                title: format!("Cookie '{name}' missing {}", missing.join(", ")),
                severity: Severity::Low,
                confidence: Confidence::Firm,
                detail: format!(
                    "Set-Cookie for '{name}' is missing: {}.",
                    missing.join(", ")
                ),
                param: Some(name),
            });
        }
    }
    v
}

/// Request parameter value reflected verbatim in a text response → candidate XSS.
fn reflected_input_hits(txn: &Transaction, body: &str, texty: bool) -> Vec<Hit> {
    if !texty || body.is_empty() {
        return Vec::new();
    }
    let mut v = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for (name, value) in request_params(txn) {
        // Avoid noise: short/numeric values reflect constantly and benignly.
        if value.len() < 4 || value.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if seen.contains(&name) {
            continue;
        }
        if body.contains(&value) {
            seen.push(name.clone());
            v.push(Hit {
                check_id: "reflected-input",
                title: format!("Reflected parameter '{name}'"),
                severity: Severity::Medium,
                confidence: Confidence::Tentative,
                detail: format!(
                    "The value of parameter '{name}' is reflected verbatim in the response body. \
                     Confirm whether it is HTML-encoded; if not, it may allow reflected XSS."
                ),
                param: Some(name),
            });
        }
    }
    v
}

/// Collect query-string and urlencoded-body parameters as (name, decoded value).
fn request_params(txn: &Transaction) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(q) = txn.request.query() {
        out.extend(parse_urlencoded(q));
    }
    let is_form = txn.request.header("content-type").is_some_and(|c| {
        c.to_ascii_lowercase()
            .contains("application/x-www-form-urlencoded")
    });
    if is_form {
        let body = String::from_utf8_lossy(&txn.request.body);
        out.extend(parse_urlencoded(&body));
    }
    out
}

fn parse_urlencoded(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| {
            let (k, val) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(k), percent_decode(val))
        })
        .collect()
}

/// Minimal application/x-www-form-urlencoded decode (`+` → space, `%XX`).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < bytes.len() => {
                let h = (hex(bytes[i + 1]), hex(bytes[i + 2]));
                if let (Some(a), Some(b)) = h {
                    out.push(a << 4 | b);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn info_disclosure_hits(resp: &crate::core::CapturedResponse) -> Vec<Hit> {
    let mut v = Vec::new();
    // A version-bearing Server/X-Powered-By banner leaks the stack.
    for header in ["server", "x-powered-by"] {
        if let Some(val) = resp.header(header)
            && val.chars().any(|c| c.is_ascii_digit())
        {
            v.push(Hit {
                check_id: if header == "server" {
                    "banner-server"
                } else {
                    "banner-powered-by"
                },
                title: format!("Version banner in {header}"),
                severity: Severity::Info,
                confidence: Confidence::Firm,
                detail: format!("The {header} header advertises a version ('{val}')."),
                param: None,
            });
        }
    }
    v
}

const STACK_SIGNATURES: &[&str] = &[
    "java.lang.",
    "Traceback (most recent call last)",
    "at System.",
    "System.NullReferenceException",
    "org.springframework.",
    ".php on line",
    "Warning: ",
    "Fatal error:",
    "ORA-0",
    "SQLSTATE[",
];

fn error_signature_hits(body: &str) -> Vec<Hit> {
    if body.is_empty() {
        return Vec::new();
    }
    if let Some(sig) = STACK_SIGNATURES.iter().find(|s| body.contains(**s)) {
        return vec![Hit {
            check_id: "stack-trace",
            title: "Stack trace / server error disclosed".into(),
            severity: Severity::Medium,
            confidence: Confidence::Firm,
            detail: format!(
                "The response body contains an error/stack-trace signature ('{sig}'), which can \
                 reveal internal paths, technologies and logic."
            ),
            param: None,
        }];
    }
    Vec::new()
}

fn mixed_content_hits(body: &str) -> Vec<Hit> {
    // An https page pulling http:// subresources (src=/href= to a plain-HTTP URL).
    let has_mixed = body.contains("src=\"http://")
        || body.contains("src='http://")
        || body.contains("href=\"http://")
        || body.contains("href='http://");
    if has_mixed {
        vec![Hit {
            check_id: "mixed-content",
            title: "Mixed content on an HTTPS page".into(),
            severity: Severity::Low,
            confidence: Confidence::Firm,
            detail: "An HTTPS page references subresources over plain HTTP, which browsers may \
                     block or which can be tampered with in transit."
                .into(),
            param: None,
        }]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{CapturedRequest, CapturedResponse};
    use bytes::Bytes;
    use std::time::Duration;

    fn txn(url: &str, ctype: &str, resp_headers: &[(&str, &str)], body: &[u8]) -> Transaction {
        let (rp, _) = hyper::Request::builder()
            .method("GET")
            .uri(url)
            .body(())
            .unwrap()
            .into_parts();
        let request = CapturedRequest::from_parts(
            1,
            "127.0.0.1:9000".parse().unwrap(),
            &rp,
            Bytes::new(),
            0,
            true,
        )
        .unwrap();
        let mut rb = hyper::Response::builder()
            .status(200)
            .header("content-type", ctype);
        for (k, val) in resp_headers {
            rb = rb.header(*k, *val);
        }
        let (sp, _) = rb.body(()).unwrap().into_parts();
        let response =
            CapturedResponse::from_parts(&sp, Bytes::copy_from_slice(body), body.len(), true);
        Transaction {
            request,
            response: Some(response),
            error: None,
            duration: Duration::from_millis(1),
        }
    }

    fn ids(hits: &[Hit]) -> Vec<&'static str> {
        hits.iter().map(|h| h.check_id).collect()
    }

    #[test]
    fn flags_missing_security_headers_on_html() {
        let t = txn("https://lab.test/", "text/html", &[], b"<html></html>");
        let got = ids(&run_checks(&t));
        for want in [
            "missing-csp",
            "missing-hsts",
            "missing-xcto",
            "missing-framing",
        ] {
            assert!(got.contains(&want), "expected {want} in {got:?}");
        }
    }

    #[test]
    fn full_headers_produce_no_header_findings() {
        let t = txn(
            "https://lab.test/",
            "text/html",
            &[
                (
                    "content-security-policy",
                    "default-src 'self'; frame-ancestors 'none'",
                ),
                ("strict-transport-security", "max-age=63072000"),
                ("x-content-type-options", "nosniff"),
            ],
            b"<html></html>",
        );
        let got = ids(&run_checks(&t));
        assert!(!got.contains(&"missing-csp"));
        assert!(!got.contains(&"missing-hsts"));
        assert!(!got.contains(&"missing-xcto"));
        assert!(
            !got.contains(&"missing-framing"),
            "CSP frame-ancestors covers framing"
        );
    }

    #[test]
    fn flags_insecure_cookies() {
        let t = txn(
            "https://lab.test/",
            "text/html",
            &[("set-cookie", "sid=abc; Path=/")],
            b"<html></html>",
        );
        let hit = run_checks(&t)
            .into_iter()
            .find(|h| h.check_id == "cookie-flags")
            .unwrap();
        assert_eq!(hit.param.as_deref(), Some("sid"));
        assert!(hit.title.contains("Secure"));
        assert!(hit.title.contains("HttpOnly"));
        assert!(hit.title.contains("SameSite"));
    }

    #[test]
    fn detects_reflected_query_parameter() {
        let t = txn(
            "https://lab.test/search?q=shrike_marker",
            "text/html",
            &[("content-security-policy", "x")],
            b"<html>results for shrike_marker here</html>",
        );
        let hit = run_checks(&t)
            .into_iter()
            .find(|h| h.check_id == "reflected-input");
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().param.as_deref(), Some("q"));
    }

    #[test]
    fn short_and_numeric_params_do_not_reflect() {
        let t = txn(
            "https://lab.test/search?p=12345&x=ab",
            "text/html",
            &[("content-security-policy", "x")],
            b"<html>12345 ab</html>",
        );
        assert!(
            run_checks(&t)
                .iter()
                .all(|h| h.check_id != "reflected-input")
        );
    }

    #[test]
    fn detects_stack_trace_and_banner() {
        let t = txn(
            "https://lab.test/x",
            "text/html",
            &[
                ("server", "Apache/2.4.1"),
                ("content-security-policy", "x"),
                ("strict-transport-security", "x"),
                ("x-content-type-options", "x"),
                ("x-frame-options", "DENY"),
            ],
            b"<html>java.lang.NullPointerException at ...</html>",
        );
        let got = ids(&run_checks(&t));
        assert!(got.contains(&"stack-trace"));
        assert!(got.contains(&"banner-server"));
    }

    #[test]
    fn detects_mixed_content_only_on_https() {
        let https = txn(
            "https://lab.test/",
            "text/html",
            &[("content-security-policy", "x")],
            b"<img src=\"http://cdn.test/a.png\">",
        );
        assert!(ids(&run_checks(&https)).contains(&"mixed-content"));
        let http = txn(
            "http://lab.test/",
            "text/html",
            &[],
            b"<img src=\"http://cdn.test/a.png\">",
        );
        assert!(!ids(&run_checks(&http)).contains(&"mixed-content"));
    }
}
