//! Native hidden-parameter discovery — a clean-room equivalent of param-miner.
//!
//! Brute-forces a wordlist of likely parameter names against a request and flags
//! the ones the server actually reacts to: the probe value reflected back in the
//! response, or the status code changing versus a baseline. Those are the
//! high-signal tells that an undocumented parameter is being processed. (Body-
//! length diffing is deliberately left out of this first version — it is noisy on
//! dynamic pages and would produce false positives.)

use super::Hit;
use crate::findings::{Confidence, Severity};
use crate::scanner::ActiveScanEvent;
use crate::sender::{RequestSpec, Sender};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::Semaphore;

/// A marker unlikely to occur naturally in a response, so seeing it reflected is
/// a reliable sign the probed parameter was processed.
const CANARY: &str = "zqx7shrikeprm";

#[derive(Debug, Clone, Copy)]
pub struct ParamMinerConfig {
    pub concurrency: usize,
}

/// Where a candidate parameter is injected.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Where {
    Query,
    Body,
}

/// Curated list of common, interesting and often-undocumented parameter names
/// (debug/feature flags, auth, redirects, formats, pagination, admin toggles).
/// Extensible; a larger wordlist can be layered on later.
const WORDLIST: &[&str] = &[
    "debug",
    "test",
    "admin",
    "adminmode",
    "verbose",
    "trace",
    "dev",
    "development",
    "edit",
    "preview",
    "draft",
    "beta",
    "feature",
    "flag",
    "flags",
    "enable",
    "disable",
    "id",
    "user",
    "userid",
    "uid",
    "account",
    "customer",
    "profile",
    "role",
    "group",
    "token",
    "access_token",
    "auth",
    "authorization",
    "apikey",
    "api_key",
    "key",
    "session",
    "sessionid",
    "sid",
    "secret",
    "password",
    "passwd",
    "pwd",
    "redirect",
    "redirect_uri",
    "redirect_url",
    "url",
    "next",
    "return",
    "returnurl",
    "return_url",
    "continue",
    "dest",
    "destination",
    "goto",
    "callback",
    "jsonp",
    "format",
    "output",
    "type",
    "mode",
    "view",
    "action",
    "do",
    "op",
    "cmd",
    "command",
    "page",
    "limit",
    "offset",
    "per_page",
    "perpage",
    "count",
    "size",
    "start",
    "end",
    "sort",
    "order",
    "orderby",
    "filter",
    "query",
    "q",
    "search",
    "keyword",
    "term",
    "lang",
    "language",
    "locale",
    "country",
    "currency",
    "timezone",
    "file",
    "filename",
    "path",
    "dir",
    "folder",
    "name",
    "title",
    "content",
    "data",
    "json",
    "xml",
    "raw",
    "pretty",
    "fields",
    "include",
    "exclude",
    "expand",
    "embed",
    "force",
    "override",
    "bypass",
    "skip",
    "all",
    "show",
    "hide",
    "include_deleted",
    "cache",
    "nocache",
    "refresh",
    "reload",
    "version",
    "v",
    "api_version",
    "impersonate",
    "as_user",
    "sudo",
    "run_as",
    "internal",
    "is_admin",
    "superuser",
    "email",
    "username",
    "login",
    "phone",
    "code",
    "otp",
    "pin",
    "state",
    "nonce",
    "status",
    "active",
    "enabled",
    "visible",
    "public",
    "private",
    "hidden",
];

/// Discover hidden parameters on `base` (already confirmed in scope by the caller).
/// Honours `stop` and bounds concurrency. Returns one hit per reacting parameter.
pub async fn run_param_discovery(
    base: RequestSpec,
    sender: Arc<Sender>,
    stop: Arc<AtomicBool>,
    config: ParamMinerConfig,
    sink: Arc<dyn Fn(ActiveScanEvent) + Send + Sync>,
) -> Vec<Hit> {
    // Baseline: the request as-is, so we can tell a reacting parameter from the
    // page's normal response.
    let baseline = match sender.send_transaction(base.clone(), 0, loopback()).await {
        Ok(txn) => txn,
        Err(e) => {
            sink(ActiveScanEvent::Error {
                message: format!("parameter discovery could not reach the target: {e}"),
            });
            sink(ActiveScanEvent::Finished {
                findings: 0,
                stopped: false,
            });
            return Vec::new();
        }
    };
    let base_status = baseline.response.as_ref().map(|r| r.status);
    let base_body = baseline
        .response
        .as_ref()
        .map(|r| String::from_utf8_lossy(&r.body).into_owned())
        .unwrap_or_default();
    // If the canary already appears in the untouched response, reflection is not a
    // usable signal here — fall back to status-change only.
    let canary_usable = !base_body.contains(CANARY);

    // Where to inject: the query always; the urlencoded body too when present.
    let mut places = vec![Where::Query];
    if is_urlencoded(&base) {
        places.push(Where::Body);
    }
    let total = WORDLIST.len() * places.len();
    if total == 0 {
        sink(ActiveScanEvent::Finished {
            findings: 0,
            stopped: false,
        });
        return Vec::new();
    }

    let sem = Arc::new(Semaphore::new(config.concurrency.max(1)));
    let done = Arc::new(AtomicUsize::new(0));
    let mut set = tokio::task::JoinSet::new();

    for place in places {
        for name in WORDLIST {
            let spec = inject(&base, place, name, CANARY);
            let sender = Arc::clone(&sender);
            let sem = Arc::clone(&sem);
            let stop = Arc::clone(&stop);
            let done = Arc::clone(&done);
            let sink = Arc::clone(&sink);
            let name = *name;
            set.spawn(async move {
                if stop.load(Ordering::Relaxed) {
                    return None;
                }
                let _permit = sem.acquire().await.ok()?;
                if stop.load(Ordering::Relaxed) {
                    return None;
                }
                let hit = match sender.send_transaction(spec, 0, loopback()).await {
                    Ok(txn) => classify(name, place, base_status, canary_usable, &txn),
                    Err(_) => None,
                };
                let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                sink(ActiveScanEvent::Progress { done: n, total });
                hit
            });
        }
    }

    let mut hits: Vec<Hit> = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(Some(hit)) = res
            && !hits.iter().any(|h| h.param == hit.param)
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

/// Decide whether a probe response shows the server reacting to `name`.
fn classify(
    name: &str,
    place: Where,
    base_status: Option<u16>,
    canary_usable: bool,
    txn: &crate::core::Transaction,
) -> Option<Hit> {
    let resp = txn.response.as_ref()?;
    let body = String::from_utf8_lossy(&resp.body);
    let reflected = canary_usable && body.contains(CANARY);
    let status_changed = base_status.is_some_and(|s| s != resp.status);
    if !reflected && !status_changed {
        return None;
    }
    let loc = match place {
        Where::Query => "query string",
        Where::Body => "request body",
    };
    let (confidence, why) = if reflected {
        (
            Confidence::Firm,
            format!("its value was reflected in the response when sent in the {loc}"),
        )
    } else {
        (
            Confidence::Tentative,
            format!(
                "the response status changed (from {} to {}) when it was sent in the {loc}",
                base_status
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "none".into()),
                resp.status,
            ),
        )
    };
    Some(Hit {
        check_id: "hidden-parameter",
        title: format!("Hidden parameter: '{name}'"),
        severity: Severity::Info,
        confidence,
        detail: format!(
            "The server appears to process an undocumented parameter '{name}': {why}. \
             Investigate what it controls — hidden parameters often expose debug modes, \
             access controls or injection points."
        ),
        param: Some(name.to_string()),
    })
}

/// Build `base` with `name=value` added to the query or urlencoded body.
fn inject(base: &RequestSpec, place: Where, name: &str, value: &str) -> RequestSpec {
    let mut out = base.clone();
    match place {
        Where::Query => {
            let (path, query) = match out.target.split_once('?') {
                Some((p, q)) => (p.to_string(), q.to_string()),
                None => (out.target.clone(), String::new()),
            };
            let pair = format!("{name}={value}");
            let query = if query.is_empty() {
                pair
            } else {
                format!("{query}&{pair}")
            };
            out.target = format!("{path}?{query}");
        }
        Where::Body => {
            let pair = format!("{name}={value}");
            out.body = if out.body.is_empty() {
                pair
            } else {
                format!("{}&{pair}", out.body)
            };
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

fn loopback() -> std::net::SocketAddr {
    "127.0.0.1:0".parse().expect("valid loopback addr")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{Header, HttpService};

    fn spec(target: &str, ctype: Option<&str>, body: &str) -> RequestSpec {
        RequestSpec {
            service: HttpService {
                host: "lab.test".into(),
                port: 443,
                secure: true,
            },
            method: "GET".into(),
            target: target.into(),
            headers: ctype
                .map(|c| {
                    vec![Header {
                        name: "Content-Type".into(),
                        value: c.into(),
                    }]
                })
                .unwrap_or_default(),
            body: body.into(),
        }
    }

    #[test]
    fn inject_appends_query_param_with_and_without_existing_query() {
        let s = inject(&spec("/app", None, ""), Where::Query, "debug", "X");
        assert_eq!(s.target, "/app?debug=X");
        let s = inject(&spec("/app?a=1", None, ""), Where::Query, "debug", "X");
        assert_eq!(s.target, "/app?a=1&debug=X");
    }

    #[test]
    fn inject_appends_body_param_for_urlencoded() {
        let s = inject(
            &spec("/app", Some("application/x-www-form-urlencoded"), "a=1"),
            Where::Body,
            "debug",
            "X",
        );
        assert_eq!(s.body, "a=1&debug=X");
    }

    #[test]
    fn body_injection_only_when_urlencoded() {
        assert!(is_urlencoded(&spec(
            "/",
            Some("application/x-www-form-urlencoded"),
            ""
        )));
        assert!(!is_urlencoded(&spec("/", Some("application/json"), "")));
        assert!(!is_urlencoded(&spec("/", None, "")));
    }

    #[test]
    fn wordlist_is_non_trivial_and_unique() {
        assert!(WORDLIST.len() > 80);
        let mut seen = std::collections::HashSet::new();
        for w in WORDLIST {
            assert!(seen.insert(*w), "duplicate wordlist entry: {w}");
        }
    }
}
