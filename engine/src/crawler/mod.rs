//! Crawler: a scope-gated spider that discovers content and feeds it into the
//! capture pipeline. It fetches with the shared [`Sender`] (so TLS, deadlines and
//! body-capture limits match the rest of Shrike), stays on the seed host and
//! honours the engagement scope's exclusions, and emits each fetched transaction
//! onto the ingest bus — so history, the site map and the passive scanner all see
//! crawled traffic as if it were proxied.
//!
//! Discovery is breadth-first in waves of up to `concurrency` fetches; it stops
//! at `max_pages`, when the frontier empties, or when cancelled.

use crate::core::{EventBus, Header, HttpService, TrafficEvent};
use crate::scope::Scope;
use crate::sender::{RequestSpec, Sender};
use hyper::Uri;
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::str::FromStr;
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, Ordering},
};
use tracing::warn;

/// Crawl tuning. Defaults come from `ProxyConfig`.
#[derive(Debug, Clone, Deserialize)]
pub struct CrawlOptions {
    pub concurrency: usize,
    pub delay_ms: u64,
    pub max_pages: usize,
}

/// Progress pushed to the UI during a crawl.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CrawlEvent {
    Progress {
        visited: usize,
        queued: usize,
        last_url: String,
    },
    Finished {
        visited: usize,
        stopped: bool,
    },
}

/// Run a crawl from `seed` until `max_pages`, an empty frontier, or cancellation.
pub async fn run_crawl(
    seed: String,
    sender: Arc<Sender>,
    scope: Arc<RwLock<Scope>>,
    bus: EventBus,
    stop: Arc<AtomicBool>,
    opts: CrawlOptions,
    sink: Arc<dyn Fn(CrawlEvent) + Send + Sync>,
) {
    let Some(seed_host) = host_of(&seed) else {
        sink(CrawlEvent::Finished {
            visited: 0,
            stopped: true,
        });
        return;
    };
    let concurrency = opts.concurrency.max(1);
    let max_pages = opts.max_pages.max(1);

    let mut frontier: VecDeque<String> = VecDeque::new();
    let mut seen: HashSet<String> = HashSet::new();
    let start = normalize(&seed);
    seen.insert(start.clone());
    frontier.push_back(start);

    let mut visited = 0usize;
    let mut next_id = 1u64;
    let mut stopped = false;

    while visited < max_pages && !frontier.is_empty() {
        if stop.load(Ordering::Relaxed) {
            stopped = true;
            break;
        }
        // Take up to `concurrency` URLs for this wave (respecting the page cap).
        let mut wave: Vec<String> = Vec::new();
        while wave.len() < concurrency && visited + wave.len() < max_pages {
            match frontier.pop_front() {
                Some(u) => wave.push(u),
                None => break,
            }
        }
        if wave.is_empty() {
            break;
        }

        let mut set = tokio::task::JoinSet::new();
        for url in wave {
            let Some(spec) = spec_for(&url) else { continue };
            let sender = Arc::clone(&sender);
            let bus = bus.clone();
            let id = next_id;
            next_id += 1;
            set.spawn(async move {
                match sender.send_transaction(spec, id, loopback()).await {
                    Ok(txn) => {
                        let links = extract_links(&url, &txn);
                        bus.emit(TrafficEvent::Completed(Arc::new(txn)));
                        (url, links)
                    }
                    Err(e) => {
                        warn!(url = %url, error = %e, "crawl fetch failed");
                        (url, Vec::new())
                    }
                }
            });
        }

        while let Some(res) = set.join_next().await {
            let Ok((url, links)) = res else { continue };
            visited += 1;
            for link in links {
                let n = normalize(&link);
                if seen.contains(&n) {
                    continue;
                }
                if allowed(&n, &seed_host, &scope) {
                    seen.insert(n.clone());
                    frontier.push_back(n);
                }
            }
            sink(CrawlEvent::Progress {
                visited,
                queued: frontier.len(),
                last_url: url,
            });
        }

        if opts.delay_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(opts.delay_ms)).await;
        }
    }

    sink(CrawlEvent::Finished { visited, stopped });
}

fn loopback() -> std::net::SocketAddr {
    "127.0.0.1:0".parse().expect("valid loopback addr")
}

/// Build a GET request spec for a URL, or `None` if it can't be parsed.
fn spec_for(url: &str) -> Option<RequestSpec> {
    let uri = Uri::from_str(url).ok()?;
    let service = HttpService::from_uri(&uri)?;
    let target = uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    Some(RequestSpec {
        service,
        method: "GET".into(),
        target,
        headers: vec![
            Header {
                name: "User-Agent".into(),
                value: "Shrike-Crawler".into(),
            },
            Header {
                name: "Accept".into(),
                value: "text/html,*/*".into(),
            },
        ],
        body: String::new(),
    })
}

/// Host (authority without userinfo/port) of a URL, lowercased.
fn host_of(url: &str) -> Option<String> {
    Uri::from_str(url)
        .ok()?
        .host()
        .map(|h| h.to_ascii_lowercase())
}

/// Drop the fragment; leave scheme/host/path/query intact.
fn normalize(url: &str) -> String {
    url.split('#').next().unwrap_or(url).trim().to_string()
}

/// A link is followed only if it is on the seed host and, when a scope is set,
/// in scope (so the operator's exclusions are honoured).
fn allowed(url: &str, seed_host: &str, scope: &RwLock<Scope>) -> bool {
    let Some(h) = host_of(url) else { return false };
    if !(h == seed_host) {
        return false;
    }
    let s = scope.read().expect("scope lock");
    s.is_empty() || s.in_scope_url(url)
}

const SKIP_SCHEMES: &[&str] = &["javascript:", "mailto:", "tel:", "data:", "#"];

/// Extract followable links from an HTML/text response: href/src/action values.
fn extract_links(base: &str, txn: &crate::core::Transaction) -> Vec<String> {
    let Some(resp) = txn.response.as_ref() else {
        return Vec::new();
    };
    let is_text = resp
        .content_type()
        .is_some_and(|c| c.contains("html") || c.contains("xml"));
    if !is_text {
        return Vec::new();
    }
    let body = String::from_utf8_lossy(&resp.body);
    let mut out = Vec::new();
    for attr in ["href=", "src=", "action="] {
        let mut rest = &*body;
        while let Some(i) = rest.find(attr) {
            rest = &rest[i + attr.len()..];
            let bytes = rest.as_bytes();
            let (quote, val) = match bytes.first() {
                Some(b'"') => ('"', &rest[1..]),
                Some(b'\'') => ('\'', &rest[1..]),
                _ => continue,
            };
            if let Some(end) = val.find(quote) {
                let raw = &val[..end];
                if !raw.is_empty()
                    && !SKIP_SCHEMES
                        .iter()
                        .any(|s| raw.to_ascii_lowercase().starts_with(s))
                    && let Some(abs) = resolve(base, raw)
                {
                    out.push(abs);
                }
                rest = &val[end + 1..];
            }
        }
    }
    out
}

/// Resolve a possibly-relative link against a base URL.
fn resolve(base: &str, link: &str) -> Option<String> {
    if link.starts_with("http://") || link.starts_with("https://") {
        return Some(link.to_string());
    }
    let base_uri = Uri::from_str(base).ok()?;
    let scheme = base_uri.scheme_str().unwrap_or("http");
    let authority = base_uri.authority()?.as_str();
    let origin = format!("{scheme}://{authority}");
    if let Some(rest) = link.strip_prefix("//") {
        return Some(format!("{scheme}://{rest}"));
    }
    if link.starts_with('/') {
        return Some(format!("{origin}{link}"));
    }
    // Relative to the base path's directory.
    let path = base_uri.path();
    let dir = match path.rfind('/') {
        Some(i) => &path[..=i],
        None => "/",
    };
    Some(format!("{origin}{dir}{link}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_relative_absolute_and_root_links() {
        let base = "https://lab.test/a/b/page.html";
        assert_eq!(
            resolve(base, "https://x.test/y").unwrap(),
            "https://x.test/y"
        );
        assert_eq!(resolve(base, "/top").unwrap(), "https://lab.test/top");
        assert_eq!(
            resolve(base, "sib.html").unwrap(),
            "https://lab.test/a/b/sib.html"
        );
        assert_eq!(
            resolve(base, "//cdn.test/x.js").unwrap(),
            "https://cdn.test/x.js"
        );
    }

    #[test]
    fn extracts_and_skips_non_navigational_links() {
        use crate::core::{CapturedRequest, CapturedResponse, Transaction};
        use bytes::Bytes;
        let (rp, _) = hyper::Request::builder()
            .method("GET")
            .uri("https://lab.test/")
            .body(())
            .unwrap()
            .into_parts();
        let request =
            CapturedRequest::from_parts(1, loopback(), &rp, Bytes::new(), 0, true).unwrap();
        let (sp, _) = hyper::Response::builder()
            .status(200)
            .header("content-type", "text/html")
            .body(())
            .unwrap()
            .into_parts();
        let html = br#"<a href="/login">x</a><script src="app.js"></script>
            <a href="javascript:void(0)">no</a><a href="mailto:a@b">no</a>
            <form action="https://lab.test/submit">"#;
        let response =
            CapturedResponse::from_parts(&sp, Bytes::from_static(html), html.len(), true);
        let txn = Transaction {
            request,
            response: Some(response),
            error: None,
            duration: std::time::Duration::from_millis(1),
        };
        let links = extract_links("https://lab.test/", &txn);
        assert!(links.contains(&"https://lab.test/login".to_string()));
        assert!(links.contains(&"https://lab.test/app.js".to_string()));
        assert!(links.contains(&"https://lab.test/submit".to_string()));
        assert!(
            !links
                .iter()
                .any(|l| l.contains("javascript") || l.contains("mailto"))
        );
    }

    #[test]
    fn scope_gates_to_seed_host() {
        let scope = RwLock::new(Scope::default());
        assert!(allowed("https://lab.test/x", "lab.test", &scope));
        assert!(!allowed("https://evil.test/x", "lab.test", &scope));
    }
}
