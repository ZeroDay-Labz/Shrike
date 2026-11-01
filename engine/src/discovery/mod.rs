//! Content discovery: brute-force paths and files against a target to surface
//! endpoints that aren't linked (admin panels, backups, API routes, config
//! files). A clean-room equivalent of ffuf/dirsearch, built on the same sender,
//! scope gate and concurrency bound as the active scanner.
//!
//! It sends traffic, so the caller scope-gates it. The signal problem — servers
//! that answer *everything* with a 200 or a soft-404 — is handled by probing a
//! couple of random paths first to learn the "not found" fingerprint, then
//! reporting only responses that deviate from it.

use crate::core::{Header, Transaction};
use crate::sender::{RequestSpec, Sender};
use serde::Serialize;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// Tuning for one content-discovery run.
#[derive(Debug, Clone)]
pub struct ContentDiscoveryConfig {
    pub concurrency: usize,
    /// Extensions to try for each word without one (e.g. `php`, `bak`, `json`).
    pub extensions: Vec<String>,
}

/// One discovered path worth the tester's attention.
#[derive(Debug, Clone, Serialize)]
pub struct ContentHit {
    /// Request path (relative to the host), e.g. `/admin`.
    pub path: String,
    pub status: u16,
    /// Response body length in bytes.
    pub length: usize,
    /// Approximate word count of a textual body (0 for binary/empty).
    pub words: usize,
    /// `Location` for a redirect, when present.
    pub redirect: Option<String>,
}

/// Progress pushed to the UI during a run.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DiscoveryEvent {
    /// The not-found fingerprint learned from random probes, for transparency.
    Baseline {
        status: Option<u16>,
        length: Option<usize>,
    },
    Found(ContentHit),
    Progress {
        done: usize,
        total: usize,
    },
    Finished {
        found: usize,
        stopped: bool,
    },
    Error {
        message: String,
    },
}

/// The learned "this path does not exist" fingerprint. A `None` status means the
/// random probes disagreed (an unpredictable server), so only clearly
/// interesting statuses are reported.
#[derive(Debug, Clone, Copy)]
struct Wildcard {
    status: Option<u16>,
    length: Option<usize>,
}

/// Run content discovery against `base` (its `target` is the base directory,
/// already confirmed in scope by the caller). `words` is the merged wordlist.
pub async fn run_content_discovery(
    base: RequestSpec,
    words: Vec<String>,
    sender: Arc<Sender>,
    stop: Arc<AtomicBool>,
    config: ContentDiscoveryConfig,
    sink: Arc<dyn Fn(DiscoveryEvent) + Send + Sync>,
) -> Vec<ContentHit> {
    let base_dir = base.target.trim_end_matches('/').to_string();

    // Learn the not-found fingerprint from two random, near-certainly-absent paths.
    let wildcard = probe_wildcard(&base, &base_dir, &sender).await;
    sink(DiscoveryEvent::Baseline {
        status: wildcard.status,
        length: wildcard.length,
    });

    let candidates = build_candidates(&words, &config.extensions);
    let total = candidates.len();
    if total == 0 {
        sink(DiscoveryEvent::Finished {
            found: 0,
            stopped: false,
        });
        return Vec::new();
    }

    let sem = Arc::new(Semaphore::new(config.concurrency.max(1)));
    let done = Arc::new(AtomicUsize::new(0));
    let mut set: JoinSet<Option<ContentHit>> = JoinSet::new();

    for cand in candidates {
        let target = join_path(&base_dir, &cand);
        let spec = probe_spec(&base, target.clone());
        let sender = Arc::clone(&sender);
        let sem = Arc::clone(&sem);
        let stop = Arc::clone(&stop);
        let done = Arc::clone(&done);
        let sink = Arc::clone(&sink);
        set.spawn(async move {
            if stop.load(Ordering::Relaxed) {
                return None;
            }
            let _permit = sem.acquire().await.ok()?;
            if stop.load(Ordering::Relaxed) {
                return None;
            }
            let hit = match sender.send_transaction(spec, 0, loopback()).await {
                Ok(txn) => classify(&target, &wildcard, &txn),
                Err(_) => None,
            };
            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            sink(DiscoveryEvent::Progress { done: n, total });
            if let Some(h) = &hit {
                sink(DiscoveryEvent::Found(h.clone()));
            }
            hit
        });
    }

    let mut hits: Vec<ContentHit> = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(Some(hit)) = res {
            hits.push(hit);
        }
    }
    hits.sort_by(|a, b| a.path.cmp(&b.path));
    let stopped = stop.load(Ordering::Relaxed);
    sink(DiscoveryEvent::Finished {
        found: hits.len(),
        stopped,
    });
    hits
}

/// Probe two random paths to learn the not-found fingerprint.
async fn probe_wildcard(base: &RequestSpec, base_dir: &str, sender: &Sender) -> Wildcard {
    let mut statuses = Vec::new();
    let mut lengths = Vec::new();
    for tag in ["shrike-x9q2znope", "shrike-7k3whoami404"] {
        let target = join_path(base_dir, tag);
        if let Ok(txn) = sender
            .send_transaction(probe_spec(base, target), 0, loopback())
            .await
            && let Some(resp) = txn.response.as_ref()
        {
            statuses.push(resp.status);
            lengths.push(resp.body.len());
        }
    }
    // A stable status across both random probes is the catch-all / soft-404.
    let status = match statuses.as_slice() {
        [a, b] if a == b => Some(*a),
        _ => None,
    };
    let length = if status.is_some() {
        lengths.first().copied()
    } else {
        None
    };
    Wildcard { status, length }
}

/// Decide whether a response is a real hit versus the not-found fingerprint.
fn classify(target: &str, wildcard: &Wildcard, txn: &Transaction) -> Option<ContentHit> {
    let resp = txn.response.as_ref()?;
    let status = resp.status;
    // An explicit 404 is never a hit.
    if status == 404 {
        return None;
    }
    let len = resp.body.len();
    let interesting = match wildcard.status {
        Some(ws) if ws == status => {
            // Same status as the catch-all — only a hit if the body length clearly
            // differs (a soft-404 page vs. real content).
            match wildcard.length {
                Some(wl) => diff_material(len, wl),
                None => false,
            }
        }
        // A different status than the catch-all is interesting.
        Some(_) => true,
        // No stable fingerprint: report only clearly meaningful statuses.
        None => is_interesting_status(status),
    };
    if !interesting {
        return None;
    }
    let redirect = resp
        .header("location")
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());
    Some(ContentHit {
        path: target.to_string(),
        status,
        length: len,
        words: word_count(&resp.body),
        redirect,
    })
}

/// Body length differs enough from the catch-all to be real content, not noise.
fn diff_material(len: usize, wildcard_len: usize) -> bool {
    let delta = len.abs_diff(wildcard_len);
    delta > (wildcard_len / 20).max(32)
}

fn is_interesting_status(status: u16) -> bool {
    matches!(
        status,
        200 | 201 | 202 | 204 | 301 | 302 | 307 | 308 | 401 | 403 | 405 | 500 | 501 | 503
    )
}

/// Expand the wordlist into concrete candidates: each word as-is, plus an
/// extension variant for each configured extension when the word has none.
fn build_candidates(words: &[String], extensions: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for raw in words {
        let w = raw.trim().trim_start_matches('/');
        if w.is_empty() || w.starts_with('#') {
            continue;
        }
        if seen.insert(w.to_string()) {
            out.push(w.to_string());
        }
        if !w.contains('.') {
            for ext in extensions {
                let ext = ext.trim().trim_start_matches('.');
                if ext.is_empty() {
                    continue;
                }
                let cand = format!("{w}.{ext}");
                if seen.insert(cand.clone()) {
                    out.push(cand);
                }
            }
        }
    }
    out
}

/// Join a base directory and a candidate into a request path with single slashes.
fn join_path(base_dir: &str, cand: &str) -> String {
    let cand = cand.trim_start_matches('/');
    let base = base_dir.trim_end_matches('/');
    if base.is_empty() {
        format!("/{cand}")
    } else {
        format!("{base}/{cand}")
    }
}

/// A GET probe for `target`, reusing the base's service and headers (minus any
/// body — discovery is GET-only). Ensures a User-Agent so servers don't 400.
fn probe_spec(base: &RequestSpec, target: String) -> RequestSpec {
    let mut headers: Vec<Header> = base
        .headers
        .iter()
        .filter(|h| {
            let n = h.name.to_ascii_lowercase();
            n != "content-length" && n != "content-type"
        })
        .cloned()
        .collect();
    if !headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("user-agent"))
    {
        headers.push(Header {
            name: "User-Agent".into(),
            value: "Shrike".into(),
        });
    }
    RequestSpec {
        service: base.service.clone(),
        method: "GET".into(),
        target,
        headers,
        body: String::new(),
    }
}

fn word_count(body: &[u8]) -> usize {
    match std::str::from_utf8(body) {
        Ok(s) => s.split_whitespace().count(),
        Err(_) => 0,
    }
}

fn loopback() -> std::net::SocketAddr {
    "127.0.0.1:0".parse().expect("valid loopback addr")
}

/// A compact built-in list of common directories and files worth checking on
/// almost any web target. The UI can append the tester's own words.
pub const DEFAULT_WORDLIST: &[&str] = &[
    "admin",
    "administrator",
    "login",
    "logout",
    "signin",
    "signup",
    "register",
    "account",
    "dashboard",
    "panel",
    "cpanel",
    "console",
    "manage",
    "manager",
    "portal",
    "secure",
    "api",
    "api/v1",
    "api/v2",
    "graphql",
    "graphiql",
    "rest",
    "swagger",
    "swagger-ui",
    "openapi.json",
    "swagger.json",
    "docs",
    "doc",
    "documentation",
    "redoc",
    "app",
    "apps",
    "static",
    "assets",
    "public",
    "private",
    "internal",
    "uploads",
    "upload",
    "files",
    "file",
    "download",
    "downloads",
    "media",
    "images",
    "img",
    "css",
    "js",
    "scripts",
    "backup",
    "backups",
    "bak",
    "old",
    "new",
    "temp",
    "tmp",
    "test",
    "tests",
    "testing",
    "dev",
    "development",
    "stage",
    "staging",
    "prod",
    "production",
    "demo",
    "sandbox",
    "config",
    "configuration",
    "settings",
    "setup",
    "install",
    "installer",
    "init",
    "db",
    "database",
    "sql",
    "data",
    "dump",
    "export",
    "import",
    "logs",
    "log",
    "status",
    "health",
    "healthz",
    "metrics",
    "monitor",
    "monitoring",
    "debug",
    "info",
    "phpinfo",
    "server-status",
    "server-info",
    "actuator",
    "actuator/health",
    "actuator/env",
    ".git",
    ".git/config",
    ".git/HEAD",
    ".svn",
    ".env",
    ".htaccess",
    ".htpasswd",
    "robots.txt",
    "sitemap.xml",
    "crossdomain.xml",
    "security.txt",
    ".well-known/security.txt",
    "web.config",
    "composer.json",
    "package.json",
    "yarn.lock",
    "composer.lock",
    "wp-admin",
    "wp-login.php",
    "wp-content",
    "wp-json",
    "xmlrpc.php",
    "user",
    "users",
    "profile",
    "profiles",
    "member",
    "members",
    "customer",
    "customers",
    "search",
    "cart",
    "checkout",
    "order",
    "orders",
    "payment",
    "payments",
    "invoice",
    "report",
    "reports",
    "analytics",
    "stats",
    "statistics",
    "auth",
    "oauth",
    "sso",
    "token",
    "tokens",
    "session",
    "sessions",
    "password",
    "reset",
    "forgot",
    "verify",
    "activate",
    "callback",
    "connect",
    "v1",
    "v2",
    "v3",
    "beta",
    "alpha",
    "legacy",
    "mobile",
    "m",
    "ajax",
    "json",
    "xml",
    "rss",
    "feed",
    "feeds",
    "webhook",
    "webhooks",
    "notify",
    "notifications",
    "cgi-bin",
    "bin",
    "lib",
    "src",
    "vendor",
    "node_modules",
    "includes",
    "inc",
    "error",
    "errors",
    "404",
    "500",
    "maintenance",
    "coming-soon",
    "index",
    "home",
    "main",
    "about",
    "contact",
    "help",
    "support",
    "faq",
    "terms",
    "privacy",
    "sitemap",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{CapturedResponse, HttpService};
    use std::time::{Duration, SystemTime};

    fn resp(status: u16, body: &str) -> CapturedResponse {
        CapturedResponse {
            status,
            version: "HTTP/1.1".into(),
            headers: vec![],
            body: body.as_bytes().to_vec().into(),
            body_len: body.len(),
            body_complete: true,
            received_at: SystemTime::now(),
        }
    }

    fn txn(status: u16, body: &str) -> Transaction {
        Transaction {
            request: crate::core::CapturedRequest {
                id: 0,
                client_addr: loopback(),
                service: HttpService {
                    host: "t".into(),
                    port: 443,
                    secure: true,
                },
                method: "GET".into(),
                target: "/x".into(),
                version: "HTTP/1.1".into(),
                headers: vec![],
                body: Vec::new().into(),
                body_len: 0,
                body_complete: true,
                started_at: SystemTime::now(),
                highlight: None,
            },
            response: Some(resp(status, body)),
            error: None,
            duration: Duration::from_millis(1),
        }
    }

    #[test]
    fn explicit_404_is_never_a_hit() {
        let w = Wildcard {
            status: Some(404),
            length: Some(20),
        };
        assert!(classify("/x", &w, &txn(404, "not found here")).is_none());
    }

    #[test]
    fn different_status_than_catch_all_is_a_hit() {
        let w = Wildcard {
            status: Some(404),
            length: Some(20),
        };
        let hit = classify("/admin", &w, &txn(200, "welcome admin panel")).unwrap();
        assert_eq!(hit.status, 200);
        assert_eq!(hit.path, "/admin");
        assert!(hit.words >= 3);
    }

    #[test]
    fn soft_404_same_length_is_suppressed_but_real_content_passes() {
        // Catch-all returns 200 with a ~40-byte page.
        let w = Wildcard {
            status: Some(200),
            length: Some(40),
        };
        // A page of the same size is noise.
        assert!(classify("/nope", &w, &txn(200, &"x".repeat(40))).is_none());
        // A clearly larger page is real content.
        assert!(classify("/real", &w, &txn(200, &"x".repeat(4000))).is_some());
    }

    #[test]
    fn unstable_server_reports_only_interesting_statuses() {
        let w = Wildcard {
            status: None,
            length: None,
        };
        assert!(classify("/a", &w, &txn(200, "ok")).is_some());
        assert!(classify("/b", &w, &txn(302, "")).is_some());
        assert!(classify("/c", &w, &txn(418, "teapot")).is_none());
    }

    #[test]
    fn candidates_expand_extensions_and_dedupe() {
        let words = vec!["admin".into(), "robots.txt".into(), "admin".into()];
        let exts = vec!["php".into(), "bak".into()];
        let c = build_candidates(&words, &exts);
        assert!(c.contains(&"admin".to_string()));
        assert!(c.contains(&"admin.php".to_string()));
        assert!(c.contains(&"admin.bak".to_string()));
        // A word that already has an extension gets no further variants.
        assert!(c.contains(&"robots.txt".to_string()));
        assert!(!c.contains(&"robots.txt.php".to_string()));
        // Deduped despite the repeat.
        assert_eq!(c.iter().filter(|x| *x == "admin").count(), 1);
    }

    #[test]
    fn join_path_normalises_slashes() {
        assert_eq!(join_path("", "admin"), "/admin");
        assert_eq!(join_path("/", "admin"), "/admin");
        assert_eq!(join_path("/app", "admin"), "/app/admin");
        assert_eq!(join_path("/app/", "/admin"), "/app/admin");
    }

    #[test]
    fn default_wordlist_is_unique() {
        let mut seen = HashSet::new();
        for w in DEFAULT_WORDLIST {
            assert!(seen.insert(*w), "duplicate default word: {w}");
        }
        assert!(DEFAULT_WORDLIST.len() > 150);
    }
}
