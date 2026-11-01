//! Templated scanner: a matcher/extractor engine driven by data, not code.
//!
//! A *template* describes one or more HTTP requests and the matchers that decide
//! whether the response indicates an issue. This lets a tester (or the wider
//! community) add detections — exposed files, known CVE fingerprints, default
//! credentials pages, misconfig tells — by dropping a JSON file in the templates
//! directory, with no Rust to write. The schema is Shrike's own, clean-room, and
//! JSON (not a third-party template format), but the shape — request + matchers
//! (word/regex/status) with and/or conditions + extractors — is the familiar one.
//!
//! Like the active scanner it sends traffic, so the caller scope-gates it; runs
//! are concurrency-bounded and abortable, and matches become Findings.

use crate::core::{Header, Transaction};
use crate::sender::{RequestSpec, Sender};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

/// Which part of the response a matcher/extractor inspects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Part {
    #[default]
    Body,
    Header,
    All,
}

/// How the terms within one matcher combine, or how matchers combine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Cond {
    And,
    Or,
}

fn cond_or() -> Cond {
    Cond::Or
}
fn cond_and() -> Cond {
    Cond::And
}
fn default_method() -> String {
    "GET".to_string()
}

/// One condition on a response.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Matcher {
    /// The response status is one of these.
    Status { status: Vec<u16> },
    /// Literal substrings in `part`, combined by `condition`.
    Word {
        #[serde(default)]
        part: Part,
        words: Vec<String>,
        #[serde(default = "cond_or")]
        condition: Cond,
        #[serde(default)]
        negative: bool,
        #[serde(default)]
        case_insensitive: bool,
    },
    /// Regular expressions against `part`, combined by `condition`.
    Regex {
        #[serde(default)]
        part: Part,
        regex: Vec<String>,
        #[serde(default = "cond_or")]
        condition: Cond,
        #[serde(default)]
        negative: bool,
    },
}

/// Pulls a value out of a matched response, for finding context.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Extractor {
    Regex {
        #[serde(default)]
        part: Part,
        regex: Vec<String>,
        #[serde(default = "one")]
        group: usize,
    },
    Word {
        #[serde(default)]
        part: Part,
        words: Vec<String>,
    },
}

fn one() -> usize {
    1
}

/// One request in a template: the paths to hit and how to judge the response.
#[derive(Debug, Clone, Deserialize)]
pub struct TemplateRequest {
    #[serde(default = "default_method")]
    pub method: String,
    /// Paths to request; each supports `{{BaseURL}}`/`{{Hostname}}`/`{{Host}}`.
    pub paths: Vec<String>,
    #[serde(default)]
    pub headers: Vec<Header>,
    #[serde(default)]
    pub body: String,
    #[serde(default = "cond_and")]
    pub matchers_condition: Cond,
    #[serde(default)]
    pub matchers: Vec<Matcher>,
    #[serde(default)]
    pub extractors: Vec<Extractor>,
}

/// Template metadata.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Info {
    pub name: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// A detection template.
#[derive(Debug, Clone, Deserialize)]
pub struct Template {
    pub id: String,
    pub info: Info,
    /// Requests to run (accepts `requests` or `http` as the key).
    #[serde(default, alias = "http")]
    pub requests: Vec<TemplateRequest>,
}

/// Template metadata for the UI list (no request internals).
#[derive(Debug, Clone, Serialize)]
pub struct TemplateSummary {
    pub id: String,
    pub name: String,
    pub severity: String,
    pub author: String,
    pub description: String,
    pub tags: Vec<String>,
    /// True for a template shipped with Shrike (vs. one loaded from disk).
    pub builtin: bool,
}

impl Template {
    pub fn summary(&self, builtin: bool) -> TemplateSummary {
        TemplateSummary {
            id: self.id.clone(),
            name: self.info.name.clone(),
            severity: self.info.severity.clone(),
            author: self.info.author.clone(),
            description: self.info.description.clone(),
            tags: self.info.tags.clone(),
            builtin,
        }
    }
}

/// One template hit against a target.
#[derive(Debug, Clone, Serialize)]
pub struct TemplateMatch {
    pub template_id: String,
    pub name: String,
    pub severity: String,
    /// The request path that matched.
    pub path: String,
    /// Values pulled by the template's extractors.
    pub extracted: Vec<String>,
}

/// Progress pushed to the UI during a run.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TemplateEvent {
    Match(TemplateMatch),
    Progress { done: usize, total: usize },
    Finished { matched: usize, stopped: bool },
    Error { message: String },
}

#[derive(Debug, Clone)]
pub struct TemplateScanConfig {
    pub concurrency: usize,
}

/// Load the built-in templates plus any `*.json` templates in `user_dir`.
/// A template that fails to parse is skipped (its error returned alongside), so
/// one bad file never stops the rest from loading.
pub fn load_templates(
    user_dir: &std::path::Path,
) -> (Vec<Arc<Template>>, Vec<Arc<Template>>, Vec<String>) {
    let mut errors = Vec::new();
    let builtin: Vec<Arc<Template>> = BUILTIN_TEMPLATES
        .iter()
        .filter_map(|src| match serde_json::from_str::<Template>(src) {
            Ok(t) => Some(Arc::new(t)),
            Err(e) => {
                errors.push(format!("built-in template parse error: {e}"));
                None
            }
        })
        .collect();

    let mut user = Vec::new();
    if let Ok(entries) = std::fs::read_dir(user_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            match std::fs::read_to_string(&path)
                .map_err(|e| e.to_string())
                .and_then(|s| serde_json::from_str::<Template>(&s).map_err(|e| e.to_string()))
            {
                Ok(t) => user.push(Arc::new(t)),
                Err(e) => errors.push(format!("{}: {e}", path.display())),
            }
        }
    }
    (builtin, user, errors)
}

/// Run `templates` against a target. `base_url` is the interpolation root
/// (`scheme://host[:port]`, no trailing slash) and `service` the sender target.
pub async fn run_templates(
    base_url: String,
    service: crate::core::HttpService,
    templates: Vec<Arc<Template>>,
    sender: Arc<Sender>,
    stop: Arc<AtomicBool>,
    config: TemplateScanConfig,
    sink: Arc<dyn Fn(TemplateEvent) + Send + Sync>,
) -> Vec<TemplateMatch> {
    // Flatten to (template, request, path) units so progress is per request sent.
    let mut units: Vec<(Arc<Template>, usize, String)> = Vec::new();
    for t in &templates {
        for (ri, req) in t.requests.iter().enumerate() {
            for p in &req.paths {
                units.push((Arc::clone(t), ri, p.clone()));
            }
        }
    }
    let total = units.len();
    if total == 0 {
        sink(TemplateEvent::Finished {
            matched: 0,
            stopped: false,
        });
        return Vec::new();
    }

    let sem = Arc::new(Semaphore::new(config.concurrency.max(1)));
    let done = Arc::new(AtomicUsize::new(0));
    let mut set: JoinSet<Option<TemplateMatch>> = JoinSet::new();

    for (tpl, ri, raw_path) in units {
        let base_url = base_url.clone();
        let service = service.clone();
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
            let req = &tpl.requests[ri];
            let target = target_from(&base_url, &service, &raw_path);
            let spec = RequestSpec {
                service: service.clone(),
                method: req.method.clone(),
                target: target.clone(),
                headers: req.headers.clone(),
                body: req.body.clone(),
            };
            let hit = match sender.send_transaction(spec, 0, loopback()).await {
                Ok(txn) => eval_request(&tpl, req, &target, &txn),
                Err(_) => None,
            };
            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            sink(TemplateEvent::Progress { done: n, total });
            if let Some(m) = &hit {
                sink(TemplateEvent::Match(m.clone()));
            }
            hit
        });
    }

    let mut matches: Vec<TemplateMatch> = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(Some(m)) = res {
            matches.push(m);
        }
    }
    matches.sort_by(|a, b| a.template_id.cmp(&b.template_id).then(a.path.cmp(&b.path)));
    let stopped = stop.load(Ordering::Relaxed);
    sink(TemplateEvent::Finished {
        matched: matches.len(),
        stopped,
    });
    matches
}

/// Evaluate a template request against one response; `Some` with any extracted
/// values when it matched per `matchers_condition`.
fn eval_request(
    tpl: &Template,
    req: &TemplateRequest,
    path: &str,
    txn: &Transaction,
) -> Option<TemplateMatch> {
    let resp = txn.response.as_ref()?;
    let status = resp.status;
    let body = String::from_utf8_lossy(&resp.body);
    let header_blob = headers_blob(&resp.headers);
    let all = format!("{header_blob}\n{body}");

    if req.matchers.is_empty() {
        return None; // a request with no matchers never "matches"
    }
    let mut results = req
        .matchers
        .iter()
        .map(|m| eval_matcher(m, status, &body, &header_blob, &all));
    let matched = match req.matchers_condition {
        Cond::And => results.all(|r| r),
        Cond::Or => results.any(|r| r),
    };
    if !matched {
        return None;
    }
    let extracted = req
        .extractors
        .iter()
        .flat_map(|e| run_extractor(e, &body, &header_blob, &all))
        .collect();
    Some(TemplateMatch {
        template_id: tpl.id.clone(),
        name: tpl.info.name.clone(),
        severity: tpl.info.severity.clone(),
        path: path.to_string(),
        extracted,
    })
}

fn eval_matcher(m: &Matcher, status: u16, body: &str, header: &str, all: &str) -> bool {
    match m {
        Matcher::Status { status: want } => want.contains(&status),
        Matcher::Word {
            part,
            words,
            condition,
            negative,
            case_insensitive,
        } => {
            let hay = pick(*part, body, header, all);
            let (hay_cmp, needles_owned);
            let needles: Vec<&str> = if *case_insensitive {
                hay_cmp = hay.to_ascii_lowercase();
                needles_owned = words
                    .iter()
                    .map(|w| w.to_ascii_lowercase())
                    .collect::<Vec<_>>();
                needles_owned.iter().map(String::as_str).collect()
            } else {
                hay_cmp = hay.to_string();
                words.iter().map(String::as_str).collect()
            };
            let hit = combine(*condition, needles.iter().map(|n| hay_cmp.contains(*n)));
            hit ^ *negative
        }
        Matcher::Regex {
            part,
            regex,
            condition,
            negative,
        } => {
            let hay = pick(*part, body, header, all);
            let hit = combine(
                *condition,
                regex.iter().map(|r| {
                    regex::Regex::new(r)
                        .map(|re| re.is_match(hay))
                        .unwrap_or(false)
                }),
            );
            hit ^ *negative
        }
    }
}

fn run_extractor(e: &Extractor, body: &str, header: &str, all: &str) -> Vec<String> {
    match e {
        Extractor::Regex { part, regex, group } => {
            let hay = pick(*part, body, header, all);
            let mut out = Vec::new();
            for r in regex {
                if let Ok(re) = regex::Regex::new(r) {
                    for caps in re.captures_iter(hay) {
                        if let Some(g) = caps.get(*group).or_else(|| caps.get(0)) {
                            out.push(g.as_str().to_string());
                        }
                    }
                }
            }
            out
        }
        Extractor::Word { part, words } => {
            let hay = pick(*part, body, header, all);
            words
                .iter()
                .filter(|w| hay.contains(w.as_str()))
                .cloned()
                .collect()
        }
    }
}

fn pick<'a>(part: Part, body: &'a str, header: &'a str, all: &'a str) -> &'a str {
    match part {
        Part::Body => body,
        Part::Header => header,
        Part::All => all,
    }
}

fn combine(cond: Cond, mut it: impl Iterator<Item = bool>) -> bool {
    match cond {
        Cond::And => it.all(|b| b),
        Cond::Or => it.any(|b| b),
    }
}

fn headers_blob(headers: &[Header]) -> String {
    let mut s = String::new();
    for h in headers {
        s.push_str(&h.name);
        s.push_str(": ");
        s.push_str(&h.value);
        s.push('\n');
    }
    s
}

/// Interpolate a template path and reduce it to a request target (path + query).
/// Accepts a full `{{BaseURL}}/x` or a bare `/x`; a cross-host absolute URL is
/// reduced to its path+query (v1 stays on the scanned host).
fn target_from(base_url: &str, service: &crate::core::HttpService, raw: &str) -> String {
    let host_port =
        if (service.secure && service.port == 443) || (!service.secure && service.port == 80) {
            service.host.clone()
        } else {
            format!("{}:{}", service.host, service.port)
        };
    let interpolated = raw
        .replace("{{BaseURL}}", base_url)
        .replace("{{RootURL}}", base_url)
        .replace("{{Hostname}}", &host_port)
        .replace("{{Host}}", &service.host);
    if let Ok(uri) = interpolated.parse::<http::Uri>()
        && uri.scheme().is_some()
    {
        return uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
    }
    if interpolated.starts_with('/') {
        interpolated
    } else {
        format!("/{interpolated}")
    }
}

fn loopback() -> std::net::SocketAddr {
    "127.0.0.1:0".parse().expect("valid loopback addr")
}

/// Templates shipped with Shrike. Each is this crate's own JSON schema and
/// detects a published, widely-applicable exposure/misconfig.
const BUILTIN_TEMPLATES: &[&str] = &[
    r#"{
      "id": "git-config-exposure",
      "info": { "name": "Exposed .git/config", "severity": "high",
        "description": "A readable .git/config exposes the repository layout and often remote URLs with credentials.",
        "tags": ["exposure","git"] },
      "requests": [{
        "paths": ["{{BaseURL}}/.git/config"],
        "matchers_condition": "and",
        "matchers": [
          { "type": "status", "status": [200] },
          { "type": "word", "part": "body", "words": ["[core]","repositoryformatversion"], "condition": "and" }
        ],
        "extractors": [{ "type": "regex", "part": "body", "regex": ["url = (.*)"], "group": 1 }]
      }]
    }"#,
    r#"{
      "id": "dotenv-exposure",
      "info": { "name": "Exposed .env file", "severity": "high",
        "description": "A readable .env file commonly leaks secrets (DB credentials, API keys, app secrets).",
        "tags": ["exposure","config"] },
      "requests": [{
        "paths": ["{{BaseURL}}/.env"],
        "matchers_condition": "and",
        "matchers": [
          { "type": "status", "status": [200] },
          { "type": "regex", "part": "body", "regex": ["(?m)^[A-Z][A-Z0-9_]+="], "condition": "or" }
        ]
      }]
    }"#,
    r#"{
      "id": "phpinfo-exposure",
      "info": { "name": "Exposed phpinfo()", "severity": "medium",
        "description": "A reachable phpinfo() page discloses PHP configuration, paths and loaded modules.",
        "tags": ["exposure","php"] },
      "requests": [{
        "paths": ["{{BaseURL}}/phpinfo.php","{{BaseURL}}/info.php","{{BaseURL}}/php_info.php"],
        "matchers_condition": "and",
        "matchers": [
          { "type": "status", "status": [200] },
          { "type": "word", "part": "body", "words": ["PHP Version","phpinfo()"], "condition": "or" }
        ],
        "extractors": [{ "type": "regex", "part": "body", "regex": ["PHP Version ([0-9.]+)"], "group": 1 }]
      }]
    }"#,
    r#"{
      "id": "spring-actuator-env",
      "info": { "name": "Spring Boot Actuator env exposed", "severity": "high",
        "description": "An unauthenticated /actuator/env endpoint leaks application configuration and often secrets.",
        "tags": ["exposure","springboot","actuator"] },
      "requests": [{
        "paths": ["{{BaseURL}}/actuator/env","{{BaseURL}}/env"],
        "matchers_condition": "and",
        "matchers": [
          { "type": "status", "status": [200] },
          { "type": "word", "part": "body", "words": ["propertySources","activeProfiles"], "condition": "or" },
          { "type": "word", "part": "header", "words": ["application/json","application/vnd.spring-boot.actuator"], "condition": "or" }
        ]
      }]
    }"#,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{CapturedRequest, CapturedResponse, HttpService};
    use std::time::{Duration, SystemTime};

    fn svc() -> HttpService {
        HttpService {
            host: "t.example".into(),
            port: 443,
            secure: true,
        }
    }

    fn txn(status: u16, headers: Vec<(&str, &str)>, body: &str) -> Transaction {
        Transaction {
            request: CapturedRequest {
                id: 0,
                client_addr: loopback(),
                service: svc(),
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
            response: Some(CapturedResponse {
                status,
                version: "HTTP/1.1".into(),
                headers: headers
                    .into_iter()
                    .map(|(n, v)| Header {
                        name: n.into(),
                        value: v.into(),
                    })
                    .collect(),
                body: body.as_bytes().to_vec().into(),
                body_len: body.len(),
                body_complete: true,
                received_at: SystemTime::now(),
            }),
            error: None,
            duration: Duration::from_millis(1),
        }
    }

    fn parse(src: &str) -> Template {
        serde_json::from_str(src).expect("template parses")
    }

    #[test]
    fn builtin_templates_all_parse() {
        for src in BUILTIN_TEMPLATES {
            let t: Template = serde_json::from_str(src).expect("builtin parses");
            assert!(!t.id.is_empty());
            assert!(!t.requests.is_empty());
        }
    }

    #[test]
    fn and_condition_requires_every_matcher() {
        let t = parse(BUILTIN_TEMPLATES[0]); // git-config, status+word AND
        let req = &t.requests[0];
        // Both status 200 and the words present → match, with the url extracted.
        let good = txn(
            200,
            vec![],
            "[core]\nrepositoryformatversion = 0\n[remote]\nurl = https://x/y.git",
        );
        let m = eval_request(&t, req, "/.git/config", &good).expect("match");
        assert_eq!(m.template_id, "git-config-exposure");
        assert!(m.extracted.iter().any(|e| e.contains("https://x/y.git")));
        // Right words but a 404 → no match (AND fails on status).
        let bad = txn(404, vec![], "[core]\nrepositoryformatversion = 0");
        assert!(eval_request(&t, req, "/.git/config", &bad).is_none());
    }

    #[test]
    fn or_word_matcher_and_header_part() {
        let t = parse(BUILTIN_TEMPLATES[3]); // actuator env
        let req = &t.requests[0];
        let ok = txn(
            200,
            vec![("Content-Type", "application/json")],
            "{\"activeProfiles\":[],\"propertySources\":[]}",
        );
        assert!(eval_request(&t, req, "/actuator/env", &ok).is_some());
        // JSON body tell present but wrong content-type AND the body word missing → fail.
        let no = txn(
            200,
            vec![("Content-Type", "text/html")],
            "<html>nope</html>",
        );
        assert!(eval_request(&t, req, "/actuator/env", &no).is_none());
    }

    #[test]
    fn negative_matcher_inverts() {
        let src = r#"{ "id":"neg","info":{"name":"n"},"requests":[{
            "paths":["/x"],
            "matchers":[{ "type":"word","part":"body","words":["blocked"],"negative":true }]
        }]}"#;
        let t = parse(src);
        let req = &t.requests[0];
        assert!(eval_request(&t, req, "/x", &txn(200, vec![], "all good")).is_some());
        assert!(eval_request(&t, req, "/x", &txn(200, vec![], "request blocked")).is_none());
    }

    #[test]
    fn interpolation_reduces_to_path_and_query() {
        let s = svc();
        assert_eq!(
            target_from("https://t.example", &s, "{{BaseURL}}/.git/config"),
            "/.git/config"
        );
        assert_eq!(
            target_from("https://t.example", &s, "/actuator/env"),
            "/actuator/env"
        );
        assert_eq!(target_from("https://t.example", &s, "admin"), "/admin");
    }

    #[test]
    fn case_insensitive_word() {
        let src = r#"{ "id":"ci","info":{"name":"n"},"requests":[{
            "paths":["/x"],
            "matchers":[{ "type":"word","part":"body","words":["PHP VERSION"],"case_insensitive":true }]
        }]}"#;
        let t = parse(src);
        assert!(
            eval_request(
                &t,
                &t.requests[0],
                "/x",
                &txn(200, vec![], "php version 8.1")
            )
            .is_some()
        );
    }
}
