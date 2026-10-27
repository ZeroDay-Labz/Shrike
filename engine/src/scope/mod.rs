//! Target scope: the single source of truth for "is this request fair game?".
//!
//! Enforced in the engine (proxy handler, and every automated tool that follows)
//! rather than in the UI, so a front-end bug can never send out-of-scope traffic.
//!
//! Semantics (deliberately conservative): a request is in scope when it matches
//! at least one enabled *include* rule and no enabled *exclude* rule. With no
//! include rules nothing is in scope, so automated tools refuse to run until the
//! user has defined a target explicitly.

use crate::core::HttpService;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleKind {
    Include,
    Exclude,
}

/// One scope rule as the user writes it (serializable, persisted as JSON).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRule {
    pub enabled: bool,
    pub kind: RuleKind,
    /// Literal host (`example.com`), a leading-dot suffix (`.example.com` =
    /// the domain and all subdomains), or a regex when `is_regex` is set.
    pub host: String,
    /// Restrict to one port; `None` means any port.
    #[serde(default)]
    pub port: Option<u16>,
    /// Path prefix (`/api/`), or a regex over the path when `is_regex` is set.
    /// `None` means any path.
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub is_regex: bool,
}

impl ScopeRule {
    pub fn include_host(host: impl Into<String>) -> Self {
        Self {
            enabled: true,
            kind: RuleKind::Include,
            host: host.into(),
            port: None,
            path: None,
            is_regex: false,
        }
    }
    pub fn exclude_host(host: impl Into<String>) -> Self {
        Self {
            kind: RuleKind::Exclude,
            ..Self::include_host(host)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ScopeError {
    #[error("rule {index} ({field}) is not a valid regex: {source}")]
    InvalidRegex {
        index: usize,
        field: &'static str,
        #[source]
        source: regex::Error,
    },
}

enum HostMatcher {
    Exact(String),
    /// Stored without the leading dot, lower-cased.
    Suffix(String),
    Regex(Regex),
}

enum PathMatcher {
    Any,
    Prefix(String),
    Regex(Regex),
}

struct Compiled {
    rule: ScopeRule,
    host: HostMatcher,
    path: PathMatcher,
}

impl Compiled {
    fn matches(&self, service: &HttpService, path: &str) -> bool {
        if let Some(p) = self.rule.port
            && p != service.port
        {
            return false;
        }
        let host = service.host.to_ascii_lowercase();
        let host_ok = match &self.host {
            HostMatcher::Exact(h) => &host == h,
            HostMatcher::Suffix(s) => &host == s || host.ends_with(&format!(".{s}")),
            HostMatcher::Regex(r) => r.is_match(&host),
        };
        if !host_ok {
            return false;
        }
        match &self.path {
            PathMatcher::Any => true,
            PathMatcher::Prefix(p) => path.starts_with(p),
            PathMatcher::Regex(r) => r.is_match(path),
        }
    }
}

/// Compiled scope. Build with [`Scope::from_rules`]; cheap to query.
pub struct Scope {
    compiled: Vec<Compiled>,
}

impl Default for Scope {
    fn default() -> Self {
        Self::empty()
    }
}

impl Scope {
    /// A scope with no rules: nothing is in scope.
    pub fn empty() -> Self {
        Self {
            compiled: Vec::new(),
        }
    }

    pub fn from_rules(rules: Vec<ScopeRule>) -> Result<Self, ScopeError> {
        let mut compiled = Vec::with_capacity(rules.len());
        for (index, rule) in rules.into_iter().enumerate() {
            let host = if rule.is_regex {
                HostMatcher::Regex(Regex::new(&rule.host).map_err(|source| {
                    ScopeError::InvalidRegex {
                        index,
                        field: "host",
                        source,
                    }
                })?)
            } else if let Some(suffix) = rule.host.strip_prefix('.') {
                HostMatcher::Suffix(suffix.to_ascii_lowercase())
            } else {
                HostMatcher::Exact(rule.host.to_ascii_lowercase())
            };
            let path = match (&rule.path, rule.is_regex) {
                (None, _) => PathMatcher::Any,
                (Some(p), true) => PathMatcher::Regex(Regex::new(p).map_err(|source| {
                    ScopeError::InvalidRegex {
                        index,
                        field: "path",
                        source,
                    }
                })?),
                (Some(p), false) => PathMatcher::Prefix(p.clone()),
            };
            compiled.push(Compiled { rule, host, path });
        }
        Ok(Self { compiled })
    }

    /// The rules this scope was built from (for persistence / the UI).
    pub fn rules(&self) -> Vec<ScopeRule> {
        self.compiled.iter().map(|c| c.rule.clone()).collect()
    }

    pub fn is_empty(&self) -> bool {
        self.compiled
            .iter()
            .all(|c| !(c.rule.enabled && c.rule.kind == RuleKind::Include))
    }

    /// True when `service`+`path` matches an enabled include rule and no
    /// enabled exclude rule. With no include rules this is always false.
    pub fn in_scope(&self, service: &HttpService, path: &str) -> bool {
        let mut included = false;
        for c in self.compiled.iter().filter(|c| c.rule.enabled) {
            if !c.matches(service, path) {
                continue;
            }
            match c.rule.kind {
                RuleKind::Exclude => return false,
                RuleKind::Include => included = true,
            }
        }
        included
    }

    /// Convenience for absolute URLs; unparsable URLs are out of scope.
    pub fn in_scope_url(&self, url: &str) -> bool {
        let Ok(uri) = url.parse::<hyper::Uri>() else {
            return false;
        };
        let Some(service) = HttpService::from_uri(&uri) else {
            return false;
        };
        let path = uri.path_and_query().map(|p| p.path()).unwrap_or("/");
        self.in_scope(&service, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(host: &str, port: u16) -> HttpService {
        HttpService {
            host: host.into(),
            port,
            secure: port == 443,
        }
    }

    #[test]
    fn empty_scope_includes_nothing() {
        let s = Scope::empty();
        assert!(s.is_empty());
        assert!(!s.in_scope(&svc("example.com", 443), "/"));
    }

    #[test]
    fn exact_and_suffix_hosts() {
        let s = Scope::from_rules(vec![
            ScopeRule::include_host("exact.test"),
            ScopeRule::include_host(".wild.test"),
        ])
        .unwrap();
        assert!(s.in_scope(&svc("exact.test", 443), "/"));
        assert!(s.in_scope(&svc("EXACT.test", 443), "/"), "case-insensitive");
        assert!(
            !s.in_scope(&svc("sub.exact.test", 443), "/"),
            "exact does not cover subdomains"
        );
        assert!(s.in_scope(&svc("wild.test", 443), "/"));
        assert!(s.in_scope(&svc("a.b.wild.test", 443), "/"));
        assert!(
            !s.in_scope(&svc("notwild.test", 443), "/"),
            "suffix must be on a label boundary"
        );
    }

    #[test]
    fn exclude_beats_include() {
        let s = Scope::from_rules(vec![
            ScopeRule::include_host(".corp.test"),
            ScopeRule {
                path: Some("/admin".into()),
                ..ScopeRule::exclude_host(".corp.test")
            },
        ])
        .unwrap();
        assert!(s.in_scope(&svc("app.corp.test", 443), "/api/x"));
        assert!(!s.in_scope(&svc("app.corp.test", 443), "/admin/users"));
    }

    #[test]
    fn port_and_path_prefix_restrict() {
        let s = Scope::from_rules(vec![ScopeRule {
            port: Some(8443),
            path: Some("/api/".into()),
            ..ScopeRule::include_host("h.test")
        }])
        .unwrap();
        assert!(s.in_scope(&svc("h.test", 8443), "/api/v1"));
        assert!(!s.in_scope(&svc("h.test", 443), "/api/v1"), "wrong port");
        assert!(!s.in_scope(&svc("h.test", 8443), "/other"), "wrong path");
    }

    #[test]
    fn regex_rules_and_invalid_regex() {
        let s = Scope::from_rules(vec![ScopeRule {
            host: r"^(dev|stage)\.r\.test$".into(),
            path: Some(r"^/v[0-9]+/".into()),
            is_regex: true,
            ..ScopeRule::include_host("")
        }])
        .unwrap();
        assert!(s.in_scope(&svc("dev.r.test", 443), "/v2/items"));
        assert!(!s.in_scope(&svc("prod.r.test", 443), "/v2/items"));
        assert!(!s.in_scope(&svc("dev.r.test", 443), "/items"));

        let bad = Scope::from_rules(vec![ScopeRule {
            host: "(".into(),
            is_regex: true,
            ..ScopeRule::include_host("")
        }]);
        assert!(matches!(
            bad,
            Err(ScopeError::InvalidRegex {
                index: 0,
                field: "host",
                ..
            })
        ));
    }

    #[test]
    fn disabled_rules_are_ignored_and_urls_parse() {
        let s = Scope::from_rules(vec![
            ScopeRule {
                enabled: false,
                ..ScopeRule::include_host("off.test")
            },
            ScopeRule::include_host("on.test"),
        ])
        .unwrap();
        assert!(!s.in_scope_url("https://off.test/"));
        assert!(s.in_scope_url("https://on.test/x?y=1"));
        assert!(!s.in_scope_url("not a url"));
        assert_eq!(s.rules().len(), 2, "rules round-trip for persistence");
    }
}
