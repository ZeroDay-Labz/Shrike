//! Match & replace: rewrite requests and responses as they pass through the
//! proxy. Like [`crate::scope`], rules live in the engine and are shared live
//! with the running handler, so edits take effect without a restart.
//!
//! Rules are pure text rewrites (literal or regex) over four parts of a message:
//! request/response headers and request/response bodies. This module is
//! transport-agnostic and unit-tested; the proxy handler converts hyper types to
//! and from the `Vec<Header>` / `String` these methods operate on.

use crate::core::Header;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Which part of a message a rule rewrites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RulePart {
    RequestHeader,
    RequestBody,
    ResponseHeader,
    ResponseBody,
}

impl RulePart {
    fn is_header(self) -> bool {
        matches!(self, RulePart::RequestHeader | RulePart::ResponseHeader)
    }
}

/// One match & replace rule as the user writes it (persisted as JSON).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchReplaceRule {
    pub enabled: bool,
    #[serde(default)]
    pub name: String,
    pub part: RulePart,
    #[serde(default)]
    pub is_regex: bool,
    /// The text or regex to find. Serialized as `"match"`.
    #[serde(rename = "match")]
    pub match_: String,
    /// The replacement. Regex rules may reference capture groups with `$1`, `${name}`.
    #[serde(default)]
    pub replace: String,
}

#[derive(Debug, thiserror::Error)]
pub enum MatchReplaceError {
    #[error("rule {index} has an invalid regex: {source}")]
    InvalidRegex {
        index: usize,
        #[source]
        source: regex::Error,
    },
    #[error("rule {index} has an empty match")]
    EmptyMatch { index: usize },
}

struct Compiled {
    rule: MatchReplaceRule,
    regex: Option<Regex>,
}

impl Compiled {
    /// Apply this rule to `text`, returning the rewrite (or `None` if unchanged).
    fn rewrite(&self, text: &str) -> Option<String> {
        let out = match &self.regex {
            Some(re) => re
                .replace_all(text, self.rule.replace.as_str())
                .into_owned(),
            None => text.replace(&self.rule.match_, &self.rule.replace),
        };
        (out != text).then_some(out)
    }
}

/// A compiled, ready-to-apply rule set.
#[derive(Default)]
pub struct MatchReplace {
    rules: Vec<Compiled>,
}

impl MatchReplace {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Validate and compile a rule set. Regex rules with a bad pattern, and any
    /// rule with an empty match, are rejected without building a `MatchReplace`.
    pub fn from_rules(rules: Vec<MatchReplaceRule>) -> Result<Self, MatchReplaceError> {
        let mut compiled = Vec::with_capacity(rules.len());
        for (index, rule) in rules.into_iter().enumerate() {
            if rule.match_.is_empty() {
                return Err(MatchReplaceError::EmptyMatch { index });
            }
            let regex = if rule.is_regex {
                Some(
                    Regex::new(&rule.match_)
                        .map_err(|source| MatchReplaceError::InvalidRegex { index, source })?,
                )
            } else {
                None
            };
            compiled.push(Compiled { rule, regex });
        }
        Ok(Self { rules: compiled })
    }

    /// The rules in this set, for display/persistence.
    pub fn rules(&self) -> Vec<MatchReplaceRule> {
        self.rules.iter().map(|c| c.rule.clone()).collect()
    }

    /// Whether any enabled rule exists (lets the handler skip all work cheaply).
    pub fn has_active(&self) -> bool {
        self.rules.iter().any(|c| c.rule.enabled)
    }

    fn active(&self, part: RulePart) -> impl Iterator<Item = &Compiled> {
        self.rules
            .iter()
            .filter(move |c| c.rule.enabled && c.rule.part == part)
    }

    /// Apply the given header part's rules to a header list, line by line
    /// (`Name: Value`). A rule that rewrites a line to empty removes that header.
    pub fn apply_headers(&self, part: RulePart, headers: &mut Vec<Header>) {
        debug_assert!(part.is_header());
        if self.active(part).next().is_none() {
            return;
        }
        let mut out = Vec::with_capacity(headers.len());
        for h in headers.drain(..) {
            let mut line = format!("{}: {}", h.name, h.value);
            for c in self.active(part) {
                if let Some(next) = c.rewrite(&line) {
                    line = next;
                }
            }
            if line.trim().is_empty() {
                continue; // rule deleted this header
            }
            match line.split_once(':') {
                Some((name, value)) => out.push(Header {
                    name: name.trim().to_string(),
                    value: value.trim().to_string(),
                }),
                None => out.push(Header {
                    name: line.trim().to_string(),
                    value: String::new(),
                }),
            }
        }
        *headers = out;
    }

    /// Apply the given body part's rules to a body string in place.
    pub fn apply_body(&self, part: RulePart, body: &mut String) {
        debug_assert!(!part.is_header());
        for c in self.active(part) {
            if let Some(next) = c.rewrite(body) {
                *body = next;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(part: RulePart, is_regex: bool, m: &str, r: &str) -> MatchReplaceRule {
        MatchReplaceRule {
            enabled: true,
            name: String::new(),
            part,
            is_regex,
            match_: m.into(),
            replace: r.into(),
        }
    }

    #[test]
    fn literal_header_value_rewrite() {
        let mr = MatchReplace::from_rules(vec![rule(
            RulePart::RequestHeader,
            false,
            "User-Agent: curl/8.0",
            "User-Agent: Shrike",
        )])
        .unwrap();
        let mut headers = vec![
            Header {
                name: "Host".into(),
                value: "x.test".into(),
            },
            Header {
                name: "User-Agent".into(),
                value: "curl/8.0".into(),
            },
        ];
        mr.apply_headers(RulePart::RequestHeader, &mut headers);
        assert_eq!(headers[1].value, "Shrike");
        assert_eq!(headers[0].value, "x.test");
    }

    #[test]
    fn regex_body_rewrite_with_group() {
        let mr = MatchReplace::from_rules(vec![rule(
            RulePart::ResponseBody,
            true,
            r#""debug":(true|false)"#,
            r#""debug":true"#,
        )])
        .unwrap();
        let mut body = r#"{"debug":false,"x":1}"#.to_string();
        mr.apply_body(RulePart::ResponseBody, &mut body);
        assert_eq!(body, r#"{"debug":true,"x":1}"#);
    }

    #[test]
    fn header_rule_can_delete_a_header() {
        let mr = MatchReplace::from_rules(vec![rule(
            RulePart::ResponseHeader,
            true,
            r"(?i)^content-security-policy:.*$",
            "",
        )])
        .unwrap();
        let mut headers = vec![
            Header {
                name: "Content-Security-Policy".into(),
                value: "default-src 'self'".into(),
            },
            Header {
                name: "X-Keep".into(),
                value: "1".into(),
            },
        ];
        mr.apply_headers(RulePart::ResponseHeader, &mut headers);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].name, "X-Keep");
    }

    #[test]
    fn disabled_rule_is_a_noop_and_wrong_part_is_skipped() {
        let mut disabled = rule(RulePart::RequestBody, false, "a", "b");
        disabled.enabled = false;
        let mr = MatchReplace::from_rules(vec![
            disabled,
            rule(RulePart::ResponseBody, false, "a", "b"),
        ])
        .unwrap();
        let mut body = "aaa".to_string();
        mr.apply_body(RulePart::RequestBody, &mut body); // only a disabled rule targets this part
        assert_eq!(body, "aaa");
        mr.apply_body(RulePart::ResponseBody, &mut body);
        assert_eq!(body, "bbb");
    }

    #[test]
    fn bad_regex_and_empty_match_are_rejected() {
        assert!(
            MatchReplace::from_rules(vec![rule(RulePart::RequestBody, true, "(", "x")]).is_err()
        );
        assert!(
            MatchReplace::from_rules(vec![rule(RulePart::RequestBody, false, "", "x")]).is_err()
        );
    }

    #[test]
    fn has_active_reflects_enabled_rules() {
        assert!(!MatchReplace::empty().has_active());
        let mut r = rule(RulePart::RequestBody, false, "a", "b");
        r.enabled = false;
        assert!(!MatchReplace::from_rules(vec![r]).unwrap().has_active());
    }
}
