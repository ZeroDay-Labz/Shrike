//! Payload sources and the payload-processing pipeline.
//!
//! Processing is deliberately separate from generation and from HTTP transport
//! encoding: a payload is produced, then each enabled processor transforms it in
//! order, then it is inserted into the request verbatim. The transport layer
//! (the sender) owns wire framing such as Content-Length.

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use serde::{Deserialize, Serialize};

/// Characters we percent-encode: everything outside the unreserved set.
const ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'\'')
    .add(b'(')
    .add(b')')
    .add(b'*')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'=')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b']')
    .add(b'{')
    .add(b'}')
    .add(b'<')
    .add(b'>')
    .add(b'\\')
    .add(b'^')
    .add(b'`')
    .add(b'|');

/// One transformation applied to a payload before it is inserted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Processor {
    UrlEncode,
    Base64Encode,
    HexEncode,
    JsonEscape,
    Upper,
    Lower,
    Prefix { text: String },
    Suffix { text: String },
    Replace { from: String, to: String },
}

impl Processor {
    pub fn apply(&self, input: &str) -> String {
        match self {
            Processor::UrlEncode => utf8_percent_encode(input, ENCODE_SET).to_string(),
            Processor::Base64Encode => B64.encode(input.as_bytes()),
            Processor::HexEncode => hex::encode(input.as_bytes()),
            Processor::JsonEscape => {
                let quoted =
                    serde_json::to_string(input).unwrap_or_else(|_| format!("\"{input}\""));
                quoted[1..quoted.len() - 1].to_string()
            }
            Processor::Upper => input.to_uppercase(),
            Processor::Lower => input.to_lowercase(),
            Processor::Prefix { text } => format!("{text}{input}"),
            Processor::Suffix { text } => format!("{input}{text}"),
            Processor::Replace { from, to } => {
                if from.is_empty() {
                    input.to_string()
                } else {
                    input.replace(from.as_str(), to)
                }
            }
        }
    }
}

/// Run a payload through an ordered processor pipeline.
pub fn apply_all(processors: &[Processor], input: &str) -> String {
    processors
        .iter()
        .fold(input.to_string(), |acc, p| p.apply(&acc))
}

/// A payload source: how a set of payload strings is produced. Kept small and
/// extensible; the UI also supports plain lists and file import by sending the
/// resolved items as a list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PayloadSource {
    /// An explicit list of payloads.
    List { items: Vec<String> },
    /// Numeric sequence from `start` to `end` inclusive, stepping by `step`.
    Numbers { start: i64, end: i64, step: i64 },
    /// Every string of `length` over `charset` (brute force). Count = charset^length.
    BruteForce { charset: String, length: u32 },
    /// A single empty payload.
    Empty,
}

impl PayloadSource {
    /// Entry count when knowable (always knowable for these sources).
    pub fn count(&self) -> Option<u64> {
        match self {
            PayloadSource::List { items } => Some(items.len() as u64),
            PayloadSource::Numbers { start, end, step } => {
                if *step == 0 || (*end - *start).signum() != step.signum() && *start != *end {
                    return Some(if *start == *end { 1 } else { 0 });
                }
                let span = (*end - *start).unsigned_abs();
                Some(span / step.unsigned_abs() + 1)
            }
            PayloadSource::BruteForce { charset, length } => {
                let base = charset.chars().count() as u64;
                base.checked_pow(*length)
            }
            PayloadSource::Empty => Some(1),
        }
    }

    /// Materialize the payloads. Brute force is capped by the caller via `max`.
    pub fn resolve(&self, max: usize) -> Vec<String> {
        match self {
            PayloadSource::List { items } => items.clone(),
            PayloadSource::Empty => vec![String::new()],
            PayloadSource::Numbers { start, end, step } => {
                let mut out = Vec::new();
                if *step == 0 {
                    return vec![start.to_string()];
                }
                let mut n = *start;
                let up = *end >= *start;
                while (up && n <= *end) || (!up && n >= *end) {
                    out.push(n.to_string());
                    if out.len() >= max {
                        break;
                    }
                    n += *step;
                }
                out
            }
            PayloadSource::BruteForce { charset, length } => {
                let chars: Vec<char> = charset.chars().collect();
                let mut out = Vec::new();
                if chars.is_empty() || *length == 0 {
                    return out;
                }
                let mut idx = vec![0usize; *length as usize];
                loop {
                    out.push(idx.iter().map(|&i| chars[i]).collect::<String>());
                    if out.len() >= max {
                        break;
                    }
                    let mut i = 0;
                    loop {
                        idx[i] += 1;
                        if idx[i] < chars.len() {
                            break;
                        }
                        idx[i] = 0;
                        i += 1;
                        if i == idx.len() {
                            return out;
                        }
                    }
                }
                out
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn processors_transform_as_specified() {
        assert_eq!(Processor::UrlEncode.apply("a b&c"), "a%20b%26c");
        assert_eq!(Processor::Base64Encode.apply("abc"), "YWJj");
        assert_eq!(Processor::HexEncode.apply("AB"), "4142");
        assert_eq!(Processor::Upper.apply("aZ"), "AZ");
        assert_eq!(Processor::Prefix { text: "x".into() }.apply("y"), "xy");
        assert_eq!(Processor::Suffix { text: "z".into() }.apply("y"), "yz");
        assert_eq!(
            Processor::Replace {
                from: "a".into(),
                to: "b".into()
            }
            .apply("aa"),
            "bb"
        );
        assert_eq!(Processor::JsonEscape.apply("a\"b\\c"), "a\\\"b\\\\c");
    }

    #[test]
    fn pipeline_applies_in_order_no_double_encoding() {
        // url-encode THEN base64: order matters and is explicit
        let out = apply_all(&[Processor::UrlEncode, Processor::Base64Encode], "a b");
        assert_eq!(out, B64.encode("a%20b"));
        // reverse order differs
        let rev = apply_all(&[Processor::Base64Encode, Processor::UrlEncode], "a b");
        assert_ne!(out, rev);
    }

    #[test]
    fn source_counts_are_correct() {
        assert_eq!(
            PayloadSource::List {
                items: vec!["a".into(), "b".into()]
            }
            .count(),
            Some(2)
        );
        assert_eq!(
            PayloadSource::Numbers {
                start: 1,
                end: 10,
                step: 1
            }
            .count(),
            Some(10)
        );
        assert_eq!(
            PayloadSource::Numbers {
                start: 0,
                end: 100,
                step: 25
            }
            .count(),
            Some(5)
        );
        assert_eq!(
            PayloadSource::BruteForce {
                charset: "ab".into(),
                length: 3
            }
            .count(),
            Some(8)
        );
        assert_eq!(PayloadSource::Empty.count(), Some(1));
    }

    #[test]
    fn sources_resolve_and_cap() {
        assert_eq!(
            PayloadSource::Numbers {
                start: 1,
                end: 3,
                step: 1
            }
            .resolve(100),
            vec!["1", "2", "3"]
        );
        assert_eq!(
            PayloadSource::Numbers {
                start: 5,
                end: 1,
                step: -2
            }
            .resolve(100),
            vec!["5", "3", "1"]
        );
        assert_eq!(
            PayloadSource::BruteForce {
                charset: "ab".into(),
                length: 2
            }
            .resolve(100)
            .len(),
            4
        );
        assert_eq!(
            PayloadSource::BruteForce {
                charset: "ab".into(),
                length: 8
            }
            .resolve(10)
            .len(),
            10,
            "capped"
        );
    }
}
