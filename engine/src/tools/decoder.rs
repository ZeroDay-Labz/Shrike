//! Decoder transforms: reversible encodings plus a few conveniences, applied
//! singly or as a chain. Pure functions, reused by the Decoder tool and by any
//! later tool that needs to encode/decode payloads.

use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use percent_encoding::{AsciiSet, CONTROLS, percent_decode_str, utf8_percent_encode};
use serde::{Deserialize, Serialize};

const URL_SET: &AsciiSet = &CONTROLS
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecodeOp {
    UrlEncode,
    UrlDecode,
    Base64Encode,
    Base64Decode,
    HexEncode,
    HexDecode,
    HtmlEncode,
    HtmlDecode,
    Upper,
    Lower,
}

/// One step's outcome in a chain: the output, or an error message.
#[derive(Debug, Clone, Serialize)]
pub struct StepResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn apply(op: DecodeOp, input: &str) -> Result<String> {
    Ok(match op {
        DecodeOp::UrlEncode => utf8_percent_encode(input, URL_SET).to_string(),
        DecodeOp::UrlDecode => percent_decode_str(input)
            .decode_utf8()
            .context("invalid percent-encoding")?
            .into_owned(),
        DecodeOp::Base64Encode => B64.encode(input.as_bytes()),
        DecodeOp::Base64Decode => {
            let bytes = B64.decode(input.trim()).context("invalid base64")?;
            String::from_utf8(bytes).context("base64 did not decode to UTF-8")?
        }
        DecodeOp::HexEncode => hex::encode(input.as_bytes()),
        DecodeOp::HexDecode => {
            let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
            let bytes = hex::decode(cleaned).context("invalid hex")?;
            String::from_utf8(bytes).context("hex did not decode to UTF-8")?
        }
        DecodeOp::HtmlEncode => html_encode(input),
        DecodeOp::HtmlDecode => html_decode(input),
        DecodeOp::Upper => input.to_uppercase(),
        DecodeOp::Lower => input.to_lowercase(),
    })
}

/// Apply ops in order, feeding each output into the next. A failing step stops
/// the chain; the returned vector has one entry per op attempted.
pub fn apply_chain(input: &str, ops: &[DecodeOp]) -> Vec<StepResult> {
    let mut out = Vec::with_capacity(ops.len());
    let mut current = input.to_string();
    for op in ops {
        match apply(*op, &current) {
            Ok(s) => {
                current = s.clone();
                out.push(StepResult {
                    output: Some(s),
                    error: None,
                });
            }
            Err(e) => {
                out.push(StepResult {
                    output: None,
                    error: Some(e.to_string()),
                });
                break;
            }
        }
    }
    out
}

fn html_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn html_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c != '&' {
            out.push(c);
            continue;
        }
        if let Some(semi) = s[i..].find(';').map(|p| i + p) {
            let entity = &s[i + 1..semi];
            let decoded = match entity {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" | "#39" => Some('\''),
                _ => entity.strip_prefix('#').and_then(|n| {
                    let code = if let Some(hex) = n.strip_prefix(['x', 'X']) {
                        u32::from_str_radix(hex, 16).ok()
                    } else {
                        n.parse::<u32>().ok()
                    };
                    code.and_then(char::from_u32)
                }),
            };
            if let Some(ch) = decoded {
                out.push(ch);
                while let Some(&(j, _)) = chars.peek() {
                    if j <= semi {
                        chars.next();
                    } else {
                        break;
                    }
                }
                continue;
            }
        }
        out.push('&');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_round_trip() {
        assert_eq!(apply(DecodeOp::UrlEncode, "a b&c").unwrap(), "a%20b%26c");
        assert_eq!(apply(DecodeOp::UrlDecode, "a%20b%26c").unwrap(), "a b&c");
    }

    #[test]
    fn base64_and_hex_round_trip() {
        assert_eq!(apply(DecodeOp::Base64Encode, "hi!").unwrap(), "aGkh");
        assert_eq!(apply(DecodeOp::Base64Decode, "aGkh").unwrap(), "hi!");
        assert_eq!(apply(DecodeOp::HexEncode, "AB").unwrap(), "4142");
        assert_eq!(apply(DecodeOp::HexDecode, "41 42").unwrap(), "AB");
    }

    #[test]
    fn html_round_trip_and_numeric_entities() {
        assert_eq!(
            apply(DecodeOp::HtmlEncode, "<a href=\"x\">&'").unwrap(),
            "&lt;a href=&quot;x&quot;&gt;&amp;&#39;"
        );
        assert_eq!(
            apply(DecodeOp::HtmlDecode, "&lt;b&gt;&amp;&#65;&#x42;").unwrap(),
            "<b>&AB"
        );
    }

    #[test]
    fn invalid_inputs_error_not_panic() {
        assert!(apply(DecodeOp::Base64Decode, "not valid base64!!!").is_err());
        assert!(apply(DecodeOp::HexDecode, "zz").is_err());
    }

    #[test]
    fn chain_feeds_each_step_and_stops_on_error() {
        // url-encode then base64-encode
        let r = apply_chain("a b", &[DecodeOp::UrlEncode, DecodeOp::Base64Encode]);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].output.as_deref(), Some("a%20b"));
        assert_eq!(r[1].output.as_deref(), Some(&*B64.encode("a%20b")));
        // a failing step halts the chain
        let bad = apply_chain("xx", &[DecodeOp::Base64Decode, DecodeOp::UrlEncode]);
        assert_eq!(bad.len(), 1);
        assert!(bad[0].error.is_some());
    }
}
