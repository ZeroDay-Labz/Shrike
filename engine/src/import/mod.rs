//! Import HTTP traffic from other tools into Shrike's history.
//!
//! Supports Burp Suite's **XML item export** (Target → "Save selected items",
//! or the Proxy/Logger XML export): a list of `<item>` elements carrying the
//! base64 request/response and some metadata. Burp's binary `.burp` *project*
//! files are a proprietary, compressed format and are **not** parsed here — the
//! honest path is to export items as XML from Burp first.

use crate::core::{CapturedRequest, CapturedResponse, Header, HttpService, Transaction};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use bytes::Bytes;
use std::time::{Duration, SystemTime};

/// Split raw HTTP bytes into (head, body) at the first blank line (CRLF or LF).
fn split_head_body(raw: &[u8]) -> (&[u8], &[u8]) {
    if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
        (&raw[..i], &raw[i + 4..])
    } else if let Some(i) = raw.windows(2).position(|w| w == b"\n\n") {
        (&raw[..i], &raw[i + 2..])
    } else {
        (raw, &[])
    }
}

fn parse_headers<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<Header> {
    lines
        .filter_map(|l| {
            l.split_once(':').map(|(n, v)| Header {
                name: n.trim().to_string(),
                value: v.trim().to_string(),
            })
        })
        .collect()
}

fn parse_request(raw: &[u8], service: HttpService) -> Option<CapturedRequest> {
    let (head, body) = split_head_body(raw);
    let head = String::from_utf8_lossy(head).replace("\r\n", "\n");
    let mut lines = head.split('\n');
    let mut first = lines.next()?.split_whitespace();
    let method = first.next()?.to_string();
    let target = first.next().unwrap_or("/").to_string();
    let version = first.next().unwrap_or("HTTP/1.1").to_string();
    Some(CapturedRequest {
        id: 0,
        client_addr: "127.0.0.1:0".parse().expect("static addr"),
        service,
        method,
        target,
        version,
        headers: parse_headers(lines),
        body: Bytes::copy_from_slice(body),
        body_len: body.len(),
        body_complete: true,
        started_at: SystemTime::now(),
    })
}

fn parse_response(raw: &[u8]) -> Option<CapturedResponse> {
    let (head, body) = split_head_body(raw);
    let head = String::from_utf8_lossy(head).replace("\r\n", "\n");
    let mut lines = head.split('\n');
    let mut first = lines.next()?.split_whitespace();
    let version = first.next().unwrap_or("HTTP/1.1").to_string();
    let status: u16 = first.next().and_then(|s| s.parse().ok())?;
    Some(CapturedResponse {
        status,
        version,
        headers: parse_headers(lines),
        body: Bytes::copy_from_slice(body),
        body_len: body.len(),
        body_complete: true,
        received_at: SystemTime::now(),
    })
}

/// Content of `<tag ...>…</tag>` within `block`, with any CDATA wrapper removed,
/// plus whether the opening tag carried `base64="true"`.
fn tag(block: &str, name: &str) -> Option<(String, bool)> {
    let open = block.find(&format!("<{name}"))?;
    let gt = block[open..].find('>')? + open;
    let attrs = &block[open..gt];
    let close = block[gt + 1..].find(&format!("</{name}>"))? + gt + 1;
    let mut content = &block[gt + 1..close];
    if let Some(inner) = content
        .strip_prefix("<![CDATA[")
        .and_then(|c| c.strip_suffix("]]>"))
    {
        content = inner;
    }
    Some((content.to_string(), attrs.contains("base64=\"true\"")))
}

fn decode_payload(content: &str, is_b64: bool) -> Vec<u8> {
    if is_b64 {
        B64.decode(content.trim()).unwrap_or_default()
    } else {
        content.as_bytes().to_vec()
    }
}

/// Parse Burp's XML item export into transactions ready for the history store.
/// Items without a parseable request are skipped.
pub fn transactions_from_burp_xml(xml: &str) -> Vec<Transaction> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<item>") {
        let after = &rest[start + 6..];
        let end = match after.find("</item>") {
            Some(e) => e,
            None => break,
        };
        let block = &after[..end];
        rest = &after[end + 7..];

        let protocol = tag(block, "protocol").map(|(c, _)| c).unwrap_or_default();
        let secure = protocol.eq_ignore_ascii_case("https");
        let host = tag(block, "host").map(|(c, _)| c).unwrap_or_default();
        let port = tag(block, "port")
            .and_then(|(c, _)| c.trim().parse::<u16>().ok())
            .unwrap_or(if secure { 443 } else { 80 });
        if host.trim().is_empty() {
            continue;
        }
        let service = HttpService {
            host: host.trim().to_string(),
            port,
            secure,
        };

        let req = match tag(block, "request") {
            Some((c, b64)) => decode_payload(&c, b64),
            None => continue,
        };
        let request = match parse_request(&req, service) {
            Some(r) => r,
            None => continue,
        };
        let response = tag(block, "response")
            .map(|(c, b64)| decode_payload(&c, b64))
            .filter(|r| !r.is_empty())
            .and_then(|r| parse_response(&r));

        out.push(Transaction {
            request,
            response,
            error: None,
            duration: Duration::ZERO,
        });
    }
    out
}

/// True if the bytes look like a Burp binary `.burp` project (not XML items).
pub fn looks_like_burp_project(bytes: &[u8]) -> bool {
    // Burp project files are a zip-like/proprietary container, not XML.
    let head = &bytes[..bytes.len().min(64)];
    !head.windows(6).any(|w| w == b"<items")
        && (bytes.starts_with(b"PK") || !is_probably_text(head))
}

fn is_probably_text(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .all(|&b| b == b'\t' || b == b'\n' || b == b'\r' || (0x20..=0x7e).contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &str) -> String {
        B64.encode(s.as_bytes())
    }

    #[test]
    fn imports_a_burp_item() {
        let req = "GET /search?q=1 HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n";
        let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\nhi";
        let xml = format!(
            "<items><item><protocol>https</protocol><host>example.com</host><port>443</port>\
             <request base64=\"true\">{}</request><status>200</status>\
             <response base64=\"true\">{}</response></item></items>",
            b64(req),
            b64(resp)
        );
        let txs = transactions_from_burp_xml(&xml);
        assert_eq!(txs.len(), 1);
        let t = &txs[0];
        assert_eq!(t.request.method, "GET");
        assert_eq!(t.request.target, "/search?q=1");
        assert!(t.request.service.secure);
        assert_eq!(t.request.service.port, 443);
        assert_eq!(t.request.header("user-agent"), Some("x"));
        let r = t.response.as_ref().expect("response parsed");
        assert_eq!(r.status, 200);
        assert_eq!(&r.body[..], b"hi");
    }

    #[test]
    fn skips_items_without_request_and_handles_cdata() {
        let xml = "<items>\
          <item><protocol>http</protocol><host>h</host><port>80</port></item>\
          <item><protocol>http</protocol><host><![CDATA[a.com]]></host><port>80</port>\
           <request base64=\"false\">GET / HTTP/1.1\r\nHost: a.com\r\n\r\n</request></item>\
          </items>";
        let txs = transactions_from_burp_xml(xml);
        assert_eq!(txs.len(), 1, "item with no request is skipped");
        assert_eq!(txs[0].request.service.host, "a.com");
        assert!(txs[0].response.is_none());
    }

    #[test]
    fn binary_project_is_detected() {
        assert!(looks_like_burp_project(
            b"PK\x03\x04\x00\x00binarygunk\x01\x02"
        ));
        assert!(!looks_like_burp_project(b"<items><item></item></items>"));
    }
}
