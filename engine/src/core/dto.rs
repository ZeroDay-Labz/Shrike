//! Serializable views of captured traffic for the UI/storage boundary.
//!
//! The engine keeps the rich [`CapturedRequest`]/[`CapturedResponse`]/[`Transaction`]
//! types with `Bytes` bodies and `SystemTime` stamps. Those cross process and
//! language boundaries badly, so everything leaving the engine (Tauri commands,
//! events, the SQLite store) is first lowered into these plain serde types.

use super::message::{CapturedRequest, CapturedResponse, Header, HttpService, Transaction};
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch (0 if the clock is before it).
pub fn epoch_millis(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A body rendered for transport: UTF-8 text when it decodes cleanly, base64 otherwise.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BodyView {
    /// Length retained in memory (may be less than the wire length when truncated).
    pub len: usize,
    /// Wire length if known; equals `len` for fully buffered bodies.
    pub wire_len: usize,
    /// False when the body was truncated or streamed through without full capture.
    pub complete: bool,
    /// True when `text` holds the body; false when `base64` does.
    pub is_text: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base64: Option<String>,
}

impl BodyView {
    fn new(body: &[u8], wire_len: usize, complete: bool) -> Self {
        let len = body.len();
        match std::str::from_utf8(body) {
            Ok(s) if !looks_binary(body) => Self {
                len,
                wire_len,
                complete,
                is_text: true,
                text: Some(s.to_string()),
                base64: None,
            },
            _ => Self {
                len,
                wire_len,
                complete,
                is_text: false,
                text: None,
                base64: Some(B64.encode(body)),
            },
        }
    }
}

/// Treat NUL-containing payloads as binary even if they happen to be valid UTF-8.
fn looks_binary(body: &[u8]) -> bool {
    body.contains(&0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestView {
    pub id: u64,
    pub client_addr: String,
    pub service: HttpService,
    pub method: String,
    pub target: String,
    pub url: String,
    pub version: String,
    pub headers: Vec<Header>,
    pub body: BodyView,
    pub started_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highlight: Option<String>,
}

impl From<&CapturedRequest> for RequestView {
    fn from(r: &CapturedRequest) -> Self {
        Self {
            id: r.id,
            client_addr: r.client_addr.to_string(),
            service: r.service.clone(),
            method: r.method.clone(),
            target: r.target.clone(),
            url: r.url(),
            version: r.version.clone(),
            headers: r.headers.clone(),
            body: BodyView::new(&r.body, r.body_len, r.body_complete),
            started_at_ms: epoch_millis(r.started_at),
            highlight: r.highlight.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseView {
    pub status: u16,
    pub reason: String,
    pub version: String,
    pub headers: Vec<Header>,
    pub body: BodyView,
    pub received_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
}

impl From<&CapturedResponse> for ResponseView {
    fn from(r: &CapturedResponse) -> Self {
        Self {
            status: r.status,
            reason: r.reason().to_string(),
            version: r.version.clone(),
            headers: r.headers.clone(),
            body: BodyView::new(&r.body, r.body_len, r.body_complete),
            received_at_ms: epoch_millis(r.received_at),
            mime: r.content_type().map(|s| s.to_string()),
        }
    }
}

/// A full request/response pair for the detail view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionView {
    pub request: RequestView,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<ResponseView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub duration_ms: u64,
}

impl From<&Transaction> for TransactionView {
    fn from(t: &Transaction) -> Self {
        Self {
            request: RequestView::from(&t.request),
            response: t.response.as_ref().map(ResponseView::from),
            error: t.error.clone(),
            duration_ms: t.duration.as_millis() as u64,
        }
    }
}

/// A compact row for the history table. Cheap to produce and to send in bulk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionSummary {
    pub id: u64,
    pub host: String,
    pub port: u16,
    pub secure: bool,
    pub method: String,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime: Option<String>,
    pub req_len: usize,
    pub resp_len: usize,
    pub duration_ms: u64,
    pub started_at_ms: u64,
    pub client_addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub highlight: Option<String>,
}

impl From<&Transaction> for TransactionSummary {
    fn from(t: &Transaction) -> Self {
        let r = &t.request;
        Self {
            id: r.id,
            host: r.service.host.clone(),
            port: r.service.port,
            secure: r.service.secure,
            method: r.method.clone(),
            url: r.url(),
            status: t.response.as_ref().map(|x| x.status),
            mime: t
                .response
                .as_ref()
                .and_then(|x| x.content_type().map(|s| s.to_string())),
            req_len: r.body_len,
            resp_len: t.response.as_ref().map(|x| x.body_len).unwrap_or(0),
            duration_ms: t.duration.as_millis() as u64,
            started_at_ms: epoch_millis(r.started_at),
            client_addr: r.client_addr.to_string(),
            error: t.error.clone(),
            highlight: r.highlight.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn req(body: &'static [u8]) -> CapturedRequest {
        let (parts, _) = hyper::Request::builder()
            .method("POST")
            .uri("https://api.test/v1?x=1")
            .header("content-type", "application/octet-stream")
            .body(())
            .unwrap()
            .into_parts();
        CapturedRequest::from_parts(
            1,
            "127.0.0.1:5000".parse().unwrap(),
            &parts,
            Bytes::from_static(body),
            body.len(),
            true,
        )
        .unwrap()
    }

    #[test]
    fn text_body_is_sent_as_text() {
        let v = RequestView::from(&req(b"hello world"));
        assert!(v.body.is_text);
        assert_eq!(v.body.text.as_deref(), Some("hello world"));
        assert!(v.body.base64.is_none());
        assert_eq!(v.url, "https://api.test/v1?x=1");
    }

    #[test]
    fn binary_body_is_base64() {
        let v = RequestView::from(&req(b"\x00\x01\x02\xff"));
        assert!(!v.body.is_text);
        assert!(v.body.text.is_none());
        assert_eq!(v.body.base64.as_deref(), Some("AAEC/w=="));
    }

    #[test]
    fn nul_containing_utf8_counts_as_binary() {
        let v = RequestView::from(&req(b"ok\x00still"));
        assert!(!v.body.is_text, "embedded NUL should force base64");
    }
}
