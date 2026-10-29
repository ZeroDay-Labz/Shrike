use bytes::Bytes;
use hyper::http::{self, HeaderMap, Uri};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Write as _,
    net::SocketAddr,
    time::{Duration, SystemTime},
};

/// Where a request was sent: host, port and whether TLS was used.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HttpService {
    pub host: String,
    pub port: u16,
    pub secure: bool,
}

impl HttpService {
    /// Derive the service from an absolute-form URI (`https://host:port/...`).
    pub fn from_uri(uri: &Uri) -> Option<Self> {
        let host = uri.host()?.to_string();
        let secure = match uri.scheme_str() {
            Some("https") | Some("wss") => true,
            Some("http") | Some("ws") => false,
            _ => return None,
        };
        let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });
        Some(Self { host, port, secure })
    }

    pub fn scheme(&self) -> &'static str {
        if self.secure { "https" } else { "http" }
    }

    pub fn is_default_port(&self) -> bool {
        self.port == if self.secure { 443 } else { 80 }
    }

    /// `https://host[:port]` with the port omitted when it is the scheme default.
    pub fn origin(&self) -> String {
        let host = if self.host.contains(':') && !self.host.starts_with('[') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.is_default_port() {
            format!("{}://{}", self.scheme(), host)
        } else {
            format!("{}://{}:{}", self.scheme(), host, self.port)
        }
    }
}

impl std::fmt::Display for HttpService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.origin())
    }
}

/// One header line, name case as received where the transport preserved it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    pub name: String,
    pub value: String,
}

fn headers_from_map(map: &HeaderMap) -> Vec<Header> {
    map.iter()
        .map(|(name, value)| Header {
            name: name.as_str().to_string(),
            value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
        })
        .collect()
}

fn header_lookup<'a>(headers: &'a [Header], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

fn version_str(v: http::Version) -> String {
    format!("{v:?}")
}

/// A request as it passed through the proxy, with its body (possibly truncated).
#[derive(Debug, Clone)]
pub struct CapturedRequest {
    /// Monotonic id assigned by the proxy; the history store reuses it.
    pub id: u64,
    pub client_addr: SocketAddr,
    pub service: HttpService,
    pub method: String,
    /// Path plus query, as sent on the request line.
    pub target: String,
    pub version: String,
    pub headers: Vec<Header>,
    /// Retained body bytes. Equal to the wire body unless `body_complete` is false.
    pub body: Bytes,
    /// Length of the body on the wire (may exceed `body.len()` when truncated,
    /// or be unknown and reported as 0 when the body was streamed through).
    pub body_len: usize,
    pub body_complete: bool,
    pub started_at: SystemTime,
    /// Container highlight colour for this request (e.g. from a PwnFox-style
    /// `X-PwnFox-Color` header the proxy strips). `None` for untagged traffic.
    pub highlight: Option<String>,
}

impl CapturedRequest {
    pub fn from_parts(
        id: u64,
        client_addr: SocketAddr,
        parts: &http::request::Parts,
        body: Bytes,
        body_len: usize,
        body_complete: bool,
    ) -> Option<Self> {
        let service = HttpService::from_uri(&parts.uri)?;
        let target = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        Some(Self {
            id,
            client_addr,
            service,
            method: parts.method.as_str().to_string(),
            target,
            version: version_str(parts.version),
            headers: headers_from_map(&parts.headers),
            body,
            body_len,
            body_complete,
            started_at: SystemTime::now(),
            highlight: None,
        })
    }

    pub fn url(&self) -> String {
        format!("{}{}", self.service.origin(), self.target)
    }

    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or(&self.target)
    }

    pub fn query(&self) -> Option<&str> {
        self.target.split_once('?').map(|(_, q)| q)
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        header_lookup(&self.headers, name)
    }

    /// HTTP/1.1-style wire rendering for display and later editing.
    pub fn to_raw(&self) -> Vec<u8> {
        let mut out = String::new();
        let _ = writeln!(out, "{} {} {}\r", self.method, self.target, self.version);
        if self.header("host").is_none() {
            let host = if self.service.is_default_port() {
                self.service.host.clone()
            } else {
                format!("{}:{}", self.service.host, self.service.port)
            };
            let _ = writeln!(out, "Host: {host}\r");
        }
        for h in &self.headers {
            let _ = writeln!(out, "{}: {}\r", h.name, h.value);
        }
        out.push_str("\r\n");
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

/// A response as returned to the client.
#[derive(Debug, Clone)]
pub struct CapturedResponse {
    pub status: u16,
    pub version: String,
    pub headers: Vec<Header>,
    pub body: Bytes,
    pub body_len: usize,
    pub body_complete: bool,
    pub received_at: SystemTime,
}

impl CapturedResponse {
    pub fn from_parts(
        parts: &http::response::Parts,
        body: Bytes,
        body_len: usize,
        body_complete: bool,
    ) -> Self {
        Self {
            status: parts.status.as_u16(),
            version: version_str(parts.version),
            headers: headers_from_map(&parts.headers),
            body,
            body_len,
            body_complete,
            received_at: SystemTime::now(),
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        header_lookup(&self.headers, name)
    }

    /// Media type without parameters, e.g. `text/html`.
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
            .map(|ct| ct.split(';').next().unwrap_or(ct).trim())
    }

    pub fn reason(&self) -> &'static str {
        http::StatusCode::from_u16(self.status)
            .ok()
            .and_then(|s| s.canonical_reason())
            .unwrap_or("")
    }

    pub fn to_raw(&self) -> Vec<u8> {
        let mut out = String::new();
        let _ = writeln!(out, "{} {} {}\r", self.version, self.status, self.reason());
        for h in &self.headers {
            let _ = writeln!(out, "{}: {}\r", h.name, h.value);
        }
        out.push_str("\r\n");
        let mut bytes = out.into_bytes();
        bytes.extend_from_slice(&self.body);
        bytes
    }
}

/// A request paired with what came back for it.
#[derive(Debug, Clone)]
pub struct Transaction {
    pub request: CapturedRequest,
    pub response: Option<CapturedResponse>,
    /// Set when the upstream request failed instead of producing a response.
    pub error: Option<String>,
    /// Time from the request being fully read to the response headers arriving.
    pub duration: Duration,
}

impl Transaction {
    pub fn status(&self) -> Option<u16> {
        self.response.as_ref().map(|r| r.status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_from_uri_fills_default_ports() {
        let s = HttpService::from_uri(&"https://example.com/x".parse().unwrap()).unwrap();
        assert_eq!(
            s,
            HttpService {
                host: "example.com".into(),
                port: 443,
                secure: true
            }
        );
        assert_eq!(s.origin(), "https://example.com");

        let s = HttpService::from_uri(&"http://example.com:8081/".parse().unwrap()).unwrap();
        assert_eq!(s.port, 8081);
        assert!(!s.secure);
        assert_eq!(s.origin(), "http://example.com:8081");

        assert!(HttpService::from_uri(&"/relative".parse().unwrap()).is_none());
    }

    #[test]
    fn request_raw_rendering_adds_host_when_missing() {
        let (parts, _) = hyper::Request::builder()
            .method("POST")
            .uri("https://api.test:8443/v1/items?x=1")
            .header("content-type", "application/json")
            .body(())
            .unwrap()
            .into_parts();
        let req = CapturedRequest::from_parts(
            7,
            "127.0.0.1:1234".parse().unwrap(),
            &parts,
            Bytes::from_static(b"{}"),
            2,
            true,
        )
        .unwrap();
        assert_eq!(req.url(), "https://api.test:8443/v1/items?x=1");
        assert_eq!(req.path(), "/v1/items");
        assert_eq!(req.query(), Some("x=1"));
        let raw = String::from_utf8(req.to_raw()).unwrap();
        assert!(raw.starts_with("POST /v1/items?x=1 HTTP/1.1\r\nHost: api.test:8443\r\n"));
        assert!(raw.ends_with("\r\n\r\n{}"));
    }

    #[test]
    fn response_content_type_strips_parameters() {
        let (parts, _) = hyper::Response::builder()
            .status(404)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(())
            .unwrap()
            .into_parts();
        let res = CapturedResponse::from_parts(&parts, Bytes::new(), 0, true);
        assert_eq!(res.content_type(), Some("text/html"));
        assert_eq!(res.reason(), "Not Found");
        assert!(
            String::from_utf8(res.to_raw())
                .unwrap()
                .starts_with("HTTP/1.1 404 Not Found\r\n")
        );
    }
}
