//! Standalone HTTP sender for manual tools (Repeater now; Intruder/Scanner later).
//!
//! Reuses the same rustls client config as the proxy's upstream path, so TLS
//! verification (or `-k`) behaves identically. One shared connection pool.

use crate::{
    config::UpstreamTlsMode,
    core::{CapturedRequest, CapturedResponse, Header, HttpService, ResponseView, Transaction},
    proxy,
};
use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Uri};
use hyper_rustls::HttpsConnector;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::TokioExecutor,
};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    str::FromStr,
    time::{Duration, Instant, SystemTime},
};

/// A request to send, as the Repeater editor describes it.
#[derive(Debug, Clone, Deserialize)]
pub struct RequestSpec {
    pub service: HttpService,
    pub method: String,
    /// Path + query as it goes on the request line.
    pub target: String,
    pub headers: Vec<Header>,
    /// Request body as text (UTF-8). Binary-body editing comes later.
    #[serde(default)]
    pub body: String,
}

/// The outcome of one send: the response plus wall-clock timing.
#[derive(Debug, Clone, Serialize)]
pub struct SendResult {
    pub response: ResponseView,
    pub duration_ms: u64,
}

/// Headers the sender manages itself; a user-supplied copy is dropped so the
/// client can set the correct value for this connection.
fn is_managed(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host" | "content-length" | "connection" | "proxy-connection" | "transfer-encoding"
    )
}

/// Hard ceiling on how many body bytes we drain before giving up on measuring
/// the true length — stops an endless stream from wasting time/bandwidth even
/// though memory is already bounded by `max_capture`.
const DRAIN_CEILING: usize = 256 * 1024 * 1024;

pub struct Sender {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    max_capture: usize,
    timeout: Duration,
}

impl Sender {
    pub fn new(mode: UpstreamTlsMode, max_capture: usize, timeout: Duration) -> Result<Self> {
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let tls = proxy::client_tls_config(mode, provider)?;
        let connector = proxy::https_connector(tls);
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Ok(Self {
            client,
            max_capture,
            timeout,
        })
    }

    /// Send a request and return the response view + timing (Repeater).
    pub async fn send(&self, spec: RequestSpec) -> Result<SendResult> {
        let addr = "127.0.0.1:0".parse().expect("valid loopback addr");
        let txn = self.send_transaction(spec, 0, addr).await?;
        let response = txn
            .response
            .as_ref()
            .map(ResponseView::from)
            .context("no response captured")?;
        Ok(SendResult {
            response,
            duration_ms: txn.duration.as_millis() as u64,
        })
    }

    /// Send a request and return the full [`Transaction`] (request + response),
    /// so callers can feed it into the capture pipeline (crawler, active scanner).
    pub async fn send_transaction(
        &self,
        spec: RequestSpec,
        id: u64,
        client_addr: SocketAddr,
    ) -> Result<Transaction> {
        tokio::time::timeout(self.timeout, self.send_inner(spec, id, client_addr))
            .await
            .map_err(|_| {
                anyhow::anyhow!("request timed out after {} ms", self.timeout.as_millis())
            })?
    }

    async fn send_inner(
        &self,
        spec: RequestSpec,
        id: u64,
        client_addr: SocketAddr,
    ) -> Result<Transaction> {
        let method = Method::from_str(spec.method.trim())
            .with_context(|| format!("invalid method {:?}", spec.method))?;
        let uri_str = format!("{}{}", spec.service.origin(), spec.target);
        let uri = Uri::from_str(&uri_str).with_context(|| format!("invalid URL {uri_str:?}"))?;

        let mut builder = Request::builder().method(method).uri(uri);
        for h in &spec.headers {
            if is_managed(&h.name) {
                continue;
            }
            builder = builder.header(h.name.as_str(), h.value.as_str());
        }
        let body_bytes = Bytes::from(spec.body.clone().into_bytes());
        let request = builder
            .body(Full::new(body_bytes.clone()))
            .context("building request")?;

        // Capture the request we're about to send, for the history/scan pipeline.
        let captured_req = CapturedRequest {
            id,
            client_addr,
            service: spec.service.clone(),
            method: spec.method.clone(),
            target: spec.target.clone(),
            version: "HTTP/1.1".into(),
            headers: spec.headers.clone(),
            body_len: body_bytes.len(),
            body: body_bytes,
            body_complete: true,
            started_at: SystemTime::now(),
            highlight: None,
        };

        let started = Instant::now();
        let response = self
            .client
            .request(request)
            .await
            .with_context(|| format!("sending request to {}", spec.service.origin()))?;
        let duration = started.elapsed();

        let (parts, mut incoming) = response.into_parts();

        // Stream frames: retain at most `max_capture` bytes (bounds memory) while
        // still counting the true wire length; drop the rest. `complete=false`
        // marks a truncated capture.
        let mut retained: Vec<u8> = Vec::new();
        let mut wire_len: usize = 0;
        let mut complete = true;
        while let Some(frame) = incoming.frame().await {
            let frame = frame.context("reading response body")?;
            let Some(chunk) = frame.data_ref() else {
                continue; // trailers etc.
            };
            wire_len += chunk.len();
            if retained.len() < self.max_capture {
                let take = (self.max_capture - retained.len()).min(chunk.len());
                retained.extend_from_slice(&chunk[..take]);
                if take < chunk.len() {
                    complete = false;
                }
            } else {
                complete = false;
            }
            if wire_len >= DRAIN_CEILING {
                complete = false;
                break;
            }
        }
        let captured =
            CapturedResponse::from_parts(&parts, Bytes::from(retained), wire_len, complete);
        Ok(Transaction {
            request: captured_req,
            response: Some(captured),
            error: None,
            duration,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;
    use hyper::{Response, body::Bytes as HBytes, service::service_fn};
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;

    async fn echo_server() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(stream),
                            service_fn(|req| async move {
                                let m = req.method().clone();
                                let p = req.uri().path().to_string();
                                let b = req.collect().await.unwrap().to_bytes();
                                Ok::<_, hyper::Error>(Response::new(Full::new(HBytes::from(
                                    format!("{m} {p} body={}", String::from_utf8_lossy(&b)),
                                ))))
                            }),
                        )
                        .await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn sends_and_reads_response() {
        let addr = echo_server().await;
        let sender = Sender::new(
            UpstreamTlsMode::Verify,
            1024 * 1024,
            Duration::from_secs(30),
        )
        .unwrap();
        let spec = RequestSpec {
            service: HttpService {
                host: "127.0.0.1".into(),
                port: addr.port(),
                secure: false,
            },
            method: "POST".into(),
            target: "/hello?x=1".into(),
            headers: vec![Header {
                name: "X-Test".into(),
                value: "1".into(),
            }],
            body: "ping".into(),
        };
        let out = sender.send(spec).await.unwrap();
        assert_eq!(out.response.status, 200);
        assert_eq!(
            out.response.body.text.as_deref(),
            Some("POST /hello body=ping")
        );
    }

    fn spec_to(addr: std::net::SocketAddr) -> RequestSpec {
        RequestSpec {
            service: HttpService {
                host: "127.0.0.1".into(),
                port: addr.port(),
                secure: false,
            },
            method: "GET".into(),
            target: "/".into(),
            headers: vec![],
            body: String::new(),
        }
    }

    /// A chunked response with no Content-Length, larger than the capture cap:
    /// memory is bounded to the cap, but the true wire length is still counted
    /// and the capture is marked truncated.
    #[tokio::test]
    async fn streams_and_bounds_body_without_content_length() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = s.read(&mut buf).await;
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap();
            // 20 chunks of 1000 bytes = 20_000 bytes total, cap is 4096.
            for _ in 0..20 {
                s.write_all(b"3e8\r\n").await.unwrap();
                s.write_all(&[b'A'; 1000]).await.unwrap();
                s.write_all(b"\r\n").await.unwrap();
            }
            s.write_all(b"0\r\n\r\n").await.unwrap();
            let _ = s.flush().await;
        });

        let sender = Sender::new(UpstreamTlsMode::Verify, 4096, Duration::from_secs(30)).unwrap();
        let out = sender.send(spec_to(addr)).await.unwrap();
        assert_eq!(out.response.body.wire_len, 20_000, "true length preserved");
        assert!(!out.response.body.complete, "capture is marked truncated");
        assert_eq!(
            out.response.body.len, 4096,
            "retained bytes bounded to the cap"
        );
    }

    /// A server that accepts but never responds must not hang the sender past its
    /// deadline — Stop/cancellation stays responsive.
    #[tokio::test]
    async fn request_times_out_against_a_hung_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (_s, _) = listener.accept().await.unwrap();
            // hold the connection open forever, never write a response
            std::future::pending::<()>().await;
        });

        let sender =
            Sender::new(UpstreamTlsMode::Verify, 4096, Duration::from_millis(300)).unwrap();
        let start = Instant::now();
        let res = sender.send(spec_to(addr)).await;
        assert!(res.is_err(), "hung server must produce a timeout error");
        assert!(start.elapsed() < Duration::from_secs(3), "returns promptly");
    }
}
