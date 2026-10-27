//! Standalone HTTP sender for manual tools (Repeater now; Intruder/Scanner later).
//!
//! Reuses the same rustls client config as the proxy's upstream path, so TLS
//! verification (or `-k`) behaves identically. One shared connection pool.

use crate::{
    config::UpstreamTlsMode,
    core::{CapturedResponse, Header, HttpService, ResponseView},
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
use std::{str::FromStr, time::Instant};

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

pub struct Sender {
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    max_capture: usize,
}

impl Sender {
    pub fn new(mode: UpstreamTlsMode, max_capture: usize) -> Result<Self> {
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let tls = proxy::client_tls_config(mode, provider)?;
        let connector = proxy::https_connector(tls);
        let client = Client::builder(TokioExecutor::new()).build(connector);
        Ok(Self {
            client,
            max_capture,
        })
    }

    pub async fn send(&self, spec: RequestSpec) -> Result<SendResult> {
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
        let body = Bytes::from(spec.body.into_bytes());
        let request = builder.body(Full::new(body)).context("building request")?;

        let started = Instant::now();
        let response = self
            .client
            .request(request)
            .await
            .with_context(|| format!("sending request to {}", spec.service.origin()))?;
        let duration_ms = started.elapsed().as_millis() as u64;

        let (parts, incoming) = response.into_parts();
        let full = incoming
            .collect()
            .await
            .context("reading response body")?
            .to_bytes();
        let wire_len = full.len();
        let (retained, complete) = if wire_len > self.max_capture {
            (full.slice(..self.max_capture), false)
        } else {
            (full, true)
        };
        let captured = CapturedResponse::from_parts(&parts, retained, wire_len, complete);
        Ok(SendResult {
            response: ResponseView::from(&captured),
            duration_ms,
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
        let sender = Sender::new(UpstreamTlsMode::Verify, 1024 * 1024).unwrap();
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
}
