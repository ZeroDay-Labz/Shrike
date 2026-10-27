//! Per-request hook into the MITM pipeline: capture, record, forward.
//!
//! hudsucker clones the handler for every request and calls `handle_request`
//! then `handle_response` (or `handle_error`) on that same clone, which is how
//! a response is paired with its request without any shared map.

use super::landing;
use crate::{
    ca::CaManager,
    config::ProxyConfig,
    core::{
        CapturedRequest, CapturedResponse, EventBus, Header, HttpService, TrafficEvent,
        Transaction, WsDirection, WsMessageEvent,
    },
    intercept::{Decision, EditedRequest, Interceptor},
    match_replace::{MatchReplace, RulePart},
    scope::Scope,
};
use bytes::Bytes;
use http_body_util::BodyExt;
use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse, WebSocketContext, WebSocketHandler,
    tokio_tungstenite::tungstenite::Message,
};
use hyper::{Method, Request, Response, StatusCode, Uri, header};
use std::{
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
use tracing::{debug, warn};

/// Longest text frame echoed into WebSocket events.
const WS_TEXT_PREVIEW: usize = 2048;

struct Shared {
    bus: EventBus,
    ca: Arc<CaManager>,
    config: ProxyConfig,
    /// Shared with the engine so scope edits apply live, no proxy restart.
    scope: Arc<RwLock<Scope>>,
    /// Shared with the engine so requests can be paused/forwarded/dropped live.
    interceptor: Arc<Interceptor>,
    /// Shared with the engine so match & replace edits apply live.
    match_replace: Arc<RwLock<MatchReplace>>,
    next_id: AtomicU64,
}

struct Pending {
    request: Arc<CapturedRequest>,
    started: Instant,
}

#[derive(Clone)]
pub struct TrafficHandler {
    shared: Arc<Shared>,
    pending: Option<Arc<Pending>>,
}

impl TrafficHandler {
    pub fn new(
        bus: EventBus,
        ca: Arc<CaManager>,
        config: ProxyConfig,
        scope: Arc<RwLock<Scope>>,
        interceptor: Arc<Interceptor>,
        match_replace: Arc<RwLock<MatchReplace>>,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                bus,
                ca,
                config,
                scope,
                interceptor,
                match_replace,
                next_id: AtomicU64::new(1),
            }),
            pending: None,
        }
    }

    fn complete(&mut self, response: Option<CapturedResponse>, error: Option<String>) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        let tx = Transaction {
            request: (*pending.request).clone(),
            response,
            error,
            duration: pending.started.elapsed(),
        };
        self.shared.bus.emit(TrafficEvent::Completed(Arc::new(tx)));
    }
}

/// Hop-by-hop headers meant for the proxy itself must not reach the server.
fn strip_proxy_headers(headers: &mut header::HeaderMap) {
    headers.remove("proxy-connection");
    headers.remove(header::PROXY_AUTHORIZATION);
}

/// On a WebSocket upgrade, remove the `Sec-WebSocket-Extensions` header so the
/// connection negotiates **uncompressed** frames.
///
/// Our intermediary WebSocket codec does not implement `permessage-deflate`. If
/// the client and server negotiate it end-to-end, compressed frames arrive with
/// RSV1 set and fail to parse ("Reserved bits are non-zero"), so the traffic is
/// unreadable and cannot be intercepted. Stripping the extension from the
/// handshake makes both legs send plain frames we can read, record and edit — the
/// same trade-off an intercepting proxy must make to see WebSocket data. Returns
/// true when the request was a WebSocket upgrade.
fn strip_ws_compression(headers: &mut header::HeaderMap) -> bool {
    let is_upgrade = headers.contains_key("sec-websocket-key");
    if is_upgrade {
        headers.remove("sec-websocket-extensions");
    }
    is_upgrade
}

/// Decide whether a body should be buffered for the record or streamed through.
/// Returns the declared length when it is too large to buffer.
fn too_large_to_buffer(headers: &header::HeaderMap, max: usize) -> Option<usize> {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|len| *len > max)
}

fn is_event_stream(headers: &header::HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| {
            ct.trim_start()
                .to_ascii_lowercase()
                .starts_with("text/event-stream")
        })
        .unwrap_or(false)
}

/// Buffer a body. Returns the bytes to forward plus (retained copy, wire length, complete).
async fn buffer_body(body: Body, max: usize) -> Result<(Bytes, Bytes, usize, bool), String> {
    let bytes = body.collect().await.map_err(|e| e.to_string())?.to_bytes();
    let len = bytes.len();
    if len > max {
        Ok((bytes.clone(), bytes.slice(..max), len, false))
    } else {
        Ok((bytes.clone(), bytes, len, true))
    }
}

/// Rebuild `parts` in place from a user's intercept edit, keeping the original
/// request's scheme and authority (the CONNECT already fixed the target host).
/// Returns the new body bytes. `Content-Length` is recomputed; a stale
/// `Transfer-Encoding` is dropped.
fn apply_edit(
    parts: &mut hyper::http::request::Parts,
    edit: &EditedRequest,
) -> Result<Bytes, String> {
    use std::str::FromStr;

    parts.method = Method::from_str(edit.method.trim())
        .map_err(|e| format!("invalid method {:?}: {e}", edit.method))?;

    let scheme = parts
        .uri
        .scheme_str()
        .ok_or("original request has no scheme")?;
    let authority = parts
        .uri
        .authority()
        .ok_or("original request has no authority")?
        .clone();
    let target = if edit.target.starts_with('/') {
        edit.target.clone()
    } else {
        format!("/{}", edit.target)
    };
    let uri_str = format!("{scheme}://{authority}{target}");
    parts.uri =
        Uri::from_str(&uri_str).map_err(|e| format!("invalid target {:?}: {e}", edit.target))?;

    let body = Bytes::from(edit.body.clone().into_bytes());

    let mut map = header::HeaderMap::new();
    for h in &edit.headers {
        // These are managed for us; a user-typed value would be ignored or wrong.
        if h.name.eq_ignore_ascii_case("content-length")
            || h.name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        let name = header::HeaderName::from_bytes(h.name.as_bytes())
            .map_err(|e| format!("invalid header name {:?}: {e}", h.name))?;
        let value = header::HeaderValue::from_str(&h.value)
            .map_err(|e| format!("invalid value for header {:?}: {e}", h.name))?;
        map.append(name, value);
    }
    if !body.is_empty() {
        let len = header::HeaderValue::from_str(&body.len().to_string()).expect("numeric length");
        map.insert(header::CONTENT_LENGTH, len);
    }
    parts.headers = map;
    Ok(body)
}

fn headers_to_vec(map: &header::HeaderMap) -> Vec<Header> {
    map.iter()
        .map(|(n, v)| Header {
            name: n.as_str().to_string(),
            value: String::from_utf8_lossy(v.as_bytes()).into_owned(),
        })
        .collect()
}

/// Rebuild a hyper header map from edited header lines, dropping any header whose
/// name/value became invalid, and setting an accurate `Content-Length`.
fn rebuild_header_map(headers: Vec<Header>, body_len: usize) -> header::HeaderMap {
    let mut map = header::HeaderMap::new();
    for h in headers {
        if h.name.eq_ignore_ascii_case("content-length")
            || h.name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue; // recomputed below
        }
        match (
            header::HeaderName::from_bytes(h.name.as_bytes()),
            header::HeaderValue::from_str(&h.value),
        ) {
            (Ok(name), Ok(value)) => {
                map.append(name, value);
            }
            _ => warn!(header = %h.name, "dropping invalid header after match & replace"),
        }
    }
    if body_len > 0 {
        let len = header::HeaderValue::from_str(&body_len.to_string()).expect("numeric length");
        map.insert(header::CONTENT_LENGTH, len);
    }
    map
}

/// Apply active request-side match & replace rules to `parts` + `body` in place,
/// returning the (possibly rewritten) body.
fn apply_match_replace_request(
    mr: &MatchReplace,
    parts: &mut hyper::http::request::Parts,
    body: Bytes,
) -> Bytes {
    let mut headers = headers_to_vec(&parts.headers);
    mr.apply_headers(RulePart::RequestHeader, &mut headers);

    let mut text = String::from_utf8_lossy(&body).into_owned();
    let before = text.clone();
    mr.apply_body(RulePart::RequestBody, &mut text);
    let body = if text != before {
        Bytes::from(text.into_bytes())
    } else {
        body
    };

    parts.headers = rebuild_header_map(headers, body.len());
    body
}

/// Apply active response-side match & replace rules to `parts` + `body` in place,
/// returning the (possibly rewritten) body.
fn apply_match_replace_response(
    mr: &MatchReplace,
    parts: &mut hyper::http::response::Parts,
    body: Bytes,
) -> Bytes {
    let mut headers = headers_to_vec(&parts.headers);
    mr.apply_headers(RulePart::ResponseHeader, &mut headers);

    let mut text = String::from_utf8_lossy(&body).into_owned();
    let before = text.clone();
    mr.apply_body(RulePart::ResponseBody, &mut text);
    let body = if text != before {
        Bytes::from(text.into_bytes())
    } else {
        body
    };

    parts.headers = rebuild_header_map(headers, body.len());
    body
}

impl HttpHandler for TrafficHandler {
    async fn handle_request(&mut self, ctx: &HttpContext, req: Request<Body>) -> RequestOrResponse {
        if landing::is_landing_request(&req) {
            return landing::respond(&self.shared.ca, &req).into();
        }
        // CONNECT opens a tunnel; the requests inside it come back through
        // this handler individually, so the tunnel itself is not a transaction.
        if req.method() == hyper::Method::CONNECT {
            return req.into();
        }

        let max = self.shared.config.max_capture_bytes;
        let id = self.shared.next_id.fetch_add(1, Ordering::Relaxed);
        let (mut parts, body) = req.into_parts();
        strip_proxy_headers(&mut parts.headers);
        if strip_ws_compression(&mut parts.headers) {
            debug!(uri = %parts.uri, "websocket upgrade: stripped compression extension for interception");
        }

        // Scope is enforced here, in the engine, so a UI bug can never leak traffic.
        if self.shared.config.drop_out_of_scope && !self.target_in_scope(&parts.uri) {
            warn!(uri = %parts.uri, "refused out-of-scope request (drop_out_of_scope is on)");
            if let Some(captured) =
                CapturedRequest::from_parts(id, ctx.client_addr, &parts, Bytes::new(), 0, true)
            {
                self.remember(captured);
            }
            self.complete(
                None,
                Some("blocked by scope: target is out of scope".into()),
            );
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .body(Body::from(
                    "shrike: request refused, target is out of scope\n",
                ))
                .expect("static response")
                .into();
        }

        // Large uploads stream through untouched; we record the head only.
        if let Some(declared) = too_large_to_buffer(&parts.headers, max) {
            if let Some(captured) = CapturedRequest::from_parts(
                id,
                ctx.client_addr,
                &parts,
                Bytes::new(),
                declared,
                false,
            ) {
                self.remember(captured);
            }
            return Request::from_parts(parts, body).into();
        }

        let (forward, retained, len, complete) = match buffer_body(body, max).await {
            Ok(v) => v,
            Err(err) => {
                warn!(%err, "failed to read request body");
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from(format!(
                        "shrike: could not read request body: {err}\n"
                    )))
                    .expect("static response")
                    .into();
            }
        };

        let captured =
            match CapturedRequest::from_parts(id, ctx.client_addr, &parts, retained, len, complete)
            {
                Some(captured) => captured,
                None => {
                    debug!(uri = %parts.uri, "request without absolute URI; not recorded");
                    return Request::from_parts(parts, Body::from(forward)).into();
                }
            };

        if self.shared.interceptor.is_enabled() {
            return self.intercept(id, ctx, parts, forward, captured).await;
        }

        self.forward_request(id, ctx.client_addr, parts, forward, captured)
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        if self.pending.is_none() {
            return res;
        }
        let max = self.shared.config.max_capture_bytes;
        let (parts, body) = res.into_parts();

        let stream_through = parts.status == StatusCode::SWITCHING_PROTOCOLS
            || is_event_stream(&parts.headers)
            || too_large_to_buffer(&parts.headers, max).is_some();
        if stream_through {
            let declared = too_large_to_buffer(&parts.headers, 0).unwrap_or(0);
            let captured = CapturedResponse::from_parts(&parts, Bytes::new(), declared, false);
            self.complete(Some(captured), None);
            return Response::from_parts(parts, body);
        }

        match buffer_body(body, max).await {
            Ok((forward, retained, len, complete)) => {
                let mr = self
                    .shared
                    .match_replace
                    .read()
                    .expect("match_replace lock");
                if mr.has_active() {
                    let mut parts = parts;
                    let body = apply_match_replace_response(&mr, &mut parts, forward);
                    drop(mr);
                    let blen = body.len();
                    let captured = CapturedResponse::from_parts(&parts, body.clone(), blen, true);
                    self.complete(Some(captured), None);
                    Response::from_parts(parts, Body::from(body))
                } else {
                    drop(mr);
                    let captured = CapturedResponse::from_parts(&parts, retained, len, complete);
                    self.complete(Some(captured), None);
                    Response::from_parts(parts, Body::from(forward))
                }
            }
            Err(err) => {
                warn!(%err, "failed to read response body");
                self.complete(None, Some(format!("reading response body: {err}")));
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from(format!("shrike: upstream body error: {err}\n")))
                    .expect("static response")
            }
        }
    }

    async fn handle_error(
        &mut self,
        _ctx: &HttpContext,
        err: hyper_util::client::legacy::Error,
    ) -> Response<Body> {
        let mut chain = err.to_string();
        let mut source = std::error::Error::source(&err);
        while let Some(s) = source {
            chain.push_str(": ");
            chain.push_str(&s.to_string());
            source = s.source();
        }
        let target = self
            .pending
            .as_ref()
            .map(|p| p.request.url())
            .unwrap_or_else(|| "<unknown>".into());
        self.complete(None, Some(chain.clone()));
        Response::builder()
            .status(StatusCode::BAD_GATEWAY)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Body::from(format!(
                "shrike: could not reach {target}\n{chain}\n"
            )))
            .expect("static response")
    }

    async fn should_intercept_connect(&mut self, ctx: &HttpContext, req: &Request<Body>) -> bool {
        let Some(host) = req.uri().host() else {
            return true;
        };
        if self.shared.config.is_passthrough(host) {
            self.shared.bus.emit(TrafficEvent::TunnelPassthrough {
                host: host.to_string(),
                client_addr: ctx.client_addr,
            });
            false
        } else {
            true
        }
    }
}

impl TrafficHandler {
    /// Scope check for a request URI; unparsable targets count as out of scope.
    fn target_in_scope(&self, uri: &hyper::Uri) -> bool {
        HttpService::from_uri(uri)
            .map(|svc| {
                self.shared
                    .scope
                    .read()
                    .expect("scope lock")
                    .in_scope(&svc, uri.path())
            })
            .unwrap_or(false)
    }

    fn remember(&mut self, captured: CapturedRequest) {
        let request = Arc::new(captured);
        self.shared
            .bus
            .emit(TrafficEvent::RequestStarted(Arc::clone(&request)));
        self.pending = Some(Arc::new(Pending {
            request,
            started: Instant::now(),
        }));
    }

    /// Pause a request, emit it to the UI, and act on the user's decision.
    async fn intercept(
        &mut self,
        id: u64,
        ctx: &HttpContext,
        mut parts: hyper::http::request::Parts,
        forward: Bytes,
        captured: CapturedRequest,
    ) -> RequestOrResponse {
        let raw = String::from_utf8_lossy(&captured.to_raw()).into_owned();
        self.shared.bus.emit(TrafficEvent::Intercepted {
            id,
            service: captured.service.clone(),
            raw,
        });

        // If the engine releases interception (toggle off / proxy stop) the
        // sender is dropped, which we treat as "forward unchanged".
        let decision = self
            .shared
            .interceptor
            .pause(id)
            .await
            .unwrap_or(Decision::Forward(None));

        match decision {
            Decision::Drop => {
                self.remember(captured);
                self.complete(None, Some("dropped by user".into()));
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .body(Body::from("shrike: request dropped by user\n"))
                    .expect("static response")
                    .into()
            }
            Decision::Forward(None) => {
                self.forward_request(id, ctx.client_addr, parts, forward, captured)
            }
            Decision::Forward(Some(edit)) => match apply_edit(&mut parts, &edit) {
                // Match & replace runs on top of the user's edit (user edits win).
                Ok(body) => self.forward_request(id, ctx.client_addr, parts, body, captured),
                Err(err) => {
                    warn!(%err, "could not apply intercept edit; forwarding original");
                    self.forward_request(id, ctx.client_addr, parts, forward, captured)
                }
            },
        }
    }

    /// Apply match & replace (when any rule is active), record the request as it
    /// is actually being sent, and forward it.
    fn forward_request(
        &mut self,
        id: u64,
        client_addr: std::net::SocketAddr,
        mut parts: hyper::http::request::Parts,
        forward: Bytes,
        captured: CapturedRequest,
    ) -> RequestOrResponse {
        let mr = self
            .shared
            .match_replace
            .read()
            .expect("match_replace lock");
        if mr.has_active() {
            let body = apply_match_replace_request(&mr, &mut parts, forward);
            drop(mr);
            let len = body.len();
            match CapturedRequest::from_parts(id, client_addr, &parts, body.clone(), len, true) {
                Some(c) => self.remember(c),
                None => self.remember(captured),
            }
            Request::from_parts(parts, Body::from(body)).into()
        } else {
            drop(mr);
            self.remember(captured);
            Request::from_parts(parts, Body::from(forward)).into()
        }
    }
}

impl WebSocketHandler for TrafficHandler {
    async fn handle_message(&mut self, ctx: &WebSocketContext, msg: Message) -> Option<Message> {
        let (direction, url, client_addr) = match ctx {
            WebSocketContext::ClientToServer { src, dst, .. } => {
                (WsDirection::ClientToServer, dst.to_string(), *src)
            }
            WebSocketContext::ServerToClient { src, dst, .. } => {
                (WsDirection::ServerToClient, src.to_string(), *dst)
            }
        };
        let (kind, len, text) = match &msg {
            Message::Text(t) => (
                "text",
                t.len(),
                Some(t.chars().take(WS_TEXT_PREVIEW).collect::<String>()),
            ),
            Message::Binary(b) => ("binary", b.len(), None),
            Message::Ping(b) => ("ping", b.len(), None),
            Message::Pong(b) => ("pong", b.len(), None),
            Message::Close(_) => ("close", 0, None),
            Message::Frame(f) => ("frame", f.len(), None),
        };
        self.shared
            .bus
            .emit(TrafficEvent::WebSocketMessage(WsMessageEvent {
                direction,
                url,
                client_addr,
                kind,
                len,
                text,
            }));
        Some(msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> header::HeaderMap {
        let mut h = header::HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                header::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn ws_upgrade_drops_permessage_deflate() {
        let mut h = headers(&[
            ("Upgrade", "websocket"),
            ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
            (
                "Sec-WebSocket-Extensions",
                "permessage-deflate; client_max_window_bits",
            ),
        ]);
        assert!(strip_ws_compression(&mut h));
        assert!(
            !h.contains_key("sec-websocket-extensions"),
            "compression extension must be removed"
        );
        assert!(
            h.contains_key("sec-websocket-key"),
            "the handshake is otherwise untouched"
        );
    }

    #[test]
    fn non_upgrade_requests_are_untouched() {
        let mut h = headers(&[("Content-Type", "application/json"), ("Accept", "*/*")]);
        assert!(!strip_ws_compression(&mut h));
        assert_eq!(h.len(), 2);
    }
}
