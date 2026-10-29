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
        Transaction, TransactionIds, WsDirection, WsMessageEvent,
    },
    intercept::{Decision, EditedRequest, Interceptor},
    match_replace::{MatchReplace, RulePart},
    scope::Scope,
};
use bytes::Bytes;
use http_body_util::{BodyExt, combinators::BoxBody};
use hudsucker::{
    Body, HttpContext, HttpHandler, RequestOrResponse, WebSocketContext, WebSocketHandler,
    tokio_tungstenite::tungstenite::Message,
};
use hyper::{
    Method, Request, Response, StatusCode, Uri,
    body::{Body as HttpBody, Frame, SizeHint},
    header,
};
use std::{
    collections::VecDeque,
    pin::Pin,
    sync::{Arc, RwLock},
    task::{Context, Poll},
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
    /// The project-wide id sequence (shared with the store), so a proxy
    /// restart continues numbering instead of reusing stored ids.
    ids: TransactionIds,
}

struct Pending {
    request: Arc<CapturedRequest>,
    started: Instant,
}

#[derive(Clone)]
pub struct TrafficHandler {
    shared: Arc<Shared>,
    pending: Option<Arc<Pending>>,
    /// Container colour for the in-flight request, from a stripped
    /// `X-PwnFox-Color` header. Stamped onto the record in [`Self::remember`].
    pending_highlight: Option<String>,
}

impl TrafficHandler {
    pub fn new(
        bus: EventBus,
        ca: Arc<CaManager>,
        config: ProxyConfig,
        scope: Arc<RwLock<Scope>>,
        interceptor: Arc<Interceptor>,
        match_replace: Arc<RwLock<MatchReplace>>,
        ids: TransactionIds,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                bus,
                ca,
                config,
                scope,
                interceptor,
                match_replace,
                ids,
            }),
            pending: None,
            pending_highlight: None,
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

/// Known PwnFox container colours. An allowlist so a client-controlled header
/// can only ever select one of these labels (never arbitrary text/markup).
const PWNFOX_COLORS: &[&str] = &[
    "red", "orange", "yellow", "green", "cyan", "blue", "pink", "purple", "gray", "grey",
];

/// Take and validate the PwnFox container colour header, removing it from the
/// outgoing request. Returns the lower-cased colour label when it is recognised.
fn take_pwnfox_color(headers: &mut header::HeaderMap) -> Option<String> {
    let raw = headers.remove("x-pwnfox-color")?;
    let label = raw.to_str().ok()?.trim().to_ascii_lowercase();
    PWNFOX_COLORS.contains(&label.as_str()).then_some(label)
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

/// Hard ceiling on how much of a body without a declared `Content-Length` the
/// proxy will buffer in memory. Bodies with a declared length over the capture
/// cap already stream through untouched before reaching [`buffer_body`]. A
/// chunked / unknown-length body that grows past this ceiling stops being
/// buffered and is streamed on in full (see [`Forward::Streaming`]), so memory
/// stays bounded and the peer still receives every byte.
const PROXY_BUFFER_CEILING: usize = 64 * 1024 * 1024;

/// The body to send on, as [`buffer_body`] left it.
///
/// Three views of a body exist and must not be confused:
/// - what is **forwarded**: always the complete original body (or the result of
///   an explicit edit / match & replace on a complete body);
/// - what is **retained** for history and the UI: at most the capture cap,
///   flagged incomplete when shorter than the wire body;
/// - what body-processing features see: the full bytes only for
///   [`Forward::Complete`]; a streamed body is never rewritten.
enum Forward {
    /// The whole body fit under the buffering ceiling; these are its exact bytes.
    Complete(Bytes),
    /// The body outgrew the ceiling: the bytes already read, chained in front of
    /// the untouched remainder of the stream, forwarded byte for byte.
    Streaming(Body),
}

impl Forward {
    fn into_body(self) -> Body {
        match self {
            Forward::Complete(bytes) => Body::from(bytes),
            Forward::Streaming(body) => body,
        }
    }
}

/// Result of [`buffer_body`]: what to forward plus what to record.
struct Buffered {
    forward: Forward,
    /// Retained copy for the record, at most the capture cap.
    retained: Bytes,
    /// Body length on the wire. For a streamed body, the bytes read before
    /// streaming began (a lower bound: the full length is not known up front).
    len: usize,
    /// True only when `retained` is the entire body.
    complete: bool,
}

/// The record's copy of `body`: the whole thing when it fits under `max`, else
/// an owned copy of the first `max` bytes (so the record never pins a much
/// larger forwarding buffer in memory). Returns the bytes and whether they are
/// the complete body.
fn retain(body: &Bytes, max: usize) -> (Bytes, bool) {
    if body.len() > max {
        (Bytes::copy_from_slice(&body[..max]), false)
    } else {
        (body.clone(), true)
    }
}

/// Buffer a body a frame at a time, up to `PROXY_BUFFER_CEILING` (or the capture
/// cap, if larger). A body that fits is returned whole; one that would exceed
/// the ceiling is handed back as a stream of the buffered bytes followed by the
/// rest, so it is forwarded intact without unbounded buffering.
async fn buffer_body(mut body: Body, max: usize) -> Result<Buffered, String> {
    let ceiling = max.max(PROXY_BUFFER_CEILING);
    let mut buf: Vec<u8> = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|e| e.to_string())?;
        let Some(data) = frame.data_ref() else {
            continue;
        };
        if buf.len() + data.len() > ceiling {
            // Keep the crossing frame separate rather than growing `buf` past the
            // ceiling (which would reallocate to double its size).
            let len = buf.len() + data.len();
            // The record keeps an owned copy of the first `max` bytes.
            let mut kept = Vec::with_capacity(max.min(len));
            kept.extend_from_slice(&buf[..buf.len().min(max)]);
            let room = max - kept.len();
            kept.extend_from_slice(&data[..room.min(data.len())]);
            let retained = Bytes::from(kept);
            let head = Bytes::from(buf);
            let crossing = frame.into_data().unwrap_or_default();
            let forward = Body::from(BoxBody::new(PrefixedBody {
                prefix: VecDeque::from([head, crossing]),
                rest: body,
            }));
            return Ok(Buffered {
                forward: Forward::Streaming(forward),
                retained,
                len,
                complete: false,
            });
        }
        buf.extend_from_slice(data);
    }
    let bytes = Bytes::from(buf);
    let (retained, complete) = retain(&bytes, max);
    Ok(Buffered {
        len: bytes.len(),
        forward: Forward::Complete(bytes),
        retained,
        complete,
    })
}

/// Already-read chunks replayed ahead of the rest of a body stream.
struct PrefixedBody {
    prefix: VecDeque<Bytes>,
    rest: Body,
}

impl HttpBody for PrefixedBody {
    type Data = Bytes;
    type Error = <Body as HttpBody>::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        while let Some(chunk) = this.prefix.pop_front() {
            if !chunk.is_empty() {
                return Poll::Ready(Some(Ok(Frame::data(chunk))));
            }
        }
        Pin::new(&mut this.rest).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.prefix.iter().all(Bytes::is_empty) && self.rest.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let buffered: u64 = self.prefix.iter().map(|b| b.len() as u64).sum();
        let rest = self.rest.size_hint();
        let mut hint = SizeHint::new();
        hint.set_lower(rest.lower() + buffered);
        if let Some(upper) = rest.upper() {
            hint.set_upper(upper + buffered);
        }
        hint
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
    let mut map = apply_edit_head(parts, edit)?;
    let body = Bytes::from(edit.body.clone().into_bytes());
    if !body.is_empty() {
        let len = header::HeaderValue::from_str(&body.len().to_string()).expect("numeric length");
        map.insert(header::CONTENT_LENGTH, len);
    }
    parts.headers = map;
    Ok(body)
}

/// Apply only the head of a user's intercept edit (method, target, headers),
/// keeping the original body and therefore its original framing headers.
fn apply_head_edit(
    parts: &mut hyper::http::request::Parts,
    edit: &EditedRequest,
) -> Result<(), String> {
    let mut map = apply_edit_head(parts, edit)?;
    copy_framing_headers(&parts.headers, &mut map);
    parts.headers = map;
    Ok(())
}

/// Copy `Content-Length` / `Transfer-Encoding` from `from` into `to`: a body
/// forwarded unchanged must keep the framing it arrived with.
fn copy_framing_headers(from: &header::HeaderMap, to: &mut header::HeaderMap) {
    for name in [header::CONTENT_LENGTH, header::TRANSFER_ENCODING] {
        to.remove(&name);
        for v in from.get_all(&name) {
            to.append(name.clone(), v.clone());
        }
    }
}

/// Set the method and target from an edit and return its headers (without
/// framing headers, which depend on which body is forwarded).
fn apply_edit_head(
    parts: &mut hyper::http::request::Parts,
    edit: &EditedRequest,
) -> Result<header::HeaderMap, String> {
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
    Ok(map)
}

/// Whether the body text of an intercept edit differs from the body the user
/// was shown. Line endings are compared loosely because editors may rewrite
/// `\r\n` as `\n`.
fn body_was_edited(edit: &EditedRequest, shown: &[u8]) -> bool {
    let shown = String::from_utf8_lossy(shown);
    edit.body.replace("\r\n", "\n") != shown.replace("\r\n", "\n")
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

/// Apply header rules to headers whose body is streamed on unchanged: framing
/// headers keep their original values, since the body itself is not rewritten.
fn apply_header_rules_keep_framing(
    mr: &MatchReplace,
    part: RulePart,
    headers: &mut header::HeaderMap,
) {
    let mut list = headers_to_vec(headers);
    mr.apply_headers(part, &mut list);
    let mut map = rebuild_header_map(list, 0);
    copy_framing_headers(headers, &mut map);
    *headers = map;
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
        let id = self.shared.ids.next();
        let (mut parts, body) = req.into_parts();
        strip_proxy_headers(&mut parts.headers);
        // PwnFox-style container colour: record it and strip it so it never
        // reaches the target (it is proxy-control metadata, not app data).
        self.pending_highlight = take_pwnfox_color(&mut parts.headers);
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

        // Scope-capture mode: when the user is recording only the engagement
        // target, out-of-scope requests still go through (so browsing works) but
        // are neither buffered nor recorded. An empty scope records nothing, so
        // treat that as "not filtering" to avoid capturing nothing at all.
        if self.shared.config.capture_in_scope_only
            && !self.shared.config.drop_out_of_scope
            && !self.scope_is_empty()
            && !self.target_in_scope(&parts.uri)
        {
            return Request::from_parts(parts, body).into();
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

        let Buffered {
            forward,
            retained,
            len,
            complete,
        } = match buffer_body(body, max).await {
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
                    return Request::from_parts(parts, forward.into_body()).into();
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
            Ok(Buffered {
                forward,
                retained,
                len,
                complete,
            }) => {
                let mr = self
                    .shared
                    .match_replace
                    .read()
                    .expect("match_replace lock");
                match forward {
                    Forward::Complete(forward) if mr.has_active() => {
                        let mut parts = parts;
                        let body = apply_match_replace_response(&mr, &mut parts, forward);
                        drop(mr);
                        let (retained, complete) = retain(&body, max);
                        let captured =
                            CapturedResponse::from_parts(&parts, retained, body.len(), complete);
                        self.complete(Some(captured), None);
                        Response::from_parts(parts, Body::from(body))
                    }
                    Forward::Streaming(forward) if mr.has_active() => {
                        // Too large to rewrite: header rules still apply, the body
                        // is forwarded exactly as received.
                        let mut parts = parts;
                        if mr.has_active_for(RulePart::ResponseBody) {
                            warn!(
                                "response body exceeds the proxy buffer ceiling; body match & \
                                 replace rules were not applied to it"
                            );
                        }
                        apply_header_rules_keep_framing(
                            &mr,
                            RulePart::ResponseHeader,
                            &mut parts.headers,
                        );
                        drop(mr);
                        let captured = CapturedResponse::from_parts(&parts, retained, len, false);
                        self.complete(Some(captured), None);
                        Response::from_parts(parts, forward)
                    }
                    forward => {
                        drop(mr);
                        let captured =
                            CapturedResponse::from_parts(&parts, retained, len, complete);
                        self.complete(Some(captured), None);
                        Response::from_parts(parts, forward.into_body())
                    }
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
    fn scope_is_empty(&self) -> bool {
        self.shared.scope.read().expect("scope lock").is_empty()
    }

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

    fn remember(&mut self, mut captured: CapturedRequest) {
        if captured.highlight.is_none() {
            captured.highlight = self.pending_highlight.clone();
        }
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
        forward: Forward,
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
            // The body shown for editing was decoded as text and may be only the
            // first part of the body. Leave the body alone unless the user
            // actually changed it, so the original bytes are forwarded exactly.
            Decision::Forward(Some(edit)) if !body_was_edited(&edit, &captured.body) => {
                if let Err(err) = apply_head_edit(&mut parts, &edit) {
                    warn!(%err, "could not apply intercept edit; forwarding original");
                }
                self.forward_request(id, ctx.client_addr, parts, forward, captured)
            }
            // A body edit made on a partial copy would forward a truncated body.
            Decision::Forward(Some(_)) if !captured.body_complete => {
                warn!(
                    "refused an intercept body edit: the body was too large to capture \
                     completely, so the edited copy is incomplete"
                );
                self.remember(captured);
                self.complete(
                    None,
                    Some("intercept edit refused: body too large to capture completely".into()),
                );
                Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                    .body(Body::from(
                        "shrike: this request's body was too large to capture completely, so \
                         an edited body cannot be forwarded safely. Forward it without editing \
                         the body, or drop it.\n",
                    ))
                    .expect("static response")
                    .into()
            }
            Decision::Forward(Some(edit)) => match apply_edit(&mut parts, &edit) {
                // Match & replace runs on top of the user's edit (user edits win).
                Ok(body) => self.forward_request(
                    id,
                    ctx.client_addr,
                    parts,
                    Forward::Complete(body),
                    captured,
                ),
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
        forward: Forward,
        captured: CapturedRequest,
    ) -> RequestOrResponse {
        let max = self.shared.config.max_capture_bytes;
        let mr = self
            .shared
            .match_replace
            .read()
            .expect("match_replace lock");
        let active = mr.has_active();
        // The recorded request is always rebuilt from the FINAL parts and body —
        // the ones actually sent — so history reflects intercept edits and match
        // & replace exactly, never the pre-edit capture. `captured` is only a
        // fallback for a request with no absolute URI (which is never recorded).
        match forward {
            Forward::Complete(mut body) => {
                if active {
                    body = apply_match_replace_request(&mr, &mut parts, body);
                }
                drop(mr);
                let (retained, complete) = retain(&body, max);
                let rec = CapturedRequest::from_parts(
                    id,
                    client_addr,
                    &parts,
                    retained,
                    body.len(),
                    complete,
                );
                self.remember(rec.unwrap_or(captured));
                Request::from_parts(parts, Body::from(body)).into()
            }
            Forward::Streaming(body) => {
                // Too large to rewrite: header rules still apply, the body is
                // forwarded exactly as received (only the captured prefix is kept).
                if active {
                    if mr.has_active_for(RulePart::RequestBody) {
                        warn!(
                            uri = %parts.uri,
                            "request body exceeds the proxy buffer ceiling; body match & replace \
                             rules were not applied to it"
                        );
                    }
                    apply_header_rules_keep_framing(
                        &mr,
                        RulePart::RequestHeader,
                        &mut parts.headers,
                    );
                }
                drop(mr);
                let rec = CapturedRequest::from_parts(
                    id,
                    client_addr,
                    &parts,
                    captured.body.clone(),
                    captured.body_len,
                    false,
                );
                self.remember(rec.unwrap_or(captured));
                Request::from_parts(parts, body).into()
            }
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
    fn pwnfox_color_is_parsed_validated_and_stripped() {
        let mut h = headers(&[("X-PwnFox-Color", "red"), ("Host", "lab.test")]);
        assert_eq!(take_pwnfox_color(&mut h).as_deref(), Some("red"));
        assert!(!h.contains_key("x-pwnfox-color"), "header must be stripped");
        assert!(h.contains_key("host"), "other headers are untouched");

        // Unknown labels are ignored (no arbitrary values reach the UI), but the
        // header is still stripped so it never reaches the target.
        let mut h2 = headers(&[("X-PwnFox-Color", "<script>")]);
        assert_eq!(take_pwnfox_color(&mut h2), None);
        assert!(!h2.contains_key("x-pwnfox-color"));

        // Case-insensitive label.
        let mut h3 = headers(&[("X-PwnFox-Color", "Blue")]);
        assert_eq!(take_pwnfox_color(&mut h3).as_deref(), Some("blue"));

        // No header -> None.
        let mut h4 = headers(&[("Host", "lab.test")]);
        assert_eq!(take_pwnfox_color(&mut h4), None);
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

    /// Deterministic payload byte at offset `i`. Covers every byte value, so a
    /// body is never valid UTF-8 (e.g. 0xFF, lone continuation bytes).
    fn pattern(i: usize) -> u8 {
        (i.wrapping_mul(2_654_435_761) >> 13) as u8
    }

    /// A generated body of `len` bytes in `frame`-sized data frames, with no
    /// size hint — like a chunked / unknown-length body off the wire.
    struct PatternBody {
        len: usize,
        pos: usize,
        frame: usize,
    }

    impl HttpBody for PatternBody {
        type Data = Bytes;
        type Error = <Body as HttpBody>::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            let this = self.get_mut();
            if this.pos >= this.len {
                return Poll::Ready(None);
            }
            let end = (this.pos + this.frame).min(this.len);
            let chunk: Vec<u8> = (this.pos..end).map(pattern).collect();
            this.pos = end;
            Poll::Ready(Some(Ok(Frame::data(Bytes::from(chunk)))))
        }
    }

    fn pattern_body(len: usize) -> Body {
        Body::from(BoxBody::new(PatternBody {
            len,
            pos: 0,
            frame: 64 * 1024,
        }))
    }

    /// Drain a body, checking every byte against the pattern; returns its length.
    async fn verify_pattern(mut body: Body) -> usize {
        let mut n = 0;
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame.unwrap().into_data() {
                for (k, b) in data.iter().enumerate() {
                    assert_eq!(*b, pattern(n + k), "byte {} differs", n + k);
                }
                n += data.len();
            }
        }
        n
    }

    const MAX: usize = 10 * 1024 * 1024;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
    }

    #[test]
    fn pattern_is_not_utf8() {
        let sample: Vec<u8> = (0..4096).map(pattern).collect();
        assert!(std::str::from_utf8(&sample).is_err());
    }

    #[test]
    fn small_body_is_buffered_whole_and_complete() {
        rt().block_on(async {
            let b = buffer_body(pattern_body(1000), MAX).await.unwrap();
            assert!(b.complete);
            assert_eq!(b.len, 1000);
            assert_eq!(b.retained.len(), 1000);
            let Forward::Complete(bytes) = b.forward else {
                panic!("small body must be buffered whole")
            };
            assert_eq!(verify_pattern(Body::from(bytes)).await, 1000);
        });
    }

    #[test]
    fn body_at_or_just_below_the_ceiling_is_buffered_whole() {
        for len in [PROXY_BUFFER_CEILING - 1, PROXY_BUFFER_CEILING] {
            rt().block_on(async {
                let b = buffer_body(pattern_body(len), MAX).await.unwrap();
                assert_eq!(b.len, len);
                assert!(!b.complete, "record is capped below the wire length");
                assert_eq!(
                    b.retained.len(),
                    MAX,
                    "record is bounded by the capture cap"
                );
                let Forward::Complete(bytes) = b.forward else {
                    panic!("{len} bytes fit under the ceiling")
                };
                assert_eq!(bytes.len(), len);
                assert_eq!(verify_pattern(Body::from(bytes)).await, len);
            });
        }
    }

    #[test]
    fn body_just_above_the_ceiling_is_streamed_in_full_not_truncated() {
        for len in [
            PROXY_BUFFER_CEILING + 1,
            PROXY_BUFFER_CEILING + 3 * 64 * 1024 + 7,
        ] {
            rt().block_on(async {
                let b = buffer_body(pattern_body(len), MAX).await.unwrap();
                assert!(!b.complete);
                assert_eq!(b.retained.len(), MAX);
                assert!(b.len > PROXY_BUFFER_CEILING && b.len <= len, "lower bound");
                assert!(
                    b.retained.iter().enumerate().all(|(i, x)| *x == pattern(i)),
                    "the record holds the true first bytes"
                );
                let Forward::Streaming(body) = b.forward else {
                    panic!("{len} bytes exceed the ceiling")
                };
                assert_eq!(verify_pattern(body).await, len, "every byte forwarded");
            });
        }
    }

    #[test]
    fn capture_cap_above_the_ceiling_still_bounds_the_record() {
        // A capture cap larger than the default ceiling raises the ceiling too.
        let max = PROXY_BUFFER_CEILING + 1024;
        rt().block_on(async {
            let b = buffer_body(pattern_body(max + 1), max).await.unwrap();
            assert_eq!(b.retained.len(), max);
            assert!(!b.complete);
            let Forward::Streaming(body) = b.forward else {
                panic!("exceeds the raised ceiling")
            };
            assert_eq!(verify_pattern(body).await, max + 1);
        });
    }

    #[test]
    fn untouched_intercept_body_is_detected_despite_line_ending_rewrites() {
        let edit = |body: &str| EditedRequest {
            method: "POST".into(),
            target: "/".into(),
            headers: vec![],
            body: body.into(),
        };
        assert!(!body_was_edited(&edit("a\nb"), b"a\r\nb"));
        assert!(!body_was_edited(&edit("\u{fffd}x"), &[0xff, b'x']));
        assert!(body_was_edited(&edit("a\nc"), b"a\r\nb"));
    }

    #[test]
    fn head_edit_keeps_the_original_framing() {
        let (mut parts, ()) = hyper::Request::builder()
            .method("POST")
            .uri("http://lab.test/up")
            .header("transfer-encoding", "chunked")
            .header("x-old", "1")
            .body(())
            .unwrap()
            .into_parts();
        let edit = EditedRequest {
            method: "PUT".into(),
            target: "/up2".into(),
            headers: vec![
                Header {
                    name: "X-New".into(),
                    value: "2".into(),
                },
                Header {
                    name: "Content-Length".into(),
                    value: "5".into(),
                },
            ],
            body: String::new(),
        };
        apply_head_edit(&mut parts, &edit).unwrap();
        assert_eq!(parts.method, Method::PUT);
        assert_eq!(parts.uri.path(), "/up2");
        assert_eq!(parts.headers.get("x-new").unwrap(), "2");
        assert!(parts.headers.get("x-old").is_none());
        assert_eq!(parts.headers.get("transfer-encoding").unwrap(), "chunked");
        assert!(
            parts.headers.get("content-length").is_none(),
            "a typed Content-Length must not override the real framing"
        );
    }
}
