//! Regression: the proxy must never truncate a body and forward it as complete.
//!
//! Bodies are pushed through a real proxy (via the `Engine`) to a local upstream
//! that checks every byte against a deterministic pattern. Sizes straddle the
//! 64 MiB in-memory buffering ceiling; chunked (unknown-length) bodies are the
//! case that used to be cut off at the ceiling.

use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{
    Request, Response,
    body::{Body as HttpBody, Bytes, Frame, Incoming, SizeHint},
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use shrike_engine::{
    Engine,
    config::{ProxyConfig, UpstreamTlsMode},
    core::{TrafficEvent, TrafficSink, TransactionView},
    intercept::{Decision, parse_request_head},
    match_replace::{MatchReplaceRule, RulePart},
    store::HistoryFilter,
};
use std::{
    convert::Infallible,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{net::TcpListener, runtime::Runtime};

const MIB: usize = 1024 * 1024;
/// The proxy's in-memory buffering ceiling (`PROXY_BUFFER_CEILING`).
const CEILING: usize = 64 * MIB;
/// Default capture cap (`ProxyConfig::max_capture_bytes`).
const CAP: usize = 10 * MIB;

/// Large-body tests hold ~64 MiB buffers; run them one at a time.
static HEAVY: Mutex<()> = Mutex::new(());

fn heavy() -> std::sync::MutexGuard<'static, ()> {
    HEAVY.lock().unwrap_or_else(|e| e.into_inner())
}

/// Deterministic payload byte at offset `i`; covers every byte value, so the
/// payload is never valid UTF-8.
fn pattern(i: usize) -> u8 {
    (i.wrapping_mul(2_654_435_761) >> 13) as u8
}

type TestBody = BoxBody<Bytes, Infallible>;

/// A generated body of `len` pattern bytes in 64 KiB frames. Without an exact
/// size hint hyper sends it chunked.
struct PatternBody {
    len: usize,
    pos: usize,
    exact: bool,
}

impl HttpBody for PatternBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let this = self.get_mut();
        if this.pos >= this.len {
            return Poll::Ready(None);
        }
        let end = (this.pos + 64 * 1024).min(this.len);
        let chunk: Vec<u8> = (this.pos..end).map(pattern).collect();
        this.pos = end;
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(chunk)))))
    }

    fn size_hint(&self) -> SizeHint {
        if self.exact {
            SizeHint::with_exact((self.len - self.pos) as u64)
        } else {
            SizeHint::default()
        }
    }
}

fn chunked(len: usize) -> TestBody {
    BoxBody::new(PatternBody {
        len,
        pos: 0,
        exact: false,
    })
}

fn sized(len: usize) -> TestBody {
    BoxBody::new(PatternBody {
        len,
        pos: 0,
        exact: true,
    })
}

fn full(bytes: impl Into<Bytes>) -> TestBody {
    Full::new(bytes.into()).boxed()
}

/// What the upstream saw for a `/check` request.
#[derive(Debug, PartialEq)]
struct Seen {
    len: usize,
    /// First offset whose byte didn't match the pattern.
    bad: Option<usize>,
    content_length: Option<String>,
    chunked: bool,
    marker: Option<String>,
    pwnfox: Option<String>,
}

impl Seen {
    fn parse(s: &str) -> Self {
        let field = |k: &str| {
            s.lines()
                .find_map(|l| l.strip_prefix(&format!("{k}=")))
                .filter(|v| !v.is_empty())
                .map(str::to_string)
        };
        Seen {
            len: field("len").unwrap().parse().unwrap(),
            bad: field("bad").map(|v| v.parse().unwrap()),
            content_length: field("cl"),
            chunked: field("chunked").as_deref() == Some("true"),
            marker: field("marker"),
            pwnfox: field("pwnfox"),
        }
    }

    /// The whole pattern arrived intact, with exactly one framing mechanism.
    fn assert_intact(&self, len: usize) {
        assert_eq!(self.len, len, "upstream received the wrong length");
        assert_eq!(self.bad, None, "upstream body differs from what was sent");
        assert!(
            self.chunked != self.content_length.is_some(),
            "exactly one of Content-Length / chunked framing: {self:?}"
        );
        if let Some(cl) = &self.content_length {
            assert_eq!(cl, &len.to_string(), "Content-Length matches the body");
        }
    }
}

struct Upstream {
    addr: SocketAddr,
    /// Requests that reached the upstream.
    hits: Arc<AtomicUsize>,
}

/// Upstream routes:
/// - `/check`: verify the request body against the pattern, report what it saw;
/// - `/echo`: return the request body bytes unchanged;
/// - `/big/<n>`: stream `n` pattern bytes back, chunked.
async fn upstream(
    req: Request<Incoming>,
    hits: Arc<AtomicUsize>,
) -> Result<Response<TestBody>, hyper::Error> {
    hits.fetch_add(1, Ordering::SeqCst);
    let path = req.uri().path().to_string();
    let header = |n: &str| {
        req.headers()
            .get(n)
            .map(|v| v.to_str().unwrap_or_default().to_string())
    };
    let cl = header("content-length");
    let is_chunked = header("transfer-encoding").is_some_and(|v| v.contains("chunked"));
    let marker = header("x-marker");
    let pwnfox = header("x-pwnfox-color");

    if let Some(n) = path.strip_prefix("/big/") {
        return Ok(Response::builder()
            .header("content-type", "application/octet-stream")
            .header("x-up", "original")
            .body(chunked(n.parse().unwrap()))
            .unwrap());
    }

    let mut body = req.into_body();
    if path == "/echo" {
        let bytes = body.collect().await?.to_bytes();
        return Ok(Response::new(full(bytes)));
    }

    let (mut len, mut bad) = (0usize, None);
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame?.into_data() {
            if bad.is_none()
                && let Some(k) = data
                    .iter()
                    .enumerate()
                    .position(|(k, b)| *b != pattern(len + k))
            {
                bad = Some(len + k);
            }
            len += data.len();
        }
    }
    let report = format!(
        "len={len}\nbad={}\ncl={}\nchunked={is_chunked}\nmarker={}\npwnfox={}\n",
        bad.map(|b| b.to_string()).unwrap_or_default(),
        cl.unwrap_or_default(),
        marker.unwrap_or_default(),
        pwnfox.unwrap_or_default(),
    );
    Ok(Response::new(full(report)))
}

async fn spawn_upstream() -> Upstream {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let svc = service_fn(move |req| upstream(req, Arc::clone(&counter)));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), svc)
                    .await;
            });
        }
    });
    Upstream { addr, hits }
}

/// Send one request through the proxy (absolute-form target, as a browser does).
async fn send(
    proxy: SocketAddr,
    req: Request<TestBody>,
) -> Result<Response<Incoming>, hyper::Error> {
    let stream = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    tokio::spawn(conn);
    tx.send_request(req).await
}

async fn text(res: Response<Incoming>) -> String {
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

/// Drain a response body, checking every byte against the pattern.
async fn verify_pattern(res: Response<Incoming>) -> (usize, Option<usize>) {
    let mut body = res.into_body();
    let (mut len, mut bad) = (0usize, None);
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame.unwrap().into_data() {
            if bad.is_none()
                && let Some(k) = data
                    .iter()
                    .enumerate()
                    .position(|(k, b)| *b != pattern(len + k))
            {
                bad = Some(len + k);
            }
            len += data.len();
        }
    }
    (len, bad)
}

struct Lab {
    helper: Runtime,
    _dir: tempfile::TempDir,
    engine: Arc<Engine>,
    proxy: SocketAddr,
    up: Upstream,
}

impl Lab {
    fn new() -> Self {
        let helper = Runtime::new().unwrap();
        let up = helper.block_on(spawn_upstream());
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::new(ProxyConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            data_dir: dir.path().to_path_buf(),
            upstream_tls: UpstreamTlsMode::Verify,
            ..ProxyConfig::default()
        })
        .unwrap();
        assert_eq!(engine.config().max_capture_bytes, CAP);
        let proxy = engine.start_proxy().unwrap();
        Lab {
            helper,
            _dir: dir,
            engine,
            proxy,
            up,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.up.addr)
    }

    /// POST `body` to `/check?case=<case>` and return what the upstream saw.
    fn check(&self, case: &str, body: TestBody, content_length: Option<usize>) -> Seen {
        let mut req = Request::builder()
            .method("POST")
            .uri(self.url(&format!("/check?case={case}")));
        if let Some(n) = content_length {
            req = req.header("content-length", n);
        }
        let req = req.body(body).unwrap();
        let res = self.helper.block_on(send(self.proxy, req)).unwrap();
        assert_eq!(res.status(), 200);
        Seen::parse(&self.helper.block_on(text(res)))
    }

    /// Wait for the history row whose URL contains `needle` to be persisted.
    fn record(&self, needle: &str) -> TransactionView {
        for _ in 0..500 {
            self.engine.store().flush().unwrap();
            let rows = self
                .engine
                .history_page(
                    &HistoryFilter {
                        search: Some(needle.into()),
                        ..Default::default()
                    },
                    10,
                    0,
                )
                .unwrap();
            if let Some(row) = rows.first() {
                return self.engine.history_get(row.id).unwrap().unwrap();
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("no history row for {needle}");
    }
}

impl Drop for Lab {
    fn drop(&mut self) {
        let _ = self.engine.stop_proxy();
    }
}

/// The record holds at most the capture cap and says it is incomplete.
fn assert_bounded_incomplete(body: &shrike_engine::core::BodyView, wire_at_least: usize) {
    assert!(
        !body.complete,
        "an oversized body must not be marked complete"
    );
    assert_eq!(body.len, CAP, "the record is bounded by the capture cap");
    assert!(
        body.wire_len >= wire_at_least,
        "wire length {} reported below {wire_at_least}",
        body.wire_len
    );
}

#[test]
fn chunked_request_just_below_the_ceiling_is_forwarded_intact() {
    let _g = heavy();
    let lab = Lab::new();
    let len = CEILING - 1;
    lab.check("below", chunked(len), None).assert_intact(len);
    let rec = lab.record("case=below");
    assert_bounded_incomplete(&rec.request.body, len);
    assert_eq!(
        rec.request.body.wire_len, len,
        "fully buffered: exact length"
    );
}

#[test]
fn chunked_request_just_above_the_ceiling_is_forwarded_intact() {
    let _g = heavy();
    let lab = Lab::new();
    for (case, len) in [("above1", CEILING + 1), ("above2", CEILING + 5 * MIB + 3)] {
        lab.check(case, chunked(len), None).assert_intact(len);
        let rec = lab.record(&format!("case={case}"));
        // Streamed past the ceiling: the wire length is a lower bound.
        assert_bounded_incomplete(&rec.request.body, CEILING);
    }
}

#[test]
fn content_length_request_above_the_ceiling_is_forwarded_intact() {
    let _g = heavy();
    let lab = Lab::new();
    let len = CEILING + 1;
    lab.check("sized", sized(len), Some(len)).assert_intact(len);
    let rec = lab.record("case=sized");
    assert!(!rec.request.body.complete);
    assert_eq!(rec.request.body.wire_len, len);
}

#[test]
fn small_binary_request_is_forwarded_byte_for_byte() {
    let lab = Lab::new();
    for (case, body) in [
        ("small-chunked", chunked(4096)),
        ("small-sized", sized(4096)),
    ] {
        let cl = (case == "small-sized").then_some(4096);
        lab.check(case, body, cl).assert_intact(4096);
        let rec = lab.record(&format!("case={case}"));
        assert!(rec.request.body.complete, "a small body is captured whole");
        assert_eq!(rec.request.body.len, 4096);
    }
}

#[test]
fn chunked_response_just_above_the_ceiling_reaches_the_client_intact() {
    let _g = heavy();
    let lab = Lab::new();
    let len = CEILING + 1;
    let req = Request::builder()
        .uri(lab.url(&format!("/big/{len}")))
        .body(full(""))
        .unwrap();
    let res = lab.helper.block_on(send(lab.proxy, req)).unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(lab.helper.block_on(verify_pattern(res)), (len, None));
    let rec = lab.record(&format!("/big/{len}"));
    assert_bounded_incomplete(&rec.response.unwrap().body, CEILING);
}

#[test]
fn match_replace_rewrites_small_bodies_and_streams_large_ones_untouched() {
    let _g = heavy();
    let lab = Lab::new();
    let rule = |part, m: &str, r: &str| MatchReplaceRule {
        enabled: true,
        name: String::new(),
        part,
        is_regex: false,
        match_: m.into(),
        replace: r.into(),
    };
    lab.engine
        .set_match_replace(vec![
            // Header rules see hyper's lower-cased header names.
            rule(
                RulePart::RequestHeader,
                "x-marker: before",
                "x-marker: after",
            ),
            rule(RulePart::RequestBody, "SECRET", "REDACT"),
            rule(
                RulePart::ResponseHeader,
                "x-up: original",
                "x-up: rewritten",
            ),
        ])
        .unwrap();

    // Small text body: the body rule applies (existing behaviour).
    let req = Request::builder()
        .method("POST")
        .uri(lab.url("/echo"))
        .body(full("hello SECRET"))
        .unwrap();
    let res = lab.helper.block_on(send(lab.proxy, req)).unwrap();
    assert_eq!(lab.helper.block_on(text(res)), "hello REDACT");

    // Small binary body the rules don't match: forwarded byte for byte.
    let binary: Vec<u8> = (0..4096).map(pattern).collect();
    let req = Request::builder()
        .method("POST")
        .uri(lab.url("/echo"))
        .body(full(binary.clone()))
        .unwrap();
    let res = lab.helper.block_on(send(lab.proxy, req)).unwrap();
    let echoed = lab
        .helper
        .block_on(res.into_body().collect())
        .unwrap()
        .to_bytes();
    assert_eq!(&echoed[..], &binary[..]);

    // Large streamed request: header rules still apply, the body is untouched.
    let len = CEILING + 1;
    let req = Request::builder()
        .method("POST")
        .uri(lab.url("/check?case=mr-big"))
        .header("x-marker", "before")
        .body(chunked(len))
        .unwrap();
    let res = lab.helper.block_on(send(lab.proxy, req)).unwrap();
    let seen = Seen::parse(&lab.helper.block_on(text(res)));
    seen.assert_intact(len);
    assert_eq!(seen.marker.as_deref(), Some("after"));

    // Large streamed response: header rule applies, body intact.
    let req = Request::builder()
        .uri(lab.url(&format!("/big/{len}")))
        .body(full(""))
        .unwrap();
    let res = lab.helper.block_on(send(lab.proxy, req)).unwrap();
    assert_eq!(res.headers()["x-up"], "rewritten");
    assert_eq!(lab.helper.block_on(verify_pattern(res)), (len, None));
}

/// Forwards each intercepted request's id and raw text to the test.
struct InterceptTap(mpsc::Sender<(u64, String)>);

impl TrafficSink for InterceptTap {
    fn handle(&mut self, event: &TrafficEvent) {
        if let TrafficEvent::Intercepted { id, raw, .. } = event {
            let _ = self.0.send((*id, raw.clone()));
        }
    }
}

/// Send `req` in the background, wait for it to be intercepted, let `decide`
/// edit the raw text shown to the user (or return `None` to forward as-is),
/// resolve it, and return the client's result.
fn intercept_with(
    lab: &Lab,
    taps: &mpsc::Receiver<(u64, String)>,
    req: Request<TestBody>,
    decide: impl FnOnce(&str) -> Option<String>,
) -> Result<Response<Incoming>, hyper::Error> {
    let proxy = lab.proxy;
    let pending = lab.helper.spawn(async move { send(proxy, req).await });
    let (id, raw) = taps
        .recv_timeout(Duration::from_secs(30))
        .expect("request was intercepted");
    let decision = match decide(&raw) {
        Some(edited) => Decision::Forward(Some(parse_request_head(&edited).unwrap())),
        None => Decision::Forward(None),
    };
    lab.engine.intercept_resolve(id, decision);
    lab.helper.block_on(pending).unwrap()
}

/// Insert a header line after the request line of a raw request.
fn with_header(raw: &str, line: &str) -> String {
    let (first, rest) = raw.split_once("\r\n").unwrap();
    format!("{first}\r\n{line}\r\n{rest}")
}

#[test]
fn interception_keeps_original_bytes_and_refuses_unsafe_body_edits() {
    let _g = heavy();
    let lab = Lab::new();
    let (tx, taps) = mpsc::channel();
    lab.engine.add_sink(Box::new(InterceptTap(tx)));
    lab.engine.set_intercept(true);

    // Small binary body forwarded through an untouched edit: the original bytes
    // go upstream, not a lossy UTF-8 rendering of them.
    let binary: Vec<u8> = (0..4096).map(pattern).collect();
    let req = Request::builder()
        .method("POST")
        .uri(lab.url("/echo"))
        .body(full(binary.clone()))
        .unwrap();
    let res = intercept_with(&lab, &taps, req, |raw| Some(raw.to_string())).unwrap();
    let echoed = lab
        .helper
        .block_on(res.into_body().collect())
        .unwrap()
        .to_bytes();
    assert_eq!(&echoed[..], &binary[..]);

    // Small text body edited by the user: the edit is forwarded (existing behaviour).
    let req = Request::builder()
        .method("POST")
        .uri(lab.url("/echo"))
        .body(full("original"))
        .unwrap();
    let res = intercept_with(&lab, &taps, req, |raw| {
        Some(raw.replace("original", "edited"))
    })
    .unwrap();
    assert_eq!(lab.helper.block_on(text(res)), "edited");

    // Large streamed body with a header-only edit: the header changes, every
    // body byte still arrives.
    let len = CEILING + 1;
    let req = Request::builder()
        .method("POST")
        .uri(lab.url("/check?case=icpt-big"))
        .body(chunked(len))
        .unwrap();
    let res = intercept_with(&lab, &taps, req, |raw| {
        Some(with_header(raw, "X-Marker: added"))
    })
    .unwrap();
    let seen = Seen::parse(&lab.helper.block_on(text(res)));
    seen.assert_intact(len);
    assert_eq!(seen.marker.as_deref(), Some("added"));

    // Large streamed body forwarded unchanged.
    let req = Request::builder()
        .method("POST")
        .uri(lab.url("/check?case=icpt-fwd"))
        .body(chunked(len))
        .unwrap();
    let res = intercept_with(&lab, &taps, req, |_| None).unwrap();
    Seen::parse(&lab.helper.block_on(text(res))).assert_intact(len);

    // A body edit on a body only partly captured (over the 10 MiB cap) would
    // forward an incomplete body: it is refused, and nothing reaches upstream.
    let before = lab.up.hits.load(Ordering::SeqCst);
    let req = Request::builder()
        .method("POST")
        .uri(lab.url("/check?case=icpt-refused"))
        .body(chunked(CAP + MIB))
        .unwrap();
    let res = intercept_with(&lab, &taps, req, |raw| {
        let (head, _) = raw.split_once("\r\n\r\n").unwrap();
        Some(format!("{head}\r\n\r\nreplaced body"))
    })
    .unwrap();
    assert_eq!(res.status(), 413);
    assert!(
        lab.helper
            .block_on(text(res))
            .contains("too large to capture")
    );
    assert_eq!(
        lab.up.hits.load(Ordering::SeqCst),
        before,
        "nothing forwarded"
    );
    let rec = lab.record("case=icpt-refused");
    assert!(
        rec.error
            .as_deref()
            .is_some_and(|e| e.contains("intercept edit refused")),
        "refusal recorded: {:?}",
        rec.error
    );
    lab.engine.set_intercept(false);
}

/// History integrity: after an intercept edit, the recorded request must match
/// what actually went upstream — method, headers and body — even with no match
/// & replace rule active. Regression for the forward_request recording bug.
#[test]
fn edited_intercept_request_is_recorded_as_sent() {
    let lab = Lab::new();
    let (tx, taps) = mpsc::channel();
    lab.engine.add_sink(Box::new(InterceptTap(tx)));
    lab.engine.set_intercept(true);

    // Original request: POST /check?case=icpt-rec with body "SECRET".
    let req = Request::builder()
        .method("POST")
        .uri(lab.url("/check?case=icpt-rec"))
        .body(full("SECRET"))
        .unwrap();
    // Edit it: add a header and replace the body entirely.
    let res = intercept_with(&lab, &taps, req, |raw| {
        let edited = with_header(raw, "X-Marker: added").replace("SECRET", "REPLACED-BODY");
        Some(edited)
    })
    .unwrap();
    let seen = Seen::parse(&lab.helper.block_on(text(res)));
    // The server received the edited header and the new body length.
    assert_eq!(
        seen.marker.as_deref(),
        Some("added"),
        "server saw the added header"
    );
    assert_eq!(
        seen.content_length.as_deref(),
        Some("13"),
        "server saw the new body length"
    );

    // History records the request as actually sent, not the pre-edit capture.
    let rec = lab.record("case=icpt-rec");
    assert_eq!(rec.request.method, "POST");
    assert!(
        rec.request
            .headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case("x-marker") && h.value == "added"),
        "recorded request is missing the edited header: {:?}",
        rec.request.headers
    );
    assert_eq!(
        rec.request.body.text.as_deref(),
        Some("REPLACED-BODY"),
        "recorded body must be the edited body that was sent"
    );
    lab.engine.set_intercept(false);
}

/// PwnFox container colour: the X-PwnFox-Color header is recorded on the
/// transaction and stripped before the request reaches the target.
#[test]
fn pwnfox_color_is_recorded_and_not_forwarded() {
    let lab = Lab::new();
    let req = Request::builder()
        .method("POST")
        .uri(lab.url("/check?case=pwnfox"))
        .header("x-pwnfox-color", "red")
        .body(full("hi"))
        .unwrap();
    let res = lab.helper.block_on(send(lab.proxy, req)).unwrap();
    let seen = Seen::parse(&lab.helper.block_on(text(res)));
    assert_eq!(
        seen.pwnfox, None,
        "X-PwnFox-Color must not reach the target"
    );

    let rec = lab.record("case=pwnfox");
    assert_eq!(
        rec.request.highlight.as_deref(),
        Some("red"),
        "colour recorded on the request"
    );
}
