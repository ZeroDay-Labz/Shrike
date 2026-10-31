//! Race-condition attack engine: fire N copies of a request engineered to arrive
//! at the server at the same instant.
//!
//! This is the one genuinely distinct capability a "turbo" fuzzer has over the
//! regular [`crate::intruder`] — which, on a pooled client, cannot control when
//! bytes hit the wire. Here we drop to raw sockets and use the classic
//! **last-byte synchronisation** technique: open one connection per copy, write
//! everything *except the final byte* of each request, park every connection on
//! a shared gate, then release the last byte on all of them together. The server
//! has already parsed each request up to its last byte and only needs that byte
//! to begin processing, so the requests are handled in a tight burst — the window
//! that exposes limit-overrun, double-spend and TOCTOU bugs.
//!
//! Results are reported through the same [`AttackEvent`] stream the Intruder
//! uses, so they render in the existing results grid: one row per copy, with its
//! status and response length, making an outlier (e.g. one `200` among `429`s)
//! obvious at a glance.
//!
//! This first version speaks HTTP/1.1 (one TCP/TLS connection per copy). An
//! HTTP/2 single-packet variant (many streams, one TCP segment) is a natural
//! later addition and would slot in behind the same config and event stream.

use crate::config::UpstreamTlsMode;
use crate::core::HttpService;
use crate::intruder::{AttackEvent, AttackResult};
use crate::proxy;
use crate::scope::Scope;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Notify;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;

/// Upper bound on synchronised copies. One connection each; beyond a couple of
/// hundred the OS/handshake cost dominates and synchronisation degrades anyway.
pub const MAX_RACE_COUNT: usize = 256;
/// How long we wait for every connection to warm up (connect + write all but the
/// last byte) before releasing the gate regardless. Keeps one slow/failed
/// connection from stalling the whole burst.
const WARMUP_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Deserialize)]
pub struct RaceConfig {
    pub service: HttpService,
    /// Raw HTTP/1.1 request (request line + headers, optional blank line + body).
    /// `Content-Length` is recalculated from the body before sending.
    pub request: String,
    /// How many synchronised copies to fire.
    pub count: usize,
    /// Per-connection ceiling for connect + warmup + reading the response.
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_timeout_ms() -> u64 {
    15_000
}

/// Build the exact wire bytes for one copy: head normalised to CRLF with a
/// correct `Content-Length`, blank-line terminator, then the body verbatim.
fn build_wire(request: &str) -> Vec<u8> {
    // Split head/body on the first blank line in the ORIGINAL text, so the body's
    // own bytes (which may contain CRLFs or none) are preserved untouched.
    let (head_raw, body) = if let Some(i) = request.find("\r\n\r\n") {
        (&request[..i], &request[i + 4..])
    } else if let Some(i) = request.find("\n\n") {
        (&request[..i], &request[i + 2..])
    } else {
        (request, "")
    };

    let has_body = !body.is_empty();
    let mut lines: Vec<String> = Vec::new();
    for line in head_raw.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        // Drop any existing Content-Length; we re-add the correct one below.
        if let Some((name, _)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        lines.push(line.to_string());
    }
    if has_body {
        lines.push(format!("Content-Length: {}", body.len()));
    }

    let mut wire = Vec::new();
    wire.extend_from_slice(lines.join("\r\n").as_bytes());
    wire.extend_from_slice(b"\r\n\r\n");
    wire.extend_from_slice(body.as_bytes());
    wire
}

/// The request-line path (before `?`), for the scope check.
fn request_path(request: &str) -> String {
    let first = request.lines().next().unwrap_or("");
    let target = first.split_whitespace().nth(1).unwrap_or("/");
    target.split('?').next().unwrap_or(target).to_string()
}

/// Either a plain TCP stream or a TLS stream over one — both are AsyncRead+Write.
trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

/// Connect to the target, with TLS when the service is secure. Disables Nagle so
/// the withheld final byte is flushed the instant we write it.
async fn connect(service: &HttpService, tls: Option<&TlsConnector>) -> Result<Box<dyn Stream>> {
    let tcp = TcpStream::connect((service.host.as_str(), service.port))
        .await
        .with_context(|| format!("connecting to {}:{}", service.host, service.port))?;
    tcp.set_nodelay(true).ok();
    match tls {
        Some(connector) => {
            let name = ServerName::try_from(service.host.clone())
                .with_context(|| format!("invalid TLS server name {:?}", service.host))?;
            let stream = connector
                .connect(name, tcp)
                .await
                .context("TLS handshake")?;
            Ok(Box::new(stream))
        }
        None => Ok(Box::new(tcp)),
    }
}

/// Read one HTTP/1.1 response far enough to report its status and body length.
async fn read_response<S: AsyncRead + Unpin>(s: &mut S) -> Result<(u16, usize)> {
    let mut buf: Vec<u8> = Vec::with_capacity(8192);
    let mut tmp = [0u8; 8192];

    // 1. Read until the end of the header block.
    let header_end = loop {
        if let Some(p) = find(&buf, b"\r\n\r\n") {
            break p + 4;
        }
        let n = s.read(&mut tmp).await.context("reading response headers")?;
        if n == 0 {
            anyhow::bail!("connection closed before response headers");
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 64 * 1024 {
            anyhow::bail!("response headers too large");
        }
    };

    let head = &buf[..header_end];
    let status = parse_status(head)?;
    let (content_len, chunked) = parse_framing(head);
    let mut body_len = buf.len() - header_end;

    // 2. Read the body far enough to measure it, per its framing.
    if chunked {
        while !ends_with_terminal_chunk(&buf[header_end..]) {
            let n = s.read(&mut tmp).await.context("reading chunked body")?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            body_len = buf.len() - header_end;
        }
    } else if let Some(cl) = content_len {
        while body_len < cl {
            let n = s.read(&mut tmp).await.context("reading response body")?;
            if n == 0 {
                break;
            }
            body_len += n;
        }
    } else {
        // No framing header: read to EOF (bounded by the caller's timeout).
        loop {
            let n = s.read(&mut tmp).await.context("reading response body")?;
            if n == 0 {
                break;
            }
            body_len += n;
        }
    }

    Ok((status, body_len))
}

fn parse_status(head: &[u8]) -> Result<u16> {
    let line = head.split(|&b| b == b'\n').next().unwrap_or(head);
    let text = String::from_utf8_lossy(line);
    let code = text
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .context("no status code in response line")?;
    Ok(code)
}

/// Returns (Content-Length, is_chunked) from a header block.
fn parse_framing(head: &[u8]) -> (Option<usize>, bool) {
    let text = String::from_utf8_lossy(head);
    let mut content_len = None;
    let mut chunked = false;
    for line in text.split("\r\n").skip(1) {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim();
            if name.eq_ignore_ascii_case("content-length") {
                content_len = value.trim().parse::<usize>().ok();
            } else if name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
            }
        }
    }
    (content_len, chunked)
}

fn ends_with_terminal_chunk(body: &[u8]) -> bool {
    body.ends_with(b"0\r\n\r\n")
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// One synchronised copy: connect, write all but the last byte, park on the gate,
/// then release the last byte and read the response. `elapsed` is measured from
/// the gate release so every copy's timing shares the same zero.
async fn one_copy(
    index: usize,
    wire: Arc<Vec<u8>>,
    service: HttpService,
    tls: Option<Arc<TlsConnector>>,
    gate: Arc<Notify>,
    ready: Arc<AtomicUsize>,
    timeout: Duration,
) -> AttackResult {
    let run = async {
        let mut stream = connect(&service, tls.as_deref()).await?;
        // Write everything except the final byte, and flush it to the kernel.
        let split = wire.len().saturating_sub(1);
        stream
            .write_all(&wire[..split])
            .await
            .context("writing request prefix")?;
        stream.flush().await.context("flushing request prefix")?;

        // Park on the gate. Register the waiter BEFORE announcing readiness so a
        // release that fires the instant we become ready cannot slip past us.
        let notified = gate.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        ready.fetch_add(1, Ordering::Relaxed);
        notified.await;

        // Release: the single withheld byte, flushed immediately (Nagle is off).
        let started = Instant::now();
        stream
            .write_all(&wire[split..])
            .await
            .context("writing final byte")?;
        stream.flush().await.context("flushing final byte")?;

        let (status, length) = read_response(&mut stream).await?;
        Ok::<_, anyhow::Error>((status, length, started.elapsed()))
    };

    match tokio::time::timeout(timeout, run).await {
        Ok(Ok((status, length, elapsed))) => AttackResult {
            index: index as u64,
            payloads: vec![format!("copy {}", index + 1)],
            status: Some(status),
            length,
            duration_ms: elapsed.as_millis() as u64,
            error: None,
        },
        Ok(Err(e)) => error_result(index, format!("{e:#}")),
        Err(_) => error_result(index, format!("timed out after {} ms", timeout.as_millis())),
    }
}

fn error_result(index: usize, message: String) -> AttackResult {
    AttackResult {
        index: index as u64,
        payloads: vec![format!("copy {}", index + 1)],
        status: None,
        length: 0,
        duration_ms: 0,
        error: Some(message),
    }
}

/// Run a race-condition attack to completion, reporting through `sink`.
///
/// Every copy is checked against `scope` (when enforced) before any socket is
/// opened — an automated burst must never leave the engagement scope.
pub async fn run_race(
    attack_id: u64,
    config: RaceConfig,
    tls_mode: UpstreamTlsMode,
    sink: Arc<dyn Fn(AttackEvent) + Send + Sync>,
    stop: Arc<AtomicBool>,
    scope: Option<Arc<RwLock<Scope>>>,
) {
    let requested = config.count;
    let count = config.count.clamp(1, MAX_RACE_COUNT);

    // Scope enforcement: the same request goes to every connection, so one check
    // gates the whole burst.
    if let Some(scope) = &scope {
        let path = request_path(&config.request);
        let ok = scope
            .read()
            .expect("scope lock")
            .in_scope(&config.service, &path);
        if !ok {
            sink(AttackEvent::Started {
                attack_id,
                total: 0,
                capped: false,
            });
            sink(AttackEvent::Done {
                attack_id,
                completed: 0,
                stopped: true,
            });
            return;
        }
    }

    sink(AttackEvent::Started {
        attack_id,
        total: count as u64,
        capped: requested > MAX_RACE_COUNT,
    });

    if stop.load(Ordering::Relaxed) {
        sink(AttackEvent::Done {
            attack_id,
            completed: 0,
            stopped: true,
        });
        return;
    }

    // Build the TLS connector once (shared across connections) when needed.
    let tls = if config.service.secure {
        match build_connector(tls_mode) {
            Ok(c) => Some(Arc::new(c)),
            Err(e) => {
                sink(AttackEvent::Results {
                    results: vec![error_result(0, format!("TLS setup failed: {e:#}"))],
                });
                sink(AttackEvent::Done {
                    attack_id,
                    completed: 0,
                    stopped: false,
                });
                return;
            }
        }
    } else {
        None
    };

    let wire = Arc::new(build_wire(&config.request));
    let gate = Arc::new(Notify::new());
    let ready = Arc::new(AtomicUsize::new(0));
    let timeout = Duration::from_millis(config.timeout_ms.max(1));

    let mut set = tokio::task::JoinSet::new();
    for index in 0..count {
        set.spawn(one_copy(
            index,
            Arc::clone(&wire),
            config.service.clone(),
            tls.clone(),
            Arc::clone(&gate),
            Arc::clone(&ready),
            timeout,
        ));
    }

    // Coordinator: once every connection has warmed up (or the deadline passes),
    // release them all at once. notify_waiters wakes every parked waiter together.
    let warmup_start = Instant::now();
    loop {
        if ready.load(Ordering::Relaxed) >= count || warmup_start.elapsed() >= WARMUP_DEADLINE {
            break;
        }
        if stop.load(Ordering::Relaxed) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    gate.notify_waiters();

    let mut results: Vec<AttackResult> = Vec::with_capacity(count);
    while let Some(joined) = set.join_next().await {
        if let Ok(r) = joined {
            results.push(r);
        }
    }
    results.sort_by_key(|r| r.index);
    let completed = results.iter().filter(|r| r.error.is_none()).count() as u64;

    sink(AttackEvent::Results { results });
    sink(AttackEvent::Done {
        attack_id,
        completed,
        stopped: stop.load(Ordering::Relaxed),
    });
}

/// A rustls connector for raw sockets, honouring the configured upstream TLS mode.
/// ALPN advertises only HTTP/1.1 — this engine speaks 1.1 on the wire.
fn build_connector(mode: UpstreamTlsMode) -> Result<TlsConnector> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = proxy::client_tls_config(mode, provider)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsConnector::from(Arc::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[test]
    fn build_wire_sets_content_length_and_crlf() {
        let wire = build_wire("POST /x HTTP/1.1\nHost: h\n\nname=value");
        let text = String::from_utf8(wire).unwrap();
        assert!(text.contains("\r\nContent-Length: 10\r\n"), "got: {text:?}");
        assert!(text.ends_with("\r\n\r\nname=value"));
        // request line and Host survived, in CRLF form
        assert!(text.starts_with("POST /x HTTP/1.1\r\nHost: h\r\n"));
    }

    #[test]
    fn build_wire_replaces_a_stale_content_length() {
        let wire = build_wire("POST /x HTTP/1.1\r\nContent-Length: 999\r\n\r\nab");
        let text = String::from_utf8(wire).unwrap();
        assert!(text.contains("Content-Length: 2"), "got: {text:?}");
        assert!(!text.contains("999"));
    }

    #[test]
    fn build_wire_no_body_has_no_content_length() {
        let wire = build_wire("GET / HTTP/1.1\nHost: h\n\n");
        let text = String::from_utf8(wire).unwrap();
        assert!(!text.to_ascii_lowercase().contains("content-length"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn request_path_strips_query() {
        assert_eq!(request_path("GET /a/b?x=1 HTTP/1.1\r\n"), "/a/b");
        assert_eq!(request_path("POST /p HTTP/1.1"), "/p");
    }

    #[test]
    fn parse_framing_reads_content_length_and_chunked() {
        let (cl, chunked) = parse_framing(b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n");
        assert_eq!(cl, Some(42));
        assert!(!chunked);
        let (cl, chunked) = parse_framing(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        assert_eq!(cl, None);
        assert!(chunked);
    }

    #[test]
    fn find_locates_subsequence() {
        assert_eq!(find(b"abc\r\n\r\nxyz", b"\r\n\r\n"), Some(3));
        assert_eq!(find(b"abc", b"\r\n\r\n"), None);
    }

    #[tokio::test]
    async fn read_response_parses_status_and_body_length() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            s.write_all(b"HTTP/1.1 429 Too Many\r\nContent-Length: 5\r\n\r\nhello")
                .await
                .unwrap();
            s.flush().await.unwrap();
            // keep the socket open so the reader relies on Content-Length, not EOF
            tokio::time::sleep(Duration::from_millis(200)).await;
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (status, len) = read_response(&mut client).await.unwrap();
        assert_eq!(status, 429);
        assert_eq!(len, 5);
    }

    /// End-to-end: a server that counts concurrent in-flight requests. With
    /// last-byte synchronisation the copies should overlap, so the peak
    /// concurrency the server sees is well above 1.
    #[tokio::test]
    async fn race_copies_arrive_concurrently() {
        use std::sync::atomic::AtomicUsize;

        let inflight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv_inflight = Arc::clone(&inflight);
        let srv_peak = Arc::clone(&peak);
        tokio::spawn(async move {
            loop {
                let (mut s, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                let inflight = Arc::clone(&srv_inflight);
                let peak = Arc::clone(&srv_peak);
                tokio::spawn(async move {
                    // Read the request headers (until blank line).
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 1024];
                    loop {
                        match s.read(&mut tmp).await {
                            Ok(0) => break,
                            Ok(n) => {
                                buf.extend_from_slice(&tmp[..n]);
                                if find(&buf, b"\r\n\r\n").is_some() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    // Enter the critical section: bump in-flight, record the peak,
                    // hold briefly so overlapping requests are visible, then leave.
                    let now = inflight.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(80)).await;
                    inflight.fetch_sub(1, Ordering::SeqCst);
                    let _ = s
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await;
                    let _ = s.flush().await;
                });
            }
        });

        let config = RaceConfig {
            service: HttpService {
                host: "127.0.0.1".into(),
                port: addr.port(),
                secure: false,
            },
            request: "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".into(),
            count: 8,
            timeout_ms: 5_000,
        };
        let results = Arc::new(std::sync::Mutex::new(Vec::<AttackResult>::new()));
        let r2 = Arc::clone(&results);
        let sink: Arc<dyn Fn(AttackEvent) + Send + Sync> = Arc::new(move |ev| {
            if let AttackEvent::Results { results } = ev {
                r2.lock().unwrap().extend(results);
            }
        });
        run_race(
            1,
            config,
            UpstreamTlsMode::Verify,
            sink,
            Arc::new(AtomicBool::new(false)),
            None,
        )
        .await;

        let got = results.lock().unwrap();
        assert_eq!(got.len(), 8, "every copy produced a result");
        assert!(
            got.iter().all(|r| r.status == Some(200)),
            "all 200: {got:?}"
        );
        assert!(
            peak.load(Ordering::SeqCst) >= 3,
            "synchronised copies must overlap at the server; peak concurrency was {}",
            peak.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn out_of_scope_race_sends_nothing() {
        // non-empty scope that does NOT include our host
        let scope = Arc::new(RwLock::new(
            Scope::from_rules(vec![crate::scope::ScopeRule::include_host("only.example")]).unwrap(),
        ));
        let config = RaceConfig {
            service: HttpService {
                host: "127.0.0.1".into(),
                port: 1, // would fail to connect if we ever tried
                secure: false,
            },
            request: "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n".into(),
            count: 4,
            timeout_ms: 500,
        };
        let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let s2 = Arc::clone(&stopped);
        let sink: Arc<dyn Fn(AttackEvent) + Send + Sync> = Arc::new(move |ev| {
            if let AttackEvent::Done { stopped, .. } = ev
                && stopped
            {
                s2.store(true, Ordering::SeqCst);
            }
        });
        run_race(
            1,
            config,
            UpstreamTlsMode::Verify,
            sink,
            Arc::new(AtomicBool::new(false)),
            Some(scope),
        )
        .await;
        assert!(
            stopped.load(Ordering::SeqCst),
            "out-of-scope burst is refused"
        );
    }
}
