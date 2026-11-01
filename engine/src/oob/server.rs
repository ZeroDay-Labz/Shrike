//! A self-hosted out-of-band interaction server (OAST).
//!
//! Blind vulnerabilities are confirmed by making the target reach out to a
//! server the tester controls and watching for the callback. This is that
//! server: a DNS responder and an HTTP listener bound to the tester's own
//! machine, under a domain the tester points at it (a wildcard `A` record for
//! `*.<domain>` → the server's public IP). Each probe gets a unique token
//! `<token>.<domain>`; when the target resolves or fetches it, the hit is
//! recorded and correlated back to the probe.
//!
//! It is clean-room and self-hosted on purpose: Shrike never routes a tester's
//! callbacks through a third party. The listeners log what reached them and
//! answer benignly; they are not a general-purpose DNS/web server.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rand::Rng;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use super::{OobHandle, OobInteraction, OobProvider};

/// Most interactions we keep in the live log (newest wins); bounds memory on a
/// long engagement. Per-token correlation lists are not capped — a probe's own
/// callbacks are the signal the scanner polls for.
const LOG_CAP: usize = 5000;

/// How the server is reachable: the domain testers point at it, the public IP a
/// DNS `A` query is answered with, and the local addresses to bind.
#[derive(Debug, Clone)]
pub struct OobConfig {
    /// Payload suffix, e.g. `oast.example.com`. Tokens are `<token>.<domain>`.
    pub domain: String,
    /// Address returned for `A` queries (the server's public IP). `None` answers
    /// with no record — the query is still logged, which is all a blind DNS
    /// check needs.
    pub public_ip: Option<Ipv4Addr>,
    /// UDP address for the DNS responder (`0.0.0.0:53` in production; port 53
    /// needs privilege, so a high port is accepted for unprivileged runs).
    pub dns_bind: SocketAddr,
    /// TCP address for the HTTP listener.
    pub http_bind: SocketAddr,
}

/// A callback fired for every recorded interaction, for live UI/event delivery.
pub type OnInteraction = Arc<dyn Fn(OobInteraction) + Send + Sync>;

#[derive(Default)]
struct Inner {
    /// Tokens handed out by [`OobServer::register`] (correlatable probes).
    registered: HashSet<String>,
    /// Interactions per registered token, in arrival order.
    by_token: HashMap<String, Vec<OobInteraction>>,
    /// The global live log (every hit under the domain), newest at the back.
    log: VecDeque<OobInteraction>,
}

/// The running interaction server. Thread-safe; shared via `Arc`.
pub struct OobServer {
    domain: String,
    dns_addr: SocketAddr,
    http_addr: SocketAddr,
    inner: Arc<Mutex<Inner>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl OobServer {
    /// Bind the listeners and start serving. Must run inside a Tokio runtime.
    /// `on_interaction` is called for each hit (in addition to being stored).
    /// A bind failure (e.g. port 53 without privilege) is returned as an error.
    pub async fn start(cfg: OobConfig, on_interaction: OnInteraction) -> Result<Arc<OobServer>> {
        let domain = normalize_domain(&cfg.domain);
        let inner = Arc::new(Mutex::new(Inner::default()));

        let udp = UdpSocket::bind(cfg.dns_bind)
            .await
            .with_context(|| format!("binding OOB DNS listener on {}", cfg.dns_bind))?;
        let dns_addr = udp.local_addr().context("OOB DNS local addr")?;

        let tcp = TcpListener::bind(cfg.http_bind)
            .await
            .with_context(|| format!("binding OOB HTTP listener on {}", cfg.http_bind))?;
        let http_addr = tcp.local_addr().context("OOB HTTP local addr")?;

        let tasks = vec![
            spawn_dns(
                udp,
                cfg.public_ip,
                domain.clone(),
                Arc::clone(&inner),
                on_interaction.clone(),
            ),
            spawn_http(tcp, domain.clone(), Arc::clone(&inner), on_interaction),
        ];

        Ok(Arc::new(OobServer {
            domain,
            dns_addr,
            http_addr,
            inner,
            tasks: Mutex::new(tasks),
        }))
    }

    /// The domain tokens are minted under.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The actual bound DNS address (useful when a `:0` port was requested).
    pub fn dns_addr(&self) -> SocketAddr {
        self.dns_addr
    }

    /// The actual bound HTTP address.
    pub fn http_addr(&self) -> SocketAddr {
        self.http_addr
    }

    /// Every interaction in the live log, oldest first.
    pub fn interactions(&self) -> Vec<OobInteraction> {
        self.inner
            .lock()
            .expect("oob inner")
            .log
            .iter()
            .cloned()
            .collect()
    }

    /// Stop serving (aborts the listener tasks).
    pub fn stop(&self) {
        for t in self.tasks.lock().expect("oob tasks").drain(..) {
            t.abort();
        }
    }
}

impl Drop for OobServer {
    fn drop(&mut self) {
        self.stop();
    }
}

impl OobProvider for OobServer {
    fn enabled(&self) -> bool {
        true
    }

    fn register(&self) -> Option<OobHandle> {
        let token = new_token();
        let payload_host = format!("{token}.{}", self.domain);
        let mut inner = self.inner.lock().expect("oob inner");
        inner.registered.insert(token.clone());
        inner.by_token.entry(token.clone()).or_default();
        Some(OobHandle {
            correlation_id: token,
            payload_url: format!("http://{payload_host}/"),
            payload_host,
        })
    }

    fn poll(&self, correlation_id: &str) -> Vec<OobInteraction> {
        self.inner
            .lock()
            .expect("oob inner")
            .by_token
            .get(correlation_id)
            .cloned()
            .unwrap_or_default()
    }
}

/// Record one interaction: correlate it to a token, store it, fire the callback.
fn record(
    inner: &Mutex<Inner>,
    on: &OnInteraction,
    domain: &str,
    kind: &str,
    source: &str,
    name: &str,
    detail: &str,
) {
    let token = correlate(name, domain);
    let hit = OobInteraction {
        kind: kind.to_string(),
        source: source.to_string(),
        at_ms: now_ms(),
        detail: detail.to_string(),
        correlation_id: token.clone().unwrap_or_default(),
    };
    {
        let mut g = inner.lock().expect("oob inner");
        if let Some(t) = &token
            && g.registered.contains(t)
        {
            g.by_token.entry(t.clone()).or_default().push(hit.clone());
        }
        g.log.push_back(hit.clone());
        while g.log.len() > LOG_CAP {
            g.log.pop_front();
        }
    }
    on(hit);
}

/// Extract the payload token from a queried name: strip the domain suffix and
/// take the last remaining label, so both `<token>.<domain>` and a prefixed
/// `data.<token>.<domain>` (DNS exfil) correlate. `None` when `name` is not
/// under `domain`.
fn correlate(name: &str, domain: &str) -> Option<String> {
    if domain.is_empty() {
        return None;
    }
    let n = name.trim().trim_end_matches('.').to_ascii_lowercase();
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    let rest = if n == d {
        return None; // the apex itself carries no token
    } else {
        n.strip_suffix(&format!(".{d}"))?
    };
    rest.rsplit('.')
        .next()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

// --- DNS -------------------------------------------------------------------

fn spawn_dns(
    socket: UdpSocket,
    public_ip: Option<Ipv4Addr>,
    domain: String,
    inner: Arc<Mutex<Inner>>,
    on: OnInteraction,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let (len, peer) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    warn!(error = %e, "OOB DNS recv failed");
                    continue;
                }
            };
            let query = &buf[..len];
            let Some(q) = parse_query(query) else {
                continue;
            };
            record(
                &inner,
                &on,
                &domain,
                "dns",
                &peer.ip().to_string(),
                &q.name,
                &format!("{} {}", qtype_name(q.qtype), q.name),
            );
            let reply = build_response(query, q.qend, public_ip, q.qtype);
            if let Err(e) = socket.send_to(&reply, peer).await {
                debug!(error = %e, "OOB DNS reply failed");
            }
        }
    })
}

struct ParsedQuery {
    name: String,
    qtype: u16,
    /// Offset just past the question's QNAME+QTYPE+QCLASS in the original buffer.
    qend: usize,
}

/// Parse the first question of a DNS query. Minimal by design: no compression
/// pointers appear in a question section, so labels are read directly.
fn parse_query(buf: &[u8]) -> Option<ParsedQuery> {
    if buf.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut i = 12;
    let mut labels = Vec::new();
    loop {
        let len = *buf.get(i)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 {
            return None; // compression pointer — not expected in a question
        }
        let end = i.checked_add(len)?;
        let label = buf.get(i..end)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        i = end;
    }
    let qtype = u16::from_be_bytes([*buf.get(i)?, *buf.get(i + 1)?]);
    let qend = i + 4; // qtype(2) + qclass(2)
    if qend > buf.len() {
        return None;
    }
    Some(ParsedQuery {
        name: labels.join("."),
        qtype,
        qend,
    })
}

/// Build a response echoing the question, answering `A` queries with `public_ip`
/// (TTL 60) and otherwise answering with no records (the query is still logged).
fn build_response(query: &[u8], qend: usize, public_ip: Option<Ipv4Addr>, qtype: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(qend + 16);
    out.extend_from_slice(&query[0..2]); // id
    let answer = qtype == 1 && public_ip.is_some();
    out.extend_from_slice(&[0x81, 0x80]); // QR=1, RD copied, RA=1, no error
    out.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    out.extend_from_slice(&[0x00, if answer { 0x01 } else { 0x00 }]); // ANCOUNT
    out.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    out.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
    out.extend_from_slice(&query[12..qend]); // original question
    if let (true, Some(ip)) = (answer, public_ip) {
        out.extend_from_slice(&[0xC0, 0x0C]); // name pointer to the question
        out.extend_from_slice(&[0x00, 0x01]); // TYPE A
        out.extend_from_slice(&[0x00, 0x01]); // CLASS IN
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL 60
        out.extend_from_slice(&[0x00, 0x04]); // RDLENGTH 4
        out.extend_from_slice(&ip.octets());
    }
    out
}

fn qtype_name(t: u16) -> &'static str {
    match t {
        1 => "A?",
        28 => "AAAA?",
        2 => "NS?",
        16 => "TXT?",
        5 => "CNAME?",
        _ => "?",
    }
}

// --- HTTP ------------------------------------------------------------------

fn spawn_http(
    listener: TcpListener,
    domain: String,
    inner: Arc<Mutex<Inner>>,
    on: OnInteraction,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    warn!(error = %e, "OOB HTTP accept failed");
                    continue;
                }
            };
            let io = TokioIo::new(stream);
            let inner = Arc::clone(&inner);
            let on = on.clone();
            let domain = domain.clone();
            let peer_ip = peer.ip().to_string();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                    let inner = Arc::clone(&inner);
                    let on = on.clone();
                    let domain = domain.clone();
                    let peer_ip = peer_ip.clone();
                    async move {
                        let host = req
                            .headers()
                            .get(hyper::header::HOST)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        let name = host.split(':').next().unwrap_or("").to_string();
                        let detail = format!("{} {} (Host: {host})", req.method(), req.uri());
                        record(&inner, &on, &domain, "http", &peer_ip, &name, &detail);
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                            Bytes::from_static(b"ok\n"),
                        )))
                    }
                });
                let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    })
}

// --- helpers ---------------------------------------------------------------

fn normalize_domain(d: &str) -> String {
    d.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// A short, DNS-safe, lowercase token (base36) unique enough per engagement.
fn new_token() -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    (0..16)
        .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
        .collect()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_qname(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out
    }

    fn dns_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        q.extend_from_slice(&encode_qname(name));
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0x00, 0x01]); // class IN
        q
    }

    #[test]
    fn parses_name_and_type() {
        let q = dns_query("abc123.oast.example", 1);
        let p = parse_query(&q).expect("parsed");
        assert_eq!(p.name, "abc123.oast.example");
        assert_eq!(p.qtype, 1);
    }

    #[test]
    fn a_response_carries_the_ip() {
        let q = dns_query("x.oast.example", 1);
        let p = parse_query(&q).unwrap();
        let r = build_response(&q, p.qend, Some(Ipv4Addr::new(203, 0, 113, 7)), p.qtype);
        assert_eq!(&r[0..2], &q[0..2], "id echoed");
        assert_eq!(r[7], 1, "one answer");
        assert_eq!(&r[r.len() - 4..], &[203, 0, 113, 7], "A record ip");
    }

    #[test]
    fn non_a_query_logs_without_an_answer() {
        let q = dns_query("x.oast.example", 16); // TXT
        let p = parse_query(&q).unwrap();
        let r = build_response(&q, p.qend, Some(Ipv4Addr::new(203, 0, 113, 7)), p.qtype);
        assert_eq!(r[7], 0, "no answer records for a non-A query");
    }

    #[test]
    fn correlate_handles_bare_and_prefixed_tokens() {
        assert_eq!(
            correlate("tok.oast.example", "oast.example").as_deref(),
            Some("tok")
        );
        // DNS exfil prefixes data labels; the token is the last label under the domain.
        assert_eq!(
            correlate("data.chunk.tok.oast.example", "oast.example").as_deref(),
            Some("tok")
        );
        assert_eq!(correlate("oast.example", "oast.example"), None); // apex
        assert_eq!(correlate("unrelated.test", "oast.example"), None); // other domain
    }

    #[tokio::test]
    async fn dns_and_http_hits_are_recorded_and_correlated() {
        let server = OobServer::start(
            OobConfig {
                domain: "oast.example".into(),
                public_ip: Some(Ipv4Addr::new(127, 0, 0, 1)),
                dns_bind: "127.0.0.1:0".parse().unwrap(),
                http_bind: "127.0.0.1:0".parse().unwrap(),
            },
            Arc::new(|_| {}),
        )
        .await
        .expect("server starts");

        let handle = server.register().expect("register");
        let token = handle.correlation_id.clone();

        // DNS hit for the token.
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .send_to(&dns_query(&handle.payload_host, 1), server.dns_addr())
            .await
            .unwrap();
        let mut buf = [0u8; 512];
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.recv_from(&mut buf),
        )
        .await
        .expect("got a DNS reply");

        // HTTP hit for the token.
        let url = format!("http://{}/probe", server.http_addr());
        let host = handle.payload_host.clone();
        tokio::task::spawn_blocking(move || {
            use std::io::Write;
            let mut s = std::net::TcpStream::connect(
                url.trim_start_matches("http://").split('/').next().unwrap(),
            )
            .unwrap();
            write!(
                s,
                "GET /probe HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            let _ = std::io::Read::read(&mut s, &mut [0u8; 64]);
        })
        .await
        .unwrap();

        // Give the HTTP task a moment to record.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let hits = server.poll(&token);
        assert!(
            hits.iter().any(|h| h.kind == "dns"),
            "dns hit recorded: {hits:?}"
        );
        assert!(
            hits.iter().any(|h| h.kind == "http"),
            "http hit recorded: {hits:?}"
        );
        assert!(server.interactions().len() >= 2, "global log populated");
    }
}
