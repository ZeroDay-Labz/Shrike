//! End-to-end: real TCP clients through the real proxy to real local servers,
//! over plain HTTP and over TLS terminated with our own CA.

use http_body_util::Full;
use hyper::{Request, Response, body::Bytes, service::service_fn};
use hyper_util::rt::TokioIo;
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use shrike_engine::{
    ca::CaManager,
    config::{ProxyConfig, UpstreamTlsMode},
    core::{EventBus, TrafficEvent, TrafficSink},
    proxy,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

struct ChannelSink(mpsc::UnboundedSender<TrafficEvent>);
impl TrafficSink for ChannelSink {
    fn handle(&mut self, event: &TrafficEvent) {
        let _ = self.0.send(event.clone());
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

async fn upstream_response(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let body = format!("hello from upstream: {} {}", req.method(), req.uri().path());
    Ok(Response::builder()
        .header("content-type", "text/plain")
        .header("x-upstream", "yes")
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}

/// Plain-HTTP upstream on an ephemeral port.
async fn spawn_http_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service_fn(upstream_response))
                    .await;
            });
        }
    });
    addr
}

/// HTTPS upstream with a self-signed cert the proxy must be told to accept.
async fn spawn_https_upstream() -> SocketAddr {
    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)
        .unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service_fn(upstream_response))
                    .await;
            });
        }
    });
    addr
}

struct RunningProxy {
    addr: SocketAddr,
    ca: Arc<CaManager>,
    events: mpsc::UnboundedReceiver<TrafficEvent>,
    _stop: oneshot::Sender<()>,
    _dir: tempfile::TempDir,
}

async fn spawn_proxy(upstream_tls: UpstreamTlsMode) -> RunningProxy {
    let dir = tempfile::tempdir().unwrap();
    let config = ProxyConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.path().to_path_buf(),
        upstream_tls,
        ..ProxyConfig::default()
    };
    let (ca, _) = CaManager::load_or_create(&config.ca_dir()).unwrap();
    let ca = Arc::new(ca);
    let (tx, events) = mpsc::unbounded_channel();
    let (bus, _bus_task) = EventBus::start(vec![Box::new(ChannelSink(tx))]);
    let listener = proxy::bind(&config).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    let ca2 = Arc::clone(&ca);
    tokio::spawn(async move {
        proxy::serve(
            listener,
            config,
            ca2,
            bus,
            Arc::new(std::sync::RwLock::new(shrike_engine::scope::Scope::empty())),
            Arc::new(shrike_engine::intercept::Interceptor::new()),
            Arc::new(std::sync::RwLock::new(
                shrike_engine::match_replace::MatchReplace::empty(),
            )),
            shrike_engine::core::TransactionIds::starting_after(0),
            Arc::new(shrike_engine::jvm::BappBridge::disabled()),
            async move {
                let _ = stop_rx.await;
            },
        )
        .await
        .unwrap();
    });
    RunningProxy {
        addr,
        ca,
        events,
        _stop: stop_tx,
        _dir: dir,
    }
}

async fn read_to_end(stream: &mut (impl AsyncReadExt + Unpin)) -> String {
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).into_owned()
}

async fn next_completed(
    events: &mut mpsc::UnboundedReceiver<TrafficEvent>,
) -> Arc<shrike_engine::core::Transaction> {
    loop {
        let ev = tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .expect("event within 5s")
            .expect("bus alive");
        if let TrafficEvent::Completed(tx) = ev {
            return tx;
        }
    }
}

#[tokio::test]
async fn plain_http_is_forwarded_and_recorded() {
    let upstream = spawn_http_upstream().await;
    let mut p = spawn_proxy(UpstreamTlsMode::Verify).await;

    let mut client = TcpStream::connect(p.addr).await.unwrap();
    client
        .write_all(
            format!(
                "GET http://{upstream}/plain?q=1 HTTP/1.1\r\nHost: {upstream}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let reply = read_to_end(&mut client).await;
    assert!(reply.starts_with("HTTP/1.1 200"), "reply: {reply}");
    assert!(
        reply.contains("hello from upstream: GET /plain"),
        "reply: {reply}"
    );

    let tx = next_completed(&mut p.events).await;
    assert_eq!(tx.request.method, "GET");
    assert_eq!(tx.request.url(), format!("http://{upstream}/plain?q=1"));
    assert!(!tx.request.service.secure);
    let res = tx.response.as_ref().expect("response recorded");
    assert_eq!(res.status, 200);
    assert_eq!(res.header("x-upstream"), Some("yes"));
    assert_eq!(res.body.as_ref(), b"hello from upstream: GET /plain");
    assert!(res.body_complete);
}

#[tokio::test]
async fn https_is_decrypted_with_our_ca_and_forwarded() {
    let upstream = spawn_https_upstream().await;
    let mut p = spawn_proxy(UpstreamTlsMode::AcceptInvalid).await;

    // 1. CONNECT tunnel to the proxy.
    let mut tcp = TcpStream::connect(p.addr).await.unwrap();
    tcp.write_all(format!("CONNECT {upstream} HTTP/1.1\r\nHost: {upstream}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    loop {
        let mut b = [0u8; 1];
        tcp.read_exact(&mut b).await.unwrap();
        head.push(b[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8_lossy(&head);
    assert!(head.starts_with("HTTP/1.1 200"), "CONNECT reply: {head}");

    // 2. TLS handshake inside the tunnel, trusting only our CA root.
    let mut roots = RootCertStore::empty();
    roots.add(p.ca.ca_cert_der().clone()).unwrap();
    let cfg = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(cfg));
    let server_name = ServerName::try_from(upstream.ip().to_string()).unwrap();
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("leaf cert for 127.0.0.1 must chain to our CA and carry an IP SAN");

    // 3. The actual request, now visible to the proxy.
    tls.write_all(
        format!("POST /secret HTTP/1.1\r\nHost: {upstream}\r\nContent-Length: 9\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\ntop=secret").as_bytes(),
    )
    .await
    .unwrap();
    let reply = read_to_end(&mut tls).await;
    assert!(reply.starts_with("HTTP/1.1 200"), "reply: {reply}");
    assert!(
        reply.contains("hello from upstream: POST /secret"),
        "reply: {reply}"
    );

    let tx = next_completed(&mut p.events).await;
    assert!(tx.request.service.secure, "service should be https");
    assert_eq!(tx.request.service.port, upstream.port());
    assert_eq!(tx.request.method, "POST");
    assert_eq!(tx.request.target, "/secret");
    assert_eq!(
        tx.request.body.as_ref(),
        b"top=secre",
        "Content-Length wins: 9 bytes"
    );
    let res = tx.response.as_ref().expect("response recorded");
    assert_eq!(res.status, 200);
    assert!(res.body.starts_with(b"hello from upstream"));
}

#[tokio::test]
async fn unreachable_upstream_yields_502_and_error_record() {
    let mut p = spawn_proxy(UpstreamTlsMode::Verify).await;
    // Nothing listens here (port 9 / discard is almost never bound).
    let dead = "127.0.0.1:9";
    let mut client = TcpStream::connect(p.addr).await.unwrap();
    client
        .write_all(
            format!("GET http://{dead}/ HTTP/1.1\r\nHost: {dead}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let reply = read_to_end(&mut client).await;
    assert!(reply.starts_with("HTTP/1.1 502"), "reply: {reply}");
    let tx = next_completed(&mut p.events).await;
    assert!(tx.response.is_none());
    assert!(
        tx.error.as_deref().unwrap_or("").contains("connect"),
        "error: {:?}",
        tx.error
    );
}

#[tokio::test]
async fn landing_page_serves_ca_cert() {
    let mut p = spawn_proxy(UpstreamTlsMode::Verify).await;
    let mut client = TcpStream::connect(p.addr).await.unwrap();
    client
        .write_all(b"GET http://shrike/cert HTTP/1.1\r\nHost: shrike\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let reply = read_to_end(&mut client).await;
    assert!(reply.starts_with("HTTP/1.1 200"), "reply: {reply}");
    assert!(reply.contains("-----BEGIN CERTIFICATE-----"));
    assert!(reply.contains(p.ca.ca_cert_pem().trim()));
    // Served locally: nothing should be recorded as a transaction.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), p.events.recv())
            .await
            .is_err(),
        "landing page must not be recorded as traffic"
    );
}
