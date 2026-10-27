//! End-to-end through the `Engine` façade the GUI uses: start the proxy, drive a
//! real request through it to a local upstream, then read the transaction back
//! out of the SQLite history store.

use http_body_util::Full;
use hyper::{Request, Response, body::Bytes, service::service_fn};
use hyper_util::rt::TokioIo;
use shrike_engine::{
    Engine,
    config::{ProxyConfig, UpstreamTlsMode},
    core::{Header, HttpService},
    intruder::{AttackEvent, AttackType, IntruderConfig},
    scope::ScopeRule,
    sender::RequestSpec,
    store::HistoryFilter,
};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    runtime::Runtime,
};

async fn upstream(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let body = format!("hello {} {}", req.method(), req.uri().path());
    Ok(Response::builder()
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}

async fn spawn_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service_fn(upstream))
                    .await;
            });
        }
    });
    addr
}

/// Make a plain-HTTP request through the proxy (absolute-form request line).
async fn through_proxy(proxy: SocketAddr, target: SocketAddr, path: &str) -> String {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    let req = format!(
        "GET http://{target}{path} HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).into_owned()
}

#[test]
fn engine_captures_traffic_into_history_store() {
    // A helper runtime drives the upstream server and the client so we never
    // call Engine's internal block_on from inside a tokio context.
    let helper = Runtime::new().unwrap();
    let up = helper.block_on(spawn_upstream());

    let dir = tempfile::tempdir().unwrap();
    let config = ProxyConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.path().to_path_buf(),
        upstream_tls: UpstreamTlsMode::Verify,
        ..ProxyConfig::default()
    };
    let engine = Engine::new(config).unwrap();
    let proxy_addr = engine.start_proxy().unwrap();

    let raw = helper.block_on(through_proxy(proxy_addr, up, "/widgets?id=7"));
    assert!(raw.starts_with("HTTP/1.1 200"), "proxied response: {raw:?}");
    assert!(raw.contains("hello GET /widgets"));

    engine.store().flush().unwrap();

    let rows = engine
        .history_page(&HistoryFilter::default(), 50, 0)
        .unwrap();
    assert_eq!(rows.len(), 1, "exactly one transaction recorded");
    let row = &rows[0];
    assert_eq!(row.method, "GET");
    assert_eq!(row.status, Some(200));
    assert!(row.url.ends_with("/widgets?id=7"), "url was {}", row.url);

    // full detail reconstructs from the store
    let view = engine.history_get(row.id).unwrap().unwrap();
    assert_eq!(view.response.as_ref().unwrap().status, 200);
    assert!(
        view.response
            .unwrap()
            .body
            .text
            .unwrap()
            .contains("hello GET /widgets")
    );

    // filtering works through the engine
    let miss = engine
        .history_page(
            &HistoryFilter {
                host: Some("no.such.host".into()),
                ..Default::default()
            },
            50,
            0,
        )
        .unwrap();
    assert!(miss.is_empty());

    engine.stop_proxy().unwrap();
}

/// Acceptance for M3: scope is enforced inside the engine. With enforcement on,
/// an out-of-scope target is refused with 403 before any upstream connection,
/// and the refusal is recorded in history; an in-scope target still flows.
#[test]
fn engine_refuses_out_of_scope_targets_when_enforcing() {
    let helper = Runtime::new().unwrap();
    let up = helper.block_on(spawn_upstream());

    let dir = tempfile::tempdir().unwrap();
    let config = ProxyConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.path().to_path_buf(),
        upstream_tls: UpstreamTlsMode::Verify,
        drop_out_of_scope: true,
        ..ProxyConfig::default()
    };
    let engine = Engine::new(config).unwrap();
    // Only the upstream host:port is in scope.
    engine
        .set_scope(vec![ScopeRule {
            port: Some(up.port()),
            ..ScopeRule::include_host("127.0.0.1")
        }])
        .unwrap();
    let proxy_addr = engine.start_proxy().unwrap();

    let ok = helper.block_on(through_proxy(proxy_addr, up, "/in"));
    assert!(
        ok.starts_with("HTTP/1.1 200"),
        "in-scope should be forwarded: {ok:?}"
    );

    // A different port is out of scope: refused at the proxy, never dialed.
    let other: SocketAddr = format!("127.0.0.1:{}", up.port().wrapping_add(1))
        .parse()
        .unwrap();
    let blocked = helper.block_on(through_proxy(proxy_addr, other, "/out"));
    assert!(
        blocked.starts_with("HTTP/1.1 403"),
        "expected 403, got {blocked:?}"
    );
    assert!(blocked.contains("out of scope"));

    engine.store().flush().unwrap();
    let rows = engine
        .history_page(&HistoryFilter::default(), 50, 0)
        .unwrap();
    assert_eq!(rows.len(), 2, "both attempts are recorded");
    let refused: Vec<_> = rows.iter().filter(|r| r.error.is_some()).collect();
    assert_eq!(refused.len(), 1, "the refused request carries an error");
    assert!(refused[0].url.ends_with("/out"));
    assert!(refused[0].error.as_deref().unwrap().contains("scope"));

    engine.stop_proxy().unwrap();
}

/// Repeater path: the engine sends an edited request and returns the response.
#[test]
fn repeater_send_through_engine() {
    let helper = Runtime::new().unwrap();
    let up = helper.block_on(spawn_upstream());

    let dir = tempfile::tempdir().unwrap();
    let config = ProxyConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.path().to_path_buf(),
        upstream_tls: UpstreamTlsMode::Verify,
        ..ProxyConfig::default()
    };
    let engine = Engine::new(config).unwrap();
    let out = engine
        .repeater_send(RequestSpec {
            service: HttpService {
                host: "127.0.0.1".into(),
                port: up.port(),
                secure: false,
            },
            method: "GET".into(),
            target: "/widgets?id=7".into(),
            headers: vec![Header {
                name: "X-Shrike".into(),
                value: "repeater".into(),
            }],
            body: String::new(),
        })
        .unwrap();
    assert_eq!(out.response.status, 200);
    assert!(
        out.response
            .body
            .text
            .unwrap()
            .contains("hello GET /widgets")
    );
}

/// Intruder: a Sniper attack with one position and three payloads sends three
/// requests through the engine and reports three results then done.
#[test]
fn intruder_sniper_runs_against_local_server() {
    use std::sync::{Arc, mpsc};
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

    let (tx, rx) = mpsc::channel::<AttackEvent>();
    let sink: Arc<dyn Fn(AttackEvent) + Send + Sync> = Arc::new(move |ev| {
        let _ = tx.send(ev);
    });
    let config = IntruderConfig {
        service: HttpService {
            host: "127.0.0.1".into(),
            port: up.port(),
            secure: false,
        },
        template: format!(
            "GET /q?v=\u{00a7}base\u{00a7} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            up.port()
        ),
        attack: AttackType::Sniper,
        payload_sets: vec![vec!["1".into(), "2".into(), "3".into()]],
        concurrency: 5,
        delay_ms: 0,
        processors: vec![],
    };
    // 127.0.0.1 must be in scope now that Intruder enforces it by default.
    engine
        .set_scope(vec![shrike_engine::scope::ScopeRule::include_host(
            "127.0.0.1",
        )])
        .unwrap();
    let _id = engine.intruder_start(config, sink).unwrap();

    let mut total = 0u64;
    let mut results = 0u64;
    let mut ok_statuses = 0u64;
    loop {
        match rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("attack event")
        {
            AttackEvent::Started { total: t, .. } => total = t,
            AttackEvent::Result(r) => {
                results += 1;
                if r.status == Some(200) {
                    ok_statuses += 1;
                }
            }
            AttackEvent::Results(batch) => {
                for r in batch {
                    results += 1;
                    if r.status == Some(200) {
                        ok_statuses += 1;
                    }
                }
            }
            AttackEvent::Done {
                completed, stopped, ..
            } => {
                assert!(!stopped);
                assert_eq!(completed, 3);
                break;
            }
        }
    }
    assert_eq!(total, 3);
    assert_eq!(results, 3);
    assert_eq!(
        ok_statuses, 3,
        "all three payloads got a 200 from the echo server"
    );
}

#[test]
fn intruder_refuses_empty_scope_and_blocks_out_of_scope() {
    use std::sync::{Arc, mpsc};
    let helper = Runtime::new().unwrap();
    let up = helper.block_on(spawn_upstream());

    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::new(ProxyConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.path().to_path_buf(),
        ..ProxyConfig::default()
    })
    .unwrap();

    let make_config = || IntruderConfig {
        service: HttpService {
            host: "127.0.0.1".into(),
            port: up.port(),
            secure: false,
        },
        template: format!(
            "GET /q?v=\u{00a7}base\u{00a7} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            up.port()
        ),
        attack: AttackType::Sniper,
        payload_sets: vec![vec!["1".into(), "2".into()]],
        concurrency: 2,
        delay_ms: 0,
        processors: vec![],
    };
    let noop: Arc<dyn Fn(AttackEvent) + Send + Sync> = Arc::new(|_| {});

    // Empty scope + enforcement on (default) → the attack is refused outright.
    assert!(
        engine
            .intruder_start(make_config(), Arc::clone(&noop))
            .is_err(),
        "empty scope must refuse an Intruder attack"
    );

    // Non-empty scope that does not cover the target → every request is blocked
    // and the upstream is never contacted.
    engine
        .set_scope(vec![shrike_engine::scope::ScopeRule::include_host(
            "example.com",
        )])
        .unwrap();
    let (tx, rx) = mpsc::channel::<AttackEvent>();
    let sink: Arc<dyn Fn(AttackEvent) + Send + Sync> = Arc::new(move |ev| {
        let _ = tx.send(ev);
    });
    engine.intruder_start(make_config(), sink).unwrap();

    let mut blocked = 0u64;
    let mut sent_ok = 0u64;
    loop {
        match rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("attack event")
        {
            AttackEvent::Results(batch) => {
                for r in batch {
                    if r.error.as_deref() == Some("blocked: out of target scope") {
                        blocked += 1;
                    } else if r.status.is_some() {
                        sent_ok += 1;
                    }
                }
            }
            AttackEvent::Result(_) => {}
            AttackEvent::Started { .. } => {}
            AttackEvent::Done { .. } => break,
        }
    }
    assert_eq!(blocked, 2, "both out-of-scope requests are blocked");
    assert_eq!(sent_ok, 0, "nothing out of scope reaches the server");
}
