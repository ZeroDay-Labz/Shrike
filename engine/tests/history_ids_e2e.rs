//! Regression: history ids must never be reused across proxy restarts, crawls
//! or app restarts. Each producer used to start numbering at 1 and the store
//! replaced rows on conflict, silently overwriting older history and leaving
//! annotations/findings pointing at unrelated traffic.

use http_body_util::Full;
use hyper::{Request, Response, body::Bytes, service::service_fn};
use hyper_util::rt::TokioIo;
use shrike_engine::{
    Engine,
    config::{ProxyConfig, UpstreamTlsMode},
    core::TransactionSummary,
    crawler::CrawlEvent,
    findings::{Confidence, NewFinding, Severity},
    scope::ScopeRule,
    store::HistoryFilter,
};
use std::{
    collections::HashSet,
    net::SocketAddr,
    path::Path,
    sync::{Arc, mpsc},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    runtime::Runtime,
};

/// `/` links to `/a` and `/b`; every other path is a leaf page.
async fn site(req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let body = match req.uri().path() {
        "/" => r#"<html><a href="/a">a</a> <a href="/b">b</a></html>"#.to_string(),
        p => format!("<html>page {p}</html>"),
    };
    Ok(Response::builder()
        .header("content-type", "text/html")
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}

async fn spawn_site() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service_fn(site))
                    .await;
            });
        }
    });
    addr
}

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

fn engine_at(dir: &Path) -> Arc<Engine> {
    Engine::new(ProxyConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.to_path_buf(),
        upstream_tls: UpstreamTlsMode::Verify,
        ..ProxyConfig::default()
    })
    .unwrap()
}

fn all_rows(engine: &Engine) -> Vec<TransactionSummary> {
    engine.store().flush().unwrap();
    engine
        .history_page(&HistoryFilter::default(), 500, 0)
        .unwrap()
}

/// Poll until exactly `want` rows are persisted (the capture path is async).
fn wait_for_rows(engine: &Engine, want: usize) -> Vec<TransactionSummary> {
    for _ in 0..150 {
        let rows = all_rows(engine);
        if rows.len() >= want {
            return rows;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    all_rows(engine)
}

fn proxied(helper: &Runtime, engine: &Engine, site: SocketAddr, path: &str) {
    let addr = engine.start_proxy().unwrap();
    let raw = helper.block_on(through_proxy(addr, site, path));
    assert!(raw.starts_with("HTTP/1.1 200"), "proxied response: {raw:?}");
}

/// Run one crawl from `/` to completion.
fn crawl(engine: &Engine, site: SocketAddr) {
    let (tx, rx) = mpsc::channel();
    let tx = std::sync::Mutex::new(tx);
    engine
        .crawler_start(
            format!("http://{site}/"),
            Arc::new(move |ev| {
                if let CrawlEvent::Finished { .. } = ev {
                    let _ = tx.lock().unwrap().send(());
                }
            }),
        )
        .unwrap();
    rx.recv_timeout(Duration::from_secs(10))
        .expect("crawl finished");
}

fn url_of(engine: &Engine, id: u64) -> String {
    let view = engine.history_get(id).unwrap().expect("row exists");
    view.request.target
}

fn assert_unique_ids(rows: &[TransactionSummary]) {
    let ids: HashSet<u64> = rows.iter().map(|r| r.id).collect();
    assert_eq!(ids.len(), rows.len(), "ids collided: {rows:?}");
}

#[test]
fn proxy_restart_and_app_restart_keep_older_history_and_triage_links() {
    let helper = Runtime::new().unwrap();
    let site = helper.block_on(spawn_site());
    let dir = tempfile::tempdir().unwrap();

    let first_id = {
        let engine = engine_at(dir.path());
        proxied(&helper, &engine, site, "/first");
        let rows = wait_for_rows(&engine, 1);
        assert_eq!(rows.len(), 1);
        let first_id = rows[0].id;

        // Triage the first request before anything restarts.
        engine
            .annotation_set(first_id, Some("red".into()), Some("keep me".into()))
            .unwrap();
        let finding = engine
            .finding_create(NewFinding {
                title: "seen on /first".into(),
                severity: Severity::Medium,
                confidence: Confidence::Firm,
                detail: String::new(),
                host: None,
                path: Some("/first".into()),
                transaction_ids: vec![first_id],
            })
            .unwrap();
        assert_eq!(finding.transaction_ids, vec![first_id]);

        // Proxy restart within the same app session.
        engine.stop_proxy().unwrap();
        proxied(&helper, &engine, site, "/second");
        let rows = wait_for_rows(&engine, 2);
        assert_eq!(rows.len(), 2, "proxy restart must not overwrite row 1");
        assert_unique_ids(&rows);
        engine.stop_proxy().unwrap();
        first_id
    };

    // App restart: a brand-new engine over the same project.
    let engine = engine_at(dir.path());
    proxied(&helper, &engine, site, "/third");
    let rows = wait_for_rows(&engine, 3);
    engine.stop_proxy().unwrap();
    assert_eq!(rows.len(), 3, "app restart must not overwrite older rows");
    assert_unique_ids(&rows);
    assert_eq!(engine.store().persist_failures(), 0);

    assert!(url_of(&engine, first_id).ends_with("/first"));
    let paths: HashSet<String> = rows.iter().map(|r| r.url.clone()).collect();
    for p in ["/first", "/second", "/third"] {
        assert!(
            paths.iter().any(|u| u.ends_with(p)),
            "{p} missing: {paths:?}"
        );
    }

    // The annotation and finding still point at the /first request.
    let notes = engine.annotations().unwrap();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].transaction_id, first_id);
    assert!(url_of(&engine, notes[0].transaction_id).ends_with("/first"));
    // (The passive scanner files its own header findings too; check ours.)
    let findings = engine.findings_list().unwrap();
    let ours = findings
        .iter()
        .find(|f| f.title == "seen on /first")
        .expect("manual finding kept");
    assert_eq!(ours.transaction_ids, vec![first_id]);
    assert!(url_of(&engine, ours.transaction_ids[0]).ends_with("/first"));
    // Every passive finding's evidence must resolve to a stored row too.
    for f in &findings {
        for &id in &f.transaction_ids {
            assert!(engine.history_get(id).unwrap().is_some(), "dangling {id}");
        }
    }
}

#[test]
fn crawler_restart_keeps_older_history() {
    let helper = Runtime::new().unwrap();
    let site = helper.block_on(spawn_site());
    let dir = tempfile::tempdir().unwrap();
    let engine = engine_at(dir.path());
    engine
        .set_scope(vec![ScopeRule::include_host("127.0.0.1")])
        .unwrap();

    crawl(&engine, site);
    let first = wait_for_rows(&engine, 3);
    assert_eq!(first.len(), 3, "crawl fetches /, /a and /b");
    let first_urls: Vec<(u64, String)> = first
        .iter()
        .map(|r| (r.id, url_of(&engine, r.id)))
        .collect();

    crawl(&engine, site);
    let both = wait_for_rows(&engine, 6);
    assert_eq!(
        both.len(),
        6,
        "a second crawl must add rows, not replace them"
    );
    assert_unique_ids(&both);
    for (id, url) in first_urls {
        assert_eq!(url_of(&engine, id), url, "row {id} was overwritten");
    }
    assert_eq!(engine.store().persist_failures(), 0);
}

#[test]
fn proxy_and_crawler_records_coexist() {
    let helper = Runtime::new().unwrap();
    let site = helper.block_on(spawn_site());
    let dir = tempfile::tempdir().unwrap();
    let engine = engine_at(dir.path());
    engine
        .set_scope(vec![ScopeRule::include_host("127.0.0.1")])
        .unwrap();

    proxied(&helper, &engine, site, "/via-proxy");
    wait_for_rows(&engine, 1);
    crawl(&engine, site);
    proxied(&helper, &engine, site, "/via-proxy-again");
    let rows = wait_for_rows(&engine, 5);
    engine.stop_proxy().unwrap();

    assert_eq!(rows.len(), 5, "2 proxied + 3 crawled: {rows:?}");
    assert_unique_ids(&rows);
    assert_eq!(engine.store().persist_failures(), 0);
    let proxied_urls = rows.iter().filter(|r| r.url.contains("/via-proxy")).count();
    assert_eq!(proxied_urls, 2, "both proxied rows survived the crawl");
}

/// A representative XML items export: one base64 HTTPS item with a response,
/// one plain-text HTTP item without one.
fn items_xml() -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
    let req = "GET /imported/one?x=1 HTTP/1.1\r\nHost: imported.example\r\n\r\n";
    let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok";
    format!(
        "<?xml version=\"1.0\"?>\n<items>\
         <item><protocol>https</protocol><host>imported.example</host><port>443</port>\
         <request base64=\"true\">{}</request><status>200</status>\
         <response base64=\"true\">{}</response></item>\
         <item><protocol>http</protocol><host>imported.example</host><port>80</port>\
         <request base64=\"false\"><![CDATA[POST /imported/two HTTP/1.1\r\nHost: imported.example\r\n\r\n]]></request>\
         </item></items>",
        B64.encode(req),
        B64.encode(resp)
    )
}

#[test]
fn xml_import_gets_fresh_ids_and_keeps_captured_history_and_annotations() {
    let helper = Runtime::new().unwrap();
    let site = helper.block_on(spawn_site());
    let dir = tempfile::tempdir().unwrap();
    let xml_path = dir.path().join("items.xml");
    std::fs::write(&xml_path, items_xml()).unwrap();

    let (captured_id, before) = {
        let engine = engine_at(dir.path());
        proxied(&helper, &engine, site, "/captured");
        let rows = wait_for_rows(&engine, 1);
        assert_eq!(rows.len(), 1);
        let captured_id = rows[0].id;
        engine
            .annotation_set(captured_id, Some("green".into()), Some("original".into()))
            .unwrap();

        let imported = engine.import_traffic(xml_path.to_str().unwrap()).unwrap();
        assert_eq!(imported, 2);

        let rows = wait_for_rows(&engine, 3);
        engine.stop_proxy().unwrap();
        assert_eq!(rows.len(), 3, "import must add rows, not replace any");
        assert_unique_ids(&rows);
        assert_eq!(engine.store().persist_failures(), 0);
        assert!(url_of(&engine, captured_id).ends_with("/captured"));
        let imported_ids: Vec<u64> = rows
            .iter()
            .filter(|r| r.host == "imported.example")
            .map(|r| r.id)
            .collect();
        assert_eq!(imported_ids.len(), 2);
        assert!(
            imported_ids.iter().all(|&id| id > captured_id),
            "imports take fresh ids after live capture: {imported_ids:?} vs {captured_id}"
        );

        let notes = engine.annotations().unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].transaction_id, captured_id);

        let before: Vec<(u64, String)> =
            rows.iter().map(|r| (r.id, url_of(&engine, r.id))).collect();
        (captured_id, before)
    };

    // Close and reopen the project: every record and the annotation survive.
    let engine = engine_at(dir.path());
    let rows = all_rows(&engine);
    assert_eq!(rows.len(), 3);
    for (id, url) in &before {
        assert_eq!(&url_of(&engine, *id), url, "row {id} changed across reopen");
    }
    let notes = engine.annotations().unwrap();
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].transaction_id, captured_id);
    assert_eq!(notes[0].note.as_deref(), Some("original"));
    assert!(url_of(&engine, notes[0].transaction_id).ends_with("/captured"));

    // And the reopened allocator continues past everything stored.
    let max = before.iter().map(|(id, _)| *id).max().unwrap();
    assert!(engine.store().transaction_ids().next() > max);
}
