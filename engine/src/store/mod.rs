//! SQLite-backed history store.
//!
//! Every completed transaction and WebSocket frame the proxy records is
//! persisted here so the UI can page/filter across runs. Writes happen on a
//! dedicated thread (rusqlite is blocking) fed from the event bus through a
//! channel, honouring the [`TrafficSink`] contract of keeping bus handlers
//! short. Reads go through a separate pooled connection; WAL mode lets the two
//! run concurrently.

use crate::core::{
    TrafficEvent, TrafficSink, Transaction, TransactionSummary, TransactionView, WsDirection,
    WsMessageEvent, epoch_millis,
};
use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params, types::Value};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, mpsc},
    time::SystemTime,
};
use tracing::{error, warn};

/// Current on-disk schema version. Bump when adding a migration below.
const SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS project (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    name            TEXT    NOT NULL,
    created_at_ms   INTEGER NOT NULL,
    schema_version  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
    id              INTEGER PRIMARY KEY,
    host            TEXT    NOT NULL,
    port            INTEGER NOT NULL,
    secure          INTEGER NOT NULL,
    method          TEXT    NOT NULL,
    url             TEXT    NOT NULL,
    status          INTEGER,
    mime            TEXT,
    req_len         INTEGER NOT NULL,
    resp_len        INTEGER NOT NULL,
    duration_ms     INTEGER NOT NULL,
    started_at_ms   INTEGER NOT NULL,
    client_addr     TEXT    NOT NULL,
    error           TEXT,
    view_json       TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_txn_host    ON transactions(host);
CREATE INDEX IF NOT EXISTS idx_txn_status  ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_txn_started ON transactions(started_at_ms);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS websocket_messages (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT    NOT NULL,
    direction   TEXT    NOT NULL,
    kind        TEXT    NOT NULL,
    len         INTEGER NOT NULL,
    text        TEXT,
    client_addr TEXT    NOT NULL,
    at_ms       INTEGER NOT NULL
);
"#;

/// Filter applied to a history page. All set fields must match (AND).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HistoryFilter {
    /// Case-insensitive substring of the host.
    pub host: Option<String>,
    /// Exact method (e.g. `GET`).
    pub method: Option<String>,
    /// Exact status code.
    pub status: Option<u16>,
    /// Status class digit: 2 => 2xx, 4 => 4xx, ...
    pub status_class: Option<u16>,
    /// Case-insensitive substring of the URL.
    pub search: Option<String>,
    /// Only rows that recorded an upstream error.
    pub only_errors: Option<bool>,
}

/// One distinct endpoint in the site map: a host + path seen in history, with a
/// representative (most recent) transaction for drill-down.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteNode {
    pub host: String,
    pub port: u16,
    pub secure: bool,
    /// Path only (no scheme, authority or query).
    pub path: String,
    /// Method of the representative transaction.
    pub method: String,
    pub status: Option<u16>,
    pub mime: Option<String>,
    /// Id of the representative (latest) transaction, for `history_get`.
    pub id: u64,
}

/// Aggregate traffic counts for the Dashboard, computed across all history.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrafficStats {
    pub total: u64,
    pub errors: u64,
    pub websockets: u64,
    pub distinct_hosts: u64,
    /// (status class digit 1..=5, count), ascending by class.
    pub by_status_class: Vec<(u16, u64)>,
    /// (method, count), most frequent first.
    pub by_method: Vec<(String, u64)>,
    /// (host, count), busiest first, capped at 10.
    pub top_hosts: Vec<(String, u64)>,
}

/// Project identity + status shown in the UI and used for save/backup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectMeta {
    pub name: String,
    /// Absolute path to the project database file.
    pub path: String,
    pub created_at_ms: u64,
    pub schema_version: i64,
    /// On-disk size of the database file in bytes (0 if unknown).
    pub size_bytes: u64,
    /// True for a temporary project whose data is discarded on close.
    pub temporary: bool,
}

/// Apply ordered schema migrations, keyed by `PRAGMA user_version`. The base
/// schema is created idempotently by [`SCHEMA`]; migrations handle upgrades.
fn run_migrations(conn: &Connection) -> Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 1 {
        // v0 (fresh or pre-versioning) -> v1: ensure a project metadata row exists.
        let now = epoch_millis(SystemTime::now()) as i64;
        conn.execute(
            "INSERT OR IGNORE INTO project (id, name, created_at_ms, schema_version) VALUES (1, ?, ?, ?)",
            params!["Shrike project", now, SCHEMA_VERSION],
        )?;
    }
    // Future migrations: `if version < 2 { ...; }` etc., then fall through.
    if version != SCHEMA_VERSION {
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    }
    Ok(())
}

/// Path portion of an absolute URL (no scheme/authority/query). `/` when absent.
fn path_of(url: &str) -> String {
    let after_scheme = url.split_once("://").map(|x| x.1).unwrap_or(url);
    match after_scheme.find('/') {
        Some(i) => {
            let p = &after_scheme[i..];
            p.split('?').next().unwrap_or(p).to_string()
        }
        None => "/".to_string(),
    }
}

enum WriteMsg {
    Completed(Arc<Transaction>),
    Ws(WsMessageEvent, u64),
    /// Round-trips through the writer; the ack fires once all prior writes are done.
    Flush(mpsc::Sender<()>),
}

/// Handle to the history database. Cheap to clone-share behind an `Arc`.
pub struct Store {
    read: Mutex<Connection>,
    tx: mpsc::Sender<WriteMsg>,
    path: PathBuf,
    /// Retention cap: keep at most this many newest transactions (0 = unlimited).
    /// Read by the writer thread; set at startup and on config change.
    max_rows: Arc<std::sync::atomic::AtomicUsize>,
}

impl Store {
    /// Open (creating if needed) the database at `path` and start the writer thread.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }

        let init =
            Connection::open(&path).with_context(|| format!("opening {}", path.display()))?;
        init.pragma_update(None, "journal_mode", "WAL")
            .context("enabling WAL")?;
        init.pragma_update(None, "synchronous", "NORMAL").ok();
        init.execute_batch(SCHEMA).context("creating schema")?;
        run_migrations(&init).context("running schema migrations")?;
        drop(init);

        let read = Connection::open(&path).context("opening read connection")?;
        read.pragma_update(None, "busy_timeout", 5000).ok();

        let (tx, rx) = mpsc::channel::<WriteMsg>();
        let writer_path = path.clone();
        let max_rows = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let writer_max = Arc::clone(&max_rows);
        std::thread::Builder::new()
            .name("shrike-store-writer".into())
            .spawn(move || writer_loop(writer_path, rx, writer_max))
            .context("spawning store writer")?;

        Ok(Self {
            read: Mutex::new(read),
            tx,
            path,
            max_rows,
        })
    }

    /// Set the history retention cap (newest-N transactions; 0 = unlimited). The
    /// writer prunes periodically, so this takes effect as new traffic arrives.
    pub fn set_max_rows(&self, max: usize) {
        self.max_rows
            .store(max, std::sync::atomic::Ordering::Relaxed);
    }

    /// Enforce the retention cap immediately (keep the newest N transactions).
    /// Returns how many rows were deleted. No-op when the cap is 0 (unlimited).
    pub fn prune_history(&self) -> Result<usize> {
        let max = self.max_rows.load(std::sync::atomic::Ordering::Relaxed);
        if max == 0 {
            return Ok(0);
        }
        let conn = self.read.lock().expect("store read lock");
        // Keep the newest `max`: the oldest row to keep is at OFFSET max-1;
        // delete everything strictly older than it.
        let n = conn.execute(
            "DELETE FROM transactions WHERE id < \
             (SELECT id FROM transactions ORDER BY id DESC LIMIT 1 OFFSET ?1)",
            [(max - 1) as i64],
        )?;
        Ok(n)
    }

    /// Current on-disk size of the database file (bytes), including the WAL.
    pub fn db_size_bytes(&self) -> u64 {
        let base = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        let wal = std::fs::metadata(self.path.with_extension("sqlite-wal"))
            .map(|m| m.len())
            .unwrap_or(0);
        base + wal
    }

    /// Path to the backing database file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// A [`TrafficSink`] that persists events into this store.
    pub fn sink(&self) -> SqliteSink {
        SqliteSink {
            tx: self.tx.clone(),
        }
    }

    /// A page of history rows matching `filter`, newest first, most recent `id` first.
    pub fn history_page(
        &self,
        filter: &HistoryFilter,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<TransactionSummary>> {
        let (where_sql, values) = build_where(filter);
        let sql = format!(
            "SELECT view_json FROM transactions {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?"
        );
        let conn = self.read.lock().expect("store read lock");
        let mut stmt = conn.prepare(&sql)?;
        let mut bound: Vec<Value> = values;
        bound.push(Value::Integer(limit as i64));
        bound.push(Value::Integer(offset as i64));
        let rows = stmt
            .query_map(rusqlite::params_from_iter(bound), |row| {
                row.get::<_, String>(0)
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows
            .into_iter()
            .filter_map(|json| serde_json::from_str::<TransactionView>(&json).ok())
            .map(|v| summary_from_view(&v))
            .collect())
    }

    /// Count of rows matching `filter`.
    pub fn count(&self, filter: &HistoryFilter) -> Result<u64> {
        let (where_sql, values) = build_where(filter);
        let sql = format!("SELECT COUNT(*) FROM transactions {where_sql}");
        let conn = self.read.lock().expect("store read lock");
        let n: i64 = conn.query_row(&sql, rusqlite::params_from_iter(values), |r| r.get(0))?;
        Ok(n as u64)
    }

    /// The full view of one transaction, if present.
    pub fn history_get(&self, id: u64) -> Result<Option<TransactionView>> {
        let conn = self.read.lock().expect("store read lock");
        let json: Option<String> = conn
            .query_row(
                "SELECT view_json FROM transactions WHERE id = ?",
                params![id as i64],
                |r| r.get(0),
            )
            .optional()?;
        Ok(json.and_then(|j| serde_json::from_str(&j).ok()))
    }

    /// Aggregate history into the distinct endpoints (host + path) seen, each
    /// with its most recent transaction. Powers the Target site-map tree.
    pub fn site_map(&self) -> Result<Vec<SiteNode>> {
        let conn = self.read.lock().expect("store read lock");
        let mut stmt = conn.prepare(
            "SELECT id, host, port, secure, method, url, status, mime \
             FROM transactions ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)? as u64,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)? as u16,
                row.get::<_, i64>(3)? != 0,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, Option<i64>>(6)?.map(|s| s as u16),
                row.get::<_, Option<String>>(7)?,
            ))
        })?;

        // ORDER BY id ASC means a later row (higher id) overwrites earlier ones
        // for the same endpoint, so the representative is always the most recent.
        let mut map: HashMap<(String, u16, bool, String), SiteNode> = HashMap::new();
        for r in rows {
            let (id, host, port, secure, method, url, status, mime) = r?;
            let path = path_of(&url);
            let key = (host.clone(), port, secure, path.clone());
            map.insert(
                key,
                SiteNode {
                    host,
                    port,
                    secure,
                    path,
                    method,
                    status,
                    mime,
                    id,
                },
            );
        }
        let mut nodes: Vec<SiteNode> = map.into_values().collect();
        nodes.sort_by(|a, b| {
            (&a.host, a.port, a.secure, &a.path).cmp(&(&b.host, b.port, b.secure, &b.path))
        });
        Ok(nodes)
    }

    /// Aggregate traffic counts for the Dashboard, across all persisted history.
    pub fn stats(&self) -> Result<TrafficStats> {
        let conn = self.read.lock().expect("store read lock");
        let scalar = |sql: &str| -> Result<u64> {
            Ok(conn.query_row(sql, [], |r| r.get::<_, i64>(0))? as u64)
        };
        let total = scalar("SELECT COUNT(*) FROM transactions")?;
        let errors = scalar("SELECT COUNT(*) FROM transactions WHERE error IS NOT NULL")?;
        let websockets = scalar("SELECT COUNT(*) FROM websocket_messages")?;
        let distinct_hosts = scalar("SELECT COUNT(DISTINCT host) FROM transactions")?;

        let pairs_u16 = |sql: &str| -> Result<Vec<(u16, u64)>> {
            let mut stmt = conn.prepare(sql)?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((r.get::<_, i64>(0)? as u16, r.get::<_, i64>(1)? as u64))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(rows)
        };
        let pairs_str = |sql: &str| -> Result<Vec<(String, u64)>> {
            let mut stmt = conn.prepare(sql)?;
            let rows = stmt
                .query_map([], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(rows)
        };

        let by_status_class = pairs_u16(
            "SELECT status/100, COUNT(*) FROM transactions WHERE status IS NOT NULL \
             GROUP BY status/100 ORDER BY 1",
        )?;
        let by_method =
            pairs_str("SELECT method, COUNT(*) FROM transactions GROUP BY method ORDER BY 2 DESC")?;
        let top_hosts = pairs_str(
            "SELECT host, COUNT(*) FROM transactions GROUP BY host ORDER BY 2 DESC LIMIT 10",
        )?;

        Ok(TrafficStats {
            total,
            errors,
            websockets,
            distinct_hosts,
            by_status_class,
            by_method,
            top_hosts,
        })
    }

    /// Project identity + current on-disk status.
    pub fn project_meta(&self, temporary: bool) -> Result<ProjectMeta> {
        let conn = self.read.lock().expect("store read lock");
        let (name, created_at_ms, schema_version): (String, i64, i64) = conn.query_row(
            "SELECT name, created_at_ms, schema_version FROM project WHERE id = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let size_bytes = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        Ok(ProjectMeta {
            name,
            path: self.path.display().to_string(),
            created_at_ms: created_at_ms as u64,
            schema_version,
            size_bytes,
            temporary,
        })
    }

    /// Rename the project (persisted immediately).
    pub fn set_project_name(&self, name: &str) -> Result<()> {
        let conn = self.read.lock().expect("store read lock");
        conn.execute("UPDATE project SET name = ? WHERE id = 1", params![name])?;
        Ok(())
    }

    /// `PRAGMA integrity_check`; true when the database reports no corruption.
    pub fn integrity_check(&self) -> Result<bool> {
        let conn = self.read.lock().expect("store read lock");
        let result: String = conn.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        Ok(result == "ok")
    }

    /// Write a consistent snapshot of the whole project to `dest` (save-a-copy /
    /// backup / export). Flushes pending writes first so the copy is complete.
    /// Uses SQLite `VACUUM INTO`, which fails if `dest` already exists.
    pub fn backup_to(&self, dest: impl AsRef<Path>) -> Result<()> {
        self.flush()?; // drain the writer thread so all records are committed
        let dest = dest.as_ref();
        if dest.exists() {
            anyhow::bail!("destination already exists: {}", dest.display());
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = self.read.lock().expect("store read lock");
        conn.execute("VACUUM INTO ?", params![dest.to_string_lossy()])
            .with_context(|| format!("backing up to {}", dest.display()))?;
        Ok(())
    }

    /// Read a small project setting (scope, UI prefs, …) stored as a string.
    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        let conn = self.read.lock().expect("store read lock");
        Ok(conn
            .query_row("SELECT value FROM meta WHERE key = ?", params![key], |r| {
                r.get(0)
            })
            .optional()?)
    }

    /// Write (upsert) a small project setting.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.read.lock().expect("store read lock");
        conn.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Insert imported transactions (e.g. from an XML items export), assigning each
    /// a fresh id after the current maximum so they don't collide with live
    /// capture. Returns how many were queued. Blocks until they are written.
    pub fn import_transactions(&self, mut txs: Vec<Transaction>) -> Result<usize> {
        let base: i64 = {
            let conn = self.read.lock().expect("store read lock");
            conn.query_row("SELECT COALESCE(MAX(id), 0) FROM transactions", [], |r| {
                r.get(0)
            })
            .unwrap_or(0)
        };
        let n = txs.len();
        for (i, tx) in txs.iter_mut().enumerate() {
            tx.request.id = base as u64 + i as u64 + 1;
        }
        for tx in txs {
            self.tx
                .send(WriteMsg::Completed(std::sync::Arc::new(tx)))
                .context("writer thread is gone")?;
        }
        self.flush()?;
        Ok(n)
    }

    /// Block until every write queued before this call has been applied.
    pub fn flush(&self) -> Result<()> {
        let (ack, done) = mpsc::channel();
        self.tx
            .send(WriteMsg::Flush(ack))
            .context("writer thread is gone")?;
        done.recv().context("writer thread dropped the flush ack")?;
        Ok(())
    }

    /// Remove all history (used by a "clear" action / new project).
    pub fn clear(&self) -> Result<()> {
        let conn = self.read.lock().expect("store read lock");
        conn.execute_batch("DELETE FROM transactions; DELETE FROM websocket_messages;")?;
        Ok(())
    }
}

/// Build a `WHERE` clause (or empty string) and its bound values.
fn build_where(f: &HistoryFilter) -> (String, Vec<Value>) {
    let mut clauses: Vec<String> = Vec::new();
    let mut values: Vec<Value> = Vec::new();
    if let Some(h) = f.host.as_deref().filter(|s| !s.is_empty()) {
        clauses.push("host LIKE ? ESCAPE '\\'".into());
        values.push(Value::Text(format!("%{}%", like_escape(h))));
    }
    if let Some(m) = f.method.as_deref().filter(|s| !s.is_empty()) {
        clauses.push("method = ?".into());
        values.push(Value::Text(m.to_uppercase()));
    }
    if let Some(s) = f.status {
        clauses.push("status = ?".into());
        values.push(Value::Integer(s as i64));
    }
    if let Some(c) = f.status_class.filter(|c| (1..=5).contains(c)) {
        clauses.push("status >= ? AND status < ?".into());
        values.push(Value::Integer((c as i64) * 100));
        values.push(Value::Integer((c as i64 + 1) * 100));
    }
    if let Some(q) = f.search.as_deref().filter(|s| !s.is_empty()) {
        clauses.push("url LIKE ? ESCAPE '\\'".into());
        values.push(Value::Text(format!("%{}%", like_escape(q))));
    }
    if f.only_errors.unwrap_or(false) {
        clauses.push("error IS NOT NULL".into());
    }
    if clauses.is_empty() {
        (String::new(), values)
    } else {
        (format!("WHERE {}", clauses.join(" AND ")), values)
    }
}

fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn summary_from_view(v: &TransactionView) -> TransactionSummary {
    let r = &v.request;
    TransactionSummary {
        id: r.id,
        host: r.service.host.clone(),
        port: r.service.port,
        secure: r.service.secure,
        method: r.method.clone(),
        url: r.url.clone(),
        status: v.response.as_ref().map(|x| x.status),
        mime: v.response.as_ref().and_then(|x| x.mime.clone()),
        req_len: r.body.wire_len,
        resp_len: v.response.as_ref().map(|x| x.body.wire_len).unwrap_or(0),
        duration_ms: v.duration_ms,
        started_at_ms: r.started_at_ms,
        client_addr: r.client_addr.clone(),
        error: v.error.clone(),
    }
}

fn writer_loop(
    path: PathBuf,
    rx: mpsc::Receiver<WriteMsg>,
    max_rows: Arc<std::sync::atomic::AtomicUsize>,
) {
    let conn = match Connection::open(&path) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "history writer could not open the database; traffic will not be persisted");
            return;
        }
    };
    conn.pragma_update(None, "busy_timeout", 5000).ok();

    let mut since_prune = 0u32;
    while let Ok(msg) = rx.recv() {
        let res = match msg {
            WriteMsg::Completed(tx) => {
                let r = insert_transaction(&conn, &tx);
                since_prune += 1;
                // Periodically enforce the retention cap: keep the newest N by id.
                let max = max_rows.load(std::sync::atomic::Ordering::Relaxed);
                if max > 0 && since_prune >= 500 {
                    since_prune = 0;
                    if let Err(e) = conn.execute(
                        "DELETE FROM transactions WHERE id < \
                         (SELECT id FROM transactions ORDER BY id DESC LIMIT 1 OFFSET ?1)",
                        [(max.max(1) - 1) as i64],
                    ) {
                        warn!(error = %e, "history retention prune failed");
                    }
                }
                r
            }
            WriteMsg::Ws(ws, at_ms) => insert_ws(&conn, &ws, at_ms),
            WriteMsg::Flush(ack) => {
                let _ = ack.send(());
                continue;
            }
        };
        if let Err(e) = res {
            warn!(error = %e, "failed to persist a traffic record");
        }
    }
}

fn insert_transaction(conn: &Connection, tx: &Transaction) -> Result<()> {
    let summary = TransactionSummary::from(tx);
    let view = TransactionView::from(tx);
    let view_json = serde_json::to_string(&view).context("serializing transaction view")?;
    conn.execute(
        "INSERT OR REPLACE INTO transactions
         (id, host, port, secure, method, url, status, mime, req_len, resp_len,
          duration_ms, started_at_ms, client_addr, error, view_json)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        params![
            summary.id as i64,
            summary.host,
            summary.port as i64,
            summary.secure as i64,
            summary.method,
            summary.url,
            summary.status.map(|s| s as i64),
            summary.mime,
            summary.req_len as i64,
            summary.resp_len as i64,
            summary.duration_ms as i64,
            summary.started_at_ms as i64,
            summary.client_addr,
            summary.error,
            view_json,
        ],
    )?;
    Ok(())
}

fn insert_ws(conn: &Connection, ws: &WsMessageEvent, at_ms: u64) -> Result<()> {
    let direction = match ws.direction {
        WsDirection::ClientToServer => "c2s",
        WsDirection::ServerToClient => "s2c",
    };
    conn.execute(
        "INSERT INTO websocket_messages (url, direction, kind, len, text, client_addr, at_ms)
         VALUES (?,?,?,?,?,?,?)",
        params![
            ws.url,
            direction,
            ws.kind,
            ws.len as i64,
            ws.text,
            ws.client_addr.to_string(),
            at_ms as i64
        ],
    )?;
    Ok(())
}

/// A [`TrafficSink`] that forwards completed transactions and WebSocket frames
/// to the store's writer thread.
pub struct SqliteSink {
    tx: mpsc::Sender<WriteMsg>,
}

impl TrafficSink for SqliteSink {
    fn handle(&mut self, event: &TrafficEvent) {
        let msg = match event {
            TrafficEvent::Completed(tx) => WriteMsg::Completed(Arc::clone(tx)),
            TrafficEvent::WebSocketMessage(ws) => {
                WriteMsg::Ws(ws.clone(), epoch_millis(SystemTime::now()))
            }
            _ => return,
        };
        // A full/closed channel just means the writer is gone; drop and warn once upstream.
        let _ = self.tx.send(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{CapturedRequest, CapturedResponse, Transaction};
    use bytes::Bytes;
    use std::time::Duration;

    fn txn(id: u64, host: &str, method: &str, status: u16, body: &'static [u8]) -> Transaction {
        let (rp, _) = hyper::Request::builder()
            .method(method)
            .uri(format!("https://{host}/path?q=1"))
            .body(())
            .unwrap()
            .into_parts();
        let request = CapturedRequest::from_parts(
            id,
            "127.0.0.1:9000".parse().unwrap(),
            &rp,
            Bytes::new(),
            0,
            true,
        )
        .unwrap();
        let (sp, _) = hyper::Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(())
            .unwrap()
            .into_parts();
        let response =
            CapturedResponse::from_parts(&sp, Bytes::from_static(body), body.len(), true);
        Transaction {
            request,
            response: Some(response),
            error: None,
            duration: Duration::from_millis(42),
        }
    }

    #[test]
    fn retention_prunes_to_the_newest_rows() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("p.sqlite")).unwrap();
        let mut sink = store.sink();
        for i in 1..=10u64 {
            sink.handle(&TrafficEvent::Completed(Arc::new(txn(
                i,
                "h.example",
                "GET",
                200,
                b"{}",
            ))));
        }
        store.flush().unwrap();
        assert_eq!(store.count(&HistoryFilter::default()).unwrap(), 10);

        store.set_max_rows(4);
        let deleted = store.prune_history().unwrap();
        assert_eq!(deleted, 6, "the 6 oldest rows are pruned");
        assert_eq!(store.count(&HistoryFilter::default()).unwrap(), 4);

        // The survivors are the newest ids (7..=10).
        let rows = store
            .history_page(&HistoryFilter::default(), 50, 0)
            .unwrap();
        let mut ids: Vec<u64> = rows.iter().map(|r| r.id).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![7, 8, 9, 10]);
    }

    #[test]
    fn persists_and_pages_and_filters() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("p.sqlite")).unwrap();
        let mut sink = store.sink();

        sink.handle(&TrafficEvent::Completed(Arc::new(txn(
            1,
            "a.example",
            "GET",
            200,
            b"{}",
        ))));
        sink.handle(&TrafficEvent::Completed(Arc::new(txn(
            2,
            "b.example",
            "POST",
            404,
            b"{}",
        ))));
        sink.handle(&TrafficEvent::Completed(Arc::new(txn(
            3,
            "a.example",
            "GET",
            500,
            b"{}",
        ))));
        store.flush().unwrap();

        // newest first
        let all = store
            .history_page(&HistoryFilter::default(), 50, 0)
            .unwrap();
        assert_eq!(all.iter().map(|s| s.id).collect::<Vec<_>>(), vec![3, 2, 1]);
        assert_eq!(store.count(&HistoryFilter::default()).unwrap(), 3);

        // host substring
        let f = HistoryFilter {
            host: Some("a.exa".into()),
            ..Default::default()
        };
        assert_eq!(store.history_page(&f, 50, 0).unwrap().len(), 2);

        // status class
        let f = HistoryFilter {
            status_class: Some(4),
            ..Default::default()
        };
        let rows = store.history_page(&f, 50, 0).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, Some(404));

        // method
        let f = HistoryFilter {
            method: Some("post".into()),
            ..Default::default()
        };
        assert_eq!(store.history_page(&f, 50, 0).unwrap()[0].id, 2);

        // full view reconstruction
        let v = store.history_get(2).unwrap().unwrap();
        assert_eq!(v.request.method, "POST");
        assert_eq!(v.response.unwrap().status, 404);

        // persistence across reopen
        drop(store);
        let store2 = Store::open(dir.path().join("p.sqlite")).unwrap();
        assert_eq!(store2.count(&HistoryFilter::default()).unwrap(), 3);
    }

    fn txn_url(id: u64, url: &str, method: &str, status: u16) -> Transaction {
        let (rp, _) = hyper::Request::builder()
            .method(method)
            .uri(url)
            .body(())
            .unwrap()
            .into_parts();
        let request = CapturedRequest::from_parts(
            id,
            "127.0.0.1:9000".parse().unwrap(),
            &rp,
            Bytes::new(),
            0,
            true,
        )
        .unwrap();
        let (sp, _) = hyper::Response::builder()
            .status(status)
            .body(())
            .unwrap()
            .into_parts();
        let response = CapturedResponse::from_parts(&sp, Bytes::new(), 0, true);
        Transaction {
            request,
            response: Some(response),
            error: None,
            duration: Duration::from_millis(1),
        }
    }

    #[test]
    fn site_map_collapses_endpoints_and_keeps_latest() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("p.sqlite")).unwrap();
        let mut sink = store.sink();
        // two hits on the same endpoint (query differs → same path), one older, one newer
        sink.handle(&TrafficEvent::Completed(Arc::new(txn_url(
            1,
            "https://a.test/api/users?p=1",
            "GET",
            200,
        ))));
        sink.handle(&TrafficEvent::Completed(Arc::new(txn_url(
            2,
            "https://a.test/api/users?p=2",
            "GET",
            500,
        ))));
        // a distinct path on the same host, and a different host
        sink.handle(&TrafficEvent::Completed(Arc::new(txn_url(
            3,
            "https://a.test/login",
            "POST",
            302,
        ))));
        sink.handle(&TrafficEvent::Completed(Arc::new(txn_url(
            4,
            "http://b.test/",
            "GET",
            200,
        ))));
        store.flush().unwrap();

        let nodes = store.site_map().unwrap();
        assert_eq!(
            nodes.len(),
            3,
            "query-only differences collapse to one endpoint"
        );

        let users = nodes
            .iter()
            .find(|n| n.host == "a.test" && n.path == "/api/users")
            .unwrap();
        assert_eq!(users.id, 2, "representative is the most recent transaction");
        assert_eq!(users.status, Some(500));

        assert!(
            nodes
                .iter()
                .any(|n| n.host == "a.test" && n.path == "/login" && n.method == "POST")
        );
        assert!(
            nodes
                .iter()
                .any(|n| n.host == "b.test" && !n.secure && n.path == "/")
        );
    }

    #[test]
    fn stats_aggregates_totals_and_breakdowns() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("p.sqlite")).unwrap();
        let mut sink = store.sink();
        sink.handle(&TrafficEvent::Completed(Arc::new(txn_url(
            1,
            "https://a.test/x",
            "GET",
            200,
        ))));
        sink.handle(&TrafficEvent::Completed(Arc::new(txn_url(
            2,
            "https://a.test/y",
            "POST",
            404,
        ))));
        sink.handle(&TrafficEvent::Completed(Arc::new(txn_url(
            3,
            "https://b.test/z",
            "GET",
            500,
        ))));
        store.flush().unwrap();

        let s = store.stats().unwrap();
        assert_eq!(s.total, 3);
        assert_eq!(s.distinct_hosts, 2);
        assert!(s.by_status_class.contains(&(2, 1)));
        assert!(s.by_status_class.contains(&(4, 1)));
        assert!(s.by_status_class.contains(&(5, 1)));
        assert_eq!(s.by_method.iter().find(|(m, _)| m == "GET").unwrap().1, 2);
        assert_eq!(s.top_hosts[0], ("a.test".to_string(), 2));
    }

    #[test]
    fn project_meta_migrations_and_rename() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.sqlite");
        let store = Store::open(&path).unwrap();

        let meta = store.project_meta(false).unwrap();
        assert_eq!(meta.schema_version, SCHEMA_VERSION);
        assert_eq!(meta.name, "Shrike project");
        assert!(!meta.temporary);
        assert!(meta.created_at_ms > 0);

        // user_version pragma was set by the migration
        {
            let conn = store.read.lock().unwrap();
            let v: i64 = conn
                .query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
            assert_eq!(v, SCHEMA_VERSION);
        }

        store.set_project_name("My Engagement").unwrap();
        assert_eq!(store.project_meta(false).unwrap().name, "My Engagement");

        // name persists across reopen (and the row is not duplicated)
        drop(store);
        let again = Store::open(&path).unwrap();
        assert_eq!(again.project_meta(false).unwrap().name, "My Engagement");
    }

    #[test]
    fn integrity_check_passes_on_fresh_db() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("p.sqlite")).unwrap();
        assert!(store.integrity_check().unwrap());
    }

    #[test]
    fn backup_is_a_consistent_copy() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("p.sqlite")).unwrap();
        let mut sink = store.sink();
        sink.handle(&TrafficEvent::Completed(Arc::new(txn(
            1,
            "a.example",
            "GET",
            200,
            b"{}",
        ))));
        sink.handle(&TrafficEvent::Completed(Arc::new(txn(
            2,
            "b.example",
            "GET",
            200,
            b"{}",
        ))));

        let backup = dir.path().join("copy.sqlite");
        store.backup_to(&backup).unwrap(); // flushes internally
        assert!(backup.exists());
        // refuses to overwrite an existing file
        assert!(store.backup_to(&backup).is_err());

        // the copy opens, passes integrity, and holds the same rows
        let copy = Store::open(&backup).unwrap();
        assert!(copy.integrity_check().unwrap());
        assert_eq!(copy.count(&HistoryFilter::default()).unwrap(), 2);
        assert_eq!(
            copy.project_meta(false).unwrap().schema_version,
            SCHEMA_VERSION
        );
    }

    #[test]
    fn like_wildcards_are_escaped() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("p.sqlite")).unwrap();
        let mut sink = store.sink();
        sink.handle(&TrafficEvent::Completed(Arc::new(txn(
            1,
            "real.example",
            "GET",
            200,
            b"",
        ))));
        store.flush().unwrap();
        // a literal '%' must not match everything
        let f = HistoryFilter {
            host: Some("%".into()),
            ..Default::default()
        };
        assert_eq!(store.history_page(&f, 50, 0).unwrap().len(), 0);
    }
    #[test]
    fn meta_round_trips_and_upserts() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("p.sqlite")).unwrap();
        assert_eq!(store.get_meta("scope").unwrap(), None);
        store.set_meta("scope", "v1").unwrap();
        store.set_meta("scope", "v2").unwrap();
        assert_eq!(store.get_meta("scope").unwrap().as_deref(), Some("v2"));
        drop(store);
        let again = Store::open(dir.path().join("p.sqlite")).unwrap();
        assert_eq!(
            again.get_meta("scope").unwrap().as_deref(),
            Some("v2"),
            "persists across reopen"
        );
    }
}
