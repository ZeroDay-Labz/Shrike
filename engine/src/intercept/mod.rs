//! Request interception: hold in-flight proxy requests until the user forwards
//! (optionally edited) or drops them.
//!
//! Like [`crate::scope`], the control lives in the engine, not the UI: the proxy
//! handler awaits a [`Decision`] here, so a paused request stays paused no matter
//! what the front end does. The handler runs on its own task per request (hudsucker
//! clones the handler), so awaiting one request never blocks the others.

use crate::core::Header;
use anyhow::{Result, anyhow};
use std::{
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::sync::oneshot;

/// A request edited by the user in the intercept pane, ready to re-send.
#[derive(Debug, Clone)]
pub struct EditedRequest {
    pub method: String,
    /// Request-line target (path + query).
    pub target: String,
    pub headers: Vec<Header>,
    pub body: String,
}

/// What the user decided about a paused request.
#[derive(Debug)]
pub enum Decision {
    /// Forward it: unchanged (`None`) or with the user's edits.
    Forward(Option<EditedRequest>),
    /// Drop it: the client gets a synthetic error, nothing goes upstream.
    Drop,
}

/// Shared interception state. Held by the engine and the live proxy handler.
#[derive(Default)]
pub struct Interceptor {
    enabled: AtomicBool,
    pending: Mutex<HashMap<u64, oneshot::Sender<Decision>>>,
}

impl Interceptor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// Turn interception on or off. Turning it off releases every request that is
    /// currently paused (forwarded unchanged) so nothing is left stuck.
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
        if !on {
            self.drain_all();
        }
    }

    /// Register a paused request and return the channel the handler awaits.
    pub fn pause(&self, id: u64) -> oneshot::Receiver<Decision> {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().expect("intercept lock").insert(id, tx);
        rx
    }

    /// Deliver the user's decision to the paused request `id`. A no-op if the id
    /// is unknown (already resolved, or the connection went away).
    pub fn resolve(&self, id: u64, decision: Decision) {
        if let Some(tx) = self.pending.lock().expect("intercept lock").remove(&id) {
            // The receiver is gone only if the client disconnected; ignore.
            let _ = tx.send(decision);
        }
    }

    /// Release every paused request, forwarding each unchanged. Called when
    /// interception is turned off and when the proxy stops.
    pub fn drain_all(&self) {
        let pending: Vec<_> = self
            .pending
            .lock()
            .expect("intercept lock")
            .drain()
            .map(|(_, tx)| tx)
            .collect();
        for tx in pending {
            let _ = tx.send(Decision::Forward(None));
        }
    }

    /// Number of requests currently waiting on a decision (for tests/diagnostics).
    pub fn pending_count(&self) -> usize {
        self.pending.lock().expect("intercept lock").len()
    }
}

/// Parse an edited raw HTTP request (the text shown in the intercept pane) back
/// into the method / target / headers / body the handler needs. The original
/// request's scheme and authority are kept by the handler; only what the user can
/// edit here is parsed. The `Host` header is preserved as a normal header.
pub fn parse_request_head(raw: &str) -> Result<EditedRequest> {
    // Tolerate both CRLF and bare-LF line endings.
    let (head, body) = match raw.split_once("\r\n\r\n") {
        Some((h, b)) => (h, b),
        None => match raw.split_once("\n\n") {
            Some((h, b)) => (h, b),
            None => (raw, ""),
        },
    };

    let mut lines = head.lines();
    let request_line = lines.next().ok_or_else(|| anyhow!("empty request"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow!("request line has no method"))?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| anyhow!("request line has no target"))?
        .to_string();
    // A version token may follow; we ignore it and reuse the original request's.

    let mut headers = Vec::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow!("malformed header line: {line:?}"))?;
        headers.push(Header {
            name: name.trim().to_string(),
            value: value.trim().to_string(),
        });
    }

    Ok(EditedRequest {
        method,
        target,
        headers,
        body: body.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_delivers_the_decision() {
        let itx = Interceptor::new();
        let rx = itx.pause(1);
        assert_eq!(itx.pending_count(), 1);
        itx.resolve(1, Decision::Drop);
        assert!(matches!(rx.await.unwrap(), Decision::Drop));
        assert_eq!(itx.pending_count(), 0);
    }

    #[tokio::test]
    async fn disabling_drains_pending_as_forward() {
        let itx = Interceptor::new();
        itx.set_enabled(true);
        let rx = itx.pause(7);
        itx.set_enabled(false);
        assert!(matches!(rx.await.unwrap(), Decision::Forward(None)));
        assert_eq!(itx.pending_count(), 0);
        assert!(!itx.is_enabled());
    }

    #[test]
    fn parse_get_without_body() {
        let raw = "GET /a?x=1 HTTP/1.1\r\nHost: example.test\r\nAccept: */*\r\n\r\n";
        let r = parse_request_head(raw).unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.target, "/a?x=1");
        assert_eq!(r.headers.len(), 2);
        assert_eq!(r.headers[0].name, "Host");
        assert_eq!(r.headers[0].value, "example.test");
        assert!(r.body.is_empty());
    }

    #[test]
    fn parse_post_with_body_and_bare_lf() {
        let raw = "POST /submit HTTP/1.1\nHost: example.test\nContent-Type: application/json\n\n{\"a\":1}";
        let r = parse_request_head(raw).unwrap();
        assert_eq!(r.method, "POST");
        assert_eq!(r.target, "/submit");
        assert_eq!(r.headers.len(), 2);
        assert_eq!(r.body, "{\"a\":1}");
    }

    #[test]
    fn parse_rejects_empty_and_malformed() {
        assert!(parse_request_head("").is_err());
        assert!(parse_request_head("GET\r\n\r\n").is_err());
        assert!(parse_request_head("GET / HTTP/1.1\r\nBadHeaderNoColon\r\n\r\n").is_err());
    }
}
