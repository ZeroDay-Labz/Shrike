//! Event bus: the proxy emits traffic events, sinks consume them off the hot path.

use super::message::{CapturedRequest, HttpService, Transaction};
use std::{net::SocketAddr, sync::Arc};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::warn;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsDirection {
    ClientToServer,
    ServerToClient,
}

#[derive(Debug, Clone)]
pub struct WsMessageEvent {
    pub direction: WsDirection,
    pub url: String,
    pub client_addr: SocketAddr,
    pub kind: &'static str,
    pub len: usize,
    /// UTF-8 payload for text frames (truncated for display), otherwise `None`.
    pub text: Option<String>,
}

#[derive(Debug, Clone)]
pub enum TrafficEvent {
    /// A request has been fully read and is about to be forwarded.
    RequestStarted(Arc<CapturedRequest>),
    /// A request has a response (or a terminal error).
    Completed(Arc<Transaction>),
    /// A CONNECT tunnel was opened without interception.
    TunnelPassthrough {
        host: String,
        client_addr: SocketAddr,
    },
    WebSocketMessage(WsMessageEvent),
    /// A request is paused at the proxy, waiting for the user to forward or drop it.
    Intercepted {
        id: u64,
        service: HttpService,
        /// Raw HTTP request text shown in the intercept editor.
        raw: String,
    },
    /// A finding was recorded (by the operator or a scanner). Carried on the bus
    /// so the GUI bridge can push it live, regardless of which source raised it.
    FindingAdded(Arc<crate::findings::Finding>),
}

/// Consumer of traffic events. Runs on the bus task, so keep work short or
/// hand it to a dedicated task of your own.
pub trait TrafficSink: Send + 'static {
    fn handle(&mut self, event: &TrafficEvent);
}

/// Cheap-to-clone handle for emitting events. Sinks can be registered up front
/// (`start`) or added later (`add_sink`) — the latter lets a long-lived bus pick
/// up a sink such as the GUI bridge after the webview exists.
#[derive(Clone)]
pub struct EventBus {
    tx: mpsc::UnboundedSender<TrafficEvent>,
    sinks: Arc<std::sync::Mutex<Vec<Box<dyn TrafficSink>>>>,
}

impl std::fmt::Debug for EventBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventBus").finish_non_exhaustive()
    }
}

impl EventBus {
    /// Spawn the dispatcher task feeding `initial` sinks (and any later added via
    /// [`add_sink`](Self::add_sink)) in registration order. The task ends once
    /// every `EventBus` clone has been dropped.
    pub fn start(initial: Vec<Box<dyn TrafficSink>>) -> (Self, JoinHandle<()>) {
        let sinks = Arc::new(std::sync::Mutex::new(initial));
        let dispatch = Arc::clone(&sinks);
        let (tx, mut rx) = mpsc::unbounded_channel::<TrafficEvent>();
        let task = tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                for sink in dispatch.lock().expect("event sinks lock").iter_mut() {
                    sink.handle(&event);
                }
            }
        });
        (Self { tx, sinks }, task)
    }

    /// Register another sink on a running bus (e.g. the passive scanner or the
    /// GUI bridge). It receives every event emitted from now on.
    pub fn add_sink(&self, sink: Box<dyn TrafficSink>) {
        self.sinks.lock().expect("event sinks lock").push(sink);
    }

    pub fn emit(&self, event: TrafficEvent) {
        if self.tx.send(event).is_err() {
            warn!("event bus closed; dropping traffic event");
        }
    }
}

/// Human-readable one-line-per-transaction log on stdout.
pub struct StdoutSink {
    /// Also dump full request/response text.
    pub verbose: bool,
    /// Longest body to print verbatim in verbose mode.
    pub max_body_print: usize,
}

impl Default for StdoutSink {
    fn default() -> Self {
        Self {
            verbose: false,
            max_body_print: 4096,
        }
    }
}

pub fn human_bytes(n: usize) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1000.0 && i < UNITS.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

fn is_texty(content_type: Option<&str>) -> bool {
    match content_type {
        Some(ct) => {
            ct.starts_with("text/")
                || ct.contains("json")
                || ct.contains("xml")
                || ct.contains("javascript")
                || ct.contains("x-www-form-urlencoded")
        }
        None => false,
    }
}

impl StdoutSink {
    fn print_body(&self, body: &[u8], content_type: Option<&str>, complete: bool) {
        if body.is_empty() {
            return;
        }
        if !is_texty(content_type) {
            println!("<{} binary body omitted>", human_bytes(body.len()));
            return;
        }
        let shown = &body[..body.len().min(self.max_body_print)];
        println!("{}", String::from_utf8_lossy(shown));
        if shown.len() < body.len() || !complete {
            println!(
                "<... {} more>",
                human_bytes(body.len().saturating_sub(shown.len()))
            );
        }
    }
}

impl TrafficSink for StdoutSink {
    fn handle(&mut self, event: &TrafficEvent) {
        match event {
            TrafficEvent::RequestStarted(req) if self.verbose => {
                println!("\n==> #{} {} {}", req.id, req.client_addr, req.url());
                let head_len = req.to_raw().len() - req.body.len();
                let raw = req.to_raw();
                print!("{}", String::from_utf8_lossy(&raw[..head_len]));
                self.print_body(&req.body, req.header("content-type"), req.body_complete);
            }
            TrafficEvent::RequestStarted(_) => {}
            TrafficEvent::Completed(tx) => {
                let req = &tx.request;
                match (&tx.response, &tx.error) {
                    (Some(res), _) => {
                        println!(
                            "#{:<5} {:<6} {:<60} -> {} {:<16} {:>9} {:>6} ms",
                            req.id,
                            req.method,
                            truncate(&req.url(), 60),
                            res.status,
                            res.content_type().unwrap_or("-"),
                            human_bytes(res.body_len),
                            tx.duration.as_millis(),
                        );
                        if self.verbose {
                            println!("<== #{} {} {}", req.id, res.status, res.reason());
                            let raw = res.to_raw();
                            let head_len = raw.len() - res.body.len();
                            print!("{}", String::from_utf8_lossy(&raw[..head_len]));
                            self.print_body(&res.body, res.content_type(), res.body_complete);
                        }
                    }
                    (None, err) => {
                        println!(
                            "#{:<5} {:<6} {:<60} !! {}",
                            req.id,
                            req.method,
                            truncate(&req.url(), 60),
                            err.as_deref().unwrap_or("upstream error")
                        );
                    }
                }
            }
            TrafficEvent::TunnelPassthrough { host, client_addr } => {
                println!("      TUNNEL {client_addr} -> {host} (not intercepted)");
            }
            TrafficEvent::WebSocketMessage(ws) => {
                let arrow = match ws.direction {
                    WsDirection::ClientToServer => "ws>>",
                    WsDirection::ServerToClient => "ws<<",
                };
                match (&ws.text, self.verbose) {
                    (Some(text), true) => println!("      {arrow} {} {} {}", ws.url, ws.kind, text),
                    _ => println!(
                        "      {arrow} {} {} {}",
                        ws.url,
                        ws.kind,
                        human_bytes(ws.len)
                    ),
                }
            }
            TrafficEvent::FindingAdded(_) => {}
            TrafficEvent::Intercepted { id, service, .. } => {
                println!("      HOLD #{id} {service} (intercepted, awaiting decision)");
            }
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_bytes_scales() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1500), "1.5 kB");
        assert_eq!(human_bytes(12_300_000), "12.3 MB");
    }

    #[tokio::test]
    async fn bus_delivers_to_sinks_in_order() {
        struct Rec(std::sync::mpsc::Sender<String>);
        impl TrafficSink for Rec {
            fn handle(&mut self, event: &TrafficEvent) {
                if let TrafficEvent::TunnelPassthrough { host, .. } = event {
                    self.0.send(host.clone()).unwrap();
                }
            }
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let (bus, task) = EventBus::start(vec![Box::new(Rec(tx))]);
        for h in ["a", "b", "c"] {
            bus.emit(TrafficEvent::TunnelPassthrough {
                host: h.into(),
                client_addr: "127.0.0.1:1".parse().unwrap(),
            });
        }
        drop(bus);
        task.await.unwrap();
        let got: Vec<String> = rx.try_iter().collect();
        assert_eq!(got, vec!["a", "b", "c"]);
    }
}
