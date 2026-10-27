//! Turns low-level TLS failures from the proxy plumbing into one-time,
//! plain-language hints. Browsers that do not trust the CA yet abort the
//! handshake with an `UnknownCA` alert; that is a setup step, not a bug.

use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
};
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

pub struct FriendlyTlsErrors {
    hinted: AtomicBool,
    cert_hint: String,
    sink: Box<dyn Fn(&str) + Send + Sync>,
}

impl FriendlyTlsErrors {
    pub fn new(cert_path: &std::path::Path) -> Self {
        Self::with_sink(cert_path, |hint| eprintln!("\n{hint}\n"))
    }

    /// Like [`Self::new`] but delivers the hint to `sink` (used by tests).
    pub fn with_sink(
        cert_path: &std::path::Path,
        sink: impl Fn(&str) + Send + Sync + 'static,
    ) -> Self {
        Self {
            hinted: AtomicBool::new(false),
            sink: Box::new(sink),
            cert_hint: format!(
                "A client rejected the proxy certificate because it does not trust the CA yet.\n\
                 Import {} (or browse to http://shrike/ through the proxy), then retry.\n\
                 Shortcut: `shrike ca trust` imports it into Firefox and Chrome profiles found on this machine.",
                cert_path.display()
            ),
        }
    }
}

/// Alerts a client sends when it does not accept our leaf certificate.
const CLIENT_REJECTED_CERT: [&str; 4] = [
    "UnknownCA",
    "BadCertificate",
    "CertificateUnknown",
    "UnknownCa",
];

/// Benign TLS/connection noise from the proxy plumbing: a peer closed the
/// connection mid-handshake, a client hung up, etc. Not actionable, so swallow
/// it rather than logging a scary ERROR on every dropped connection.
const BENIGN_TLS_NOISE: [&str; 4] = [
    "handshake eof",
    "UnexpectedEof",
    "unexpected end of file",
    "connection reset",
];

fn is_benign_tls_noise(event: &Event<'_>) -> bool {
    if !event.metadata().target().starts_with("hudsucker") {
        return false;
    }
    let mut text = Collect(String::new());
    event.record(&mut text);
    let lower = text.0.to_ascii_lowercase();
    BENIGN_TLS_NOISE
        .iter()
        .any(|needle| lower.contains(&needle.to_ascii_lowercase()))
}

struct Collect(String);
impl Visit for Collect {
    fn record_debug(&mut self, _field: &Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        let _ = write!(self.0, "{value:?} ");
    }
}

fn is_client_cert_rejection(event: &Event<'_>) -> bool {
    if !event.metadata().target().starts_with("hudsucker") {
        return false;
    }
    let mut text = Collect(String::new());
    event.record(&mut text);
    CLIENT_REJECTED_CERT
        .iter()
        .any(|needle| text.0.contains(needle))
}

impl<S> Layer<S> for FriendlyTlsErrors
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    /// Swallow the raw hudsucker error so the fmt layer does not print it, and
    /// print the hint once instead. (When this returns false no layer, including
    /// this one, gets `on_event`, so the hint has to happen here.)
    fn event_enabled(&self, event: &Event<'_>, _ctx: Context<'_, S>) -> bool {
        if is_benign_tls_noise(event) {
            return false; // dropped connection — not worth a log line
        }
        if !is_client_cert_rejection(event) {
            return true;
        }
        if !self.hinted.swap(true, Ordering::Relaxed) {
            (self.sink)(&self.cert_hint);
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn hints_once_and_suppresses_raw_error() {
        let hints = Arc::new(Mutex::new(Vec::<String>::new()));
        let h = Arc::clone(&hints);
        let layer = FriendlyTlsErrors::with_sink(std::path::Path::new("/tmp/ca.pem"), move |s| {
            h.lock().unwrap().push(s.to_string());
        });
        let printed = Arc::new(Mutex::new(Vec::<String>::new()));
        let p = Arc::clone(&printed);
        let recorder = tracing_subscriber::fmt::layer()
            .with_writer(move || Recorder(Arc::clone(&p)))
            .with_ansi(false);
        let subscriber = tracing_subscriber::registry().with(recorder).with(layer);

        tracing::subscriber::with_default(subscriber, || {
            // Mimic hudsucker's log line.
            tracing::error!(target: "hudsucker::proxy::internal", error = "received fatal alert: UnknownCA", "Failed to establish TLS connection");
            tracing::error!(target: "hudsucker::proxy::internal", error = "received fatal alert: UnknownCA", "Failed to establish TLS connection");
            tracing::error!(target: "hudsucker::proxy::internal", "Failed to connect to example.com");
            tracing::error!(target: "shrike_engine::proxy", "UnknownCA mentioned by us must not be swallowed");
        });

        let hints = hints.lock().unwrap();
        assert_eq!(hints.len(), 1, "hint exactly once");
        assert!(hints[0].contains("/tmp/ca.pem"));
        let out = printed.lock().unwrap().join("");
        assert!(
            !out.contains("fatal alert"),
            "raw error must be suppressed: {out}"
        );
        assert!(out.contains("Failed to connect to example.com"));
        assert!(out.contains("must not be swallowed"));
    }

    struct Recorder(Arc<Mutex<Vec<String>>>);
    impl std::io::Write for Recorder {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(buf).into_owned());
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}
