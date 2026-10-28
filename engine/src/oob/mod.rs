//! Out-of-band (OAST) interaction service — the interface only.
//!
//! Blind vulnerabilities (blind SQLi, SSRF, blind XSS, some RCE) are confirmed
//! by making the target reach out to a server the tester controls and watching
//! for the callback. That server (a DNS + HTTP listener on a public domain) is a
//! later milestone; this module defines the provider contract and ships a
//! disabled [`NullProvider`] so the active scanner's blind checks compile and run
//! but stay inert until a provider is configured. OOB is opt-in and off by
//! default — Shrike never silently points traffic at a third-party listener.

use serde::Serialize;

/// A registered OOB correlation: the payload to inject and the id to poll.
#[derive(Debug, Clone, Serialize)]
pub struct OobHandle {
    /// Unique token tying an interaction back to a specific probe.
    pub correlation_id: String,
    /// Hostname to inject (e.g. `<id>.oast.example`).
    pub payload_host: String,
    /// Full URL to inject for HTTP-reaching checks.
    pub payload_url: String,
}

/// One observed callback to the OOB server.
#[derive(Debug, Clone, Serialize)]
pub struct OobInteraction {
    /// `dns` | `http` | `smtp` …
    pub kind: String,
    /// Source address that reached the listener.
    pub source: String,
    pub at_ms: u64,
    pub detail: String,
}

/// An out-of-band interaction server.
pub trait OobProvider: Send + Sync {
    /// Whether a usable server is configured.
    fn enabled(&self) -> bool;
    /// Allocate a correlation + payload, or `None` when disabled.
    fn register(&self) -> Option<OobHandle>;
    /// Interactions seen for `correlation_id` (empty when disabled).
    fn poll(&self, correlation_id: &str) -> Vec<OobInteraction>;
}

/// Disabled provider: registers nothing and never reports interactions.
pub struct NullProvider;

impl OobProvider for NullProvider {
    fn enabled(&self) -> bool {
        false
    }
    fn register(&self) -> Option<OobHandle> {
        None
    }
    fn poll(&self, _correlation_id: &str) -> Vec<OobInteraction> {
        Vec::new()
    }
}

/// Build the provider for the configured server. Until a hosted listener is
/// implemented this is always the [`NullProvider`]; a non-empty `oob_server`
/// is accepted but not yet honoured (documented as a later milestone).
pub fn provider_for(_oob_server: &str) -> Box<dyn OobProvider> {
    Box::new(NullProvider)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_provider_is_inert() {
        let p = provider_for("");
        assert!(!p.enabled());
        assert!(p.register().is_none());
        assert!(p.poll("anything").is_empty());
    }

    #[test]
    fn a_configured_server_is_not_yet_honoured() {
        // Deliberate: the hosted listener is a later milestone; a set server must
        // not silently behave as if interactions can be observed.
        let p = provider_for("oast.example");
        assert!(!p.enabled());
    }
}
