//! Extras: Shrike's native capability surface.
//!
//! **The safety contract of this module is the passive/active split.**
//!
//! - [`ExtraKind::Passive`] extras *observe* captured traffic and never send a
//!   request. They run automatically (subject to their enable toggle), because
//!   analysing traffic that already happened is safe.
//! - [`ExtraKind::Active`] extras *send* requests to the target. They are never
//!   run automatically and have no "enabled" auto-run state — they only run from
//!   a deliberate, per-target user action (a button, a context-menu item). This
//!   is what stops Shrike from ever touching a target by accident.
//!
//! This module owns the catalogue of built-in extras and the persisted enable
//! state of the passive ones. Active extras are advertised here but driven by
//! their own explicit entry points (e.g. the active scanner, the crawler).

use serde::Serialize;
use std::collections::HashSet;
use std::sync::{Arc, RwLock};

/// Whether an extra observes traffic (safe to auto-run) or sends traffic (must
/// be invoked deliberately).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtraKind {
    /// Observe-only. Runs automatically on captured traffic; never sends a request.
    Passive,
    /// Sends requests to the target. Only ever runs on an explicit user action.
    Active,
}

impl ExtraKind {
    /// The safety-critical property: does running this extra put traffic on the
    /// wire? Exactly the active extras do.
    pub fn sends_traffic(self) -> bool {
        matches!(self, ExtraKind::Active)
    }
}

/// A built-in capability.
#[derive(Debug, Clone, Copy)]
pub struct Extra {
    pub id: &'static str,
    pub name: &'static str,
    pub category: &'static str,
    pub kind: ExtraKind,
    pub description: &'static str,
    /// Passive extras default on; active extras have no auto-run state and are
    /// reported as disabled (they run on demand).
    pub default_enabled: bool,
}

/// The built-in catalogue. Order is the display order.
pub const CATALOG: &[Extra] = &[
    Extra {
        id: "http-hygiene",
        name: "HTTP hygiene",
        category: "Passive checks",
        kind: ExtraKind::Passive,
        description: "Flags missing security headers, insecure cookie flags, \
                      information disclosure, server error signatures and mixed content.",
        default_enabled: true,
    },
    Extra {
        id: "reflected-input",
        name: "Reflected input",
        category: "Passive checks",
        kind: ExtraKind::Passive,
        description: "Notes request parameters reflected unencoded in the response — \
                      a lead for reflected XSS to confirm deliberately.",
        default_enabled: true,
    },
    Extra {
        id: "jwt",
        name: "JWT scanner",
        category: "Passive checks",
        kind: ExtraKind::Passive,
        description: "Inspects JWTs in Authorization, cookies and Set-Cookie for the \
                      unsigned \"none\" algorithm, guessable secrets and expiry problems.",
        default_enabled: true,
    },
    Extra {
        id: "pwnfox",
        name: "Container colouring",
        category: "Workflow",
        kind: ExtraKind::Passive,
        description: "Tags captured traffic with the container colour from a PwnFox-style \
                      X-PwnFox-Color header (stripped before it reaches the target).",
        default_enabled: true,
    },
    Extra {
        id: "active-audit",
        name: "Active audit",
        category: "Active tools",
        kind: ExtraKind::Active,
        description: "Probes a chosen request for reflected XSS, error-based SQL injection, \
                      SSTI, path traversal and command injection. Sends crafted requests, so \
                      run it deliberately on an in-scope target.",
        default_enabled: false,
    },
];

/// A catalogue entry plus its live enable state, for the UI.
#[derive(Debug, Clone, Serialize)]
pub struct ExtraStatus {
    pub id: String,
    pub name: String,
    pub category: String,
    pub kind: ExtraKind,
    pub description: String,
    /// True when traffic hits the wire if this runs (the active extras).
    pub sends_traffic: bool,
    /// Passive: whether it auto-runs. Active: always false (runs on demand only).
    pub enabled: bool,
}

/// Live enable state for passive extras, shared with the passive scanner so a
/// toggle takes effect on the next captured transaction.
#[derive(Clone)]
pub struct Extras {
    /// Ids of passive extras currently enabled. Active extras are never in here.
    enabled: Arc<RwLock<HashSet<String>>>,
}

fn find(id: &str) -> Option<&'static Extra> {
    CATALOG.iter().find(|e| e.id == id)
}

impl Extras {
    /// Build from persisted enable state (a set of enabled passive ids). Unknown
    /// ids are ignored; passive ids absent from `persisted` fall back to their
    /// default. `None` means "no stored state yet" — use defaults.
    pub fn from_enabled(persisted: Option<HashSet<String>>) -> Self {
        let enabled = match persisted {
            Some(set) => CATALOG
                .iter()
                .filter(|e| e.kind == ExtraKind::Passive && set.contains(e.id))
                .map(|e| e.id.to_string())
                .collect(),
            None => CATALOG
                .iter()
                .filter(|e| e.kind == ExtraKind::Passive && e.default_enabled)
                .map(|e| e.id.to_string())
                .collect(),
        };
        Self {
            enabled: Arc::new(RwLock::new(enabled)),
        }
    }

    /// Whether a passive extra is currently enabled. Active extras are never
    /// "enabled" here (they run on demand), so this is always false for them.
    pub fn is_enabled(&self, id: &str) -> bool {
        self.enabled.read().expect("extras lock").contains(id)
    }

    /// A snapshot of enabled passive ids, for the passive scanner to consult.
    pub fn enabled_snapshot(&self) -> HashSet<String> {
        self.enabled.read().expect("extras lock").clone()
    }

    /// Toggle a passive extra. Active extras cannot be toggled (they have no
    /// auto-run state); attempting to does nothing and returns `false`.
    pub fn set_enabled(&self, id: &str, on: bool) -> bool {
        match find(id) {
            Some(e) if e.kind == ExtraKind::Passive => {
                let mut set = self.enabled.write().expect("extras lock");
                if on {
                    set.insert(id.to_string());
                } else {
                    set.remove(id);
                }
                true
            }
            _ => false,
        }
    }

    /// The full catalogue with live enable state, for the UI.
    pub fn statuses(&self) -> Vec<ExtraStatus> {
        let enabled = self.enabled.read().expect("extras lock");
        CATALOG
            .iter()
            .map(|e| ExtraStatus {
                id: e.id.to_string(),
                name: e.name.to_string(),
                category: e.category.to_string(),
                kind: e.kind,
                description: e.description.to_string(),
                sends_traffic: e.kind.sends_traffic(),
                enabled: e.kind == ExtraKind::Passive && enabled.contains(e.id),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_extras_never_auto_run_and_cannot_be_enabled() {
        let x = Extras::from_enabled(None);
        // Active audit sends traffic and is never enabled for auto-run.
        assert!(!x.is_enabled("active-audit"));
        assert!(
            !x.set_enabled("active-audit", true),
            "active extras cannot be toggled on"
        );
        assert!(!x.is_enabled("active-audit"), "still not auto-running");
        // And the catalogue marks exactly the active ones as sending traffic.
        let sends: Vec<_> = x
            .statuses()
            .into_iter()
            .filter(|s| s.sends_traffic)
            .map(|s| s.id)
            .collect();
        assert_eq!(sends, vec!["active-audit"]);
    }

    #[test]
    fn passive_extras_default_on_and_toggle() {
        let x = Extras::from_enabled(None);
        assert!(x.is_enabled("jwt"));
        assert!(x.set_enabled("jwt", false));
        assert!(!x.is_enabled("jwt"));
        assert!(!x.enabled_snapshot().contains("jwt"));
        assert!(x.set_enabled("jwt", true));
        assert!(x.is_enabled("jwt"));
    }

    #[test]
    fn persisted_state_restores_passive_toggles() {
        let saved: HashSet<String> = ["http-hygiene".to_string()].into_iter().collect();
        let x = Extras::from_enabled(Some(saved));
        assert!(x.is_enabled("http-hygiene"));
        assert!(!x.is_enabled("jwt"), "jwt not in the saved set -> off");
        // Unknown and active ids in storage are ignored.
        let x2 = Extras::from_enabled(Some(
            ["active-audit".to_string(), "nope".to_string()]
                .into_iter()
                .collect(),
        ));
        assert!(!x2.is_enabled("active-audit"));
    }
}
