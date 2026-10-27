//! Extender: Shrike's own plugin system.
//!
//! This module is the **foundation**: an original, declarative plugin model —
//! manifests describing a plugin's identity, the permissions it requests, and the
//! hook points it wants — plus a persisted registry the UI manages (install,
//! enable/disable, remove). It is deliberately data-only and safe: nothing here
//! executes third-party code. The sandboxed execution runtime that actually runs
//! an enabled plugin against live traffic is the next milestone; the permission
//! and hook model defined here is what that runtime will enforce.
//!
//! Compatibility with third-party (e.g. BApp) extensions is a non-goal — Shrike
//! ships this clean-room API instead.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A capability a plugin must request up front; the runtime will enforce these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginPermission {
    /// Observe requests and responses.
    ReadTraffic,
    /// Rewrite requests and responses in flight.
    ModifyTraffic,
    /// Issue its own requests (active testing).
    ActiveScan,
    /// Persist its own data in the project.
    Storage,
}

/// Where a plugin asks to run. Declared now; invoked by the future runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginHook {
    OnRequest,
    OnResponse,
    PassiveScan,
    ActiveScan,
}

/// A plugin's manifest: everything Shrike knows about it without running it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginManifest {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub permissions: Vec<PluginPermission>,
    #[serde(default)]
    pub hooks: Vec<PluginHook>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    #[error("a plugin id must not be empty")]
    EmptyId,
    #[error("duplicate plugin id: {0}")]
    DuplicateId(String),
}

/// The set of installed plugins, validated for unique non-empty ids.
#[derive(Default)]
pub struct PluginRegistry {
    plugins: Vec<PluginManifest>,
}

impl PluginRegistry {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn from_manifests(list: Vec<PluginManifest>) -> Result<Self, PluginError> {
        let mut seen = HashSet::new();
        for p in &list {
            if p.id.trim().is_empty() {
                return Err(PluginError::EmptyId);
            }
            if !seen.insert(p.id.clone()) {
                return Err(PluginError::DuplicateId(p.id.clone()));
            }
        }
        Ok(Self { plugins: list })
    }

    pub fn manifests(&self) -> Vec<PluginManifest> {
        self.plugins.clone()
    }

    /// Install a new plugin, or replace an existing one with the same id.
    pub fn upsert(&mut self, manifest: PluginManifest) -> Result<(), PluginError> {
        if manifest.id.trim().is_empty() {
            return Err(PluginError::EmptyId);
        }
        match self.plugins.iter_mut().find(|p| p.id == manifest.id) {
            Some(existing) => *existing = manifest,
            None => self.plugins.push(manifest),
        }
        Ok(())
    }

    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.plugins.len();
        self.plugins.retain(|p| p.id != id);
        self.plugins.len() != before
    }

    pub fn set_enabled(&mut self, id: &str, on: bool) -> bool {
        match self.plugins.iter_mut().find(|p| p.id == id) {
            Some(p) => {
                p.enabled = on;
                true
            }
            None => false,
        }
    }

    /// Enabled plugins declaring the given hook — what the runtime will dispatch to.
    pub fn active_for(&self, hook: PluginHook) -> impl Iterator<Item = &PluginManifest> {
        self.plugins
            .iter()
            .filter(move |p| p.enabled && p.hooks.contains(&hook))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(id: &str) -> PluginManifest {
        PluginManifest {
            id: id.into(),
            name: id.into(),
            version: "1.0".into(),
            description: String::new(),
            author: String::new(),
            permissions: vec![PluginPermission::ReadTraffic],
            hooks: vec![PluginHook::OnResponse],
            enabled: true,
        }
    }

    #[test]
    fn rejects_empty_and_duplicate_ids() {
        assert!(PluginRegistry::from_manifests(vec![manifest("")]).is_err());
        assert!(PluginRegistry::from_manifests(vec![manifest("a"), manifest("a")]).is_err());
        assert!(PluginRegistry::from_manifests(vec![manifest("a"), manifest("b")]).is_ok());
    }

    #[test]
    fn upsert_replaces_and_remove_deletes() {
        let mut reg = PluginRegistry::empty();
        reg.upsert(manifest("x")).unwrap();
        let mut m = manifest("x");
        m.name = "renamed".into();
        reg.upsert(m).unwrap();
        assert_eq!(reg.manifests().len(), 1);
        assert_eq!(reg.manifests()[0].name, "renamed");
        assert!(reg.remove("x"));
        assert!(reg.manifests().is_empty());
    }

    #[test]
    fn enable_toggle_and_active_for_hook() {
        let mut reg = PluginRegistry::from_manifests(vec![manifest("a"), manifest("b")]).unwrap();
        assert!(reg.set_enabled("b", false));
        assert_eq!(reg.active_for(PluginHook::OnResponse).count(), 1);
        assert_eq!(reg.active_for(PluginHook::OnRequest).count(), 0);
        assert!(!reg.set_enabled("missing", true));
    }
}
