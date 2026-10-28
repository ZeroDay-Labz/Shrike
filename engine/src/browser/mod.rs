//! Launch a Chromium-family browser pre-configured to use Shrike as its proxy,
//! with Shrike's CA trusted and an isolated profile.
//!
//! The launcher is binary-agnostic: the GUI passes the path to the *bundled*
//! Chromium (Chrome for Testing), and [`find_system_chromium`] is only a fallback
//! for development or when no bundle is present. Nothing here touches the user's
//! real browser profile or any system trust store — the CA is trusted for this
//! one browser via `--ignore-certificate-errors-spki-list`.

use anyhow::{Context, Result};
use serde::Serialize;
use std::{
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command},
};

pub struct BrowserConfig {
    pub chromium_bin: PathBuf,
    pub listen: SocketAddr,
    /// base64(SHA-256(CA SubjectPublicKeyInfo)) — from `CaManager::spki_sha256_base64`.
    pub spki_b64: String,
    pub profile_dir: PathBuf,
    pub start_url: String,
}

/// What the UI shows after a successful launch.
#[derive(Debug, Clone, Serialize)]
pub struct BrowserStatus {
    pub pid: u32,
    pub proxy: String,
    pub profile: String,
    pub chromium: String,
}

/// The command-line flags that wire a Chromium instance to Shrike.
pub fn build_args(cfg: &BrowserConfig) -> Vec<String> {
    let mut args = vec![
        format!("--user-data-dir={}", cfg.profile_dir.display()),
        // Route all of this browser's traffic through Shrike (HTTP + HTTPS via CONNECT).
        format!("--proxy-server=http://{}", cfg.listen),
        // Trust only certificates chaining to Shrike's CA (also bypasses pinning).
        format!("--ignore-certificate-errors-spki-list={}", cfg.spki_b64),
        // Isolate and quiet it down.
        "--no-first-run".into(),
        "--no-default-browser-check".into(),
        "--disable-background-networking".into(),
        "--disable-sync".into(),
        "--disable-component-update".into(),
        "--disable-features=Translate,OptimizationHints".into(),
    ];
    // Chrome's setuid/namespace sandbox cannot nest inside the Flatpak sandbox, so
    // the browser refuses to start there unless we disable it. Only inside Flatpak.
    if in_flatpak() {
        args.push("--no-sandbox".into());
    }
    args.push(cfg.start_url.clone());
    args
}

/// True when running inside a Flatpak sandbox (set by the runtime).
fn in_flatpak() -> bool {
    std::env::var_os("FLATPAK_ID").is_some() || std::path::Path::new("/.flatpak-info").exists()
}

/// Launch the browser (non-blocking). A second launch against the same profile is
/// handled by Chromium's single-instance logic (opens a new window).
pub fn launch(cfg: &BrowserConfig) -> Result<Child> {
    std::fs::create_dir_all(&cfg.profile_dir)
        .with_context(|| format!("creating browser profile {}", cfg.profile_dir.display()))?;
    Command::new(&cfg.chromium_bin)
        .args(build_args(cfg))
        .spawn()
        .with_context(|| format!("launching {}", cfg.chromium_bin.display()))
}

/// Best-effort discovery of a system Chromium-family browser (fallback only).
/// Honours `override_path` first, then well-known absolute locations, then `PATH`.
pub fn find_system_chromium(override_path: Option<&str>) -> Option<PathBuf> {
    if let Some(p) = override_path.filter(|s| !s.is_empty()) {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }

    const ABSOLUTE: &[&str] = &[
        // Linux distro + snap locations (PATH-name search below misses these).
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/brave-browser",
        "/usr/bin/microsoft-edge",
        "/snap/bin/chromium",
        "/snap/bin/google-chrome",
        "/var/lib/flatpak/exports/bin/org.chromium.Chromium",
        // macOS app bundles.
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        // Windows install locations.
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    ];
    for a in ABSOLUTE {
        let pb = PathBuf::from(a);
        if pb.is_file() {
            return Some(pb);
        }
    }

    const NAMES: &[&str] = &[
        "chromium",
        "chromium-browser",
        "google-chrome",
        "google-chrome-stable",
        "brave-browser",
        "microsoft-edge",
        "chrome",
    ];
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for n in NAMES {
            let cand = dir.join(n);
            if cand.is_file() {
                return Some(cand);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> BrowserConfig {
        BrowserConfig {
            chromium_bin: PathBuf::from("/usr/bin/chromium"),
            listen: "127.0.0.1:8080".parse().unwrap(),
            spki_b64: "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKK=".into(),
            profile_dir: PathBuf::from("/tmp/shrike-profile"),
            start_url: "http://shrike/".into(),
        }
    }

    #[test]
    fn args_wire_proxy_ca_and_profile() {
        let a = build_args(&cfg());
        assert!(
            a.iter()
                .any(|s| s == "--proxy-server=http://127.0.0.1:8080")
        );
        assert!(a.iter().any(|s| s == "--ignore-certificate-errors-spki-list=AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKK="));
        assert!(a.iter().any(|s| s.starts_with("--user-data-dir=")));
        assert_eq!(a.last().unwrap(), "http://shrike/");
    }

    #[test]
    fn find_honours_override_path() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("my-chrome");
        std::fs::write(&fake, b"#!/bin/sh\n").unwrap();
        let found = find_system_chromium(Some(fake.to_str().unwrap())).unwrap();
        assert_eq!(found, fake);
        // a non-existent override path is ignored
        assert_ne!(
            find_system_chromium(Some("/no/such/browser")),
            Some(PathBuf::from("/no/such/browser"))
        );
    }
}
