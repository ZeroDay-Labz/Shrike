//! JVM compatibility host integration.
//!
//! Drives the Java side (`jvm-host/`, built to `shrike-host.jar`): launches a JVM
//! that loads a BApp extension against our Montoya API implementation and reports
//! what it did as JSON. This is the bridge that lets Shrike run real Java BApps.
//! Python (Jython) extensions are run through the same host with the Jython jar on
//! the classpath (scaffolded).

mod serve;
pub use serve::{BappBridge, HandlerAction, Phase, ServeHost, Target, process_chain};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::mpsc,
    time::Duration,
};

/// Resolved paths the host needs at runtime (bundled by the GUI, or found in dev).
#[derive(Debug, Clone)]
pub struct JvmRuntime {
    pub java: PathBuf,
    pub host_jar: PathBuf,
    pub montoya_jar: PathBuf,
    pub jython_jar: Option<PathBuf>,
    /// Legacy `burp.*` Extender API jar, needed to load Python (Jython) extensions.
    pub legacy_api_jar: Option<PathBuf>,
}

/// The bundled jar paths the GUI resolves (host + Montoya API + optional Jython).
/// Combined with a discovered `java` to form a [`JvmRuntime`].
#[derive(Debug, Clone)]
pub struct JvmResources {
    /// Bundled JRE launcher, if one was shipped (else a system `java` is used).
    pub java: Option<PathBuf>,
    pub host_jar: PathBuf,
    pub montoya_jar: PathBuf,
    pub jython_jar: Option<PathBuf>,
    pub legacy_api_jar: Option<PathBuf>,
}

/// An extension that has been installed into Shrike's BApp directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledBapp {
    pub sha256: String,
    pub filename: String,
    pub path: String,
    pub format: String,
    pub name: Option<String>,
    pub enabled: bool,
    /// Human-readable status (loaded / needs Jython / unsupported / error).
    pub status: String,
    #[serde(default)]
    pub registered: Vec<String>,
    #[serde(default)]
    pub outputs: Vec<String>,
    #[serde(default)]
    pub errors: Vec<String>,
    /// Catalog entry id this was installed from, if it came from the store.
    /// Lets the store show a reliable Install/Uninstall toggle per card.
    #[serde(default)]
    pub origin: Option<String>,
}

/// Result of a one-click catalog install: either it installed, or the entry has
/// no package Shrike can install yet, in which case the UI points the user at the
/// source instead of showing a dead "Install" button.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InstallOutcome {
    Installed { installed: Vec<InstalledBapp> },
    NotInstallable { reason: String, source_url: String },
}

/// Live state of a BApp whose host process is running, for its console tab.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RunningBapp {
    pub sha256: String,
    pub name: Option<String>,
    #[serde(default)]
    pub registered: Vec<String>,
    /// Titles of suite tabs the extension registered (Swing windows it opened).
    #[serde(default)]
    pub suite_tabs: Vec<String>,
    #[serde(default)]
    pub windows: u32,
    #[serde(default)]
    pub outputs: Vec<String>,
    #[serde(default)]
    pub errors: Vec<String>,
}

/// A single streamed line from a running BApp's host process.
#[derive(Debug, Clone, Serialize)]
pub struct BappOutput {
    pub sha256: String,
    /// "out", "err", or "meta" (the load summary).
    pub stream: String,
    pub line: String,
}

/// Suite-tab titles the host reported (it records them as `suiteTab:<title>`).
pub fn suite_tabs(registered: &[String]) -> Vec<String> {
    registered
        .iter()
        .filter_map(|r| r.strip_prefix("suiteTab:").map(|s| s.to_string()))
        .collect()
}

/// Availability of the JVM runtime, for the Extender's "Java runtime" panel.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JvmStatus {
    pub available: bool,
    pub java: Option<String>,
    pub version: Option<String>,
    pub host_jar: bool,
    pub jython: bool,
}

/// What the host reported after loading an extension.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExtensionLoad {
    pub ok: bool,
    pub name: Option<String>,
    #[serde(default)]
    pub registered: Vec<String>,
    #[serde(default)]
    pub outputs: Vec<String>,
    #[serde(default)]
    pub errors: Vec<String>,
    #[serde(default, rename = "uiWindows")]
    pub ui_windows: u32,
    #[serde(default)]
    pub error: Option<String>,
}

/// Find a `java` launcher: an explicit override, then `$JAVA_HOME/bin/java`, then `PATH`.
pub fn find_java(override_path: Option<&str>) -> Option<PathBuf> {
    if let Some(p) = override_path.filter(|s| !s.is_empty()) {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    let exe = if cfg!(windows) { "java.exe" } else { "java" };
    if let Some(home) = std::env::var_os("JAVA_HOME") {
        let pb = PathBuf::from(home).join("bin").join(exe);
        if pb.is_file() {
            return Some(pb);
        }
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(exe))
        .find(|p| p.is_file())
}

/// `java -version` string (from stderr), e.g. "25.0.4.1".
pub fn java_version(java: &Path) -> Option<String> {
    let out = Command::new(java).arg("-version").output().ok()?;
    let text = String::from_utf8_lossy(&out.stderr);
    let first = text.lines().next()?;
    let start = first.find('"')? + 1;
    let end = first[start..].find('"')? + start;
    Some(first[start..end].to_string())
}

/// JPMS reflection openings legacy extensions need on a modern JDK (16+, hard
/// on 25). Many BApps bundle Gson/Swing code that reflects into `java.desktop`
/// and `java.base` internals (e.g. `java.awt.Color#value`); without these opens
/// the JDK denies the access and the extension fails after loading. Mirrors the
/// launcher flags such extensions were written to run under.
const JVM_ADD_OPENS: &[&str] = &[
    "--add-opens=java.base/java.lang=ALL-UNNAMED",
    "--add-opens=java.base/java.lang.reflect=ALL-UNNAMED",
    "--add-opens=java.base/java.util=ALL-UNNAMED",
    "--add-opens=java.base/java.text=ALL-UNNAMED",
    "--add-opens=java.base/java.io=ALL-UNNAMED",
    "--add-opens=java.base/java.net=ALL-UNNAMED",
    "--add-opens=java.base/java.nio=ALL-UNNAMED",
    "--add-opens=java.base/sun.nio.ch=ALL-UNNAMED",
    "--add-opens=java.desktop/java.awt=ALL-UNNAMED",
    "--add-opens=java.desktop/java.awt.event=ALL-UNNAMED",
    "--add-opens=java.desktop/java.awt.color=ALL-UNNAMED",
    "--add-opens=java.desktop/java.awt.font=ALL-UNNAMED",
    "--add-opens=java.desktop/java.awt.geom=ALL-UNNAMED",
    "--add-opens=java.desktop/javax.swing=ALL-UNNAMED",
    "--add-opens=java.desktop/javax.swing.table=ALL-UNNAMED",
    "--add-opens=java.desktop/javax.swing.text=ALL-UNNAMED",
    "--add-opens=java.desktop/javax.swing.plaf.basic=ALL-UNNAMED",
    "--add-opens=java.desktop/sun.awt=ALL-UNNAMED",
    "--add-opens=java.desktop/sun.swing=ALL-UNNAMED",
    "--add-opens=java.desktop/sun.font=ALL-UNNAMED",
    "--add-opens=java.xml/com.sun.org.apache.xerces.internal.jaxp=ALL-UNNAMED",
];

fn classpath(rt: &JvmRuntime) -> String {
    let sep = if cfg!(windows) { ';' } else { ':' };
    let mut parts = vec![rt.host_jar.clone(), rt.montoya_jar.clone()];
    if let Some(j) = &rt.jython_jar {
        parts.push(j.clone());
    }
    if let Some(j) = &rt.legacy_api_jar {
        parts.push(j.clone());
    }
    parts
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(&sep.to_string())
}

/// Spawn the host for an extension without waiting, for "run" mode where a UI
/// extension keeps its Swing window open. Returns the running process.
pub fn spawn(rt: &JvmRuntime, ext: &Path, mode: &str) -> Result<std::process::Child> {
    Command::new(&rt.java)
        .args(JVM_ADD_OPENS)
        .arg("-cp")
        .arg(classpath(rt))
        .arg("shrike.host.Host")
        .arg(ext)
        .arg(mode)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("launching java host for {}", ext.display()))
}

/// Spawn the host in "run" mode with stdout captured, forwarding each line to
/// `on_line` from a reader thread (which ends when the process exits). Used by
/// the engine to stream a running extension's load summary and live log output
/// into its console tab. Returns the running process.
pub fn spawn_streaming(
    rt: &JvmRuntime,
    ext: &Path,
    on_line: impl Fn(String) + Send + 'static,
) -> Result<std::process::Child> {
    let mut child = Command::new(&rt.java)
        .args(JVM_ADD_OPENS)
        .arg("-cp")
        .arg(classpath(rt))
        .arg("shrike.host.Host")
        .arg(ext)
        .arg("run")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("launching java host for {}", ext.display()))?;

    if let Some(stdout) = child.stdout.take() {
        std::thread::spawn(move || {
            use std::io::BufRead;
            let reader = std::io::BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                on_line(line);
            }
        });
    }
    Ok(child)
}

/// Load an extension through the host. `mode` is "probe" (load, report, exit) or
/// "run" (keep any UI window alive). Bounded by `timeout`.
pub fn run_extension(
    rt: &JvmRuntime,
    ext: &Path,
    mode: &str,
    timeout: Duration,
) -> Result<ExtensionLoad> {
    let mut child = Command::new(&rt.java)
        .args(JVM_ADD_OPENS)
        .arg("-cp")
        .arg(classpath(rt))
        .arg("shrike.host.Host")
        .arg(ext)
        .arg(mode)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .with_context(|| format!("launching java host for {}", ext.display()))?;

    let mut stdout = child.stdout.take().context("capturing host stdout")?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = String::new();
        let _ = stdout.read_to_string(&mut buf);
        let _ = tx.send(buf);
    });

    let buf = match rx.recv_timeout(timeout) {
        Ok(b) => b,
        Err(_) => {
            let _ = child.kill();
            return Err(anyhow!(
                "extension load timed out after {}s",
                timeout.as_secs()
            ));
        }
    };
    let _ = child.wait();

    // The host prints one JSON object as its last non-empty line.
    let line = buf
        .lines()
        .rev()
        .find(|l| l.trim_start().starts_with('{'))
        .ok_or_else(|| anyhow!("host produced no result (output: {})", buf.trim()))?;
    serde_json::from_str::<ExtensionLoad>(line).context("parsing host result")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_java_honours_override() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("java");
        std::fs::write(&fake, b"#!/bin/sh\n").unwrap();
        assert_eq!(find_java(Some(fake.to_str().unwrap())), Some(fake));
        assert_eq!(find_java(Some("/no/such/java")), find_java(None)); // bad override ignored
    }

    #[test]
    fn parses_host_result_json() {
        let json = r#"{"ok":true,"name":"X","registered":["registerHttpHandler"],"outputs":["hi"],"errors":[],"uiWindows":1}"#;
        let r: ExtensionLoad = serde_json::from_str(json).unwrap();
        assert!(r.ok);
        assert_eq!(r.name.as_deref(), Some("X"));
        assert_eq!(r.registered, vec!["registerHttpHandler"]);
        assert_eq!(r.ui_windows, 1);
    }
}
