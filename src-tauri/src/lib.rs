//! Shrike desktop GUI backend.
//!
//! Thin Tauri layer over [`shrike_engine::Engine`]: commands the webview calls,
//! and a [`TauriSink`] that forwards live traffic from the engine's event bus to
//! the frontend as Tauri events. All real work lives in the engine crate.

use serde::{Deserialize, Serialize};
use shrike_engine::{
    Engine,
    config::{ProxyConfig, UpstreamTlsMode},
    core::{TrafficEvent, TrafficSink, TransactionSummary, TransactionView, WsDirection},
    intercept::{Decision, parse_request_head},
    intruder::{AttackEvent, IntruderConfig, PreviewResult},
    jvm::{InstalledBapp, JvmResources, JvmStatus},
    match_replace::MatchReplaceRule,
    plugins::PluginManifest,
    scope::ScopeRule,
    sender::{RequestSpec, SendResult},
    store::{HistoryFilter, ProjectMeta, SiteNode, TrafficStats},
    tools::comparer::{DiffMode, Seg},
    tools::decoder::{DecodeOp, StepResult},
    tools::sequencer::SequencerReport,
};
use std::sync::Arc;
use tauri::{AppHandle, Emitter, Manager, State};
use tracing::warn;

struct AppState {
    engine: Arc<Engine>,
}

/// A [`TrafficSink`] that re-emits bus events to the webview.
struct TauriSink {
    app: AppHandle,
}

#[derive(Clone, Serialize)]
struct WsView {
    url: String,
    direction: &'static str,
    kind: String,
    len: usize,
    text: Option<String>,
    client_addr: String,
}

#[derive(Clone, Serialize)]
struct TunnelView {
    host: String,
    client_addr: String,
}

#[derive(Clone, Serialize)]
struct InterceptView {
    id: u64,
    raw: String,
    host: String,
    port: u16,
    secure: bool,
}

impl TrafficSink for TauriSink {
    fn handle(&mut self, event: &TrafficEvent) {
        let result = match event {
            TrafficEvent::Completed(tx) => self
                .app
                .emit("traffic-completed", TransactionSummary::from(tx.as_ref())),
            TrafficEvent::WebSocketMessage(ws) => {
                let view = WsView {
                    url: ws.url.clone(),
                    direction: match ws.direction {
                        WsDirection::ClientToServer => "c2s",
                        WsDirection::ServerToClient => "s2c",
                    },
                    kind: ws.kind.to_string(),
                    len: ws.len,
                    text: ws.text.clone(),
                    client_addr: ws.client_addr.to_string(),
                };
                self.app.emit("traffic-ws", view)
            }
            TrafficEvent::TunnelPassthrough { host, client_addr } => self.app.emit(
                "traffic-tunnel",
                TunnelView {
                    host: host.clone(),
                    client_addr: client_addr.to_string(),
                },
            ),
            TrafficEvent::Intercepted { id, service, raw } => self.app.emit(
                "intercept-request",
                InterceptView {
                    id: *id,
                    raw: raw.clone(),
                    host: service.host.clone(),
                    port: service.port,
                    secure: service.secure,
                },
            ),
            TrafficEvent::RequestStarted(_) => Ok(()),
        };
        if let Err(e) = result {
            warn!(error = %e, "failed to emit traffic event to the webview");
        }
    }
}

// ---- command payload / view types ----

#[derive(Serialize)]
struct ProxyStatus {
    running: bool,
    listen: String,
}

#[derive(Serialize, Deserialize)]
struct ConfigView {
    listen: String,
    insecure_upstream: bool,
    passthrough_hosts: Vec<String>,
    max_capture_bytes: usize,
    data_dir: String,
    drop_out_of_scope: bool,
    #[serde(default)]
    chromium_path: String,
    #[serde(default)]
    github_token: String,
    #[serde(default = "default_true")]
    intruder_require_scope: bool,
    #[serde(default = "default_timeout_ms")]
    request_timeout_ms: u64,
    #[serde(default)]
    history_max_rows: usize,
}

fn default_true() -> bool {
    true
}
fn default_timeout_ms() -> u64 {
    30_000
}

impl ConfigView {
    fn from_config(c: &ProxyConfig) -> Self {
        Self {
            listen: c.listen.to_string(),
            insecure_upstream: c.upstream_tls == UpstreamTlsMode::AcceptInvalid,
            passthrough_hosts: c.passthrough_hosts.clone(),
            max_capture_bytes: c.max_capture_bytes,
            data_dir: c.data_dir.display().to_string(),
            drop_out_of_scope: c.drop_out_of_scope,
            chromium_path: c.chromium_path.clone().unwrap_or_default(),
            github_token: c.github_token.clone(),
            intruder_require_scope: c.intruder_require_scope,
            request_timeout_ms: c.request_timeout_ms,
            history_max_rows: c.history_max_rows,
        }
    }
    fn apply_to(&self, base: &ProxyConfig) -> Result<ProxyConfig, String> {
        let listen = self
            .listen
            .parse()
            .map_err(|e| format!("invalid listen address: {e}"))?;
        Ok(ProxyConfig {
            listen,
            data_dir: base.data_dir.clone(),
            upstream_tls: if self.insecure_upstream {
                UpstreamTlsMode::AcceptInvalid
            } else {
                UpstreamTlsMode::Verify
            },
            max_capture_bytes: self.max_capture_bytes,
            passthrough_hosts: self.passthrough_hosts.clone(),
            drop_out_of_scope: self.drop_out_of_scope,
            chromium_path: {
                let p = self.chromium_path.trim();
                if p.is_empty() {
                    None
                } else {
                    Some(p.to_string())
                }
            },
            github_token: self.github_token.trim().to_string(),
            intruder_require_scope: self.intruder_require_scope,
            request_timeout_ms: self.request_timeout_ms.clamp(1_000, 600_000),
            history_max_rows: self.history_max_rows,
        })
    }
}

#[derive(Serialize)]
struct CaInfo {
    cert_path: String,
    fingerprint: String,
}

type CmdResult<T> = Result<T, String>;

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

// ---- commands ----

#[tauri::command]
fn proxy_status(state: State<AppState>) -> ProxyStatus {
    match state.engine.local_addr() {
        Some(addr) => ProxyStatus {
            running: true,
            listen: addr.to_string(),
        },
        None => ProxyStatus {
            running: false,
            listen: state.engine.config().listen.to_string(),
        },
    }
}

#[tauri::command]
fn proxy_start(state: State<AppState>) -> CmdResult<ProxyStatus> {
    let addr = state.engine.start_proxy().map_err(err)?;
    Ok(ProxyStatus {
        running: true,
        listen: addr.to_string(),
    })
}

#[tauri::command]
fn proxy_stop(state: State<AppState>) -> CmdResult<ProxyStatus> {
    state.engine.stop_proxy().map_err(err)?;
    Ok(ProxyStatus {
        running: false,
        listen: state.engine.config().listen.to_string(),
    })
}

#[tauri::command]
fn config_get(state: State<AppState>) -> ConfigView {
    ConfigView::from_config(&state.engine.config())
}

#[tauri::command]
fn config_set(state: State<AppState>, config: ConfigView) -> CmdResult<ConfigView> {
    let base = state.engine.config();
    let next = config.apply_to(&base)?;
    state.engine.set_config(next).map_err(err)?;
    Ok(ConfigView::from_config(&state.engine.config()))
}

#[tauri::command]
fn history_page(
    state: State<AppState>,
    filter: HistoryFilter,
    limit: u32,
    offset: u32,
) -> CmdResult<Vec<TransactionSummary>> {
    state
        .engine
        .history_page(&filter, limit, offset)
        .map_err(err)
}

#[tauri::command]
fn history_count(state: State<AppState>, filter: HistoryFilter) -> CmdResult<u64> {
    state.engine.history_count(&filter).map_err(err)
}

#[tauri::command]
fn history_get(state: State<AppState>, id: u64) -> CmdResult<Option<TransactionView>> {
    state.engine.history_get(id).map_err(err)
}

#[tauri::command]
fn history_clear(state: State<AppState>) -> CmdResult<()> {
    state.engine.clear_history().map_err(err)
}

#[tauri::command]
fn site_map(state: State<AppState>) -> CmdResult<Vec<SiteNode>> {
    state.engine.site_map().map_err(err)
}

#[tauri::command]
fn traffic_stats(state: State<AppState>) -> CmdResult<TrafficStats> {
    state.engine.traffic_stats().map_err(err)
}

// ---- project lifecycle ----

#[tauri::command]
fn project_info(state: State<AppState>) -> CmdResult<ProjectMeta> {
    state.engine.project_info().map_err(err)
}

#[tauri::command]
fn project_set_name(state: State<AppState>, name: String) -> CmdResult<ProjectMeta> {
    state.engine.set_project_name(&name).map_err(err)?;
    state.engine.project_info().map_err(err)
}

/// Save a consistent copy of the project to `path` (save-a-copy / backup).
#[tauri::command]
fn project_backup(state: State<AppState>, path: String) -> CmdResult<String> {
    state.engine.backup_project(&path).map_err(err)?;
    Ok(path)
}

#[tauri::command]
fn project_integrity(state: State<AppState>) -> CmdResult<bool> {
    state.engine.project_integrity().map_err(err)
}

/// Tool the UI should open on launch, from `SHRIKE_START_TOOL` (automation /
/// screenshots); `None` for the normal default.
#[tauri::command]
fn startup_tool() -> Option<String> {
    std::env::var("SHRIKE_START_TOOL")
        .ok()
        .filter(|s| !s.trim().is_empty())
}

/// Import traffic from an XML item export at `path`; returns the count added.
#[tauri::command]
async fn import_traffic(state: State<'_, AppState>, path: String) -> CmdResult<usize> {
    let engine = state.engine.clone();
    tauri::async_runtime::spawn_blocking(move || engine.import_traffic(&path))
        .await
        .map_err(err)?
        .map_err(err)
}

#[tauri::command]
fn ui_state_get(state: State<AppState>, key: String) -> CmdResult<Option<String>> {
    state.engine.ui_state_get(&key).map_err(err)
}

#[tauri::command]
fn ui_state_set(state: State<AppState>, key: String, value: String) -> CmdResult<()> {
    state.engine.ui_state_set(&key, &value).map_err(err)
}

#[tauri::command]
fn ca_info(state: State<AppState>) -> CaInfo {
    let ca = state.engine.ca();
    CaInfo {
        cert_path: ca.cert_path().display().to_string(),
        fingerprint: ca.fingerprint_sha256(),
    }
}

/// Export the CA certificate (PEM) to `path`, returning the path written.
#[tauri::command]
fn ca_export(state: State<AppState>, path: String) -> CmdResult<String> {
    let p = std::path::PathBuf::from(&path);
    state.engine.ca().export_cert(&p).map_err(err)?;
    Ok(p.display().to_string())
}

// ---- target scope ----

#[tauri::command]
fn scope_get(state: State<AppState>) -> Vec<ScopeRule> {
    state.engine.scope_rules()
}

/// Validate + persist a new rule set; returns the rules now in force.
#[tauri::command]
fn scope_set(state: State<AppState>, rules: Vec<ScopeRule>) -> CmdResult<Vec<ScopeRule>> {
    state.engine.set_scope(rules).map_err(err)?;
    Ok(state.engine.scope_rules())
}

#[tauri::command]
fn scope_check(state: State<AppState>, url: String) -> bool {
    state.engine.in_scope_url(&url)
}

// ---- match & replace ----

#[tauri::command]
fn match_replace_get(state: State<AppState>) -> Vec<MatchReplaceRule> {
    state.engine.match_replace_rules()
}

#[tauri::command]
fn match_replace_set(
    state: State<AppState>,
    rules: Vec<MatchReplaceRule>,
) -> CmdResult<Vec<MatchReplaceRule>> {
    state.engine.set_match_replace(rules).map_err(err)?;
    Ok(state.engine.match_replace_rules())
}

// ---- intercept ----

#[tauri::command]
fn intercept_get_enabled(state: State<AppState>) -> bool {
    state.engine.intercept_enabled()
}

#[tauri::command]
fn intercept_set_enabled(state: State<AppState>, on: bool) {
    state.engine.set_intercept(on);
}

/// Resolve a paused request. `action` is "forward" or "drop"; on "forward" an
/// edited `raw` request (if given) is parsed and re-sent, else it goes unchanged.
#[tauri::command]
fn intercept_resolve(
    state: State<AppState>,
    id: u64,
    action: String,
    raw: Option<String>,
) -> CmdResult<()> {
    let decision = match action.as_str() {
        "drop" => Decision::Drop,
        "forward" => match raw {
            Some(text) => Decision::Forward(Some(parse_request_head(&text).map_err(err)?)),
            None => Decision::Forward(None),
        },
        other => return Err(format!("unknown intercept action: {other:?}")),
    };
    state.engine.intercept_resolve(id, decision);
    Ok(())
}

// ---- repeater ----

#[tauri::command]
fn repeater_send(state: State<AppState>, spec: RequestSpec) -> CmdResult<SendResult> {
    state.engine.repeater_send(spec).map_err(err)
}

// ---- intruder ----

#[tauri::command]
fn intruder_start(
    state: State<AppState>,
    app: AppHandle,
    config: IntruderConfig,
) -> CmdResult<u64> {
    let app2 = app.clone();
    let engine2 = std::sync::Arc::clone(&state.engine);
    let sink: std::sync::Arc<dyn Fn(AttackEvent) + Send + Sync> = std::sync::Arc::new(move |ev| {
        if let AttackEvent::Done { attack_id, .. } = &ev {
            engine2.intruder_finished(*attack_id);
        }
        let _ = app2.emit("intruder-event", ev);
    });
    state.engine.intruder_start(config, sink).map_err(err)
}

#[tauri::command]
fn intruder_stop(state: State<AppState>, id: u64) {
    state.engine.intruder_stop(id);
}

#[tauri::command]
fn intruder_preview(config: IntruderConfig) -> PreviewResult {
    shrike_engine::intruder::preview(&config, 8)
}

#[tauri::command]
fn intruder_generate(generator: shrike_engine::intruder::generators::Generator) -> Vec<String> {
    shrike_engine::intruder::generators::generate(&generator)
}

// ---- decoder ----

#[tauri::command]
fn decode_chain(input: String, ops: Vec<DecodeOp>) -> Vec<StepResult> {
    shrike_engine::tools::decoder::apply_chain(&input, &ops)
}

// ---- comparer ----

#[tauri::command]
fn compare(a: String, b: String, mode: DiffMode) -> Vec<Seg> {
    shrike_engine::tools::comparer::compare(&a, &b, mode)
}

// ---- sequencer ----

#[tauri::command]
fn sequencer_analyze(tokens: Vec<String>) -> SequencerReport {
    shrike_engine::tools::sequencer::analyze(&tokens)
}

// ---- extender (plugins) ----

#[tauri::command]
fn plugins_list(state: State<AppState>) -> Vec<PluginManifest> {
    state.engine.plugins()
}

#[tauri::command]
fn plugin_add(state: State<AppState>, manifest: PluginManifest) -> CmdResult<Vec<PluginManifest>> {
    state.engine.add_plugin(manifest).map_err(err)
}

#[tauri::command]
fn plugin_remove(state: State<AppState>, id: String) -> CmdResult<Vec<PluginManifest>> {
    state.engine.remove_plugin(&id).map_err(err)
}

#[tauri::command]
fn plugin_set_enabled(
    state: State<AppState>,
    id: String,
    on: bool,
) -> CmdResult<Vec<PluginManifest>> {
    state.engine.set_plugin_enabled(&id, on).map_err(err)
}

// ---- BApp Store ----

#[tauri::command]
fn bapp_catalog(state: State<AppState>) -> Vec<shrike_engine::bapp::BappEntry> {
    state.engine.bapp_catalog()
}

// Catalog fetch, installs and JVM setup do blocking network / subprocess work;
// run them off the UI thread via spawn_blocking so the webview never freezes.
#[tauri::command]
async fn bapp_catalog_full(
    state: State<'_, AppState>,
    refresh: bool,
) -> CmdResult<Vec<shrike_engine::bapp::BappEntry>> {
    let engine = state.engine.clone();
    tauri::async_runtime::spawn_blocking(move || engine.bapp_catalog_full(refresh))
        .await
        .map_err(err)
}

#[tauri::command]
fn bapp_imports(state: State<AppState>) -> CmdResult<Vec<shrike_engine::bapp::PackageInspection>> {
    state.engine.bapp_imports().map_err(err)
}

#[tauri::command]
fn bapp_import(
    state: State<AppState>,
    path: String,
) -> CmdResult<Vec<shrike_engine::bapp::PackageInspection>> {
    state.engine.bapp_import(&path).map_err(err)
}

#[tauri::command]
fn bapp_remove(
    state: State<AppState>,
    sha256: String,
) -> CmdResult<Vec<shrike_engine::bapp::PackageInspection>> {
    state.engine.bapp_remove(&sha256).map_err(err)
}

// ---- JVM / BApp host ----

/// Find a jar in `dir` whose filename starts with `prefix`.
fn jar_in(dir: &std::path::Path, prefix: &str) -> Option<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.extension().is_some_and(|x| x == "jar")
                && p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with(prefix))
        })
}

/// Resolve the JVM host jars: from bundled app resources (`resources/jvm/`), else
/// the dev build dir (`<cwd>/jvm-host/{build,lib}`) when running `tauri dev`.
fn resolve_jvm_resources(app: &AppHandle) -> Option<JvmResources> {
    let from = |host: std::path::PathBuf, libdir: &std::path::Path| -> Option<JvmResources> {
        if !host.is_file() {
            return None;
        }
        // A bundled JRE (jlink output) sits next to the jars under runtime/bin/.
        let java_exe = if cfg!(windows) { "java.exe" } else { "java" };
        let java = libdir.join("runtime").join("bin").join(java_exe);
        Some(JvmResources {
            java: java.is_file().then_some(java),
            host_jar: host,
            montoya_jar: jar_in(libdir, "montoya-api")?,
            jython_jar: jar_in(libdir, "jython"),
            legacy_api_jar: jar_in(libdir, "burp-extender-api"),
        })
    };
    // 1. Packaged: resources/jvm next to the app.
    if let Ok(res) = app.path().resource_dir() {
        let jvm = res.join("jvm");
        if let Some(r) = from(jvm.join("shrike-host.jar"), &jvm) {
            return Some(r);
        }
    }
    // 2. Dev: the cwd and the executable's path land somewhere under the repo, so
    //    search every ancestor of both for the committed/dev jars (tauri dev runs
    //    the binary from an unpredictable cwd, so one fixed relative path is not enough).
    let mut bases: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        bases.extend(cwd.ancestors().map(|p| p.to_path_buf()));
    }
    if let Ok(exe) = std::env::current_exe() {
        bases.extend(exe.ancestors().map(|p| p.to_path_buf()));
    }
    for base in bases {
        let res = base.join("src-tauri/resources/jvm");
        if let Some(r) = from(res.join("shrike-host.jar"), &res) {
            return Some(r);
        }
        let dev = base.join("jvm-host");
        if let Some(r) = from(dev.join("build/shrike-host.jar"), &dev.join("lib")) {
            return Some(r);
        }
    }
    None
}

#[tauri::command]
fn jvm_status(state: State<AppState>) -> JvmStatus {
    state.engine.jvm_status()
}

#[tauri::command]
async fn jvm_setup(state: State<'_, AppState>) -> CmdResult<JvmStatus> {
    let engine = state.engine.clone();
    tauri::async_runtime::spawn_blocking(move || engine.jvm_setup())
        .await
        .map_err(err)?
        .map_err(err)
}

#[tauri::command]
async fn jython_setup(state: State<'_, AppState>) -> CmdResult<JvmStatus> {
    let engine = state.engine.clone();
    tauri::async_runtime::spawn_blocking(move || engine.jython_setup())
        .await
        .map_err(err)?
        .map_err(err)
}

#[tauri::command]
async fn bapp_install(state: State<'_, AppState>, path: String) -> CmdResult<Vec<InstalledBapp>> {
    let engine = state.engine.clone();
    tauri::async_runtime::spawn_blocking(move || engine.bapp_install(&path))
        .await
        .map_err(err)?
        .map_err(err)
}

#[tauri::command]
async fn bapp_install_url(
    state: State<'_, AppState>,
    url: String,
) -> CmdResult<Vec<InstalledBapp>> {
    let engine = state.engine.clone();
    tauri::async_runtime::spawn_blocking(move || engine.bapp_install_url(&url))
        .await
        .map_err(err)?
        .map_err(err)
}

#[tauri::command]
async fn bapp_install_entry(
    state: State<'_, AppState>,
    id: String,
) -> CmdResult<shrike_engine::jvm::InstallOutcome> {
    let engine = state.engine.clone();
    tauri::async_runtime::spawn_blocking(move || engine.bapp_install_entry(&id))
        .await
        .map_err(err)?
        .map_err(err)
}

#[tauri::command]
fn bapp_installed(state: State<AppState>) -> CmdResult<Vec<InstalledBapp>> {
    state.engine.bapp_installed().map_err(err)
}

#[tauri::command]
fn bapp_uninstall(state: State<AppState>, sha256: String) -> CmdResult<Vec<InstalledBapp>> {
    state.engine.bapp_uninstall(&sha256).map_err(err)
}

#[tauri::command]
async fn bapp_run(
    state: State<'_, AppState>,
    app: AppHandle,
    sha256: String,
) -> CmdResult<Vec<String>> {
    let app2 = app.clone();
    let sink: std::sync::Arc<dyn Fn(shrike_engine::jvm::BappOutput) + Send + Sync> =
        std::sync::Arc::new(move |ev| {
            let _ = app2.emit("bapp-output", ev);
        });
    let engine = state.engine.clone();
    tauri::async_runtime::spawn_blocking(move || {
        engine
            .bapp_run(&sha256, sink)
            .map(|_| engine.bapp_running())
    })
    .await
    .map_err(err)?
    .map_err(err)
}

#[tauri::command]
fn bapp_stop(state: State<AppState>, sha256: String) -> CmdResult<Vec<String>> {
    state.engine.bapp_stop(&sha256).map_err(err)?;
    Ok(state.engine.bapp_running())
}

#[tauri::command]
fn bapp_running(state: State<AppState>) -> Vec<String> {
    state.engine.bapp_running()
}

#[tauri::command]
fn bapp_running_meta(state: State<AppState>) -> Vec<shrike_engine::jvm::RunningBapp> {
    state.engine.bapp_running_meta()
}

// ---- native JWT tool ----

#[tauri::command]
fn jwt_decode(token: String) -> CmdResult<shrike_engine::tools::jwt::JwtParts> {
    shrike_engine::tools::jwt::decode(&token).map_err(err)
}

#[tauri::command]
fn jwt_sign(header: String, payload: String, alg: String, secret: String) -> CmdResult<String> {
    shrike_engine::tools::jwt::sign(&header, &payload, &alg, &secret).map_err(err)
}

#[tauri::command]
fn jwt_verify(token: String, secret: String) -> CmdResult<bool> {
    shrike_engine::tools::jwt::verify(&token, &secret).map_err(err)
}

// ---- integrated browser ----

/// Resolve the bundled Chrome-for-Testing binary from the app's resources, if present.
fn resolve_bundled_chromium(app: &AppHandle) -> Option<std::path::PathBuf> {
    let base = app.path().resource_dir().ok()?.join("chromium");
    let candidates: &[&str] = if cfg!(target_os = "windows") {
        &["chrome.exe", "chrome-win64\\chrome.exe"]
    } else if cfg!(target_os = "macos") {
        &[
            "Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
            "chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
            "chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
        ]
    } else {
        &["chrome", "chrome-linux64/chrome"]
    };
    candidates
        .iter()
        .map(|c| base.join(c))
        .find(|p| p.is_file())
}

#[tauri::command]
fn launch_browser(
    state: State<AppState>,
    app: AppHandle,
) -> CmdResult<shrike_engine::browser::BrowserStatus> {
    state
        .engine
        .launch_browser(resolve_bundled_chromium(&app))
        .map_err(err)
}

#[tauri::command]
fn browser_available(state: State<AppState>, app: AppHandle) -> bool {
    state
        .engine
        .browser_available(resolve_bundled_chromium(&app))
}

/// Validate a URL we're about to hand to the OS opener: http(s) only, a real
/// host, and no whitespace / control / quote characters. (Query metacharacters
/// like `&` are allowed — safe because we never route the URL through a shell.)
fn validate_external_url(url: &str) -> Result<(), String> {
    let lower = url.to_ascii_lowercase();
    let rest = lower
        .strip_prefix("http://")
        .or_else(|| lower.strip_prefix("https://"))
        .ok_or("only http(s) URLs can be opened")?;
    if rest.is_empty() || rest.starts_with('/') {
        return Err("URL has no host".into());
    }
    if url
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '`'))
    {
        return Err("URL contains invalid characters".into());
    }
    Ok(())
}

/// Open an external http(s) URL in the user's default browser (official listings/repos).
/// Never routed through a shell, so URL metacharacters can't become commands.
#[tauri::command]
fn open_external(url: String) -> CmdResult<()> {
    validate_external_url(&url)?;
    #[cfg(target_os = "linux")]
    let spawned = std::process::Command::new("xdg-open").arg(&url).spawn();
    #[cfg(target_os = "macos")]
    let spawned = std::process::Command::new("open").arg(&url).spawn();
    // No cmd.exe: rundll32 hands the URL straight to the protocol handler as a
    // single argument, so `&`/`|`/`^` are data, not shell operators.
    #[cfg(target_os = "windows")]
    let spawned = std::process::Command::new("rundll32.exe")
        .args(["url.dll,FileProtocolHandler", &url])
        .spawn();
    spawned.map(|_| ()).map_err(err)
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("shrike_gui_lib=info,shrike_engine=info,hudsucker=warn")
    });
    // Same friendly TLS layer as the CLI: swallows benign client-abort noise
    // ("handshake eof", resets) and turns UnknownCA into a "trust the CA" hint.
    let ca_cert = resolve_data_dir()
        .join("ca")
        .join(shrike_engine::ca::CA_CERT_FILE);
    tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_target(false))
        .with(shrike_engine::diagnostics::FriendlyTlsErrors::new(&ca_cert))
        .try_init()
        .ok();
}

/// Build the data directory, respecting `SHRIKE_DATA_DIR` if set.
fn resolve_data_dir() -> std::path::PathBuf {
    std::env::var_os("SHRIKE_DATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(ProxyConfig::default_data_dir)
}

pub fn run() {
    // WebKitGTK's DMABUF renderer crashes the webview on a number of Linux
    // GPU/driver combinations (blank window, or a mid-session crash that takes
    // the whole app down with no Rust panic). Disabling it is the documented
    // workaround. We set it here — before the webview is created and before any
    // threads spawn — unless the user has already chosen a value.
    #[cfg(target_os = "linux")]
    {
        // SAFETY: called at the very start of the program, before any other
        // threads are spawned, so there is no concurrent env access. Each is only
        // set when the user has not chosen a value, so it stays overridable.
        if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
            unsafe { std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1") };
        }
        // Accelerated compositing on WebKitGTK aborts the whole app on some Mesa
        // GPU/driver combos (SIGABRT on the GTK main thread, no Rust panic),
        // especially under heavy DOM updates. Disabling it trades a little
        // scrolling smoothness for stability.
        if std::env::var_os("WEBKIT_DISABLE_COMPOSITING_MODE").is_none() {
            unsafe { std::env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1") };
        }
    }

    init_tracing();

    let config = ProxyConfig {
        data_dir: resolve_data_dir(),
        ..ProxyConfig::default()
    };
    let engine = match Engine::new(config) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("shrike: failed to start engine: {e:#}");
            std::process::exit(1);
        }
    };

    let engine_for_setup = Arc::clone(&engine);
    tauri::Builder::default()
        .manage(AppState {
            engine: Arc::clone(&engine),
        })
        .setup(move |app| {
            // Register the live-traffic bridge now that we have an AppHandle.
            let handle = app.handle().clone();
            engine_for_setup.add_sink_factory(Box::new(move || {
                Box::new(TauriSink {
                    app: handle.clone(),
                })
            }));
            // Resolve the bundled JVM host jars so Java BApps can be run.
            engine_for_setup.set_jvm_resources(resolve_jvm_resources(app.handle()));
            // Automation/screenshots: with SHRIKE_START_TOOL set, bring the proxy up
            // immediately so captured traffic is there without clicking Start.
            if std::env::var_os("SHRIKE_START_TOOL").is_some()
                && let Err(e) = engine_for_setup.start_proxy()
            {
                warn!(error = %e, "demo proxy auto-start failed");
            }
            // Window icon: shows in the X11 title bar / taskbar and on Windows.
            // On Wayland the dock icon comes from the installed .desktop entry
            // (packaged builds), so a dev run may still show a generic icon there.
            if let Some(win) = app.get_webview_window("main") {
                match tauri::image::Image::from_bytes(include_bytes!("../icons/128x128.png")) {
                    Ok(icon) => {
                        if let Err(e) = win.set_icon(icon) {
                            warn!(error = %e, "could not set window icon");
                        }
                    }
                    Err(e) => warn!(error = %e, "could not decode window icon"),
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            proxy_status,
            proxy_start,
            proxy_stop,
            config_get,
            config_set,
            history_page,
            history_count,
            history_get,
            history_clear,
            site_map,
            project_info,
            project_set_name,
            project_backup,
            project_integrity,
            import_traffic,
            startup_tool,
            ui_state_get,
            ui_state_set,
            ca_info,
            ca_export,
            scope_get,
            scope_set,
            scope_check,
            match_replace_get,
            match_replace_set,
            intercept_get_enabled,
            intercept_set_enabled,
            intercept_resolve,
            repeater_send,
            intruder_start,
            intruder_stop,
            intruder_preview,
            intruder_generate,
            decode_chain,
            compare,
            traffic_stats,
            sequencer_analyze,
            plugins_list,
            plugin_add,
            plugin_remove,
            plugin_set_enabled,
            bapp_catalog,
            bapp_catalog_full,
            bapp_imports,
            bapp_import,
            bapp_remove,
            launch_browser,
            browser_available,
            open_external,
            jvm_status,
            jvm_setup,
            jython_setup,
            bapp_install,
            bapp_install_url,
            bapp_install_entry,
            bapp_installed,
            bapp_uninstall,
            bapp_run,
            bapp_stop,
            bapp_running,
            bapp_running_meta,
            jwt_decode,
            jwt_sign,
            jwt_verify,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Shrike");
}

#[cfg(test)]
mod url_tests {
    use super::validate_external_url;
    #[test]
    fn external_url_validation() {
        assert!(validate_external_url("https://github.com/PortSwigger/logger").is_ok());
        assert!(validate_external_url("https://x.io/a?b=1&c=2").is_ok()); // query & is fine
        assert!(validate_external_url("ftp://x").is_err());
        assert!(validate_external_url("https://").is_err());
        assert!(validate_external_url("https:///nohost").is_err());
        assert!(validate_external_url("https://x.io/a&calc.exe").is_ok()); // safe: no shell
        assert!(validate_external_url("https://x.io/a b").is_err()); // whitespace
        assert!(validate_external_url("https://x.io/\n").is_err()); // control char
    }
}
