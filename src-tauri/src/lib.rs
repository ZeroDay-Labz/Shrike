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
    findings::{Annotation, Finding, FindingUpdate, NewFinding},
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

/// A [`TrafficSink`] that re-emits bus events to the webview. Completed
/// transactions are queued and sent in batches by [`spawn_traffic_flusher`];
/// everything else (intercepts above all) is emitted immediately.
struct TauriSink {
    app: AppHandle,
    batch: TrafficBatch,
}

/// Captured-traffic summaries waiting to go to the webview. A burst of traffic
/// then costs one IPC message and one UI render per flush, not one per request.
#[derive(Clone, Default)]
struct TrafficBatch(Arc<std::sync::Mutex<Vec<TransactionSummary>>>);

/// How often queued traffic is flushed to the webview.
const TRAFFIC_FLUSH: std::time::Duration = std::time::Duration::from_millis(80);

/// Emit queued summaries as one `traffic-batch` event (oldest first) every
/// [`TRAFFIC_FLUSH`], for the lifetime of the app.
fn spawn_traffic_flusher(app: AppHandle, batch: TrafficBatch) {
    std::thread::Builder::new()
        .name("shrike-ui-traffic".into())
        .spawn(move || {
            loop {
                std::thread::sleep(TRAFFIC_FLUSH);
                let rows = std::mem::take(&mut *batch.0.lock().expect("traffic batch lock"));
                if !rows.is_empty()
                    && let Err(e) = app.emit("traffic-batch", rows)
                {
                    warn!(error = %e, "failed to emit traffic batch to the webview");
                }
            }
        })
        .expect("spawning the traffic flusher");
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
            TrafficEvent::Completed(tx) => {
                self.batch
                    .0
                    .lock()
                    .expect("traffic batch lock")
                    .push(TransactionSummary::from(tx.as_ref()));
                Ok(())
            }
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
            TrafficEvent::FindingAdded(f) => self.app.emit("finding-added", f.as_ref()),
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
    capture_in_scope_only: bool,
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
    #[serde(default = "default_true")]
    passive_scan_enabled: bool,
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
            capture_in_scope_only: c.capture_in_scope_only,
            chromium_path: c.chromium_path.clone().unwrap_or_default(),
            github_token: c.github_token.clone(),
            intruder_require_scope: c.intruder_require_scope,
            request_timeout_ms: c.request_timeout_ms,
            history_max_rows: c.history_max_rows,
            passive_scan_enabled: c.passive_scan_enabled,
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
            capture_in_scope_only: self.capture_in_scope_only,
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
            passive_scan_enabled: self.passive_scan_enabled,
            // Crawler/active/OOB settings aren't on this form; keep the base values.
            ..base.clone()
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

/// Run engine work on Tauri's blocking pool. Synchronous commands execute on
/// the main (webview) thread, so anything touching disk, the network or child
/// processes goes through here to keep the window responsive.
async fn off_main<T: Send + 'static>(
    state: &State<'_, AppState>,
    f: impl FnOnce(&Engine) -> CmdResult<T> + Send + 'static,
) -> CmdResult<T> {
    let engine = Arc::clone(&state.engine);
    tauri::async_runtime::spawn_blocking(move || f(&engine))
        .await
        .map_err(err)?
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
async fn proxy_start(state: State<'_, AppState>) -> CmdResult<ProxyStatus> {
    off_main(&state, |e| {
        let addr = e.start_proxy().map_err(err)?;
        Ok(ProxyStatus {
            running: true,
            listen: addr.to_string(),
        })
    })
    .await
}

#[tauri::command]
async fn proxy_stop(state: State<'_, AppState>) -> CmdResult<ProxyStatus> {
    off_main(&state, |e| {
        e.stop_proxy().map_err(err)?;
        Ok(ProxyStatus {
            running: false,
            listen: e.config().listen.to_string(),
        })
    })
    .await
}

#[tauri::command]
fn config_get(state: State<AppState>) -> ConfigView {
    ConfigView::from_config(&state.engine.config())
}

#[tauri::command]
async fn config_set(state: State<'_, AppState>, config: ConfigView) -> CmdResult<ConfigView> {
    // Restarts the proxy when it is running, which can take a moment.
    off_main(&state, move |e| {
        let next = config.apply_to(&e.config())?;
        e.set_config(next).map_err(err)?;
        Ok(ConfigView::from_config(&e.config()))
    })
    .await
}

#[tauri::command]
async fn history_page(
    state: State<'_, AppState>,
    filter: HistoryFilter,
    limit: u32,
    offset: u32,
) -> CmdResult<Vec<TransactionSummary>> {
    off_main(&state, move |e| {
        e.history_page(&filter, limit, offset).map_err(err)
    })
    .await
}

#[tauri::command]
async fn history_count(state: State<'_, AppState>, filter: HistoryFilter) -> CmdResult<u64> {
    off_main(&state, move |e| e.history_count(&filter).map_err(err)).await
}

#[tauri::command]
async fn history_query(
    state: State<'_, AppState>,
    query: String,
    limit: u32,
    offset: u32,
) -> CmdResult<Vec<TransactionSummary>> {
    off_main(&state, move |e| {
        e.history_query(&query, limit, offset).map_err(err)
    })
    .await
}

#[tauri::command]
async fn history_query_count(state: State<'_, AppState>, query: String) -> CmdResult<u64> {
    off_main(&state, move |e| e.history_query_count(&query).map_err(err)).await
}

#[tauri::command]
async fn history_get(state: State<'_, AppState>, id: u64) -> CmdResult<Option<TransactionView>> {
    off_main(&state, move |e| e.history_get(id).map_err(err)).await
}

#[tauri::command]
async fn history_clear(state: State<'_, AppState>) -> CmdResult<()> {
    off_main(&state, |e| e.clear_history().map_err(err)).await
}

#[tauri::command]
async fn site_map(state: State<'_, AppState>) -> CmdResult<Vec<SiteNode>> {
    off_main(&state, |e| e.site_map().map_err(err)).await
}

// ---- crawler ----

#[tauri::command]
fn crawler_start(state: State<AppState>, app: AppHandle, seed: String) -> CmdResult<()> {
    let app2 = app.clone();
    let sink: std::sync::Arc<dyn Fn(shrike_engine::crawler::CrawlEvent) + Send + Sync> =
        std::sync::Arc::new(move |ev| {
            let _ = app2.emit("crawl-progress", ev);
        });
    state.engine.crawler_start(seed, sink).map_err(err)
}

#[tauri::command]
fn crawler_stop(state: State<AppState>) -> CmdResult<()> {
    state.engine.crawler_stop();
    Ok(())
}

// ---- active scanner ----

#[tauri::command]
async fn active_scan_start(
    state: State<'_, AppState>,
    app: AppHandle,
    transaction_id: u64,
) -> CmdResult<()> {
    let sink: std::sync::Arc<dyn Fn(shrike_engine::scanner::ActiveScanEvent) + Send + Sync> =
        std::sync::Arc::new(move |ev| {
            let _ = app.emit("scan-progress", ev);
        });
    off_main(&state, move |e| {
        e.active_scan_start(transaction_id, sink).map_err(err)
    })
    .await
}

#[tauri::command]
fn active_scan_stop(state: State<AppState>) -> CmdResult<()> {
    state.engine.active_scan_stop();
    Ok(())
}

#[tauri::command]
async fn traffic_stats(state: State<'_, AppState>) -> CmdResult<TrafficStats> {
    off_main(&state, |e| e.traffic_stats().map_err(err)).await
}

// ---- findings & annotations ----

#[tauri::command]
async fn findings_list(state: State<'_, AppState>) -> CmdResult<Vec<Finding>> {
    off_main(&state, |e| e.findings_list().map_err(err)).await
}

#[tauri::command]
async fn finding_create(state: State<'_, AppState>, finding: NewFinding) -> CmdResult<Finding> {
    off_main(&state, move |e| e.finding_create(finding).map_err(err)).await
}

#[tauri::command]
async fn finding_update(
    state: State<'_, AppState>,
    id: u64,
    update: FindingUpdate,
) -> CmdResult<Option<Finding>> {
    off_main(&state, move |e| e.finding_update(id, update).map_err(err)).await
}

#[tauri::command]
async fn finding_delete(state: State<'_, AppState>, id: u64) -> CmdResult<bool> {
    off_main(&state, move |e| e.finding_delete(id).map_err(err)).await
}

#[tauri::command]
async fn annotations(state: State<'_, AppState>) -> CmdResult<Vec<Annotation>> {
    off_main(&state, |e| e.annotations().map_err(err)).await
}

#[tauri::command]
async fn annotation_set(
    state: State<'_, AppState>,
    transaction_id: u64,
    color: Option<String>,
    note: Option<String>,
) -> CmdResult<()> {
    off_main(&state, move |e| {
        e.annotation_set(transaction_id, color, note).map_err(err)
    })
    .await
}

/// Render the findings report; `format` is `"json"` or `"html"`.
#[tauri::command]
async fn findings_report(state: State<'_, AppState>, format: String) -> CmdResult<String> {
    off_main(&state, move |e| e.findings_report(&format).map_err(err)).await
}

// ---- project lifecycle ----

#[tauri::command]
async fn project_info(state: State<'_, AppState>) -> CmdResult<ProjectMeta> {
    off_main(&state, |e| e.project_info().map_err(err)).await
}

#[tauri::command]
async fn project_set_name(state: State<'_, AppState>, name: String) -> CmdResult<ProjectMeta> {
    off_main(&state, move |e| {
        e.set_project_name(&name).map_err(err)?;
        e.project_info().map_err(err)
    })
    .await
}

/// Save a consistent copy of the project to `path` (save-a-copy / backup).
#[tauri::command]
async fn project_backup(state: State<'_, AppState>, path: String) -> CmdResult<String> {
    off_main(&state, move |e| {
        e.backup_project(&path).map_err(err)?;
        Ok(path)
    })
    .await
}

#[tauri::command]
async fn project_integrity(state: State<'_, AppState>) -> CmdResult<bool> {
    off_main(&state, |e| e.project_integrity().map_err(err)).await
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
async fn ui_state_get(state: State<'_, AppState>, key: String) -> CmdResult<Option<String>> {
    off_main(&state, move |e| e.ui_state_get(&key).map_err(err)).await
}

#[tauri::command]
async fn ui_state_set(state: State<'_, AppState>, key: String, value: String) -> CmdResult<()> {
    off_main(&state, move |e| e.ui_state_set(&key, &value).map_err(err)).await
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
async fn repeater_send(state: State<'_, AppState>, spec: RequestSpec) -> CmdResult<SendResult> {
    // A send can wait up to the request timeout; never on the UI thread.
    off_main(&state, move |e| e.repeater_send(spec).map_err(err)).await
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
// Async commands run off the main thread; a large diff is CPU-heavy.
async fn compare(a: String, b: String, mode: DiffMode) -> Vec<Seg> {
    shrike_engine::tools::comparer::compare(&a, &b, mode)
}

// ---- sequencer ----

#[tauri::command]
async fn sequencer_analyze(tokens: Vec<String>) -> SequencerReport {
    shrike_engine::tools::sequencer::analyze(&tokens)
}

// ---- extender (plugins) ----

#[tauri::command]
fn plugins_list(state: State<AppState>) -> Vec<PluginManifest> {
    state.engine.plugins()
}

// ---- native Extras (passive = automatic, active = deliberate) ----

#[tauri::command]
fn extras_list(state: State<AppState>) -> Vec<shrike_engine::extras::ExtraStatus> {
    state.engine.extras()
}

#[tauri::command]
fn extra_set_enabled(
    state: State<AppState>,
    id: String,
    on: bool,
) -> CmdResult<Vec<shrike_engine::extras::ExtraStatus>> {
    state.engine.set_extra_enabled(&id, on).map_err(err)
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
async fn bapp_installed(state: State<'_, AppState>) -> CmdResult<Vec<InstalledBapp>> {
    off_main(&state, |e| e.bapp_installed().map_err(err)).await
}

#[tauri::command]
async fn bapp_uninstall(
    state: State<'_, AppState>,
    sha256: String,
) -> CmdResult<Vec<InstalledBapp>> {
    off_main(&state, move |e| e.bapp_uninstall(&sha256).map_err(err)).await
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
async fn bapp_stop(state: State<'_, AppState>, sha256: String) -> CmdResult<Vec<String>> {
    // Kills and reaps the host process.
    off_main(&state, move |e| {
        e.bapp_stop(&sha256).map_err(err)?;
        Ok(e.bapp_running())
    })
    .await
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
/// Probes the packaged resource dir, the Flatpak install prefix, and (dev) repo
/// ancestors — the Flatpak manifest installs resources under /app/share/shrike,
/// which is not where `resource_dir()` points.
fn resolve_bundled_chromium(app: &AppHandle) -> Option<std::path::PathBuf> {
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

    // `chromium` base directories to try, in order.
    let mut bases: Vec<std::path::PathBuf> = Vec::new();
    if let Ok(res) = app.path().resource_dir() {
        bases.push(res.join("chromium"));
    }
    // Flatpak: resources are installed next to the binary's share prefix.
    bases.push(std::path::PathBuf::from(
        "/app/share/shrike/resources/chromium",
    ));
    // Dev: search repo ancestors of cwd and the executable.
    if let Ok(cwd) = std::env::current_dir() {
        bases.extend(
            cwd.ancestors()
                .map(|p| p.join("src-tauri/resources/chromium")),
        );
    }
    if let Ok(exe) = std::env::current_exe() {
        bases.extend(
            exe.ancestors()
                .map(|p| p.join("src-tauri/resources/chromium")),
        );
    }

    bases
        .iter()
        .flat_map(|base| candidates.iter().map(move |c| base.join(c)))
        .find(|p| p.is_file())
}

#[tauri::command]
async fn launch_browser(
    state: State<'_, AppState>,
    app: AppHandle,
) -> CmdResult<shrike_engine::browser::BrowserStatus> {
    // May start the proxy first, then spawns Chromium.
    let bin = resolve_bundled_chromium(&app);
    off_main(&state, move |e| e.launch_browser(bin).map_err(err)).await
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
            let batch = TrafficBatch::default();
            spawn_traffic_flusher(handle.clone(), batch.clone());
            engine_for_setup.add_sink(Box::new(TauriSink { app: handle, batch }));
            // Clear the "browser launched" banner when the integrated browser closes.
            let handle_browser = app.handle().clone();
            engine_for_setup.set_browser_exit_hook(move || {
                let _ = handle_browser.emit("browser-closed", ());
            });
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
            history_query,
            history_query_count,
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
            crawler_start,
            crawler_stop,
            active_scan_start,
            active_scan_stop,
            findings_list,
            finding_create,
            finding_update,
            finding_delete,
            annotations,
            annotation_set,
            findings_report,
            sequencer_analyze,
            plugins_list,
            extras_list,
            extra_set_enabled,
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
