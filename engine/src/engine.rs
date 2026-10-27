//! The engine: one object that owns the proxy lifecycle, CA, history store and
//! live configuration. Both the headless CLI and the Tauri GUI construct an
//! `Engine` and drive it through these methods; the engine itself knows nothing
//! about either front end.

use crate::{
    bapp::{self, BappEntry, PackageInspection},
    browser::{self, BrowserConfig, BrowserStatus},
    ca::CaManager,
    config::ProxyConfig,
    core::{EventBus, HttpService, TrafficSink, TransactionSummary, TransactionView},
    intercept::{Decision, Interceptor},
    intruder::{self, AttackEvent, IntruderConfig},
    jvm::{
        self, BappOutput, InstallOutcome, InstalledBapp, JvmResources, JvmRuntime, JvmStatus,
        RunningBapp,
    },
    match_replace::{MatchReplace, MatchReplaceRule},
    plugins::{PluginManifest, PluginRegistry},
    proxy,
    scope::{Scope, ScopeRule},
    sender::{RequestSpec, SendResult, Sender},
    store::{HistoryFilter, ProjectMeta, SiteNode, Store, TrafficStats},
};
use anyhow::{Context, Result, anyhow};
use std::path::Path;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};
use tokio::{runtime::Runtime, sync::oneshot, task::JoinHandle};
use tracing::{info, warn};

/// Builds a fresh sink each time the proxy starts (the bus consumes its sinks).
/// Front ends register one of these to receive live traffic (e.g. a Tauri sink).
pub type SinkFactory = Box<dyn Fn() -> Box<dyn TrafficSink> + Send + Sync>;

struct RunningProxy {
    shutdown: oneshot::Sender<()>,
    task: JoinHandle<Result<()>>,
    local_addr: SocketAddr,
}

/// Project-setting key under which the scope rules are stored as JSON.
const META_SCOPE: &str = "scope";
/// Project-setting key under which the match & replace rules are stored as JSON.
const META_MATCH_REPLACE: &str = "match_replace";
/// Project-setting key under which the installed plugin manifests are stored as JSON.
const META_PLUGINS: &str = "plugins";

/// Maven Central downloads for the one-click JVM/Jython setup.
const JVM_MONTOYA_URL: &str = "https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/2026.7/montoya-api-2026.7.jar";
const JVM_JYTHON_URL: &str = "https://repo1.maven.org/maven2/org/python/jython-standalone/2.7.5b1/jython-standalone-2.7.5b1.jar";
/// Published legacy Extender API (the `burp.*` interfaces) — needed so
/// Jython Python extensions can `import burp` and we can proxy the callbacks.
const JVM_LEGACY_API_URL: &str = "https://repo1.maven.org/maven2/net/portswigger/burp/extender/burp-extender-api/2.3/burp-extender-api-2.3.jar";

/// Download `url` to `dest` atomically via the system `curl` (follows redirects).
fn download(url: &str, dest: &Path) -> Result<()> {
    if let Some(p) = dest.parent() {
        std::fs::create_dir_all(p).ok();
    }
    let tmp = dest.with_extension("part");
    let status = std::process::Command::new("curl")
        .args(["-fL", "--retry", "2", "--connect-timeout", "20", "-o"])
        .arg(&tmp)
        .arg(url)
        .status()
        .context("running curl (is it installed?)")?;
    if !status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(anyhow!("download failed ({}): {url}", status));
    }
    std::fs::rename(&tmp, dest).context("finalizing download")?;
    Ok(())
}

/// Fetch a URL's body as text via the system `curl`, with the headers the GitHub
/// REST API expects (it rejects requests without a User-Agent). A non-empty
/// `token` is sent as a Bearer credential to lift the unauthenticated rate limit.
fn curl_text(url: &str, token: Option<&str>) -> Result<String> {
    let mut cmd = std::process::Command::new("curl");
    cmd.args([
        "-fsSL",
        "--retry",
        "2",
        "--connect-timeout",
        "20",
        "-H",
        "Accept: application/vnd.github+json",
        "-H",
        "User-Agent: Shrike-BApp-Catalog",
    ]);
    if let Some(tok) = token.filter(|t| !t.is_empty()) {
        cmd.arg("-H").arg(format!("Authorization: Bearer {tok}"));
    }
    let out = cmd
        .arg(url)
        .output()
        .context("running curl (is it installed?)")?;
    if !out.status.success() {
        return Err(anyhow!("fetch failed ({}): {url}", out.status));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// GitHub org whose repos mirror the public BApp Store catalog.
const BAPP_ORG: &str = "PortSwigger";
/// Re-fetch the remote catalog at most this often; serve the cache in between.
const BAPP_CATALOG_TTL_MS: u128 = 24 * 60 * 60 * 1000;

#[derive(serde::Serialize, serde::Deserialize)]
struct CatalogCache {
    fetched_at_ms: u128,
    entries: Vec<BappEntry>,
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Fold one line from a running BApp host into `state` and return the event to
/// forward to the UI. Lines are `@OUT:`/`@ERR:` log lines, the `{…}` load summary
/// the host prints once, or the extension's own stdout (kept as output only).
fn ingest_host_line(state: &Arc<Mutex<RunningBapp>>, sha: &str, line: &str) -> BappOutput {
    const MAX_LINES: usize = 500;
    let trim = |v: &mut Vec<String>| {
        if v.len() > MAX_LINES {
            let overflow = v.len() - MAX_LINES;
            v.drain(0..overflow);
        }
    };
    let ev = |stream: &str, msg: &str| BappOutput {
        sha256: sha.to_string(),
        stream: stream.to_string(),
        line: msg.to_string(),
    };

    if let Some(msg) = line.strip_prefix("@OUT:") {
        let mut s = state.lock().expect("state");
        s.outputs.push(msg.to_string());
        trim(&mut s.outputs);
        return ev("out", msg);
    }
    if let Some(msg) = line.strip_prefix("@ERR:") {
        let mut s = state.lock().expect("state");
        s.errors.push(msg.to_string());
        trim(&mut s.errors);
        return ev("err", msg);
    }
    if line.trim_start().starts_with('{')
        && let Ok(load) = serde_json::from_str::<jvm::ExtensionLoad>(line)
    {
        let mut s = state.lock().expect("state");
        if load.name.is_some() {
            s.name = load.name.clone();
        }
        s.suite_tabs = jvm::suite_tabs(&load.registered);
        s.windows = load.ui_windows;
        s.registered = load.registered;
        for o in load.outputs {
            if !s.outputs.contains(&o) {
                s.outputs.push(o);
            }
        }
        for e in load.errors {
            if !s.errors.contains(&e) {
                s.errors.push(e);
            }
        }
        trim(&mut s.outputs);
        trim(&mut s.errors);
        return ev("meta", line);
    }
    // Unprefixed line: the extension's own stdout — show it, don't trust it as state.
    ev("out", line)
}

pub struct Engine {
    runtime: Runtime,
    ca: Arc<CaManager>,
    store: Arc<Store>,
    config: RwLock<ProxyConfig>,
    /// Shared with the running proxy handler so edits apply live.
    scope: Arc<RwLock<Scope>>,
    /// Shared with the running proxy handler so requests can be paused/forwarded/dropped.
    interceptor: Arc<Interceptor>,
    /// Shared with the running proxy handler so match & replace edits apply live.
    match_replace: Arc<RwLock<MatchReplace>>,
    /// Installed plugins (Extender). Data-only registry; persisted in the project.
    plugins: RwLock<PluginRegistry>,
    /// The integrated browser process, if one has been launched.
    browser: Mutex<Option<std::process::Child>>,
    /// Bundled JVM host jars (set by the GUI once resolved from app resources).
    jvm_resources: Mutex<Option<JvmResources>>,
    /// Running Java BApp host processes, keyed by the extension's SHA-256.
    bapp_procs: Mutex<HashMap<String, std::process::Child>>,
    /// Live console state (name, registrations, captured output) for each running
    /// BApp, updated by its host-process reader thread.
    bapp_state: Mutex<HashMap<String, Arc<Mutex<RunningBapp>>>>,
    /// HTTP sender for manual tools (Repeater); rebuilt when TLS config changes.
    sender: RwLock<Arc<Sender>>,
    /// Cancellation flags for running Intruder attacks, keyed by attack id.
    attacks: Mutex<HashMap<u64, Arc<AtomicBool>>>,
    next_attack_id: AtomicU64,
    proxy: Mutex<Option<RunningProxy>>,
    sink_factories: Mutex<Vec<SinkFactory>>,
}

impl Engine {
    /// Load/create the CA and open the project's history store under the
    /// configured data directory, ready to start the proxy on demand.
    pub fn new(config: ProxyConfig) -> Result<Arc<Self>> {
        let runtime = Runtime::new().context("starting engine tokio runtime")?;
        let (ca, created) = CaManager::load_or_create(&config.ca_dir())?;
        if created {
            info!("generated a new CA");
        }
        let store_path = config.data_dir.join("projects").join("default.sqlite");
        let store = Arc::new(Store::open(&store_path)?);
        store.set_max_rows(config.history_max_rows);
        let scope = Arc::new(RwLock::new(load_scope(&store)));
        let match_replace = Arc::new(RwLock::new(load_match_replace(&store)));
        let plugins = RwLock::new(load_plugins(&store));
        let sender = Arc::new(Sender::new(
            config.upstream_tls,
            config.max_capture_bytes,
            std::time::Duration::from_millis(config.request_timeout_ms),
        )?);

        let engine = Arc::new(Self {
            runtime,
            ca: Arc::new(ca),
            store: Arc::clone(&store),
            config: RwLock::new(config),
            scope,
            interceptor: Arc::new(Interceptor::new()),
            match_replace,
            plugins,
            browser: Mutex::new(None),
            jvm_resources: Mutex::new(None),
            bapp_procs: Mutex::new(HashMap::new()),
            bapp_state: Mutex::new(HashMap::new()),
            sender: RwLock::new(sender),
            attacks: Mutex::new(HashMap::new()),
            next_attack_id: AtomicU64::new(1),
            proxy: Mutex::new(None),
            sink_factories: Mutex::new(Vec::new()),
        });

        // The store always receives traffic; its sink is rebuilt per proxy run.
        let store_for_sink = Arc::clone(&store);
        engine.add_sink_factory(Box::new(move || Box::new(store_for_sink.sink())));
        Ok(engine)
    }

    pub fn ca(&self) -> &Arc<CaManager> {
        &self.ca
    }

    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// Current proxy configuration (a snapshot clone).
    pub fn config(&self) -> ProxyConfig {
        self.config.read().expect("config lock").clone()
    }

    /// The configured GitHub token, if any (empty string means none).
    fn github_token(&self) -> Option<String> {
        let t = self
            .config
            .read()
            .expect("config lock")
            .github_token
            .clone();
        (!t.is_empty()).then_some(t)
    }

    // --- target scope (enforced in the core; persisted in the project) ---

    pub fn scope_rules(&self) -> Vec<ScopeRule> {
        self.scope.read().expect("scope lock").rules()
    }

    /// Validate, persist and atomically swap in a new rule set. Invalid regexes
    /// are rejected without touching the live scope.
    pub fn set_scope(&self, rules: Vec<ScopeRule>) -> Result<()> {
        let compiled = Scope::from_rules(rules.clone()).map_err(|e| anyhow!("{e}"))?;
        let json = serde_json::to_string(&rules).context("serializing scope")?;
        self.store.set_meta(META_SCOPE, &json)?;
        *self.scope.write().expect("scope lock") = compiled;
        info!(rules = rules.len(), "scope updated");
        Ok(())
    }

    pub fn in_scope(&self, service: &HttpService, path: &str) -> bool {
        self.scope
            .read()
            .expect("scope lock")
            .in_scope(service, path)
    }

    pub fn in_scope_url(&self, url: &str) -> bool {
        self.scope.read().expect("scope lock").in_scope_url(url)
    }

    // --- match & replace (applied in the proxy handler) ---

    pub fn match_replace_rules(&self) -> Vec<MatchReplaceRule> {
        self.match_replace
            .read()
            .expect("match_replace lock")
            .rules()
    }

    /// Validate, persist and atomically swap in a new rule set. A bad regex (or
    /// an empty match) is rejected without touching the live rules.
    pub fn set_match_replace(&self, rules: Vec<MatchReplaceRule>) -> Result<()> {
        let compiled = MatchReplace::from_rules(rules.clone()).map_err(|e| anyhow!("{e}"))?;
        let json = serde_json::to_string(&rules).context("serializing match & replace rules")?;
        self.store.set_meta(META_MATCH_REPLACE, &json)?;
        *self.match_replace.write().expect("match_replace lock") = compiled;
        info!(rules = rules.len(), "match & replace updated");
        Ok(())
    }

    // --- request interception ---

    pub fn intercept_enabled(&self) -> bool {
        self.interceptor.is_enabled()
    }

    /// Turn interception on/off. Turning it off releases anything currently paused.
    pub fn set_intercept(&self, on: bool) {
        self.interceptor.set_enabled(on);
        info!(on, "intercept toggled");
    }

    /// Deliver the user's decision for a paused request.
    pub fn intercept_resolve(&self, id: u64, decision: Decision) {
        self.interceptor.resolve(id, decision);
    }

    // --- manual tools ---

    /// Send one request (Repeater). Manual and user-initiated, so not gated by scope.
    pub fn repeater_send(&self, spec: RequestSpec) -> Result<SendResult> {
        let sender = Arc::clone(&*self.sender.read().expect("sender lock"));
        self.runtime.block_on(sender.send(spec))
    }

    /// Start an Intruder attack in the background. `sink` is called for every
    /// event (started/result/done). Returns the attack id for cancellation.
    pub fn intruder_start(
        &self,
        config: IntruderConfig,
        sink: Arc<dyn Fn(AttackEvent) + Send + Sync>,
    ) -> Result<u64> {
        // Scope is an enforcement boundary for automated tools. When required,
        // reject an attack whose scope can't possibly admit anything (empty
        // scope = nothing in scope), and enforce per-request inside `run`.
        let require_scope = self.config().intruder_require_scope;
        let scope = if require_scope {
            if self.scope.read().expect("scope lock").is_empty() {
                return Err(anyhow!(
                    "target scope is empty, so nothing is in scope — add an include rule in \
                     Settings, or turn off \"require scope for Intruder\" there"
                ));
            }
            Some(Arc::clone(&self.scope))
        } else {
            None
        };

        let id = self.next_attack_id.fetch_add(1, Ordering::Relaxed);
        let stop = Arc::new(AtomicBool::new(false));
        self.attacks
            .lock()
            .expect("attacks lock")
            .insert(id, Arc::clone(&stop));
        let sender = Arc::clone(&*self.sender.read().expect("sender lock"));
        self.runtime.spawn(async move {
            intruder::run(id, config, sender, sink, stop, scope).await;
        });
        Ok(id)
    }

    /// Request cancellation of a running attack.
    pub fn intruder_stop(&self, id: u64) {
        if let Some(stop) = self.attacks.lock().expect("attacks lock").get(&id) {
            stop.store(true, Ordering::Relaxed);
        }
    }

    /// Drop the bookkeeping for a finished attack.
    pub fn intruder_finished(&self, id: u64) {
        self.attacks.lock().expect("attacks lock").remove(&id);
    }

    /// Replace the configuration. Takes effect on the next proxy start; if the
    /// proxy is running it is restarted so listener/TLS/passthrough changes apply.
    pub fn set_config(&self, config: ProxyConfig) -> Result<()> {
        let was_running = self.local_addr().is_some();
        let (mode, max, timeout) = (
            config.upstream_tls,
            config.max_capture_bytes,
            std::time::Duration::from_millis(config.request_timeout_ms),
        );
        let max_rows = config.history_max_rows;
        *self.config.write().expect("config lock") = config;
        if let Ok(sender) = Sender::new(mode, max, timeout) {
            *self.sender.write().expect("sender lock") = Arc::new(sender);
        }
        self.store.set_max_rows(max_rows);
        if was_running {
            self.stop_proxy()?;
            self.start_proxy()?;
        }
        Ok(())
    }

    /// Register a sink factory invoked each time the proxy (re)starts.
    pub fn add_sink_factory(&self, factory: SinkFactory) {
        self.sink_factories.lock().expect("sink lock").push(factory);
    }

    /// The address the proxy is listening on, or `None` when stopped.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.proxy
            .lock()
            .expect("proxy lock")
            .as_ref()
            .map(|p| p.local_addr)
    }

    pub fn is_running(&self) -> bool {
        self.local_addr().is_some()
    }

    /// Start the proxy with the current config. Returns the bound address.
    /// A no-op returning the existing address if already running.
    pub fn start_proxy(&self) -> Result<SocketAddr> {
        let mut guard = self.proxy.lock().expect("proxy lock");
        if let Some(p) = guard.as_ref() {
            return Ok(p.local_addr);
        }

        let config = self.config();
        let ca = Arc::clone(&self.ca);

        let listener = self
            .runtime
            .block_on(proxy::bind(&config))
            .context("binding proxy listener")?;
        let local_addr = listener.local_addr().context("reading listener address")?;

        let sinks: Vec<Box<dyn TrafficSink>> = self
            .sink_factories
            .lock()
            .expect("sink lock")
            .iter()
            .map(|f| f())
            .collect();
        // EventBus::start spawns a dispatcher task, so build it inside the runtime context.
        let (bus, bus_task) = {
            let _enter = self.runtime.enter();
            EventBus::start(sinks)
        };

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let shutdown = async move {
            let _ = shutdown_rx.await;
        };
        let scope = Arc::clone(&self.scope);
        let interceptor = Arc::clone(&self.interceptor);
        let match_replace = Arc::clone(&self.match_replace);

        let task = self.runtime.spawn(async move {
            let result = proxy::serve(
                listener,
                config,
                ca,
                bus,
                scope,
                interceptor,
                match_replace,
                shutdown,
            )
            .await;
            // handlers (and their bus clones) are dropped inside serve(); drain the bus.
            let _ = bus_task.await;
            result
        });

        info!(%local_addr, "proxy started");
        *guard = Some(RunningProxy {
            shutdown: shutdown_tx,
            task,
            local_addr,
        });
        Ok(local_addr)
    }

    /// Stop the proxy, draining in-flight connections. No-op if already stopped.
    pub fn stop_proxy(&self) -> Result<()> {
        let running = self.proxy.lock().expect("proxy lock").take();
        let Some(running) = running else {
            return Ok(());
        };
        // Release any paused requests so their connections can drain and the
        // proxy task can actually finish shutting down.
        self.interceptor.drain_all();
        let _ = running.shutdown.send(());
        // Bound the wait: a long-lived connection (e.g. an open WebSocket) would
        // otherwise keep the graceful-shutdown future alive forever and hang the
        // Stop action. Give it a short grace period, then force the task down.
        let mut task = running.task;
        self.runtime.block_on(async {
            tokio::select! {
                res = &mut task => {
                    if let Ok(Err(e)) = res {
                        warn!(error = %e, "proxy task returned an error");
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {
                    warn!("proxy still draining after 2s (open connection?); forcing stop");
                    task.abort();
                    let _ = task.await;
                }
            }
        });
        self.store.flush().ok();
        info!("proxy stopped");
        Ok(())
    }

    // --- history queries (delegates to the store) ---

    pub fn history_page(
        &self,
        filter: &HistoryFilter,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<TransactionSummary>> {
        self.store.history_page(filter, limit, offset)
    }

    pub fn history_count(&self, filter: &HistoryFilter) -> Result<u64> {
        self.store.count(filter)
    }

    pub fn history_get(&self, id: u64) -> Result<Option<TransactionView>> {
        self.store.history_get(id)
    }

    /// Distinct endpoints (host + path) seen in history, for the Target site map.
    pub fn site_map(&self) -> Result<Vec<SiteNode>> {
        self.store.site_map()
    }

    // --- project lifecycle (disk-backed, autosaving) ---

    /// Identity + on-disk status of the active project.
    pub fn project_info(&self) -> Result<ProjectMeta> {
        self.store.project_meta(false)
    }

    pub fn set_project_name(&self, name: &str) -> Result<()> {
        self.store.set_project_name(name)
    }

    /// Write a consistent snapshot of the project to `dest` (save-a-copy / export).
    pub fn backup_project(&self, dest: impl AsRef<Path>) -> Result<()> {
        self.store.backup_to(dest)
    }

    /// Integrity check of the project database.
    pub fn project_integrity(&self) -> Result<bool> {
        self.store.integrity_check()
    }

    /// Import HTTP traffic from an **XML item export** (the common `<items>` format) into history,
    /// returning how many transactions were added. Other tools' binary project files
    /// are proprietary and not supported — export items as XML first.
    pub fn import_traffic(&self, path: &str) -> Result<usize> {
        let bytes = std::fs::read(path).with_context(|| format!("reading {path}"))?;
        if crate::import::looks_like_binary_project(&bytes) {
            return Err(anyhow!(
                "this looks like a binary project file from another tool, which Shrike can't read. Export \
                 its items as XML ('Save selected items' / export history), then import that file."
            ));
        }
        let xml = String::from_utf8_lossy(&bytes);
        let txs = crate::import::transactions_from_items_xml(&xml);
        if txs.is_empty() {
            return Err(anyhow!(
                "no importable items found — expected an XML items export containing <item> entries"
            ));
        }
        self.store.import_transactions(txs)
    }

    /// Persisted per-tool UI state (Repeater tabs, filters, …). Namespaced under
    /// `ui:` so it can never clobber engine settings (scope, match&replace, …).
    pub fn ui_state_get(&self, key: &str) -> Result<Option<String>> {
        self.store.get_meta(&format!("ui:{key}"))
    }

    pub fn ui_state_set(&self, key: &str, value: &str) -> Result<()> {
        self.store.set_meta(&format!("ui:{key}"), value)
    }

    /// Aggregate traffic counts for the Dashboard.
    pub fn traffic_stats(&self) -> Result<TrafficStats> {
        self.store.stats()
    }

    // --- extender (plugin registry; data-only foundation) ---

    pub fn plugins(&self) -> Vec<PluginManifest> {
        self.plugins.read().expect("plugins lock").manifests()
    }

    fn persist_plugins(&self, reg: &PluginRegistry) -> Result<()> {
        let json = serde_json::to_string(&reg.manifests()).context("serializing plugins")?;
        self.store.set_meta(META_PLUGINS, &json)
    }

    /// Install a plugin manifest (or replace one with the same id); persists.
    pub fn add_plugin(&self, manifest: PluginManifest) -> Result<Vec<PluginManifest>> {
        let mut reg = self.plugins.write().expect("plugins lock");
        reg.upsert(manifest).map_err(|e| anyhow!("{e}"))?;
        self.persist_plugins(&reg)?;
        Ok(reg.manifests())
    }

    pub fn remove_plugin(&self, id: &str) -> Result<Vec<PluginManifest>> {
        let mut reg = self.plugins.write().expect("plugins lock");
        reg.remove(id);
        self.persist_plugins(&reg)?;
        Ok(reg.manifests())
    }

    // --- integrated browser ---

    /// True if a Chromium binary is available (the bundled one passed as `bin`,
    /// else a system one / the configured override).
    pub fn browser_available(&self, bin: Option<std::path::PathBuf>) -> bool {
        if bin.as_ref().is_some_and(|p| p.is_file()) {
            return true;
        }
        let override_path = self.config().chromium_path;
        browser::find_system_chromium(override_path.as_deref()).is_some()
    }

    /// Launch the integrated browser, pre-configured to proxy through Shrike with
    /// the CA trusted and an isolated profile. `bin` is the bundled Chromium path
    /// resolved by the GUI; when `None`, a system/override Chromium is used. Starts
    /// the proxy first if it is not already running.
    pub fn launch_browser(&self, bin: Option<std::path::PathBuf>) -> Result<BrowserStatus> {
        let chromium_bin = match bin.filter(|p| p.is_file()) {
            Some(p) => p,
            None => {
                let override_path = self.config().chromium_path;
                browser::find_system_chromium(override_path.as_deref()).ok_or_else(|| {
                    anyhow!(
                        "no Chromium found. Install Chromium/Chrome, or set a path in \
                         Settings → Chromium path."
                    )
                })?
            }
        };

        let listen = match self.local_addr() {
            Some(addr) => addr,
            None => self.start_proxy()?,
        };

        let profile_dir = self.config().data_dir.join("browser-profile");
        let cfg = BrowserConfig {
            chromium_bin: chromium_bin.clone(),
            listen,
            spki_b64: self.ca.spki_sha256_base64().to_string(),
            profile_dir: profile_dir.clone(),
            start_url: "http://shrike/".to_string(),
        };
        let child = browser::launch(&cfg)?;
        let pid = child.id();
        *self.browser.lock().expect("browser lock") = Some(child);
        info!(pid, %listen, "integrated browser launched");
        Ok(BrowserStatus {
            pid,
            proxy: listen.to_string(),
            profile: profile_dir.display().to_string(),
            chromium: chromium_bin.display().to_string(),
        })
    }

    // --- BApp Store (catalog + safe inspection; nothing is executed) ---

    pub fn bapp_catalog(&self) -> Vec<BappEntry> {
        bapp::catalog()
    }

    /// The full BApp catalog: the curated, featured top entries followed by the
    /// complete catalog mirror pulled from GitHub. Cache-first — the remote
    /// list is fetched at most once a day (or when `refresh` is set) and served
    /// from `<data_dir>/bapp-catalog.json` in between. If the network is
    /// unavailable, it falls back to the cache, then to the curated list alone,
    /// so the store is never empty.
    pub fn bapp_catalog_full(&self, refresh: bool) -> Vec<BappEntry> {
        let featured = bapp::catalog();
        let remote = self.remote_catalog(refresh).unwrap_or_default();

        // Featured first; then every remote entry not already featured (dedupe by id).
        let featured_ids: std::collections::HashSet<&str> =
            featured.iter().map(|e| e.id.as_str()).collect();
        let mut out = featured.clone();
        out.extend(
            remote
                .into_iter()
                .filter(|e| !featured_ids.contains(e.id.as_str())),
        );
        out
    }

    /// Load the cached remote catalog, refreshing from GitHub when stale/forced.
    /// On a fetch failure, returns whatever is cached (possibly stale) so the
    /// store degrades gracefully offline.
    fn remote_catalog(&self, refresh: bool) -> Result<Vec<BappEntry>> {
        let cache_path = self.config().data_dir.join("bapp-catalog.json");
        let cached: Option<CatalogCache> = std::fs::read_to_string(&cache_path)
            .ok()
            .and_then(|j| serde_json::from_str(&j).ok());

        if !refresh
            && let Some(c) = &cached
            && now_ms().saturating_sub(c.fetched_at_ms) < BAPP_CATALOG_TTL_MS
        {
            return Ok(c.entries.clone());
        }

        match self.fetch_github_catalog() {
            Ok(entries) => {
                let cache = CatalogCache {
                    fetched_at_ms: now_ms(),
                    entries: entries.clone(),
                };
                if let Ok(j) = serde_json::to_string(&cache) {
                    if let Some(p) = cache_path.parent() {
                        std::fs::create_dir_all(p).ok();
                    }
                    std::fs::write(&cache_path, j).ok();
                }
                Ok(entries)
            }
            // Offline / rate-limited: serve the last good cache if we have one.
            Err(e) => match cached {
                Some(c) => Ok(c.entries),
                None => Err(e),
            },
        }
    }

    /// Fetch and parse every page of the catalog organisation's public repositories.
    fn fetch_github_catalog(&self) -> Result<Vec<BappEntry>> {
        let mut all = Vec::new();
        // ~530 repos at 100/page ≈ 6 pages; cap at 10 as a safety stop.
        for page in 1..=10 {
            let url = format!(
                "https://api.github.com/orgs/{BAPP_ORG}/repos?per_page=100&page={page}&type=public&sort=full_name"
            );
            let body = curl_text(&url, self.github_token().as_deref())?;
            // Raw element count decides pagination; the mapped list is filtered.
            let raw_len = serde_json::from_str::<Vec<serde_json::Value>>(&body)
                .map(|v| v.len())
                .unwrap_or(0);
            all.extend(bapp::parse_github_repos(&body)?);
            // GitHub returns fewer than per_page only on the last page.
            if raw_len < 100 {
                break;
            }
        }
        all.sort_by_key(|e| e.name.to_lowercase());
        Ok(all)
    }

    /// One-click install of a catalog entry by id. Uses the entry's direct
    /// download URL when it has one, otherwise resolves the latest GitHub release
    /// package (.jar/.bapp) for `<org>/<id>`. When there is no installable
    /// package, reports [`InstallOutcome::NotInstallable`] so the UI can send the
    /// user to the source rather than failing a button.
    pub fn bapp_install_entry(&self, id: &str) -> Result<InstallOutcome> {
        let entry = self
            .bapp_catalog_full(false)
            .into_iter()
            .find(|e| e.id == id)
            .ok_or_else(|| anyhow!("unknown catalog entry: {id}"))?;
        let source = if entry.repo_url.is_empty() {
            entry.listing_url.clone()
        } else {
            entry.repo_url.clone()
        };

        if let Some(url) = entry.download_url.as_deref() {
            return Ok(InstallOutcome::Installed {
                installed: self.install_from_url(url, Some(id))?,
            });
        }

        let api = format!("https://api.github.com/repos/{BAPP_ORG}/{id}/releases/latest");
        let body = curl_text(&api, self.github_token().as_deref())
            .with_context(|| format!("looking up the latest release for {id}"))?;
        if let Some((url, _kind)) = bapp::parse_release_asset(&body) {
            return Ok(InstallOutcome::Installed {
                installed: self.install_from_url(&url, Some(id))?,
            });
        }
        // No release package — grab it from source: a committed .jar/.bapp or a
        // Python entry point anywhere in the repo tree (no compilation needed).
        if let Some(installed) = self.try_install_from_source(id)? {
            return Ok(InstallOutcome::Installed { installed });
        }
        Ok(InstallOutcome::NotInstallable {
            reason: format!(
                "{} has no release package and no directly-installable source (it is likely \
                 Java/Kotlin that must be compiled) — open its source to build it.",
                entry.name
            ),
            source_url: source,
        })
    }

    /// Install a BApp straight from its repo source, without compiling: list the
    /// repo tree, then try each candidate (committed `.jar`/`.bapp` first, then
    /// `.py`), downloading the raw file and installing the first that fits. A `.py`
    /// must look like a legacy BApp (a `BurpExtender` with `registerExtenderCallbacks`).
    fn try_install_from_source(&self, id: &str) -> Result<Option<Vec<InstalledBapp>>> {
        let tree_api =
            format!("https://api.github.com/repos/{BAPP_ORG}/{id}/git/trees/HEAD?recursive=1");
        let body = match curl_text(&tree_api, self.github_token().as_deref()) {
            Ok(b) => b,
            Err(_) => return Ok(None),
        };
        let paths = bapp::parse_tree_paths(&body);
        let dl_dir = self.config().data_dir.join("bapps").join("download");
        for path in bapp::source_candidates(&paths).into_iter().take(8) {
            let raw = format!(
                "https://raw.githubusercontent.com/{BAPP_ORG}/{id}/HEAD/{}",
                path.replace(' ', "%20")
            );
            let fname = path.rsplit('/').next().unwrap_or("extension");
            let tmp = dl_dir.join(fname);
            if download(&raw, &tmp).is_err() {
                continue;
            }
            if fname.to_ascii_lowercase().ends_with(".py") {
                let looks_like = std::fs::read_to_string(&tmp)
                    .map(|s| s.contains("BurpExtender") && s.contains("registerExtenderCallbacks"))
                    .unwrap_or(false);
                if !looks_like {
                    let _ = std::fs::remove_file(&tmp);
                    continue;
                }
            }
            let res = self.install_pkg(&tmp.to_string_lossy(), Some(id));
            let _ = std::fs::remove_file(&tmp);
            return res.map(Some);
        }
        Ok(None)
    }

    pub fn bapp_imports(&self) -> Result<Vec<PackageInspection>> {
        Ok(self
            .store
            .get_meta("bapp:imports")?
            .and_then(|j| serde_json::from_str(&j).ok())
            .unwrap_or_default())
    }

    /// Inspect a downloaded package (hash + classify) and record it, deduped by
    /// SHA-256. Never extracts or runs the package.
    pub fn bapp_import(&self, path: &str) -> Result<Vec<PackageInspection>> {
        let pkg = bapp::inspect_package(path)?;
        let mut list = self.bapp_imports()?;
        list.retain(|p| p.sha256 != pkg.sha256);
        list.push(pkg);
        self.store
            .set_meta("bapp:imports", &serde_json::to_string(&list)?)?;
        Ok(list)
    }

    pub fn bapp_remove(&self, sha256: &str) -> Result<Vec<PackageInspection>> {
        let mut list = self.bapp_imports()?;
        list.retain(|p| p.sha256 != sha256);
        self.store
            .set_meta("bapp:imports", &serde_json::to_string(&list)?)?;
        Ok(list)
    }

    // --- JVM compatibility host + installed BApps ---

    /// Set the bundled JVM jars (host + Montoya API + optional Jython), resolved
    /// by the GUI from app resources (or dev paths).
    pub fn set_jvm_resources(&self, res: Option<JvmResources>) {
        *self.jvm_resources.lock().expect("jvm lock") = res;
    }

    fn jvm_runtime(&self) -> Option<JvmRuntime> {
        let res = self.jvm_resources.lock().expect("jvm lock").clone()?;
        let java = res.java.clone().or_else(|| jvm::find_java(None))?;
        Some(JvmRuntime {
            java,
            host_jar: res.host_jar,
            montoya_jar: res.montoya_jar,
            jython_jar: res.jython_jar,
            legacy_api_jar: res.legacy_api_jar,
        })
    }

    /// Whether a JVM runtime is ready to run Java BApps.
    pub fn jvm_status(&self) -> JvmStatus {
        let res = self.jvm_resources.lock().expect("jvm lock").clone();
        let java = res
            .as_ref()
            .and_then(|r| r.java.clone())
            .or_else(|| jvm::find_java(None));
        let host_ok = res
            .as_ref()
            .is_some_and(|r| r.host_jar.is_file() && r.montoya_jar.is_file());
        JvmStatus {
            available: java.is_some() && host_ok,
            version: java.as_ref().and_then(|j| jvm::java_version(j)),
            java: java.map(|j| j.display().to_string()),
            host_jar: host_ok,
            jython: res.and_then(|r| r.jython_jar).is_some_and(|j| j.is_file()),
        }
    }

    pub fn bapp_installed(&self) -> Result<Vec<InstalledBapp>> {
        Ok(self
            .store
            .get_meta("bapp:installed")?
            .and_then(|j| serde_json::from_str(&j).ok())
            .unwrap_or_default())
    }

    /// Install a downloaded extension by **quarantining** it: copy it into the
    /// managed BApp directory, hash and classify it, and record it as *not loaded*.
    /// It is never executed here — a third-party extension is untrusted code, so
    /// loading only happens on an explicit [`Engine::bapp_run`]. Deduped by SHA-256.
    pub fn bapp_install(&self, src: &str) -> Result<Vec<InstalledBapp>> {
        self.install_pkg(src, None)
    }

    fn install_pkg(&self, src: &str, origin: Option<&str>) -> Result<Vec<InstalledBapp>> {
        let inspection = bapp::inspect_package(src)?;
        let dir = self.config().data_dir.join("bapps");
        std::fs::create_dir_all(&dir).context("creating bapps directory")?;
        let short = &inspection.sha256[..16.min(inspection.sha256.len())];
        let ext = std::path::Path::new(src)
            .extension()
            .map(|e| e.to_string_lossy().into_owned())
            .unwrap_or_else(|| "bin".into());
        let dest = dir.join(format!("{short}.{ext}"));
        std::fs::copy(src, &dest).with_context(|| format!("copying into {}", dest.display()))?;

        // Classify only — no code runs at install time. The status tells the user
        // what pressing Run will do; name/registrations are captured then.
        let status = match inspection.format.as_str() {
            "jar" | "bapp" => "installed — not loaded (press Run to load)".to_string(),
            "python" => {
                let jython = self.jvm_runtime().is_some_and(|rt| rt.jython_jar.is_some());
                if jython {
                    "installed — not loaded (Python/Jython; press Run)".to_string()
                } else {
                    "installed — needs Jython (Install Jython in Addons, then Run)".to_string()
                }
            }
            other => format!("installed — unsupported format: {other}"),
        };

        let record = InstalledBapp {
            sha256: inspection.sha256.clone(),
            filename: inspection.filename,
            path: dest.display().to_string(),
            format: inspection.format,
            name: None,
            enabled: false,
            status,
            registered: vec![],
            outputs: vec![],
            errors: vec![],
            origin: origin.map(str::to_string),
        };
        let mut list = self.bapp_installed()?;
        list.retain(|b| b.sha256 != record.sha256);
        list.push(record);
        self.store
            .set_meta("bapp:installed", &serde_json::to_string(&list)?)?;
        Ok(list)
    }

    /// One-click install from the catalog: download the release jar to a temp
    /// file and install it (load through the JVM host, record it).
    pub fn bapp_install_url(&self, url: &str) -> Result<Vec<InstalledBapp>> {
        self.install_from_url(url, None)
    }

    fn install_from_url(&self, url: &str, origin: Option<&str>) -> Result<Vec<InstalledBapp>> {
        let name = url
            .rsplit('/')
            .next()
            .filter(|s| !s.is_empty() && s.contains('.'))
            .unwrap_or("extension.jar");
        let tmp = self
            .config()
            .data_dir
            .join("bapps")
            .join("download")
            .join(name);
        download(url, &tmp)?;
        let res = self.install_pkg(&tmp.to_string_lossy(), origin);
        let _ = std::fs::remove_file(&tmp);
        res
    }

    pub fn bapp_uninstall(&self, sha256: &str) -> Result<Vec<InstalledBapp>> {
        let mut list = self.bapp_installed()?;
        if let Some(b) = list.iter().find(|b| b.sha256 == sha256) {
            let _ = std::fs::remove_file(&b.path);
        }
        list.retain(|b| b.sha256 != sha256);
        self.store
            .set_meta("bapp:installed", &serde_json::to_string(&list)?)?;
        Ok(list)
    }

    /// Run an installed Java BApp in a persistent host process (its Swing UI, if
    /// any, opens in its own window). No-op if it is already running. `sink`
    /// receives the load summary and each live log line for the console tab.
    pub fn bapp_run(
        &self,
        sha256: &str,
        sink: Arc<dyn Fn(BappOutput) + Send + Sync>,
    ) -> Result<()> {
        // reap any finished process holding this slot
        {
            let mut procs = self.bapp_procs.lock().expect("bapp procs lock");
            if let Some(child) = procs.get_mut(sha256) {
                if matches!(child.try_wait(), Ok(None)) {
                    return Ok(()); // still running
                }
                procs.remove(sha256);
            }
        }
        let record = self
            .bapp_installed()?
            .into_iter()
            .find(|b| b.sha256 == sha256)
            .ok_or_else(|| anyhow!("no such installed BApp"))?;
        if !matches!(record.format.as_str(), "jar" | "bapp" | "python") {
            return Err(anyhow!(
                "can't run a {} package in the JVM host",
                record.format
            ));
        }
        let rt = self
            .jvm_runtime()
            .ok_or_else(|| anyhow!("Java runtime not set up — set it up in Addons first"))?;
        if record.format == "python" && rt.jython_jar.is_none() {
            return Err(anyhow!(
                "this is a Python extension — click Install Jython in Addons first"
            ));
        }

        let state = Arc::new(Mutex::new(RunningBapp {
            sha256: sha256.to_string(),
            name: record.name.clone(),
            ..Default::default()
        }));
        self.bapp_state
            .lock()
            .expect("bapp state lock")
            .insert(sha256.to_string(), Arc::clone(&state));

        let sha_owned = sha256.to_string();
        let child = jvm::spawn_streaming(&rt, std::path::Path::new(&record.path), move |line| {
            let ev = ingest_host_line(&state, &sha_owned, &line);
            sink(ev);
        })?;
        self.bapp_procs
            .lock()
            .expect("bapp procs lock")
            .insert(sha256.to_string(), child);
        info!(sha = sha256, "BApp running");
        Ok(())
    }

    pub fn bapp_stop(&self, sha256: &str) -> Result<()> {
        if let Some(mut child) = self
            .bapp_procs
            .lock()
            .expect("bapp procs lock")
            .remove(sha256)
        {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.bapp_state
            .lock()
            .expect("bapp state lock")
            .remove(sha256);
        Ok(())
    }

    /// SHA-256s of BApps whose host process is still alive (reaps exited ones).
    pub fn bapp_running(&self) -> Vec<String> {
        let mut procs = self.bapp_procs.lock().expect("bapp procs lock");
        procs.retain(|_, child| matches!(child.try_wait(), Ok(None)));
        let alive: Vec<String> = procs.keys().cloned().collect();
        drop(procs);
        self.bapp_state
            .lock()
            .expect("bapp state lock")
            .retain(|sha, _| alive.contains(sha));
        alive
    }

    /// Live console state for every running BApp (name, registrations, suite-tab
    /// titles, captured output), for the per-extension tabs.
    pub fn bapp_running_meta(&self) -> Vec<RunningBapp> {
        let alive = self.bapp_running();
        let state = self.bapp_state.lock().expect("bapp state lock");
        alive
            .iter()
            .filter_map(|sha| state.get(sha).map(|s| s.lock().expect("state").clone()))
            .collect()
    }

    /// One-click Java runtime setup: stage the host + Montoya jars into the
    /// project data dir (copying the bundled/dev copies, downloading Montoya if
    /// absent) and point the runtime at them. Uses a bundled or system `java`.
    pub fn jvm_setup(&self) -> Result<JvmStatus> {
        let dest = self.config().data_dir.join("jvm");
        std::fs::create_dir_all(&dest).context("creating jvm directory")?;
        let host = dest.join("shrike-host.jar");
        let montoya = dest.join("montoya-api.jar");

        // Copy whatever the GUI already resolved (bundled, or the dev build dir).
        let (src, bundled_java) = {
            let g = self.jvm_resources.lock().expect("jvm lock");
            (g.clone(), g.as_ref().and_then(|r| r.java.clone()))
        };
        if let Some(r) = &src {
            if r.host_jar.is_file() && r.host_jar != host {
                std::fs::copy(&r.host_jar, &host).ok();
            }
            if r.montoya_jar.is_file() && r.montoya_jar != montoya {
                std::fs::copy(&r.montoya_jar, &montoya).ok();
            }
        }
        if !host.is_file() {
            return Err(anyhow!(
                "the JVM host jar is unavailable — reinstall Shrike, or run jvm-host/build.sh in a dev checkout"
            ));
        }
        if !montoya.is_file() {
            download(JVM_MONTOYA_URL, &montoya)?;
        }

        let jython = dest.join("jython-standalone.jar");
        let jython = jython.is_file().then_some(jython);
        let legacy = dest.join("burp-extender-api.jar");
        let legacy = legacy.is_file().then_some(legacy);
        *self.jvm_resources.lock().expect("jvm lock") = Some(JvmResources {
            java: bundled_java,
            host_jar: host,
            montoya_jar: montoya,
            jython_jar: jython,
            legacy_api_jar: legacy,
        });
        Ok(self.jvm_status())
    }

    /// One-click Jython setup: ensure the Java runtime is staged, then download
    /// the Jython standalone jar and the legacy Extender API so Python BApps
    /// can run (they `import burp` and use the legacy callbacks API).
    pub fn jython_setup(&self) -> Result<JvmStatus> {
        self.jvm_setup()?;
        let dest = self.config().data_dir.join("jvm");
        let jython = dest.join("jython-standalone.jar");
        if !jython.is_file() {
            download(JVM_JYTHON_URL, &jython)?;
        }
        let legacy = dest.join("burp-extender-api.jar");
        if !legacy.is_file() {
            download(JVM_LEGACY_API_URL, &legacy)?;
        }
        if let Some(r) = self.jvm_resources.lock().expect("jvm lock").as_mut() {
            r.jython_jar = Some(jython);
            r.legacy_api_jar = Some(legacy);
        }
        Ok(self.jvm_status())
    }

    pub fn set_plugin_enabled(&self, id: &str, on: bool) -> Result<Vec<PluginManifest>> {
        let mut reg = self.plugins.write().expect("plugins lock");
        reg.set_enabled(id, on);
        self.persist_plugins(&reg)?;
        Ok(reg.manifests())
    }

    pub fn clear_history(&self) -> Result<()> {
        self.store.clear()
    }
}

/// Read the persisted scope; a missing or corrupt entry yields an empty scope
/// (nothing in scope) rather than silently widening it.
fn load_scope(store: &Store) -> Scope {
    match store.get_meta(META_SCOPE) {
        Ok(Some(json)) => match serde_json::from_str::<Vec<ScopeRule>>(&json) {
            Ok(rules) => match Scope::from_rules(rules) {
                Ok(scope) => scope,
                Err(e) => {
                    warn!(error = %e, "stored scope has an invalid rule; starting with an empty scope");
                    Scope::empty()
                }
            },
            Err(e) => {
                warn!(error = %e, "stored scope is unreadable; starting with an empty scope");
                Scope::empty()
            }
        },
        Ok(None) => Scope::empty(),
        Err(e) => {
            warn!(error = %e, "could not read stored scope; starting with an empty scope");
            Scope::empty()
        }
    }
}

/// Read the persisted match & replace rules; a missing or corrupt entry yields
/// an empty rule set (nothing rewritten) rather than failing engine startup.
fn load_match_replace(store: &Store) -> MatchReplace {
    match store.get_meta(META_MATCH_REPLACE) {
        Ok(Some(json)) => serde_json::from_str::<Vec<MatchReplaceRule>>(&json)
            .ok()
            .and_then(|rules| MatchReplace::from_rules(rules).ok())
            .unwrap_or_else(|| {
                warn!("stored match & replace rules are unreadable; starting with none");
                MatchReplace::empty()
            }),
        _ => MatchReplace::empty(),
    }
}

/// Read the persisted plugin manifests; a missing or corrupt entry yields an
/// empty registry rather than failing engine startup.
fn load_plugins(store: &Store) -> PluginRegistry {
    match store.get_meta(META_PLUGINS) {
        Ok(Some(json)) => serde_json::from_str::<Vec<PluginManifest>>(&json)
            .ok()
            .and_then(|list| PluginRegistry::from_manifests(list).ok())
            .unwrap_or_else(|| {
                warn!("stored plugins are unreadable; starting with none");
                PluginRegistry::empty()
            }),
        _ => PluginRegistry::empty(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UpstreamTlsMode;

    fn test_config(dir: &std::path::Path) -> ProxyConfig {
        ProxyConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            data_dir: dir.to_path_buf(),
            upstream_tls: UpstreamTlsMode::Verify,
            max_capture_bytes: 1024 * 1024,
            passthrough_hosts: Vec::new(),
            drop_out_of_scope: false,
            chromium_path: None,
            github_token: String::new(),
            intruder_require_scope: true,
            request_timeout_ms: 30_000,
            history_max_rows: 0,
        }
    }

    #[test]
    fn host_lines_update_state_and_events() {
        let state = Arc::new(Mutex::new(RunningBapp::default()));
        assert_eq!(ingest_host_line(&state, "sha", "@OUT:hello").stream, "out");
        assert_eq!(ingest_host_line(&state, "sha", "@ERR:boom").line, "boom");
        let meta = r#"{"ok":true,"name":"X","registered":["registerHttpHandler","suiteTab:Logger"],"outputs":["o1"],"errors":[],"uiWindows":1}"#;
        assert_eq!(ingest_host_line(&state, "sha", meta).stream, "meta");
        // an unprefixed line is the extension's own stdout -> shown as output
        assert_eq!(ingest_host_line(&state, "sha", "noise").stream, "out");

        let s = state.lock().unwrap();
        assert_eq!(s.name.as_deref(), Some("X"));
        assert_eq!(s.suite_tabs, vec!["Logger".to_string()]);
        assert_eq!(s.windows, 1);
        assert!(s.outputs.contains(&"hello".to_string()));
        assert!(s.outputs.contains(&"o1".to_string()));
        // unprefixed noise is forwarded as an event but not trusted into state
        assert!(!s.outputs.contains(&"noise".to_string()));
        assert!(s.errors.contains(&"boom".to_string()));
    }

    #[test]
    fn start_stop_is_idempotent_and_binds() {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::new(test_config(dir.path())).unwrap();
        assert!(!engine.is_running());

        let addr = engine.start_proxy().unwrap();
        assert_ne!(addr.port(), 0, "should bind a concrete port");
        assert!(engine.is_running());
        // second start returns the same address, does not rebind
        assert_eq!(engine.start_proxy().unwrap(), addr);

        engine.stop_proxy().unwrap();
        assert!(!engine.is_running());
        engine.stop_proxy().unwrap(); // idempotent
    }

    #[test]
    fn scope_persists_across_engine_restart_and_rejects_bad_regex() {
        let dir = tempfile::tempdir().unwrap();
        {
            let engine = Engine::new(test_config(dir.path())).unwrap();
            assert!(engine.scope_rules().is_empty());
            engine
                .set_scope(vec![ScopeRule::include_host(".kept.test")])
                .unwrap();
            assert!(engine.in_scope_url("https://a.kept.test/"));
            // an invalid rule set is rejected and the live scope is untouched
            let bad = ScopeRule {
                host: "(".into(),
                is_regex: true,
                ..ScopeRule::include_host("")
            };
            assert!(engine.set_scope(vec![bad]).is_err());
            assert!(
                engine.in_scope_url("https://a.kept.test/"),
                "scope unchanged after rejected update"
            );
        }
        let engine = Engine::new(test_config(dir.path())).unwrap();
        assert_eq!(
            engine.scope_rules().len(),
            1,
            "scope reloaded from the project store"
        );
        assert!(engine.in_scope_url("https://a.kept.test/"));
        assert!(!engine.in_scope_url("https://other.test/"));
    }
}
