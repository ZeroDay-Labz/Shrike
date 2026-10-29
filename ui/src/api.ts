import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  CaInfo, ConfigView, DiffMode, DiffSeg, HistoryFilter, InterceptItem, MatchReplaceRule, PluginManifest, ProjectMeta, ProxyStatus, ScopeRule, SequencerReport, SiteNode, TrafficStats,
  AttackEvent, DecodeOp, Generator, IntruderConfig, PreviewResult, RequestSpec, SendResult, StepResult, TransactionSummary, TransactionView, WsMessage,
  Annotation, Finding, FindingUpdate, NewFinding,
} from "./types";

export const api = {
  proxyStatus: () => invoke<ProxyStatus>("proxy_status"),
  proxyStart: () => invoke<ProxyStatus>("proxy_start"),
  proxyStop: () => invoke<ProxyStatus>("proxy_stop"),
  configGet: () => invoke<ConfigView>("config_get"),
  configSet: (config: ConfigView) => invoke<ConfigView>("config_set", { config }),
  historyPage: (filter: HistoryFilter, limit: number, offset: number) =>
    invoke<TransactionSummary[]>("history_page", { filter, limit, offset }),
  historyCount: (filter: HistoryFilter) => invoke<number>("history_count", { filter }),
  historyQuery: (query: string, limit: number, offset: number) =>
    invoke<TransactionSummary[]>("history_query", { query, limit, offset }),
  historyQueryCount: (query: string) => invoke<number>("history_query_count", { query }),
  historyGet: (id: number) => invoke<TransactionView | null>("history_get", { id }),
  historyClear: () => invoke<void>("history_clear"),
  siteMap: () => invoke<SiteNode[]>("site_map"),
  trafficStats: () => invoke<TrafficStats>("traffic_stats"),
  crawlerStart: (seed: string) => invoke<void>("crawler_start", { seed }),
  crawlerStop: () => invoke<void>("crawler_stop"),
  activeScanStart: (transactionId: number) => invoke<void>("active_scan_start", { transactionId }),
  activeScanStop: () => invoke<void>("active_scan_stop"),
  findingsList: () => invoke<Finding[]>("findings_list"),
  findingCreate: (finding: NewFinding) => invoke<Finding>("finding_create", { finding }),
  findingUpdate: (id: number, update: FindingUpdate) =>
    invoke<Finding | null>("finding_update", { id, update }),
  findingDelete: (id: number) => invoke<boolean>("finding_delete", { id }),
  annotations: () => invoke<Annotation[]>("annotations"),
  annotationSet: (transactionId: number, color: string | null, note: string | null) =>
    invoke<void>("annotation_set", { transactionId, color, note }),
  findingsReport: (format: "json" | "html") => invoke<string>("findings_report", { format }),
  projectInfo: () => invoke<ProjectMeta>("project_info"),
  projectSetName: (name: string) => invoke<ProjectMeta>("project_set_name", { name }),
  projectBackup: (path: string) => invoke<string>("project_backup", { path }),
  projectIntegrity: () => invoke<boolean>("project_integrity"),
  importTraffic: (path: string) => invoke<number>("import_traffic", { path }),
  startupTool: () => invoke<string | null>("startup_tool"),
  uiStateGet: (key: string) => invoke<string | null>("ui_state_get", { key }),
  uiStateSet: (key: string, value: string) => invoke<void>("ui_state_set", { key, value }),
  caInfo: () => invoke<CaInfo>("ca_info"),
  caExport: (path: string) => invoke<string>("ca_export", { path }),
  scopeGet: () => invoke<ScopeRule[]>("scope_get"),
  scopeSet: (rules: ScopeRule[]) => invoke<ScopeRule[]>("scope_set", { rules }),
  scopeCheck: (url: string) => invoke<boolean>("scope_check", { url }),
  matchReplaceGet: () => invoke<MatchReplaceRule[]>("match_replace_get"),
  matchReplaceSet: (rules: MatchReplaceRule[]) => invoke<MatchReplaceRule[]>("match_replace_set", { rules }),
  interceptGetEnabled: () => invoke<boolean>("intercept_get_enabled"),
  interceptSetEnabled: (on: boolean) => invoke<void>("intercept_set_enabled", { on }),
  interceptResolve: (id: number, action: "forward" | "drop", raw?: string) =>
    invoke<void>("intercept_resolve", { id, action, raw: raw ?? null }),
  repeaterSend: (spec: RequestSpec) => invoke<SendResult>("repeater_send", { spec }),
  intruderStart: (config: IntruderConfig) => invoke<number>("intruder_start", { config }),
  intruderStop: (id: number) => invoke<void>("intruder_stop", { id }),
  intruderPreview: (config: IntruderConfig) => invoke<PreviewResult>("intruder_preview", { config }),
  intruderGenerate: (generator: Generator) => invoke<string[]>("intruder_generate", { generator }),
  decodeChain: (input: string, ops: DecodeOp[]) => invoke<StepResult[]>("decode_chain", { input, ops }),
  compare: (a: string, b: string, mode: DiffMode) => invoke<DiffSeg[]>("compare", { a, b, mode }),
  sequencerAnalyze: (tokens: string[]) => invoke<SequencerReport>("sequencer_analyze", { tokens }),
  pluginsList: () => invoke<PluginManifest[]>("plugins_list"),
  extrasList: () => invoke<import("./types").ExtraStatus[]>("extras_list"),
  extraSetEnabled: (id: string, on: boolean) =>
    invoke<import("./types").ExtraStatus[]>("extra_set_enabled", { id, on }),
  pluginAdd: (manifest: PluginManifest) => invoke<PluginManifest[]>("plugin_add", { manifest }),
  pluginRemove: (id: string) => invoke<PluginManifest[]>("plugin_remove", { id }),
  pluginSetEnabled: (id: string, on: boolean) => invoke<PluginManifest[]>("plugin_set_enabled", { id, on }),
  bappCatalog: () => invoke<import("./types").BappEntry[]>("bapp_catalog"),
  bappCatalogFull: (refresh: boolean) => invoke<import("./types").BappEntry[]>("bapp_catalog_full", { refresh }),
  bappInstallEntry: (id: string) => invoke<import("./types").InstallOutcome>("bapp_install_entry", { id }),
  bappImports: () => invoke<import("./types").PackageInspection[]>("bapp_imports"),
  bappImport: (path: string) => invoke<import("./types").PackageInspection[]>("bapp_import", { path }),
  bappRemove: (sha256: string) => invoke<import("./types").PackageInspection[]>("bapp_remove", { sha256 }),
  openExternal: (url: string) => invoke<void>("open_external", { url }),
  launchBrowser: () => invoke<import("./types").BrowserStatus>("launch_browser"),
  browserAvailable: () => invoke<boolean>("browser_available"),
  jvmStatus: () => invoke<import("./types").JvmStatus>("jvm_status"),
  jvmSetup: () => invoke<import("./types").JvmStatus>("jvm_setup"),
  jythonSetup: () => invoke<import("./types").JvmStatus>("jython_setup"),
  bappInstall: (path: string) => invoke<import("./types").InstalledBapp[]>("bapp_install", { path }),
  bappInstallUrl: (url: string) => invoke<import("./types").InstalledBapp[]>("bapp_install_url", { url }),
  bappInstalled: () => invoke<import("./types").InstalledBapp[]>("bapp_installed"),
  bappUninstall: (sha256: string) => invoke<import("./types").InstalledBapp[]>("bapp_uninstall", { sha256 }),
  bappRun: (sha256: string) => invoke<string[]>("bapp_run", { sha256 }),
  bappStop: (sha256: string) => invoke<string[]>("bapp_stop", { sha256 }),
  bappRunning: () => invoke<string[]>("bapp_running"),
  bappRunningMeta: () => invoke<import("./types").RunningBapp[]>("bapp_running_meta"),
  jwtDecode: (token: string) => invoke<import("./types").JwtParts>("jwt_decode", { token }),
  jwtSign: (header: string, payload: string, alg: string, secret: string) =>
    invoke<string>("jwt_sign", { header, payload, alg, secret }),
  jwtVerify: (token: string, secret: string) => invoke<boolean>("jwt_verify", { token, secret }),
};

export const events = {
  /** Newly captured transactions, oldest first, flushed every ~80 ms. */
  onTrafficBatch: (cb: (rows: TransactionSummary[]) => void): Promise<UnlistenFn> =>
    listen<TransactionSummary[]>("traffic-batch", (e) => cb(e.payload)),
  onWs: (cb: (w: WsMessage) => void): Promise<UnlistenFn> =>
    listen<WsMessage>("traffic-ws", (e) => cb(e.payload)),
  onIntruder: (cb: (ev: AttackEvent) => void): Promise<UnlistenFn> =>
    listen<AttackEvent>("intruder-event", (e) => cb(e.payload)),
  onIntercept: (cb: (item: InterceptItem) => void): Promise<UnlistenFn> =>
    listen<InterceptItem>("intercept-request", (e) => cb(e.payload)),
  onBappOutput: (cb: (o: import("./types").BappOutput) => void): Promise<UnlistenFn> =>
    listen<import("./types").BappOutput>("bapp-output", (e) => cb(e.payload)),
  onFinding: (cb: (f: Finding) => void): Promise<UnlistenFn> =>
    listen<Finding>("finding-added", (e) => cb(e.payload)),
  onCrawl: (cb: (ev: import("./types").CrawlEvent) => void): Promise<UnlistenFn> =>
    listen<import("./types").CrawlEvent>("crawl-progress", (e) => cb(e.payload)),
  onScan: (cb: (ev: import("./types").ActiveScanEvent) => void): Promise<UnlistenFn> =>
    listen<import("./types").ActiveScanEvent>("scan-progress", (e) => cb(e.payload)),
  onBrowserClosed: (cb: () => void): Promise<UnlistenFn> =>
    listen("browser-closed", () => cb()),
};
