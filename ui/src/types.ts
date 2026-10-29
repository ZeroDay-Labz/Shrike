export interface Header { name: string; value: string }

export interface Service { host: string; port: number; secure: boolean }

export interface BodyView {
  len: number;
  wire_len: number;
  complete: boolean;
  is_text: boolean;
  text?: string;
  base64?: string;
}

export interface RequestView {
  id: number;
  client_addr: string;
  service: Service;
  method: string;
  target: string;
  url: string;
  version: string;
  headers: Header[];
  body: BodyView;
  started_at_ms: number;
}

export interface ResponseView {
  status: number;
  reason: string;
  version: string;
  headers: Header[];
  body: BodyView;
  received_at_ms: number;
  mime?: string;
}

export interface TransactionView {
  request: RequestView;
  response?: ResponseView;
  error?: string;
  duration_ms: number;
}

export interface TransactionSummary {
  id: number;
  host: string;
  port: number;
  secure: boolean;
  method: string;
  url: string;
  status?: number;
  mime?: string;
  req_len: number;
  resp_len: number;
  duration_ms: number;
  started_at_ms: number;
  client_addr: string;
  error?: string;
  /** Container highlight colour (e.g. from a PwnFox X-PwnFox-Color header). */
  highlight?: string;
}

export interface HistoryFilter {
  host?: string | null;
  method?: string | null;
  status?: number | null;
  status_class?: number | null;
  search?: string | null;
  only_errors?: boolean | null;
}

export interface ProxyStatus { running: boolean; listen: string }

export interface ConfigView {
  listen: string;
  insecure_upstream: boolean;
  passthrough_hosts: string[];
  max_capture_bytes: number;
  data_dir: string;
  drop_out_of_scope: boolean;
  capture_in_scope_only: boolean;
  chromium_path: string;
  github_token: string;
  intruder_require_scope: boolean;
  request_timeout_ms: number;
  history_max_rows: number;
  passive_scan_enabled: boolean;
}

export interface BrowserStatus {
  pid: number;
  proxy: string;
  profile: string;
  chromium: string;
}

export type RuleKind = "include" | "exclude";

export interface ScopeRule {
  enabled: boolean;
  kind: RuleKind;
  host: string;
  port?: number | null;
  path?: string | null;
  is_regex: boolean;
}

export type MatchReplacePart =
  | "request_header" | "request_body" | "response_header" | "response_body";

export interface MatchReplaceRule {
  enabled: boolean;
  name: string;
  part: MatchReplacePart;
  is_regex: boolean;
  match: string;
  replace: string;
}

export interface ProjectMeta {
  name: string;
  path: string;
  created_at_ms: number;
  schema_version: number;
  size_bytes: number;
  temporary: boolean;
}

export interface CaInfo { cert_path: string; fingerprint: string }

export interface SiteNode {
  host: string;
  port: number;
  secure: boolean;
  path: string;
  method: string;
  status?: number;
  mime?: string;
  id: number;
}

export interface InterceptItem {
  id: number;
  raw: string;
  host: string;
  port: number;
  secure: boolean;
}

export interface WsMessage {
  url: string;
  direction: "c2s" | "s2c";
  kind: string;
  len: number;
  text?: string;
  client_addr: string;
}

export interface RequestSpec {
  service: Service;
  method: string;
  target: string;
  headers: Header[];
  body: string;
}

export interface SendResult {
  response: ResponseView;
  duration_ms: number;
}

export type AttackType = "sniper" | "battering_ram" | "pitchfork" | "cluster_bomb";

export type Processor =
  | { type: "url_encode" }
  | { type: "base64_encode" }
  | { type: "hex_encode" }
  | { type: "json_escape" }
  | { type: "upper" }
  | { type: "lower" }
  | { type: "prefix"; text: string }
  | { type: "suffix"; text: string }
  | { type: "replace"; from: string; to: string };

export interface IntruderConfig {
  service: Service;
  template: string;
  attack: AttackType;
  payload_sets: string[][];
  concurrency: number;
  delay_ms: number;
  processors: Processor[];
}

export type Generator =
  | { kind: "numbers"; from: number; to: number; step: number }
  | { kind: "brute_force"; charset: string; min_len: number; max_len: number }
  | { kind: "case_variations"; word: string }
  | { kind: "null_payloads"; count: number };

export interface PreviewResult {
  positions: number;
  total: number | null;
  capped_at: number;
  requests: string[];
}

export interface AttackResult {
  index: number;
  payloads: string[];
  status?: number;
  length: number;
  duration_ms: number;
  error?: string;
}

export type AttackEvent =
  | { kind: "started"; attack_id: number; total: number; capped: boolean }
  | ({ kind: "result" } & AttackResult)
  | { kind: "results"; results: AttackResult[] }
  | { kind: "done"; attack_id: number; completed: number; stopped: boolean };

export type DecodeOp =
  | "url_encode" | "url_decode"
  | "base64_encode" | "base64_decode"
  | "hex_encode" | "hex_decode"
  | "html_encode" | "html_decode"
  | "upper" | "lower";

export interface StepResult { output?: string; error?: string }

export interface TrafficStats {
  total: number;
  errors: number;
  websockets: number;
  distinct_hosts: number;
  by_status_class: [number, number][];
  by_method: [string, number][];
  top_hosts: [string, number][];
}

export interface SequencerReport {
  count: number;
  unique: number;
  min_len: number;
  max_len: number;
  mean_len: number;
  bits_per_char: number;
  alphabet: number;
  bits_per_token: number;
  verdict: string;
}

export type PluginPermission = "read_traffic" | "modify_traffic" | "active_scan" | "storage";
export type PluginHook = "on_request" | "on_response" | "passive_scan" | "active_scan";

export interface PluginManifest {
  id: string;
  name: string;
  version: string;
  description: string;
  author: string;
  permissions: PluginPermission[];
  hooks: PluginHook[];
  enabled: boolean;
}

export interface BappEntry {
  id: string;
  name: string;
  author: string;
  category: string;
  description: string;
  repo_url: string;
  listing_url: string;
  runtime: string;
  native_equivalent: string | null;
  download_url?: string | null;
  featured?: boolean;
}

export interface PackageInspection {
  filename: string;
  sha256: string;
  size_bytes: number;
  format: string;
  runtime: string;
  compatibility: string;
  warnings: string[];
}

export interface JvmStatus {
  available: boolean;
  java: string | null;
  version: string | null;
  host_jar: boolean;
  jython: boolean;
}

export interface InstalledBapp {
  sha256: string;
  filename: string;
  path: string;
  format: string;
  name: string | null;
  enabled: boolean;
  status: string;
  registered: string[];
  outputs: string[];
  errors: string[];
  origin?: string | null;
}

export type InstallOutcome =
  | { kind: "installed"; installed: InstalledBapp[] }
  | { kind: "not_installable"; reason: string; source_url: string };

export interface RunningBapp {
  sha256: string;
  name: string | null;
  registered: string[];
  suite_tabs: string[];
  windows: number;
  outputs: string[];
  errors: string[];
}

export interface BappOutput {
  sha256: string;
  stream: "out" | "err" | "meta";
  line: string;
}

export interface JwtParts {
  header: string;
  payload: string;
  signature: string;
  alg: string | null;
  typ: string | null;
  warnings: string[];
}

export type DiffMode = "words" | "chars";

export type DiffSeg =
  | { kind: "equal"; text: string }
  | { kind: "insert"; text: string }
  | { kind: "delete"; text: string };

// ---- Findings & annotations ----

export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "tentative" | "firm" | "certain";
export type FindingStatus = "open" | "confirmed" | "false_positive" | "resolved";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export interface Finding {
  id: number;
  severity: Severity;
  confidence: Confidence;
  status: FindingStatus;
  title: string;
  detail: string;
  host: string | null;
  path: string | null;
  transaction_ids: number[];
  created_at_ms: number;
  updated_at_ms: number;
}

export interface NewFinding {
  title: string;
  severity?: Severity;
  confidence?: Confidence;
  detail?: string;
  host?: string | null;
  path?: string | null;
  transaction_ids?: number[];
}

export interface FindingUpdate {
  severity?: Severity;
  confidence?: Confidence;
  status?: FindingStatus;
  title?: string;
  detail?: string;
  transaction_ids?: number[];
}

export interface Annotation {
  transaction_id: number;
  color: string | null;
  note: string | null;
  updated_at_ms: number;
}

export type CrawlEvent =
  | { type: "progress"; visited: number; queued: number; last_url: string }
  | { type: "finished"; visited: number; stopped: boolean };

export type ActiveScanEvent =
  | { type: "progress"; done: number; total: number }
  | { type: "finished"; findings: number; stopped: boolean }
  | { type: "error"; message: string };

export interface ExtraStatus {
  id: string;
  name: string;
  category: string;
  kind: "passive" | "active";
  description: string;
  sends_traffic: boolean;
  enabled: boolean;
}
