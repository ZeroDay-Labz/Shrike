# Plugin / extension compatibility model

Shrike ships its **own** extension API. BApp extensions are not binary-compatible
(they target the JVM-based Montoya/Extender API). Compatibility is therefore
staged and each extension is classified honestly.

## Current state

Implemented today (`engine/src/plugins`): a **data-only registry** — plugin
manifests (`id`, `name`, `version`, `author`, `description`, `permissions`,
`hooks`, `enabled`), validated for unique ids, persisted in the project, with
install/enable/disable/remove and a UI (Extender tool). **There is no execution
runtime yet** — installing records a manifest; it does not run code. The
permission and hook model defined here is what the runtime will enforce.

## Three runtime types (staged)

### 1. Native sandboxed plugins (primary)
Plugins written for Shrike, run in a lightweight isolated environment. Evaluation:
**WebAssembly / WASI** (e.g. `wasmtime`) with per-plugin memory bounds, execution
timeouts, fuel/CPU limits, and explicit host capabilities — no JVM. A typed,
versioned host interface (not raw access to engine internals) exposes:
request/response analysis, passive analysis, payload transforms, context-menu
actions, data extraction, history annotations, scanner checks, report generation,
and plugin settings. Deliverable for this track: a typed ABI, a sample plugin, and
lifecycle tests (init / event dispatch / timeout / cancel / crash-recovery /
disabled-receives-nothing).

### 2. BApp compatibility host (investigation, optional)
An *optional, on-demand* Java worker process implementing a **minimal subset** of
Montoya services actually used by one or two high-value extensions, talking to the
Rust core over typed, bounded local IPC. Rules: do not recreate the whole API; pick
one small representative extension; inspect its real API usage, license, and
permissions; prototype; measure memory/CPU/latency; only expand if justified. If
direct execution needs substantial missing APIs, that is **reported as a
limitation, not hidden**. Never one JVM per extension; never required for native
plugins.

### 3. Source-based native adaptation
For extensions whose source + license permit, port the *small useful function*
into the native API, keeping required attribution/license notices. Preferred over
bridging when a native equivalent is cheap — and skipped entirely when Shrike
already has the capability.

## Classification states

Every imported extension carries one status: `catalog-only`, `downloaded`,
`inspected`, `license-verified` / `license-unresolved`, `native-compatible`,
`bridge-compatible`, `needs-source-adaptation`, `unsupported`, `disabled`,
`quarantined`. Only a supported runtime + satisfied dependencies yields an
executable status. The UI explains *why* something is unsupported and what, if
anything, unlocks it.

## First-extension value matrix (candidates — not promises)

| Extension | Want | Shrike already has | Preferred path |
| --- | --- | --- | --- |
| Logger++ | rich history + filtering | Logger tool (history + filter) | native (extend Logger) |
| Hackvertor | payload transforms | Decoder + match&replace + Intruder processors | native (extend transforms) |
| JWT Editor | decode/edit/verify JWTs | — (gap) | native plugin (good first WASM plugin) |
| Param Miner | hidden param discovery | partial (Intruder) | native scanner check later |
| Turbo Intruder | advanced request scheduling | Intruder (bounded concurrency) | native enhancement |

Most high-value workflows map to **native** work, not bridging. The first native
plugin target is likely **JWT inspection** (clear gap, self-contained, safe).

## Security posture

Downloaded extensions are untrusted: staging/quarantine dir, SHA-256 recorded
(for identity/integrity, not authenticity), archive inspected before install
(path-traversal / zip-bomb / malformed guards), never auto-executed, explicit
per-capability approval, disable/uninstall/quarantine controls, audit log, and
crash/timeout isolation so a faulty plugin cannot take down the core or corrupt
the project DB. Core scope limits stay in the core — a plugin cannot widen scope
or bypass safety limits. A subprocess boundary alone is not treated as a complete
sandbox; OS isolation is applied where practical and residual risk documented.
