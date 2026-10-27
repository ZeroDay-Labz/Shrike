# Shrike — Architecture

Shrike is an original, clean-room web-security testing suite in Rust. It models the
*workflows* of the established commercial web security suites but shares no code, assets, or
project format with it. This document describes the architecture as it exists today.

## Workspace layout (Cargo workspace)

| Crate | Path | Role |
| --- | --- | --- |
| `shrike-engine` (`shrike_engine`) | `engine/` | All real logic: CA, proxy, capture model, store, scope, intercept, match&replace, sender, intruder, tools, plugins. Front-end agnostic, headless-testable. |
| `shrike-cli` (`shrike`) | `cli/` | Headless proxy/CLI binary. |
| `shrike-gui` | `src-tauri/` | Tauri v2 desktop app: thin command layer + event bridge over the engine. |
| UI | `ui/` | React + TypeScript + Vite frontend (CodeMirror 6, TanStack Table/Virtual). |

The engine knows nothing about Tauri or React. Both front ends construct an
`Engine` (`engine/src/engine.rs`) and drive it through its methods; the GUI
additionally registers a sink that forwards live traffic to the webview.

## Core data model (`engine/src/core`)

- `message.rs` — the rich capture types: `CapturedRequest`, `CapturedResponse`,
  `Transaction` (request + optional response + error + duration), with `Bytes`
  bodies and `SystemTime` stamps, plus `HttpService` and `Header`. `to_raw()`
  renders HTTP/1.1 wire text.
- `dto.rs` — serializable *views* (`RequestView`, `ResponseView`,
  `TransactionView`, `TransactionSummary`, `BodyView`). Everything crossing the
  engine boundary (Tauri commands, events, the SQLite store) is lowered into
  these. `BodyView` carries text when it decodes cleanly, base64 otherwise, so
  **binary bodies survive** the boundary.
- `events.rs` — the `EventBus`: the proxy emits `TrafficEvent`s
  (`RequestStarted`, `Completed`, `TunnelPassthrough`, `WebSocketMessage`,
  `Intercepted`); a dispatcher task fans them out to `TrafficSink`s off the hot
  path. Sinks today: the SQLite store and the Tauri bridge.

## Capture pipeline

`proxy/` is an intercepting MITM proxy (hudsucker + rustls + a custom CA/leaf
authority). `handler.rs` buffers bodies **frame-by-frame with a memory ceiling**
(so a huge response can't balloon RAM before truncation), enforces **scope**
(`drop_out_of_scope`), applies **intercept** (await a user decision when enabled)
and **match & replace** (text rewrites on request/response), records a
`CapturedRequest`/`Transaction`, and forwards. Shared live state (`scope`,
`interceptor`, `match_replace`) is threaded in as `Arc<RwLock<…>>` so edits apply
without a restart. The manual `sender/` applies the same streaming-bounded capture
plus a per-request deadline.

## Persistence (`engine/src/store`)

A SQLite database (WAL mode) at `<data_dir>/projects/default.sqlite`. A dedicated
writer thread consumes bus events through a channel (rusqlite is blocking), so bus
handlers stay short; a separate pooled read connection runs queries concurrently.

Tables: `project` (metadata + `schema_version`), `transactions` (indexed columns +
full `view_json`), `websocket_messages`, `meta` (key/value: scope, match&replace,
plugins, and `ui:*` per-tool UI state). Schema version is tracked in
`PRAGMA user_version` with a migration runner in `Store::open`. See
[storage-design.md](storage-design.md).

## Tools (all on the shared model)

- **Repeater** — `sender/` sends a `RequestSpec`; manual, not scope-gated.
- **Intruder** — `intruder/` (`§…§` templates, 4 attack types, bounded
  concurrency, payload processing pipeline, payload generators). Enforces target
  **scope** per request and honours an abortable Stop.
- **Decoder / Comparer / Sequencer / JWT** — `tools/` stateless utilities
  (`tools/jwt.rs` decodes/edits and HS-signs/verifies tokens, no JVM).
- **Query** — `query/` compiles the Shrike Query Language into parameterised SQL
  for history search (`Store::query_page`/`query_count`).
- **Import** — `import/` parses XML item exports from other proxy tools into history.
- **Target / site map** — `Store::site_map()` aggregates history into a host→path tree.
- **Dashboard** — `Store::stats()` traffic aggregates.
- **Addons** — `plugins/` native manifest registry (data-only foundation) + a JVM
  **BApp host** (`jvm/` + `jvm-host/`): Java via the Montoya API, Python via Jython +
  the legacy Extender API. `bapp/` is the catalog + quarantining package inspector;
  installs are never executed until an explicit Run.

## GUI boundary (`src-tauri/src/lib.rs`)

Each feature is a `#[tauri::command]` that delegates to an `Engine` method, listed
in `generate_handler![]`. Live traffic flows the other way via `TauriSink`
emitting `traffic-completed` / `traffic-ws` / `traffic-tunnel` /
`intercept-request` / `intruder-event`. The UI wraps these in `ui/src/api.ts`
(`api.*` for commands, `events.*` for listeners).

## Data flow

```
browser → proxy handler → (scope, intercept, match&replace) → EventBus
        → SQLite store (persisted history)  → Tauri event → UI history
        → "Send to" → Repeater / Intruder / Comparer / Decoder
        → Target scope → site map
```

Every record keeps its originating request/response relationship through the
shared `Transaction`/`TransactionView` model and the transaction id.
