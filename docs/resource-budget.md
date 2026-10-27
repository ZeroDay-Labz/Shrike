# Resource budget (low CPU / RAM is a core constraint)

Efficiency is a design constraint, not a late optimization. Shrike reuses its
existing async (tokio), HTTP (hyper/rustls), storage (SQLite WAL + writer thread),
and UI (Tauri webview) components rather than adding heavyweight frameworks or a
permanently-running JVM.

## Standing principles (enforced as features land)

Idle:
- Catalog is cache-first; **no background polling** of external servers.
- Disabled plugins process nothing and hold no ongoing resources.
- Compatibility runtimes (if any) stay unstarted / shut down when idle; never one
  JVM per extension.
- No scanners/requests run merely because something is installed.
- No busy loops — event-driven (the proxy uses an `EventBus` with an unbounded
  channel today; plugin fan-out will use **bounded** channels, see below).

Memory:
- Bounded channels/queues and configurable concurrency for plugin work.
- Stream large HTTP bodies and downloads; `max_capture_bytes` caps retained bodies;
  response-body retention becomes per-project configurable.
- Paginate history (`history_page`); never load the whole project DB into memory.
- Avoid body cloning; share immutable `Bytes`. Planned content-addressed body
  store dedupes identical bodies.
- Per-plugin limits on output size, body inspection, retained results, queued jobs;
  runtime memory caps where supported (WASM linear-memory limit).

CPU:
- Plugin processing async with cancellation + timeouts; backpressure when
  extensions are slower than capture.
- No expensive regex / full-body scans on every UI update; debounce search/filter.
- Events dispatched only to plugins that **registered** for them — never broadcast
  everything to everyone.
- Expensive extensions are independently disableable.

UI thread is never blocked on network, DB, plugin init, or search.

## Benchmark plan (to run before/after the plugin manager)

Scenarios (each measured at steady state):
1. App idle, no extensions.
2. App with cached BApp metadata.
3. Freshly opened project with a large request history.
4. One native plugin enabled.
5. Several native plugins enabled.
6. One Java compatibility worker (if implemented).
7. Several plugins processing captured traffic.
8. A large binary HTTP response.
9. A bounded Intruder attack against the **local mock server** (never a live site).

Record: resident memory (RSS), CPU over a fixed interval, startup time, plugin init
time, per-request processing overhead, UI responsiveness, and queue lengths /
dropped-or-failed events.

Tools available on this box: `/usr/bin/time -v` (max RSS, wall/CPU), `ps -o rss`,
`top`/`/proc/<pid>/status`, and Tauri's own process. Integration load is generated
by a loopback mock HTTP server in the test suite.

## Current baseline

**Not yet formally benchmarked** — no numbers are claimed here. Establishing the
idle + large-history baselines (scenarios 1–3) is the first task of the benchmark
milestone; targets are set *after* measuring, and real results are recorded here.
If a Java compatibility host is built, its measured overhead is documented and
compared against native/WASM, and it stays optional + on-demand.
