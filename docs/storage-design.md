# Shrike — Storage / project design

## Choice

A single **SQLite** database per project (rusqlite, WAL mode). SQLite is
transactional, crash-safe, embeddable, and gives a consistent single-file project
artifact — a good fit for single-file project files without a server. Large binary
bodies are stored inside the row today (see "Bodies" for the evolution path).

## Current schema (`schema_version = 1`)

- `project(id=1, name, created_at_ms, schema_version)` — one row of project identity.
- `transactions(id, host, port, secure, method, url, status, mime, req_len,
  resp_len, duration_ms, started_at_ms, client_addr, error, view_json)` —
  indexed metadata columns for fast filtered paging + the full `TransactionView`
  as JSON (`view_json`) for faithful restore, including base64 binary bodies.
  Indexes: host, status, started_at.
- `websocket_messages(seq, url, direction, kind, len, text, client_addr, at_ms)`.
- `meta(key, value)` — key/value settings: `scope`, `match_replace`, `plugins`,
  and `ui:*` per-tool UI state (e.g. `ui:repeater`).

Writes go through a dedicated writer thread fed by a channel from the event bus
(keeps bus handlers short); reads use a separate pooled connection. WAL lets them
run concurrently. This is **incremental persistence** — each transaction is one
`INSERT`, never a full-project rewrite.

## Versioning & migrations

`PRAGMA user_version` holds the on-disk schema version. `run_migrations()` in
`Store::open` applies ordered upgrades and stamps the version. The base tables are
created idempotently (`CREATE TABLE IF NOT EXISTS`), so existing databases upgrade
in place. New versions add `if version < N { … }` blocks.

## Consistency, backup, recovery

- **Autosave**: every record is committed as it arrives (WAL). `Store::flush()`
  drains the writer (used before shutdown and backup).
- **Consistent copy / export** (`backup_to`): `flush()` then `VACUUM INTO <dest>`
  — an atomic, fully consistent snapshot of the whole project (fails if dest
  exists, so it never clobbers). Exposed as `project_backup`. Tested: the copy
  opens, passes integrity check, and holds the same rows.
- **Integrity** (`integrity_check`): `PRAGMA integrity_check`. Exposed as
  `project_integrity`.
- **Crash safety**: WAL + `synchronous=NORMAL` recover the last committed state
  after an interrupted write; reopening replays/truncates the WAL.

## Bodies (large binary responses)

Bodies live in `view_json` (base64 for binary), bounded by `max_capture_bytes`.
Capture is **streaming and memory-bounded**: the sender reads the response
frame-by-frame and retains at most `max_capture_bytes` while still counting the
true wire length and flagging truncated captures; the proxy buffers frame-by-frame
up to a 64 MiB ceiling. A huge response can no longer balloon memory before being
truncated. **Planned**: a separate content-addressed body store (hash → blob)
referenced by transactions, so identical bodies dedupe and the metadata DB stays
small, plus a zero-copy proxy tee that forwards past the ceiling while retaining
only the head.

## What exists vs. planned (project lifecycle)

**Done**: disk project, autosave, schema version + migrations, project metadata,
integrity check, consistent backup/export, Repeater-tab persistence, generic
`ui:*` UI-state persistence, **history retention** (keep newest-N, pruned in the
writer thread; `history_max_rows`, 0 = unlimited) and an on-disk size readout.

**Planned** (next slices, in order):
1. Temporary projects: open a temp-file DB, warn on close, discard on exit.
2. Project chooser at launch (new temp / new disk / open / recent) + a recents
   list stored in an app-level config outside any project.
3. Live open/switch without restart: make the `Store` swappable behind the engine
   (`Arc<ArcSwap<Store>>`-style), rebuild sinks, reload scope/match&replace/
   plugins/UI-state on switch.
4. Intruder config + results persistence; findings + notes/annotations; proxy filter prefs.
5. Content-addressed body store + per-project retention by age/size + disk warnings.

No incompatible or undocumented on-disk format is introduced: it is plain SQLite,
inspectable with any SQLite tool. Compatibility with other tools' proprietary project
files is **not** claimed.
