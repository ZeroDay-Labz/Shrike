# Shrike — Feature-gap matrix

Status vs. the workflows of the established commercial suites (community / professional tiers). Honest
labels: **done** (works + tested), **partial** (usable, gaps noted), **planned**.

## Foundational / Community toolkit

| Capability | CE/Pro | Shrike | Notes |
| --- | --- | --- | --- |
| HTTP/HTTPS intercepting proxy | CE | **done** | hudsucker + own CA; `engine/src/proxy`. |
| HTTP(S) history | CE | **done** | SQLite-persisted; full req/resp incl. binary bodies. |
| WebSocket history | CE | **partial** | Messages captured + listed; no WS editor/replay yet. |
| Intercept (pause/edit/forward/drop) | CE | **done (requests)** | Request interception + edit; response interception planned. |
| Match & replace | Pro(auto)/CE(manual) | **done** | Regex/literal over req/resp header/body; persisted. |
| Repeater | CE | **done** | Tabs persist to project (request); responses on Send. |
| Decoder | CE | **done** | url/base64/hex/html/case chains. |
| Sequencer | CE | **partial** | Entropy + shape stats; not a full FIPS battery. |
| Comparer | CE | **done** | Word/char LCS diff. |
| JWT tool | Pro(BApp) | **done** | Native decode / edit / HS256-384-512 + `none` sign & verify (`engine/src/tools/jwt`). |
| Target scope & exclusions | CE | **done** | Enforced in core for proxy **and Intruder** (out-of-scope requests blocked, never sent); include/exclude, regex. |
| Site map | CE | **partial** | Built from history; no active crawl yet. |
| Integrated browser | Pro | **done** | Bundled/system Chromium launched pre-configured for the proxy and already trusting the CA (SPKI allow-list). |
| History query language | Pro | **done** | Shrike Query Language (`engine/src/query`) → parameterised SQL; one query box over history. |
| Import traffic | Pro | **done** | XML item exports from other proxy tools import into history (`engine/src/import`). |

## Projects & persistence (spec priority #1)

| Capability | Commercial Pro tier | Shrike | Notes |
| --- | --- | --- | --- |
| Disk-backed project, autosave | Pro | **done** | SQLite WAL; writer thread autosaves. |
| Schema version + migrations | — | **done** | `PRAGMA user_version` + migration runner. |
| Consistent copy / backup / export | Pro | **done** | `VACUUM INTO` snapshot (`project_backup`). |
| Integrity check / crash recovery | Pro | **partial** | `integrity_check`; WAL gives crash-safety. Formal recovery tests partial. |
| Project metadata (name/path/size/version) | Pro | **done** | Shown + renamable in the top bar. |
| Temporary vs disk project lifecycle | Pro | **planned** | Flag modeled; temp-file create/discard + selection dialog pending. |
| Open/switch projects at runtime | Pro | **planned** | Needs store-swap refactor; today the project opens at launch (`SHRIKE_DATA_DIR`). |
| Recent-projects list, launch chooser | Pro | **planned** | — |
| Repeater tabs persisted | Pro | **done** | Via `ui:repeater` project state. |
| Intruder configs/results persisted | Pro | **planned** | Config persistence next; results persistence after. |
| Notes/annotations | Pro | **planned** | Arrives with Findings. |
| History retention cap | Pro | **done** | Keep newest-N (configurable; 0 = unlimited), pruned in the writer thread. |

## Reliability & safety (hardening)

| Capability | Shrike | Notes |
| --- | --- | --- |
| Streaming bounded body capture | **done** | Sender reads frame-by-frame, retaining ≤ `max_capture` while counting true length; proxy has a 64 MiB buffering ceiling. Handles chunked / no-Content-Length. |
| Request deadlines + cancellation | **done** | Per-request total timeout (`request_timeout_ms`); Intruder Stop aborts in-flight tasks immediately. |
| Safe extension install | **done** | Installs are quarantined (download + hash + classify), never executed until an explicit Run. |
| Hardened external-URL open | **done** | http(s)-only, validated, no shell on Windows. |
| Content-Security-Policy | **done** | Restrictive CSP on the webview. |

## Professional features

| Capability | Commercial Pro tier | Shrike | Notes |
| --- | --- | --- | --- |
| Intruder (unthrottled, §-positions) | Pro | **done** | 4 attack types; payload processing; generators (numbers/brute/case/null). |
| Global project search | Pro | **partial** | Shrike Query Language (`engine/src/query`): host/method/code/url/path/mime/port/len/body, AND/OR/NOT, compiled to parameterised SQL. Cross-tool unification planned. |
| Advanced history filters | Pro | **done** | Basic host/method/status/errors filters + the query language in the Proxy bar. |
| Active scanner + issues | Pro | **planned** | Not started; passive checks need captured responses. |
| Crawler | Pro | **planned** | — |
| Out-of-band (Collaborator-style) | Pro | **planned** | Opt-in, user-configured; not started. |
| Extensibility / plugin API | Pro | **partial** | Manifest registry + permissions/hooks; BApps run in a JVM host (Java/Montoya + Python/Jython). Installs are quarantined and never executed until an explicit Run. Native sandboxed execution runtime planned. |
| BApp store integration | Pro | **done** | Full public catalog mirrored from GitHub; one-click install from a release, committed jar, or source (Python). JVM host runs Java (Montoya) + Python (Jython). See [bapp-integration.md](bapp-integration.md). |
| Reporting (HTML/XML/JSON) | Pro | **planned** | Project backup/export exists at DB level; a Findings-driven report is next. |
| Findings / issues + annotations | Pro | **planned** | Next milestone; central findings list + per-request notes/colours. |
| Workflows / rules engine | Pro | **planned** | Passive/active rules (match → tag/colour/extract); sandboxed native-plugin runtime. |
| REST API | Pro | **planned** | — |

## Explicit non-goals
- Binary compatibility with other tools' proprietary project files.
- Running the proprietary Montoya/Extender API in-process. Shrike ships its own
  plugin API; a *separate, optional* Java bridge is an investigation item only
  (see [plugin-compatibility.md](plugin-compatibility.md)).
