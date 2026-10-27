# Shrike — Feature-gap matrix

Status vs. the public Burp Community (CE) / Professional (Pro) workflows. Honest
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
| Target scope & exclusions | CE | **done** | Enforced in core; include/exclude, regex. |
| Site map | CE | **partial** | Built from history; no active crawl yet. |

## Projects & persistence (spec priority #1)

| Capability | Burp Pro | Shrike | Notes |
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
| Notes/annotations | Pro | **planned** | — |

## Professional features

| Capability | Burp Pro | Shrike | Notes |
| --- | --- | --- | --- |
| Intruder (unthrottled, §-positions) | Pro | **done** | 4 attack types; payload processing; generators (numbers/brute/case/null). |
| Global project search | Pro | **planned** | History LIKE filters exist; full search planned. |
| Advanced history filters | Pro | **partial** | host/method/status/search/errors; more planned. |
| Active scanner + issues | Pro | **planned** | Not started; passive checks need captured responses. |
| Crawler | Pro | **planned** | — |
| Out-of-band (Collaborator-style) | Pro | **planned** | Opt-in, user-configured; not started. |
| Extensibility / plugin API | Pro | **partial** | Manifest registry + permissions/hooks; execution runtime planned. |
| BApp store integration | Pro | **planned** | See [bapp-integration.md](bapp-integration.md). |
| Reporting (HTML/XML/JSON) | Pro | **planned** | Backup/export exists at DB level. |
| REST API | Pro | **planned** | — |

## Explicit non-goals
- Binary compatibility with Burp's proprietary `.burp` project files.
- Running the proprietary Montoya/Extender API in-process. Shrike ships its own
  plugin API; a *separate, optional* Java bridge is an investigation item only
  (see [plugin-compatibility.md](plugin-compatibility.md)).
