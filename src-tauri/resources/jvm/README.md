# Bundled JVM BApp host

Populated by `scripts/fetch-jvm.sh` (not committed — too big):
- `shrike-host.jar`            — Shrike's compatibility host (built from `jvm-host/`)
- `montoya-api-<ver>.jar`      — PortSwigger's published Montoya API (compile/link target)
- `jython-standalone-<ver>.jar`— Jython, for Python BApps
- `runtime/`                   — a minimal JRE from `jlink` (so no system Java is required)

`tauri build` copies this into the app bundle; `resolve_jvm_resources` in
`src-tauri/src/lib.rs` finds `java` (runtime/bin/java) + the jars. In `tauri dev`
the app falls back to a system `java` + `jvm-host/build`+`lib`.
