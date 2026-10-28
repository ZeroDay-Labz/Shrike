# Developing & testing Shrike

Everything here runs from the repo root: the repository root.
Prereqs are already installed on this box: Rust 1.98, Node 22, webkit2gtk-4.1.

## First time only
```sh
npm --prefix ui install      # frontend deps (React, Vite, Tauri CLI, CodeMirror…)
```

## Run the desktop GUI
```sh
npm run dev                  # starts Vite + the Shrike window, with hot reload
```
- Edit anything in `ui/` and the window reloads automatically.
- Edit Rust in `engine/` or `src-tauri/` and Tauri rebuilds and relaunches.
- If the webview glitches on this Fedora box:
  `WEBKIT_DISABLE_DMABUF_RENDERER=1 npm run dev`
- `cargo run` does **not** launch the GUI (Tauri needs its own CLI). Use `npm run dev`.

### Webview stability on Linux (WebKitGTK)
WebKitGTK's GPU/DMABUF renderer crashes the webview on some Linux GPU/driver combos
(Mesa). The symptom is the **whole app aborting mid-session with SIGABRT and no Rust
panic** — the abort is on the GTK/WebKit main thread, inside Mesa, not in our code.
Captured traffic is **not lost** (history autosaves to the project DB via WAL).
Mitigations, already applied:
- Shrike sets `WEBKIT_DISABLE_DMABUF_RENDERER=1` automatically at startup on Linux
  (in `src-tauri/src/lib.rs::run`, overridable by setting the env var yourself), and
  the `npm run dev` script exports it too.
- The UI avoids `backdrop-filter`/blur, a known WebKitGTK compositing crash trigger.

If it still crashes, add the stronger fallback (disables accelerated compositing
entirely — more stable, slightly less smooth):
```sh
WEBKIT_DISABLE_COMPOSITING_MODE=1 npm run dev
```

## Run the headless proxy (no window)
```sh
cargo cli                        # listens on 127.0.0.1:8080
cargo cli -- -v                  # verbose: dump full requests/responses
cargo cli -- -l 0.0.0.0:8080 -k  # LAN listener, accept invalid upstream certs
cargo cli -- ca info             # CA path + SHA-256 fingerprint
cargo cli -- ca trust            # trust the CA in local Firefox/Chrome profiles
```

## Browser setup and trusting the CA

**Easiest: the integrated browser.** In the GUI, Start the proxy and click **Browser** —
Shrike launches a bundled (or system) Chromium already pointed at the proxy and already
trusting the CA (via an SPKI allow-list), in an isolated profile. No FoxyProxy, no manual
certificate import. The steps below are only for using your *own* external browser.

1. **Point the browser at Shrike.** Add an HTTP proxy: host `127.0.0.1`, port `8080`
   (or whatever Shrike's Start shows), enabled for all URLs. Any browser works; Shrike
   is a plain HTTP(S) proxy.
2. **Trust the CA once** (already done on this box for Chrome/Firefox/Thunderbird):
   ```sh
   cargo cli -- ca trust            # imports into local Firefox/Chrome/Thunderbird NSS stores
   ```
   Then **restart the browser** so it reloads its certificate database. To check it took, browse to
   `http://shrike/` *through the proxy*: the landing page shows the CA fingerprint; compare it with
   `cargo cli -- ca info`.
3. **For curl / system tools** (optional):
   ```sh
   sudo cp ~/.local/share/shrike/ca/ca.cert.pem /etc/pki/ca-trust/source/anchors/shrike-ca.crt && sudo update-ca-trust
   ```

### Reading the TLS errors in the log
- `UnknownCA` — that browser does not trust the Shrike CA yet. Run `ca trust` and restart it.
- `BadCertificate` — either the CA is only partially imported in that profile (restart the browser),
  **or the site pins its certificate**. Browsers hard-pin their vendors' own domains (Chrome: Google
  properties; Firefox: Mozilla properties) and reject *any* interception, exactly as happens with
  every MITM proxy. Those sites cannot be intercepted; add them to **Settings → Passthrough** so they
  tunnel untouched, e.g. `.google.com`, `.gstatic.com`, `.googleapis.com`, `.mozilla.org`,
  `.mozilla.net`, `.firefox.com`. Add any other domain that keeps failing the same way.
- Shrike's own certificates are verified well-formed (SAN, server-auth EKU, AKI/SKI, ECDSA-P256,
  365-day validity under Chrome's 398-day cap; `openssl verify` passes against the CA).

### App icon
- **Windows:** taken from `src-tauri/icons/icon.ico` via the bundle config.
- **Linux X11:** set programmatically on the main window (title bar / taskbar), in dev and packaged.
- **Linux Wayland:** compositors take the dock icon from the installed `.desktop` entry matching the
  app id (`com.zerodaylabz.shrike`), which the packaged build (`.rpm`/AppImage/Flatpak) installs. A
  bare `npm run dev` may therefore still show a generic icon on Wayland; the packaged app will not.

## Quick end-to-end smoke test (no browser)
```sh
# terminal 1: start the proxy
cargo cli
# terminal 2: push a request through it
cargo cli -- ca export /tmp/shrike-ca.crt
curl -s --proxy http://127.0.0.1:8080 --cacert /tmp/shrike-ca.crt https://example.com/ | head
```
Then open the GUI (`npm run dev`), click **Start**, and browse — rows stream into
HTTP history live.

## Tests
```sh
cargo test                   # whole workspace: engine unit + e2e (130+ engine lib + 8 e2e)
cargo test -p shrike-engine  # engine only
cargo test -p shrike-engine --lib store   # one module
cargo clippy --workspace --all-targets -- -D warnings   # lint (CI gate)
npm --prefix ui run build    # type-check + bundle the frontend (tsc + vite)
```

Point Shrike at a throwaway project with `SHRIKE_DATA_DIR=/tmp/shrike-dev` (CA, history
and settings live there) — handy for tests, demos and screenshots.

## Build release artifacts (packaging)
```sh
npm run build                # Tauri bundles for THIS host:
                             #   Linux  -> AppImage + .rpm
                             #   Windows-> NSIS .exe installer
scripts/package-tarball.sh   # portable Linux .tar.gz (GUI + CLI + resources)
```
Releases are automated: pushing a `v*` tag runs `.github/workflows/release.yml`, which
builds the `.rpm`, AppImage, portable `.tar.gz` (Linux), the NSIS `.exe` (Windows runner)
and a `.flatpak` (from the tarball via `packaging/flatpak/`), and attaches them to the
GitHub release. Re-run against an existing tag with
`gh workflow run release.yml -f tag=vX.Y.Z`.

**Chromium is bundled into every release.** CI runs `node scripts/fetch-chromium.mjs`
(cross-platform; pins `src-tauri/chromium-version.txt`) before `tauri build`, so Chrome for
Testing is folded into each installer and the integrated browser works offline with no system
browser. This adds ~150–250 MB per installer. For a local self-contained build run the same
script first. `scripts/fetch-jvm.sh` similarly fetches the JVM host jars + a jlink runtime;
Jython is still fetched on demand at runtime.

## Where things live
| What | Path |
| --- | --- |
| Data dir (CA, project DB) | `~/.local/share/shrike/` |
| Project history DB | `~/.local/share/shrike/projects/default.sqlite` |
| Proxy default listen | `127.0.0.1:8080` |
| Vite dev server | `http://localhost:1420` |
| Override data dir | `SHRIKE_DATA_DIR=/path npm run dev` |
| Log level | `RUST_LOG=shrike_engine=debug npm run dev` |
