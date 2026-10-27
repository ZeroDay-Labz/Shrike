# Bundled Chromium (Chrome for Testing)

This directory holds the Chromium that Shrike ships as its **integrated browser**.
The actual binaries are **not committed** (hundreds of MB) — they are downloaded at
package time by `scripts/fetch-chromium.sh`, which extracts a
[Chrome for Testing](https://googlechromelabs.github.io/chrome-for-testing/) build
(pinned by `src-tauri/chromium-version.txt`) into this folder, e.g.:

```
resources/chromium/chrome-linux64/chrome          (Linux)
resources/chromium/chrome-win64/chrome.exe        (Windows)
resources/chromium/.../Google Chrome for Testing  (macOS .app)
```

`tauri build` copies this directory into the app bundle (see `bundle.resources`),
and at runtime `src-tauri/src/lib.rs::resolve_bundled_chromium` finds the binary.
In `tauri dev` (no fetched Chromium) the app falls back to a system Chromium.

Run before packaging:

```sh
scripts/fetch-chromium.sh
```

Licensing: Chromium is distributed under a permissive license; include its notices
when redistributing. Chrome for Testing does not auto-update — bump
`chromium-version.txt` to pick up security fixes.
