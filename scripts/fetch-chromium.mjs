#!/usr/bin/env node
// Download a Chrome for Testing build into src-tauri/resources/chromium/ so the
// integrated browser can be bundled into the app. Cross-platform (Node 22+):
// used by CI on every runner, and locally on any OS. Node ships `fetch`; zip
// extraction shells out to the platform's bundled tool (`tar` = bsdtar on
// Windows/macOS handles zip; `unzip` on Linux).
//
// Usage: node scripts/fetch-chromium.mjs [platform]
//   platform defaults to the host; one of linux64 | win64 | mac-x64 | mac-arm64
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = join(dirname(fileURLToPath(import.meta.url)), "..");
const DEST = join(HERE, "src-tauri", "resources", "chromium");
const VERSION = readFileSync(join(HERE, "src-tauri", "chromium-version.txt"), "utf8").trim();

function hostPlatform() {
  const p = process.platform;
  const a = process.arch;
  if (p === "linux") return "linux64";
  if (p === "win32") return "win64";
  if (p === "darwin") return a === "arm64" ? "mac-arm64" : "mac-x64";
  throw new Error(`unsupported host platform ${p}-${a}`);
}

const PLAT = process.argv[2] || hostPlatform();

async function resolveUrl() {
  if (VERSION === "stable") {
    const json = await (await fetch(
      "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json",
    )).json();
    const d = json.channels.Stable.downloads.chrome.find((x) => x.platform === PLAT);
    if (!d) throw new Error(`no Stable chrome download for ${PLAT}`);
    return d.url;
  }
  const json = await (await fetch(
    "https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json",
  )).json();
  const e = json.versions.find((x) => x.version === VERSION);
  if (!e) throw new Error(`version ${VERSION} not found`);
  const d = e.downloads.chrome.find((c) => c.platform === PLAT);
  if (!d) throw new Error(`no chrome download for ${VERSION} ${PLAT}`);
  return d.url;
}

function extract(zip, dest) {
  const r = process.platform === "win32"
    ? spawnSync("tar", ["-xf", zip, "-C", dest], { stdio: "inherit" }) // bsdtar handles zip
    : spawnSync("unzip", ["-q", zip, "-d", dest], { stdio: "inherit" });
  if (r.status !== 0) throw new Error(`extract failed (status ${r.status})`);
}

const url = await resolveUrl();
console.log(`Chrome for Testing ${VERSION} (${PLAT})\n  ${url}`);

const tmp = mkdtempSync(join(tmpdir(), "shrike-cft-"));
try {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`download ${res.status} ${res.statusText}`);
  const zip = join(tmp, "chrome.zip");
  writeFileSync(zip, Buffer.from(await res.arrayBuffer()));

  // Replace any previous Chromium but keep the committed README placeholder.
  for (const name of readdirSync(DEST, { withFileTypes: true })) {
    if (name.name !== "README.md") rmSync(join(DEST, name.name), { recursive: true, force: true });
  }
  mkdirSync(DEST, { recursive: true });
  extract(zip, DEST);
  console.log(`Extracted into ${DEST}:`);
  for (const e of readdirSync(DEST)) console.log(`  ${e}`);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
