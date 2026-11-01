#!/usr/bin/env node
// Download a Firefox build into src-tauri/resources/firefox/ so the integrated
// browser can be bundled into the app, self-contained and offline. Cross-platform
// (Node 22+): used by CI on every runner, and locally on any OS.
//
// Firefox is the integrated browser Shrike configures with its proxy and CA
// (see engine/src/browser). Linux extracts a clean .tar.xz with `tar`; Windows
// unpacks the installer with 7-Zip; macOS is not wired (no macOS release leg).
//
// Usage: node scripts/fetch-firefox.mjs [os]
//   os defaults to the host; one of linux64 | win64 | osx
import { spawnSync } from "node:child_process";
import {
  cpSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = join(dirname(fileURLToPath(import.meta.url)), "..");
const DEST = join(HERE, "src-tauri", "resources", "firefox");
const VER_FILE = join(HERE, "src-tauri", "firefox-version.txt");
const VERSION = existsSync(VER_FILE) ? readFileSync(VER_FILE, "utf8").trim() : "latest";
const LANG = "en-US";

function hostOs() {
  const p = process.platform;
  if (p === "linux") return "linux64";
  if (p === "win32") return "win64";
  if (p === "darwin") return "osx";
  throw new Error(`unsupported host platform ${p}`);
}

const OS = process.argv[2] || hostOs();
const product = VERSION === "latest" ? "firefox-latest-ssl" : `firefox-${VERSION}-ssl`;
// Mozilla's direct-download endpoint 302-redirects to the real artifact.
const url = `https://download.mozilla.org/?product=${product}&os=${OS}&lang=${LANG}`;

console.log(`Firefox ${VERSION} (${OS})\n  ${url}`);
mkdirSync(DEST, { recursive: true });
const tmp = mkdtempSync(join(tmpdir(), "shrike-ff-"));
try {
  const res = await fetch(url); // follows redirects
  if (!res.ok) throw new Error(`download ${res.status} ${res.statusText}`);
  const buf = Buffer.from(await res.arrayBuffer());

  // Replace any previous Firefox but keep the committed README placeholder.
  for (const e of readdirSync(DEST, { withFileTypes: true })) {
    if (e.name !== "README.md") rmSync(join(DEST, e.name), { recursive: true, force: true });
  }

  if (OS === "linux64") {
    const tar = join(tmp, "firefox.tar.xz");
    writeFileSync(tar, buf);
    // The tarball contains a top-level firefox/ directory.
    const r = spawnSync("tar", ["-xJf", tar, "-C", DEST], { stdio: "inherit" });
    if (r.status !== 0) throw new Error(`tar failed (status ${r.status})`);
  } else if (OS === "win64") {
    const exe = join(tmp, "firefox.exe");
    writeFileSync(exe, buf);
    const out = join(tmp, "ff");
    const seven = process.env.SEVENZIP || "7z";
    const r = spawnSync(seven, ["x", "-y", `-o${out}`, exe], { stdio: "inherit" });
    if (r.status !== 0) throw new Error(`7z failed (status ${r.status}); install 7-Zip`);
    // Mozilla installers lay the app out under core/.
    const core = join(out, "core");
    cpSync(existsSync(core) ? core : out, join(DEST, "firefox"), { recursive: true });
  } else {
    throw new Error(`bundling for ${OS} is not wired yet`);
  }

  console.log("Firefox extracted into", DEST);
  for (const e of readdirSync(DEST)) console.log(" ", e);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
