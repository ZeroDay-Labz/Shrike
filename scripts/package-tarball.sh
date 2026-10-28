#!/usr/bin/env bash
# Package a portable Linux tarball from a release build:
#   dist/shrike-<version>-linux-<arch>.tar.gz
# containing the GUI + CLI binaries, the bundled JVM-host jars, the app icon and
# docs. Used by the Release workflow and as the source for the flatpak.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(python3 -c 'import json;print(json.load(open("'"$HERE"'/src-tauri/tauri.conf.json"))["version"])')"
ARCH="$(uname -m)"
NAME="shrike-${VERSION}-linux-${ARCH}"
STAGE="$HERE/dist/$NAME"

GUI="$HERE/target/release/shrike-gui"
CLI="$HERE/target/release/shrike"
[ -x "$GUI" ] || { echo "missing $GUI — run a release build first (tauri build)" >&2; exit 1; }

rm -rf "$STAGE"
mkdir -p "$STAGE/resources"
cp "$GUI" "$STAGE/shrike-gui"
[ -x "$CLI" ] && cp "$CLI" "$STAGE/shrike" || true
cp -r "$HERE/src-tauri/resources/jvm" "$STAGE/resources/" 2>/dev/null || true
# Bundled Chromium (Chrome for Testing), when fetched — the flatpak is built from
# this tarball, so it must carry the browser too.
cp -r "$HERE/src-tauri/resources/chromium" "$STAGE/resources/" 2>/dev/null || true
cp "$HERE/src-tauri/icons/icon.png" "$STAGE/icon.png"
cp "$HERE/README.md" "$STAGE/"
[ -f "$HERE/LICENSE" ] && cp "$HERE/LICENSE" "$STAGE/" || true

mkdir -p "$HERE/dist"
tar -C "$HERE/dist" -czf "$HERE/dist/$NAME.tar.gz" "$NAME"
rm -rf "$STAGE"
echo "built $HERE/dist/$NAME.tar.gz"
