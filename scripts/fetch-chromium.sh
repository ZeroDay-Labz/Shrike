#!/usr/bin/env bash
# Download a Chrome for Testing build into src-tauri/resources/chromium/ so the
# integrated browser can be bundled with the app. Not run automatically — invoke
# before `npm run build` when you want a self-contained package.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$HERE/src-tauri/resources/chromium"
VER_FILE="$HERE/src-tauri/chromium-version.txt"
VERSION="$(tr -d ' \t\r\n' < "$VER_FILE")"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)   PLAT=linux64 ;;
  Darwin-x86_64)  PLAT=mac-x64 ;;
  Darwin-arm64)   PLAT=mac-arm64 ;;
  MINGW*|MSYS*|CYGWIN*) PLAT=win64 ;;
  *) echo "unsupported platform: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

echo "Resolving Chrome for Testing ($VERSION, $PLAT)…"
if [ "$VERSION" = "stable" ]; then
  JSON="https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json"
  URL="$(curl -fsSL "$JSON" | python3 -c "import json,sys;d=json.load(sys.stdin);print(next(x['url'] for x in d['channels']['Stable']['downloads']['chrome'] if x['platform']=='$PLAT'))")"
else
  JSON="https://googlechromelabs.github.io/chrome-for-testing/known-good-versions-with-downloads.json"
  URL="$(curl -fsSL "$JSON" | python3 -c "import json,sys;d=json.load(sys.stdin);e=next(x for x in d['versions'] if x['version']=='$VERSION');print(next(c['url'] for c in e['downloads']['chrome'] if c['platform']=='$PLAT'))")"
fi

echo "Downloading $URL"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fL "$URL" -o "$tmp/chrome.zip"

# Keep the README; replace any previous Chromium.
find "$DEST" -mindepth 1 ! -name README.md -prune -exec rm -rf {} + 2>/dev/null || true
mkdir -p "$DEST"
unzip -q "$tmp/chrome.zip" -d "$DEST"

echo "Chromium extracted into $DEST"
ls -1 "$DEST"
