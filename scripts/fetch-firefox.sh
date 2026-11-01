#!/usr/bin/env bash
# Download a Firefox build into src-tauri/resources/firefox/ so the integrated
# browser can be bundled with the app, self-contained and offline. Not run
# automatically; invoke before `npm run build` (or in CI) for a bundled browser.
#
# Firefox is the integrated browser Shrike configures with its proxy and CA
# (see engine/src/browser). Linux extracts a clean tarball; Windows and macOS
# need platform tools (7z / hdiutil) and are handled best-effort.
set -euo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$HERE/src-tauri/resources/firefox"
LANG_CODE="en-US"
# Pin via src-tauri/firefox-version.txt when present, else track the latest.
VER_FILE="$HERE/src-tauri/firefox-version.txt"
VERSION="latest"
if [ -f "$VER_FILE" ]; then
  VERSION="$(tr -d ' \t\r\n' < "$VER_FILE")"
fi

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64)        OS=linux64 ;;
  Darwin-x86_64|Darwin-arm64) OS=osx ;;
  MINGW*|MSYS*|CYGWIN*) OS=win64 ;;
  *) echo "unsupported platform: $(uname -s)-$(uname -m)" >&2; exit 1 ;;
esac

# Mozilla's direct-download endpoint redirects to the real artifact. `latest`
# maps to firefox-latest-ssl; a pinned version downloads that exact release.
if [ "$VERSION" = "latest" ]; then
  URL="https://download.mozilla.org/?product=firefox-latest-ssl&os=${OS}&lang=${LANG_CODE}"
else
  URL="https://download.mozilla.org/?product=firefox-${VERSION}-ssl&os=${OS}&lang=${LANG_CODE}"
fi

echo "Resolving Firefox ($VERSION, $OS)…"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# Keep the README; replace any previous Firefox.
mkdir -p "$DEST"
find "$DEST" -mindepth 1 ! -name README.md -prune -exec rm -rf {} + 2>/dev/null || true

case "$OS" in
  linux64)
    echo "Downloading $URL"
    curl -fL "$URL" -o "$tmp/firefox.tar.xz"
    # The tarball contains a top-level firefox/ directory.
    tar -xJf "$tmp/firefox.tar.xz" -C "$DEST"
    ;;
  win64)
    echo "Downloading $URL"
    curl -fL "$URL" -o "$tmp/firefox.exe"
    # The stub/full installer is a 7z self-extractor; needs 7z on the runner.
    if ! command -v 7z >/dev/null 2>&1; then
      echo "7z is required to unpack the Windows Firefox installer" >&2; exit 1
    fi
    7z x -y -o"$tmp/ff" "$tmp/firefox.exe" >/dev/null
    # Mozilla installers lay the app out under core/.
    if [ -d "$tmp/ff/core" ]; then
      mkdir -p "$DEST/firefox"
      cp -a "$tmp/ff/core/." "$DEST/firefox/"
    else
      cp -a "$tmp/ff/." "$DEST/firefox/"
    fi
    ;;
  osx)
    echo "Downloading $URL"
    curl -fL "$URL" -o "$tmp/firefox.dmg"
    MNT="$(hdiutil attach -nobrowse -readonly "$tmp/firefox.dmg" | awk 'END{print $NF}')"
    mkdir -p "$DEST"
    cp -a "$MNT/Firefox.app" "$DEST/Firefox.app"
    hdiutil detach "$MNT" >/dev/null
    ;;
esac

echo "Firefox extracted into $DEST"
ls -1 "$DEST"
