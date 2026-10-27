#!/usr/bin/env bash
# Stage the bundled JVM BApp host into src-tauri/resources/jvm/:
#   - Montoya API jar + Jython standalone jar (from Maven Central)
#   - the compiled Shrike host jar
#   - a minimal JRE (jlink)
# Requires a JDK (javac + jlink). Run before `npm run build` for a self-contained package.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
LIB="$HERE/jvm-host/lib"
RES="$HERE/src-tauri/resources/jvm"
MONTOYA_VER="${MONTOYA_VER:-2026.7}"
JYTHON_VER="${JYTHON_VER:-2.7.5b1}"
LEGACY_VER="${LEGACY_VER:-2.3}"
mkdir -p "$LIB" "$RES"

echo "Fetching Montoya API $MONTOYA_VER…"
[ -f "$LIB/montoya-api-$MONTOYA_VER.jar" ] || \
  curl -fsSL -o "$LIB/montoya-api-$MONTOYA_VER.jar" \
    "https://repo1.maven.org/maven2/net/portswigger/burp/extensions/montoya-api/$MONTOYA_VER/montoya-api-$MONTOYA_VER.jar"

echo "Fetching legacy Extender API $LEGACY_VER (for Python/Jython extensions)…"
[ -f "$LIB/burp-extender-api-$LEGACY_VER.jar" ] || \
  curl -fsSL -o "$LIB/burp-extender-api-$LEGACY_VER.jar" \
    "https://repo1.maven.org/maven2/net/portswigger/burp/extender/burp-extender-api/$LEGACY_VER/burp-extender-api-$LEGACY_VER.jar"

echo "Fetching Jython $JYTHON_VER (large)…"
[ -f "$LIB/jython-standalone-$JYTHON_VER.jar" ] || \
  curl -fsSL -o "$LIB/jython-standalone-$JYTHON_VER.jar" \
    "https://repo1.maven.org/maven2/org/python/jython-standalone/$JYTHON_VER/jython-standalone-$JYTHON_VER.jar"

echo "Building host jar…"
"$HERE/jvm-host/build.sh"

echo "Staging resources…"
cp "$HERE/jvm-host/build/shrike-host.jar" "$RES/"
cp "$LIB/montoya-api-$MONTOYA_VER.jar" "$RES/"
cp "$LIB/burp-extender-api-$LEGACY_VER.jar" "$RES/" 2>/dev/null || true
cp "$LIB/jython-standalone-$JYTHON_VER.jar" "$RES/" 2>/dev/null || true

if command -v jlink >/dev/null 2>&1; then
  echo "Building minimal JRE with jlink…"
  rm -rf "$RES/runtime"
  jlink --add-modules java.base,java.desktop,java.logging,java.naming,java.sql,jdk.unsupported \
        --no-header-files --no-man-pages --compress=2 --output "$RES/runtime" \
    || echo "jlink failed — bundle a full JRE into $RES/runtime manually"
else
  echo "jlink not found — packaged build will need a system Java unless you add $RES/runtime"
fi
echo "Done: $RES"
