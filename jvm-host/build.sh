#!/usr/bin/env bash
# Compile the Shrike BApp compatibility host (shrike-host.jar) against the
# bundled Montoya API. Requires a JDK (javac). Run from anywhere.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
MONTOYA="$(ls "$HERE"/lib/montoya-api-*.jar 2>/dev/null | head -1 || true)"
if [ -z "$MONTOYA" ]; then
  echo "Montoya API jar missing in $HERE/lib — run scripts/fetch-jvm.sh first" >&2
  exit 1
fi
rm -rf "$HERE/build/host"
mkdir -p "$HERE/build/host"
# Compile every host source, not just the entry point, so the Montoya object
# model and the bridge compile in alongside Host.
find "$HERE/src" -name '*.java' > "$HERE/build/sources.txt"
javac -cp "$MONTOYA" -d "$HERE/build/host" @"$HERE/build/sources.txt"
jar cfe "$HERE/build/shrike-host.jar" shrike.host.Host -C "$HERE/build/host" .
echo "built $HERE/build/shrike-host.jar (against $(basename "$MONTOYA"))"
