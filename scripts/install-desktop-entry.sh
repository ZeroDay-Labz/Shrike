#!/usr/bin/env bash
# Install a user-level desktop entry + icon so the taskbar/dock shows the Shrike
# icon for dev runs too (packaged builds ship their own). On Wayland the panel
# matches the window's app id (com.zerodaylabz.shrike) to this .desktop file.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
APP_ID="com.zerodaylabz.shrike"
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
ICONS="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor"
EXEC="${1:-$HERE/target/debug/shrike-gui}"

mkdir -p "$APPS" "$ICONS/512x512/apps" "$ICONS/128x128/apps" "$ICONS/scalable/apps"
cp "$HERE/assets/shrike.png"        "$ICONS/512x512/apps/$APP_ID.png"
cp "$HERE/src-tauri/icons/128x128.png" "$ICONS/128x128/apps/$APP_ID.png"
cp "$HERE/assets/shrike.svg"        "$ICONS/scalable/apps/$APP_ID.svg"

cat > "$APPS/$APP_ID.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Shrike
Comment=Web security testing suite — proxy, repeater, intruder, addons
Exec=$EXEC
Icon=$APP_ID
Terminal=false
Categories=Development;Security;Network;
StartupWMClass=$APP_ID
EOF

command -v update-desktop-database >/dev/null && update-desktop-database "$APPS" 2>/dev/null || true
command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -f -t "$ICONS" 2>/dev/null || true
echo "installed $APPS/$APP_ID.desktop (icon $APP_ID)"
