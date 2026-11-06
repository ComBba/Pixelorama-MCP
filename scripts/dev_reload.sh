#!/usr/bin/env bash
# Install ./PixMcpBridge.pck into Pixelorama (macOS) and restart it, then wait for the bridge.
#   scripts/dev_reload.sh [--force]
# Refuses to restart when any open canvas has unsaved changes (checked through the bridge) unless
# --force. Pixelorama quarantines an extension that is listed in extensions/Monitoring.ini when a
# session ends abnormally, so that file is removed before the app is stopped.
# Also installs the boot open guard (pixelorama-plugin/{boot_guard,guard_install,open_guard,security}.gd
# -> <data>/pix_mcp_guard/, autoload line in <data>/override.cfg) and requires /health open_guard=boot.
set -euo pipefail
cd "$(dirname "$0")/.."
DATA="$HOME/Library/Application Support/pixelorama"
APP="/Applications/Pixelorama.app"
PCK="PixMcpBridge.pck"
TOKEN_FILE="$HOME/.pixelorama-mcp/token"
force="${1:-}"

[ -f "$PCK" ] || { echo "build first: godot --headless --script pack.gd"; exit 1; }

if pgrep -x Pixelorama >/dev/null; then
  if [ "$force" != "--force" ]; then
    # token goes through curl's stdin config, never through argv (visible in `ps`)
    if [ -f "$TOKEN_FILE" ] && out=$(printf 'header = "X-Pix-Mcp-Token: %s"\n' "$(cat "$TOKEN_FILE")" | curl -s -m 3 --config - \
        -H "Host: 127.0.0.1:7373" -H "Content-Type: application/json" \
        -d '{"tool":"list_canvases","params":{}}' http://127.0.0.1:7373/command); then
      if printf '%s' "$out" | python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if any(c.get("has_unsaved_changes") for c in d["data"]["canvases"]) else 1)'; then
        echo "Refusing: a canvas has unsaved changes. Save it in Pixelorama or pass --force."; exit 2
      fi
    else
      echo "Refusing: bridge not reachable, cannot confirm there is no unsaved work (use --force)."; exit 2
    fi
  fi
  rm -f "$DATA/extensions/Monitoring.ini"
  kill -TERM "$(pgrep -x Pixelorama)"
  for _ in $(seq 1 20); do pgrep -x Pixelorama >/dev/null || break; sleep 0.5; done
fi

mkdir -p "$DATA/extensions"
rm -f "$DATA/extensions/Monitoring.ini" "$DATA/give_in_bug_report/$PCK"
cp "$PCK" "$DATA/extensions/$PCK"
grep -q '^PixMcpBridge=true' "$DATA/config.ini" 2>/dev/null || printf '\n[extensions]\n\nPixMcpBridge=true\n' >> "$DATA/config.ini"
mkdir -p "$DATA/pix_mcp_guard"
for f in boot_guard.gd guard_install.gd open_guard.gd security.gd; do cp "pixelorama-plugin/$f" "$DATA/pix_mcp_guard/$f"; done
GUARD_LINE='PixMcpOpenGuard="*user://pix_mcp_guard/boot_guard.gd"'
grep -qF "$GUARD_LINE" "$DATA/override.cfg" 2>/dev/null || printf '\n[autoload]\n\n%s\n' "$GUARD_LINE" >> "$DATA/override.cfg"
echo "installed $(shasum -a 256 "$DATA/extensions/$PCK" | cut -c1-16)…"
open -a "$APP"
for i in $(seq 1 40); do
  if r=$(curl -s -m 2 -H "Host: 127.0.0.1:7373" http://127.0.0.1:7373/health) && [ -n "$r" ]; then
    echo "bridge up after ${i}s: $r"
    case "$r" in *'"open_guard":"boot"'*) exit 0 ;; esac
    echo "open guard is not active from boot (see Pixelorama's log)"; exit 3
  fi
  sleep 1
done
echo "bridge did not come up"; exit 1
