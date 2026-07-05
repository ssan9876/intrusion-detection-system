#!/usr/bin/env bash
# In-place updater for an existing Signature NIDS install.
#
# Safe to re-run. Pulls the latest code, refreshes the deployed app and its
# dependencies, and restarts the service — WITHOUT touching your data
# (alert DB + daily logs) or your config (/etc/nids/nids.env).
#
# Run as root inside the container, from a checkout of this repo:
#   git -C /opt/nids-src pull   # or clone it once; see README
#   bash /opt/nids-src/deploy/update.sh
#
# You can also point it at a specific checkout / branch:
#   SRC_DIR=/root/intrusion-detection-system bash deploy/update.sh
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/nids}"
SRC_DIR="${SRC_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
SERVICE="${SERVICE:-nids.service}"

if [ ! -d "$APP_DIR" ]; then
  echo "[!] $APP_DIR not found — this box doesn't look installed yet."
  echo "    Run deploy/install.sh for a first-time install instead."
  exit 1
fi

old_ver="$("$APP_DIR/venv/bin/python" -c 'import ids; print(ids.__version__)' 2>/dev/null || echo "unknown")"
new_ver="$(cd "$SRC_DIR" && python3 -c 'import ids; print(ids.__version__)' 2>/dev/null || echo "unknown")"
echo "[*] Updating Signature NIDS: $old_ver -> $new_ver"

# If the source is a git checkout, fast-forward it so 'update' also fetches.
if [ -d "$SRC_DIR/.git" ]; then
  echo "[*] Fetching latest code in $SRC_DIR"
  git -C "$SRC_DIR" pull --ff-only || echo "[!] git pull skipped (local changes or detached HEAD)"
fi

echo "[*] Validating new rules before deploying"
if ! (cd "$SRC_DIR" && python3 -c "from ids.rules import RuleSet; RuleSet.load('rules/default.rules.json')"); then
  echo "[!] New ruleset failed to load — aborting update, service left running."
  exit 1
fi

echo "[*] Refreshing application code in $APP_DIR"
# Replace code dirs atomically-ish; data/ and the venv are left untouched.
for d in ids rules web; do
  rm -rf "$APP_DIR/$d.new"
  cp -r "$SRC_DIR/$d" "$APP_DIR/$d.new"
  rm -rf "$APP_DIR/$d"
  mv "$APP_DIR/$d.new" "$APP_DIR/$d"
done
cp "$SRC_DIR/requirements.txt" "$APP_DIR/requirements.txt"

echo "[*] Updating Python dependencies"
"$APP_DIR/venv/bin/pip" install --upgrade pip -q
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

echo "[*] Refreshing systemd unit"
cp "$SRC_DIR/deploy/nids.service" "/etc/systemd/system/$SERVICE"
# Show any new settings the operator may want to add (never overwrites their env).
if ! diff -q "$SRC_DIR/deploy/nids.env.example" /etc/nids/nids.env >/dev/null 2>&1; then
  echo "[i] deploy/nids.env.example changed since your /etc/nids/nids.env was written."
  echo "    Review new options (e.g. IDS_PORTSCAN_THRESHOLD) — your config was NOT modified."
fi

chown -R nids:nids "$APP_DIR/data" 2>/dev/null || true

echo "[*] Restarting $SERVICE"
systemctl daemon-reload
systemctl restart "$SERVICE"
sleep 1
systemctl is-active --quiet "$SERVICE" && state="active" || state="FAILED"

echo
echo "[+] Update complete: now running $new_ver (service: $state)"
if [ "$state" != "active" ]; then
  echo "[!] Service is not active — check: journalctl -u $SERVICE -n 40 --no-pager"
  exit 1
fi
echo "    Verify:  curl -s http://localhost:8080/api/status"
