#!/usr/bin/env bash
# Provision the Signature NIDS inside a fresh Debian 12 LXC / VM.
# Run as root *inside* the container:  bash install.sh
set -euo pipefail

APP_DIR=/opt/nids
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "[*] Installing OS dependencies"
apt-get update -qq
apt-get install -y --no-install-recommends python3 python3-venv python3-pip libpcap0.8 tcpdump

echo "[*] Creating service user 'nids'"
id nids >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin nids

echo "[*] Deploying application to $APP_DIR"
mkdir -p "$APP_DIR"
cp -r "$SRC_DIR/ids" "$SRC_DIR/rules" "$SRC_DIR/web" "$SRC_DIR/requirements.txt" "$APP_DIR/"
mkdir -p "$APP_DIR/data"

echo "[*] Building virtualenv"
python3 -m venv "$APP_DIR/venv"
"$APP_DIR/venv/bin/pip" install --upgrade pip -q
"$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"

echo "[*] Installing config + systemd unit"
mkdir -p /etc/nids
[ -f /etc/nids/nids.env ] || cp "$SRC_DIR/deploy/nids.env.example" /etc/nids/nids.env
cp "$SRC_DIR/deploy/nids.service" /etc/systemd/system/nids.service
chown -R nids:nids "$APP_DIR/data"

echo "[*] Enabling service"
systemctl daemon-reload
systemctl enable --now nids.service

echo
echo "[+] Done. Dashboard: http://$(hostname -I | awk '{print $1}'):8080"
echo "    Logs:  journalctl -u nids -f"
echo "    Config: /etc/nids/nids.env  (edit then: systemctl restart nids)"
