#!/bin/bash
set -e
if [ "$EUID" -ne 0 ]; then exit 1; fi
SERVICE_NAME="$1"
AGENT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
systemctl stop "$SERVICE_NAME" 2>/dev/null || true
systemctl disable "$SERVICE_NAME" 2>/dev/null || true
pkill -f "$AGENT_DIR/main.py" 2>/dev/null || true
sleep 2
rm -f "/etc/systemd/system/$SERVICE_NAME.service"
systemctl daemon-reload
rm -rf "$AGENT_DIR"
echo "✅ Self-destruct complete."
