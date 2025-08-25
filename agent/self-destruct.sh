#!/bin/bash
# self-destruct.sh (Final & Robust Version)
set -e

if [ "$EUID" -ne 0 ]; then
    echo "⛔ This script must be run with sudo."
    exit 1
fi

PM2_APP_NAME="$1"
AGENT_DIR=$(dirname "$(readlink -f "$0")")

echo "🛑 Receiving self-destruct command for '$PM2_APP_NAME'..."

echo "[-] Stopping and deleting PM2 process: $PM2_APP_NAME"
# BUG FIX: Run PM2 as root
pm2 stop "$PM2_APP_NAME" || true
pm2 delete "$PM2_APP_NAME" || true
pm2 save --force

echo "🗑️ Deleting agent installation directory: $AGENT_DIR"
# BUG FIX: Use rm -rf to delete files and directories
rm -rf "$AGENT_DIR"

echo "✅ Agent self-destruct process complete."
