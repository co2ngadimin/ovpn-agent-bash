#!/usr/bin/env bash
# Safe in-place upgrade of an installed agent: replaces ONLY main.py, then restarts the agent service.
# Never touches .env, .agent_state.json, OpenVPN, PM2 or snmpd. Any failure leaves the node as it was.
#   Real:  sudo bash upgrade-agent.sh <git-ref>
#   Test:  EXTRACT_ONLY=1 bash upgrade-agent.sh <deploymentovpn.sh> <out.py>   (no network, no systemd)
set -euo pipefail

EXPECT_VERSION='AGENT_VERSION = "2.0.0-geo"'
REPO_RAW="https://raw.githubusercontent.com/co2ngadimin/ovpn-agent-bash"

die() { echo "ERROR: $*" >&2; exit 1; }

# Print the body of the Python heredoc (and only that one) from installer $1 into $2.
extract() {
  awk '
    !on && /^[[:space:]]*cat << .?_PYTHON_SCRIPT_EOF_.?([[:space:]]|$)/ { on=1; next }
    on && $0 == "_PYTHON_SCRIPT_EOF_" { done=1; exit }
    on { print }
    END { exit !done }' "$1" > "$2" || die "Python heredoc not found or unterminated in $1"
  [ -s "$2" ] || die "extracted agent is empty"
}

if [ "${EXTRACT_ONLY:-}" = 1 ]; then
  [ $# -eq 2 ] || die "usage: EXTRACT_ONLY=1 $0 <deploymentovpn.sh> <out.py>"
  extract "$1" "$2"
  exit 0
fi

[ $# -eq 1 ] || die "usage: $0 <git-ref>"
REF=$1
[[ $REF =~ ^[A-Za-z0-9._/-]+$ ]] || die "invalid git ref: $REF"
[ "$(id -u)" -eq 0 ] || die "must run as root"

SVC=${SERVICE_NAME:-openvpn-agent}
if ! systemctl cat "$SVC" >/dev/null 2>&1; then
  echo "Service '$SVC' not found. Agent-like services:" >&2
  systemctl list-units --type=service | grep -i agent >&2 || true
  die "set SERVICE_NAME=<name> if the agent uses another service name"
fi

DIR=$(systemctl show -p WorkingDirectory --value "$SVC")
PY=$(systemctl show -p ExecStart --value "$SVC" | sed -n 's/.*argv\[\]=\([^ ;]*\).*/\1/p')
[ -n "$DIR" ] && [ -f "$DIR/main.py" ] || die "cannot find $DIR/main.py for service $SVC"
[ -n "$PY" ] && [ -x "$PY" ] || die "cannot determine the service's python (got '$PY')"

T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
URL="$REPO_RAW/$REF/deploymentovpn.sh"
echo "Downloading $URL"
if command -v curl >/dev/null; then curl -fsSL "$URL" -o "$T/inst.sh"
elif command -v wget >/dev/null; then wget -qO- "$URL" > "$T/inst.sh"
else die "need curl or wget"; fi

extract "$T/inst.sh" "$T/main.py"
"$PY" -m py_compile "$T/main.py" || die "new agent fails py_compile; nothing changed"
grep -q "$EXPECT_VERSION" "$T/main.py" || die "new agent is not $EXPECT_VERSION; nothing changed"

BAK="$DIR/main.py.bak.$(date +%Y%m%d%H%M%S)"
cp -p "$DIR/main.py" "$BAK"
# Restore the old agent and say honestly whether it is running again. Always attempts the restart.
rollback() {
  trap - INT TERM HUP
  cp -p "$BAK" "$DIR/main.py" || echo "WARNING: could not restore $BAK" >&2
  systemctl restart "$SVC" || true
  sleep 3
  if systemctl is-active --quiet "$SVC" && cmp -s "$BAK" "$DIR/main.py"; then
    echo "Rolled back, old agent active ($BAK)." >&2
  else
    echo "ROLLBACK FAILED - old agent not active, run: cp -p '$BAK' '$DIR/main.py' && systemctl restart $SVC" >&2
  fi
}
trap 'rollback; exit 1' INT TERM HUP

# Stage next to the target (same filesystem) so the swap is an atomic rename.
cp "$T/main.py" "$DIR/main.py.new"
{ chmod --reference="$DIR/main.py" "$DIR/main.py.new" && chown --reference="$DIR/main.py" "$DIR/main.py.new"; } \
  || { rm -f "$DIR/main.py.new"; die "cannot copy perms/owner; nothing changed"; }
mv -f "$DIR/main.py.new" "$DIR/main.py"

# Restart=always would hide a crash loop behind "active", so also require an unchanged MainPID.
healthy=0
if systemctl restart "$SVC"; then
  PID1=$(systemctl show -p MainPID --value "$SVC") || PID1=0
  sleep 15
  PID2=$(systemctl show -p MainPID --value "$SVC") || PID2=0
  if systemctl is-active --quiet "$SVC" && [ "$PID1" != 0 ] && [ "$PID1" = "$PID2" ]; then healthy=1; fi
fi

if [ "$healthy" = 1 ]; then
  trap - INT TERM HUP
  journalctl -u "$SVC" -n 20 --no-pager || true
  [ -f "$DIR/logs/agent.log" ] && tail -n 20 "$DIR/logs/agent.log" || true
  echo "Upgrade OK. Backup: $BAK"
  echo "Rollback: cp -p '$BAK' '$DIR/main.py' && systemctl restart $SVC"
  exit 0
fi

echo "Service unhealthy after upgrade; rolling back." >&2
journalctl -u "$SVC" -n 20 --no-pager >&2 || true
[ -f "$DIR/logs/agent.log" ] && tail -n 20 "$DIR/logs/agent.log" >&2 || true  # unit redirects Python output here
rollback
exit 1
