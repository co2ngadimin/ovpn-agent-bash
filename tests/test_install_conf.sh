#!/usr/bin/env bash
# Tests for installer pieces (server.conf ensure, event scripts, logrotate) on fixture dirs only.
cd "$(dirname "$0")/.." || exit 1
D=$(mktemp -d); trap 'rm -rf "$D"' EXIT
fail=0
ok()  { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; fail=1; }
# Source functions only; main must not run. Stub systemctl so no real unit is queried.
mkdir -p "$D/bin"; printf '#!/bin/sh\nexit 3\n' > "$D/bin/systemctl"; chmod +x "$D/bin/systemctl"
load() { export PATH="$D/bin:$PATH"; set +e; source ./deploymentovpn.sh; set +e; OVPN_ROOT=$1; }
BASE="port 1194\nuser nobody\nstatus /var/log/openvpn/status.log\nverb 3"

# 1. new layout: detect, install scripts, add missing directives with backup
R="$D/new"; mkdir -p "$R/etc/openvpn/server"; printf "$BASE" > "$R/etc/openvpn/server/server.conf"  # no final newline
( load "$R"
  detect_openvpn_conf && [ "$OVPN_CONF" = "$R/etc/openvpn/server/server.conf" ] && [ "$OVPN_UNIT" = openvpn-server@server ] \
    && ok "new layout detected" || bad "new layout detected"
  setup_access_logging > "$D/out1"
  [ "$OVPN_CONF_CHANGED" = 1 ] && ok "changed flag" || bad "changed flag"
)
C="$R/etc/openvpn/server/server.conf"
for want in "status-version 2" "log-append /var/log/openvpn/openvpn.log" "script-security 2" \
            "client-connect /etc/openvpn/server/connect.sh" "client-disconnect /etc/openvpn/server/disconnect.sh"; do
  grep -qx "$want" "$C" && ok "added: $want" || bad "added: $want"
done
[ "$(grep -c '^verb' "$C")" = 1 ] && [ "$(grep -c '^status ' "$C")" = 1 ] && ok "existing kept once" || bad "existing kept once"
grep -qx "verb 3" "$C" && ok "no line merged at missing final newline" || bad "no line merged"
ls "$C".bak.* >/dev/null 2>&1 && ok "backup made" || bad "backup made"
[ -x "$R/etc/openvpn/server/connect.sh" ] && [ -x "$R/etc/openvpn/server/disconnect.sh" ] && ok "scripts installed" || bad "scripts installed"
bash -n "$R/etc/openvpn/server/connect.sh" && bash -n "$R/etc/openvpn/server/disconnect.sh" && ok "scripts syntax" || bad "scripts syntax"

( load "$D/new"; [ "$(openvpn_unit)" = openvpn-server@server ] ) && ok "env unit new layout" || bad "env unit new layout"
( load "$D/none"; [ "$(openvpn_unit)" = openvpn@server ] ) && ok "env unit default" || bad "env unit default"
grep -q '^OPENVPN_UNIT="$(openvpn_unit)"$' deploymentovpn.sh && ok "unit written to .env" || bad "unit written to .env"

# 2. idempotent: second run changes nothing, no new backup
cp "$C" "$D/before"; nb=$(ls "$C".bak.* | wc -l)
( load "$R"; detect_openvpn_conf; setup_access_logging >/dev/null; [ "$OVPN_CONF_CHANGED" = 0 ] ) && ok "rerun: flag 0" || bad "rerun: flag 0"
cmp -s "$C" "$D/before" && [ "$(ls "$C".bak.* | wc -l)" = "$nb" ] && ok "rerun: unchanged" || bad "rerun: unchanged"

# 3. old layout + conflicting client-connect: warn, keep it, unit openvpn@server
R="$D/old"; mkdir -p "$R/etc/openvpn"; C="$R/etc/openvpn/server.conf"
printf "$BASE\nclient-connect /etc/openvpn/other.sh\n#client-disconnect /x\n" > "$C"
( load "$R"; detect_openvpn_conf && [ "$OVPN_UNIT" = openvpn@server ] && setup_access_logging > "$D/out3" ) \
  && ok "old layout detected" || bad "old layout detected"
grep -qx "client-connect /etc/openvpn/other.sh" "$C" && [ "$(grep -c '^client-connect' "$C")" = 1 ] && ok "conflict kept" || bad "conflict kept"
grep -q "other.sh" "$D/out3" && ok "conflict warned" || bad "conflict warned"
grep -qx "client-disconnect /etc/openvpn/disconnect.sh" "$C" && ok "commented directive ignored" || bad "commented directive ignored"

# 4. existing `log` directive blocks log-append
R="$D/log"; mkdir -p "$R/etc/openvpn"; printf "log /var/log/openvpn.log\n" > "$R/etc/openvpn/server.conf"
( load "$R"; detect_openvpn_conf; setup_access_logging >/dev/null )
grep -q "^log-append" "$R/etc/openvpn/server.conf" && bad "log not doubled" || ok "log not doubled"

# 5. no config: skip, no failure
( load "$D/none"; setup_access_logging >/dev/null ) && ok "no conf skipped" || bad "no conf skipped"

# 6. writers keep the exact line format; no Telegram call without env file
S="$D/new/etc/openvpn/server"
printf '#!/bin/sh\ntouch %s/curl-called\n' "$D" > "$D/bin/curl"; chmod +x "$D/bin/curl"
for s in connect disconnect; do sed "s#/var/log/openvpn/user_activity.log#$D/act.log#" "$S/$s.sh" > "$D/$s.sh"; done
PATH="$D/bin:$PATH" common_name='an,di' trusted_ip=1.2.3.4 ifconfig_pool_remote_ip=10.8.0.2 bash "$D/connect.sh"; r1=$?
PATH="$D/bin:$PATH" common_name=andi trusted_ip=1.2.3.4 bytes_received=100 bytes_sent=x bash "$D/disconnect.sh"; r2=$?
[ $r1 = 0 ] && [ $r2 = 0 ] && ok "scripts exit 0" || bad "scripts exit 0"
grep -Eqx '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]{8},CONNECT,an_di,1\.2\.3\.4,10\.8\.0\.2' "$D/act.log" && ok "CONNECT format" || bad "CONNECT format"
grep -Eqx '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]{8},DISCONNECT,andi,1\.2\.3\.4,100,0' "$D/act.log" && ok "DISCONNECT format" || bad "DISCONNECT format"
[ ! -e "$D/curl-called" ] && ok "no telegram without env" || bad "no telegram without env"
grep -q "TELEGRAM_BOT_TOKEN" "$S/connect.sh" && ! grep -Eq '[0-9]{8,}:[A-Za-z0-9_-]{20,}' "$S/connect.sh" "$S/disconnect.sh" \
  && ok "token from env only" || bad "token from env only"

# 7. logrotate configs: copytruncate for openvpn/agent logs, create for activity, no postrotate; valid syntax
R="$D/lr"; mkdir -p "$R/etc/logrotate.d"
( load "$R"; SCRIPT_DIR="$D/agent"; setup_openvpn_logrotate; setup_user_activity_logrotate; setup_agent_logrotate ) <<< $'y\ny\ny' >/dev/null
L="$R/etc/logrotate.d"
grep -q copytruncate "$L/openvpn-main-log" && grep -q copytruncate "$L/openvpn-agent-logs" && ok "copytruncate" || bad "copytruncate"
grep -q "create 0640 nobody nogroup" "$L/openvpn-activity-log" && grep -q delaycompress "$L/openvpn-activity-log" && ok "activity create" || bad "activity create"
grep -rq "postrotate\|reload" "$L" && bad "no postrotate" || ok "no postrotate"
grep -q "size 10M" "$L/openvpn-agent-logs" && grep -q "rotate 2" "$L/openvpn-agent-logs" && ! grep -q monthly "$L/openvpn-agent-logs" \
  && ok "agent size 10M rotate 2" || bad "agent size 10M rotate 2"
for f in "$L"/*; do sed "s#/var/log/openvpn#$D/vl#" "$f" > "$D/lr.conf"; logrotate -d -s "$D/lr.state" "$D/lr.conf" >/dev/null 2>&1 \
  && ok "logrotate -d $(basename "$f")" || bad "logrotate -d $(basename "$f")"; done
# Rerun rewrites our own (outdated) file instead of skipping it.
printf '/var/log/openvpn/openvpn.log {\n postrotate\n endscript\n}\n' > "$L/openvpn-main-log"
( load "$R"; setup_openvpn_logrotate ) <<< y >/dev/null
grep -q postrotate "$L/openvpn-main-log" && bad "own config refreshed" || ok "own config refreshed"

# 7b. Telegram fires when telegram.env sets both vars (curl is backgrounded, so poll briefly)
printf 'TELEGRAM_BOT_TOKEN=1\nTELEGRAM_CHAT_ID=1\n' > "$D/telegram.env"
PATH="$D/bin:$PATH" common_name=andi bash "$D/connect.sh"
for _ in 1 2 3 4 5 6 7 8 9 10; do [ -e "$D/curl-called" ] && break; sleep 0.2; done
[ -e "$D/curl-called" ] && ok "telegram with env" || bad "telegram with env"

# 8. installer no longer force-rotates every system log
grep -q "logrotate -f" deploymentovpn.sh && bad "no logrotate -f" || ok "no logrotate -f"
# 9. executed via `bash -c "$(curl ...)"` main still runs (refuses non-root here)
if [ "$(id -u)" -ne 0 ]; then
  bash -c "$(cat deploymentovpn.sh)" </dev/null 2>&1 | grep -q "root privileges" && ok "bash -c runs main" || bad "bash -c runs main"
fi
exit $fail
