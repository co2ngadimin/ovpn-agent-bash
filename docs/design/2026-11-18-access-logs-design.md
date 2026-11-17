# Agent revamp: collect all access logs, ship to dashboard, survive logrotate

Status: approved direction (user, 2026-11-18). Base: branch `feat/agent-revamp` = reviewed `feat/geo-map` (`8b83ec2`).

## Intent
Every node must send ALL OpenVPN access events (who connected/disconnected, public IP, VPN IP, bytes, time) and the OpenVPN server log to the dashboard (`/api/agent/report-activity-logs`, `/api/agent/report-openvpn-logs` -> Loki). Logs on the node keep rotating without losing lines.

## Findings (recon)
- Nothing in this repo writes `/var/log/openvpn/user_activity.log`; the installer only `touch`es it. `server.conf` is never edited, so OpenVPN output likely goes to journald and `openvpn.log` stays empty.
- `node-setup/` (outside git) already has the writers used by hand on some prod nodes: `connect.sh` / `disconnect.sh` write `YYYY-MM-DD HH:MM:SS,CONNECT,cn,publicIp,vpnIp` / `...,DISCONNECT,cn,publicIp,bytesReceived,bytesSent` (exact format the agent parses), plus optional Telegram. Its `server.conf` has `status`, `verb 3`, `log-append`, `script-security 2`, `client-connect`, `client-disconnect`.
- Agent tailing: inode change resets offset to 0 and loses the unread tail of the rotated file; truncation (copytruncate) is not detected; state file write is not atomic.
- logrotate: openvpn-main-log postrotate reloads `openvpn-server@server` while the rest of the installer uses `openvpn@server`; agent's own logs use create-mode while systemd holds `StandardOutput=append:`.

## Decisions
1. **Writers:** installer installs `client-connect`/`client-disconnect` scripts (from `node-setup/connect.sh`/`disconnect.sh`, same line format; Telegram part kept optional and off unless `TELEGRAM_BOT_TOKEN`+`TELEGRAM_CHAT_ID` are set) into the server dir next to `server.conf`.
2. **server.conf:** installer detects the active config (`/etc/openvpn/server.conf` or `/etc/openvpn/server/server.conf`) and the unit (`openvpn@server` or `openvpn-server@server`), then ensures — idempotently, only adding missing directives, backup first — `status /var/log/openvpn/status.log`, `status-version 2`, `log-append /var/log/openvpn/openvpn.log`, `verb 3`, `script-security 2`, `client-connect <dir>/connect.sh`, `client-disconnect <dir>/disconnect.sh`. If a `client-connect`/`client-disconnect` already exists pointing elsewhere: do not overwrite, print a warning. Restart OpenVPN only when something changed and only after the user confirms (or `--yes`).
3. **logrotate (node):** `openvpn.log` and agent logs -> `copytruncate` (no reload, works with `log-append` and systemd `append:`), activity log -> `create 0640 nobody nogroup` (scripts open-append per line). Keep monthly/rotate 6 for openvpn logs; agent logs size 10M rotate 2. Remove the unit-name-mismatched postrotate. Never run `logrotate -f /etc/logrotate.conf` (rotates every system log).
4. **Agent tailing:** on inode change, first finish reading the rotated predecessor (`<path>.1`, if its inode matches the saved one) from the saved offset, then start the new file at 0; on `size < position` (truncation) reset to 0; write state atomically (temp + `os.replace`).
5. **Out of scope now:** dashboard parsing changes, Loki labels, 404/Loki-500 retry policy, per-line split of 400 batches (listed as follow-ups).

## Approaches considered
- Derive events from `status.log` diffs (no OpenVPN config change) — rejected: misses short sessions between polls and has no bytes on disconnect.
- Parse OpenVPN's own log for connect/disconnect — rejected: format varies by verb/version, fragile.
- Client-connect/disconnect scripts (chosen) — exact events with public IP and bytes, already proven on prod nodes, same line format the agent and dashboard already handle.

## Verification
TDD in `tests/test_agent.py` for: rotation with unread tail in `.1`, truncation, first run, atomic state, DISCONNECT and malformed-line parsing. Installer pieces: a bash test (`tests/test_install_conf.sh` style, like `tests/test_upgrade.sh`) that runs the server.conf-ensure function on fixture configs (both layouts, already-configured, conflicting client-connect) in a temp dir. `bash -n` on scripts; `python3 -m py_compile` on the extracted agent.

## Implementation notes (2026-11-18)
Commits on `feat/agent-revamp`: `1ed2eb0` (agent tailing), `db0c16e` (installer + logrotate).

What changed (`deploymentovpn.sh`):
- Agent (Decision 4): `save_state` writes `<state>.tmp` then `os.replace` (:546). `process_log_file` (:776) on inode change first drains `<path>.1` from the saved offset when its inode matches the saved one, then reads the new file from 0; `size < position` resets to 0. The read loop moved into `read_log_from` (:821), which now saves state after every pass (also when no line parsed) and returns False on a failed send so a rotated tail is retried, not skipped.
- Writers (Decision 1): `write_connect_script` / `write_disconnect_script` / `install_event_scripts` (:1136-1255) write `connect.sh` / `disconnect.sh` next to `server.conf`; a differing old copy is kept as `*.bak.<ts>` mode 600.
- server.conf (Decision 2): `detect_openvpn_conf` (:1125), `ensure_openvpn_conf` (:1256), `setup_access_logging` (:1285), `restart_openvpn_if_changed` (:1304). Called from `main` (:1500, :1506); `--yes` (:1489) skips the restart prompt.
- logrotate (Decision 3): openvpn.log `copytruncate`, postrotate reload removed (:1321-1360); activity log keeps `create 0640 nobody nogroup` + `delaycompress` (:1368); agent logs `size 10M`, `rotate 2`, `copytruncate`, `monthly` dropped (:1408-1446). The forced `logrotate -f /etc/logrotate.conf` + `restart openvpn@server` prompt is gone.
- Tests: `tests/test_agent.py` (`TailTest`, `ActivityParseTest`), new `tests/test_install_conf.sh` (fixture dirs only, `systemctl`/`curl` stubbed).

Follow-up (commit after `5acb1a4`):
- Service status: installer writes `OPENVPN_UNIT` to `.env` (:451) via `openvpn_unit()` (:1147, reuses `detect_openvpn_conf`, default `openvpn@server`); agent reads it (:521, default `openvpn@server` for old nodes) and `get_openvpn_service_status` (:599) runs `systemctl is-active --quiet <unit>` via `subprocess.run` (list args, no shell).
- copytruncate: on `size < position` (same inode) the agent first reads `<path>.1` from the saved position to its end when `.1` size >= saved position, then the truncated file from 0 (:818). Limits: truncation is only seen if the new file is already smaller than the saved position; a `.1` that is not the copy but happens to be large enough would be read from that offset.

Deviations / choices:
- Telegram env file is `<conf dir>/telegram.env` with `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` (and optional `SERVER_IP`), mode `root:nogroup 0640`, not root-only 0600: OpenVPN runs the scripts as `nobody` (`user nobody`), so a 0600 root file would be unreadable and Telegram would never fire. The installer does not create this file; it prints how to.
- Existing nodes using `node-setup/roti.env` (`BOT_TOKEN`/`CHAT_ID` in `/etc/openvpn/server/script/`) are not migrated; those nodes keep their own `client-connect` line, which the installer leaves in place with a warning.
- Every differing existing directive is warned about (not just `client-connect`/`-disconnect`); an existing `log` or `syslog` also blocks adding `log-append`.
- If both layouts exist, the new one wins only when `openvpn-server@server` is active; otherwise the old one is used.
- The logrotate "already configured" check now ignores the installer's own file, so a rerun rewrites an outdated `openvpn-main-log` instead of skipping it.
- `deploymentovpn.sh` only runs `main` when executed (also via `bash -c`/pipe), not when sourced (needed for the bash test).
- The test venv for `tests/test_agent.py` is `repos/.venv` (has pycryptodome); system `python3` lacks `Crypto` and pytest is not installed, so tests run with `unittest`.

Not done:
- Existing nodes get only the agent fix (via `upgrade-agent.sh`, which replaces `main.py` only); writers, server.conf and logrotate changes need a separate rollout step, since `deploymentovpn.sh` must not be re-run on a node.
- No real `status.log`/server.conf sample from a node was checked; a line half-written at the moment of reading is still sent as-is (writers use one `printf` per line, so unlikely).
