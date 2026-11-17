# ADR-002: Collect OpenVPN access logs with client-connect scripts and logrotate-safe tailing

**Status:** Accepted
**Date:** 2026-11-18
**Deciders:** repo owner (yoga / kki)

## Context

The dashboard needs every node's access events (who connected or disconnected, from which public IP, VPN IP, bytes, time) plus the OpenVPN server log, shipped to `/api/agent/report-activity-logs` and `/api/agent/report-openvpn-logs` (forwarded to Loki). Logs on the node must keep rotating without losing lines.

Today the installer only `touch`es `/var/log/openvpn/user_activity.log` and `openvpn.log`; nothing writes them and `server.conf` is never configured, so on a fresh node the activity feed stays empty and OpenVPN output goes to journald. Some prod nodes were fixed by hand with `node-setup/connect.sh` / `disconnect.sh`. The agent's tailer loses the unread tail of a rotated file and does not notice truncation; one logrotate rule reloads a unit name the rest of the installer does not use.

Constraints: no new dependencies on nodes (bash + Python stdlib + the agent's existing venv); must not break nodes already configured by hand; the dashboard contract stays as is.

## Decision

1. Installer installs `client-connect` / `client-disconnect` scripts that append one CSV line per event (`YYYY-MM-DD HH:MM:SS,CONNECT,cn,publicIp,vpnIp` and `...,DISCONNECT,cn,publicIp,bytesReceived,bytesSent`), the format the agent and dashboard already parse. Telegram notify stays optional (off unless its env file is set).
2. Installer ensures, idempotently and with a backup, `status ... status-version 2`, `log-append /var/log/openvpn/openvpn.log`, `verb 3`, `script-security 2`, `client-connect`, `client-disconnect` in whichever `server.conf` layout and unit (`openvpn@server` / `openvpn-server@server`) the node uses. Existing hooks pointing elsewhere are not overwritten (warn instead). OpenVPN restarts only when something changed and the operator confirms.
3. Node logrotate: `copytruncate` for `openvpn.log` and the agent's own logs; `create` for the activity log. No forced global `logrotate -f`.
4. Agent tailer: finish the rotated predecessor (`<path>.1`) from the saved offset before starting the new file, reset on truncation, write state atomically.

## Options Considered

### Option A: client-connect / client-disconnect scripts (chosen)
| Dimension | Assessment |
|-----------|------------|
| Complexity | Low: two short bash scripts + conf directives |
| Cost | None |
| Scalability | One line per event; fine for hundreds of users per node |
| Team familiarity | High: already used by hand on prod nodes |

**Pros:** exact events incl. short sessions; public IP and bytes at disconnect; same format as today.
**Cons:** needs `script-security 2` and an OpenVPN restart once; a node's existing custom hook must be merged by hand.

### Option B: derive events from `status.log` diffs
| Dimension | Assessment |
|-----------|------------|
| Complexity | Medium: state diffing in the agent |
| Cost | None |
| Scalability | Fine |
| Team familiarity | Medium |

**Pros:** no OpenVPN config change or restart.
**Cons:** misses sessions shorter than the poll interval; no bytes on disconnect; timestamps only as precise as the poll.

### Option C: parse OpenVPN's own server log
| Dimension | Assessment |
|-----------|------------|
| Complexity | Medium-high: regexes per verb level and version |
| Cost | None |
| Scalability | Fine |
| Team familiarity | Low |

**Pros:** no scripts.
**Cons:** format varies by version/verb; fragile; bytes not reliably present.

## Trade-off Analysis

A is the only option that gives complete, exact events with public IP and traffic, and it is already proven on prod nodes. Its one cost (a one-time OpenVPN restart, `script-security 2`) is paid once per node with operator confirmation. B and C avoid the restart but produce incomplete or fragile data, which defeats the point of an access log.

## Consequences

- Easier: fresh nodes (e.g. client Singhapay) report access events out of the box; logs rotate without loss.
- Harder: nodes with hand-made hooks need a manual merge (installer warns, does not overwrite).
- Revisit: dashboard retry policy for permanent 404 / Loki-500 and per-line split of rejected batches (out of scope here); timezone of OpenVPN server log timestamps.

## Action Items

1. [ ] Implement per `docs/design/2026-11-18-access-logs-design.md` with tests (in progress on `feat/agent-revamp`).
2. [ ] Pilot on one node (reuse `upgrade-agent.sh` for the agent; run the conf-ensure step once), compare the dashboard Logs page with `user_activity.log`.
3. [ ] Follow-ups listed under Revisit.
