#!/usr/bin/env bash
# Tests for upgrade-agent.sh (extract mode only: no network, no systemd).
cd "$(dirname "$0")/.." || exit 1
D=$(mktemp -d); trap 'rm -rf "$D"' EXIT
fail=0
ok()  { echo "PASS: $1"; }
bad() { echo "FAIL: $1"; fail=1; }

# 1. extraction of the real installer
if EXTRACT_ONLY=1 bash upgrade-agent.sh deploymentovpn.sh "$D/x.py"; then ok "extract exit 0"; else bad "extract exit 0"; fi
python3 -m py_compile "$D/x.py" 2>/dev/null && ok "py_compile" || bad "py_compile"
[ "$(grep -c 'AGENT_VERSION = "2.0.0-geo"' "$D/x.py" 2>/dev/null)" = 1 ] && ok "version once" || bad "version once"
grep -q '_PYTHON_SCRIPT_EOF_\|^cat << ' "$D/x.py" && bad "no heredoc markers leaked" || ok "no heredoc markers leaked"

# 2. input without the python heredoc (other heredocs only) must fail
printf '#!/bin/bash\ncat << '"'EOF'"'\nhello\nEOF\n' > "$D/none.sh"
if EXTRACT_ONLY=1 bash upgrade-agent.sh "$D/none.sh" "$D/none.py" 2>/dev/null; then bad "no heredoc -> nonzero"; else ok "no heredoc -> nonzero"; fi

# 3. unterminated heredoc must fail
printf "cat << '_PYTHON_SCRIPT_EOF_' | tee x\nprint(1)\n" > "$D/unt.sh"
if EXTRACT_ONLY=1 bash upgrade-agent.sh "$D/unt.sh" "$D/unt.py" 2>/dev/null; then bad "unterminated -> nonzero"; else ok "unterminated -> nonzero"; fi

# 4. real mode as non-root refuses (skip when run as root)
if [ "$(id -u)" -ne 0 ]; then
  if bash upgrade-agent.sh main 2>"$D/err"; then bad "non-root refused"; else grep -qi root "$D/err" && ok "non-root refused" || bad "non-root message"; fi
fi
exit $fail
