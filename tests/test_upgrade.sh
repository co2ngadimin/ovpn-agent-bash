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

# 5. real mode with PATH stubs (no root, no network, no systemd, no real sleeping)
REPO=$PWD
run_real() { # $1=scenario: ok | 404 | crash
  local S="$D/$1"; mkdir -p "$S/bin" "$S/agent" "$S/venv/bin"
  ln -s "$(command -v python3)" "$S/venv/bin/python3"
  echo OLD > "$S/agent/main.py"; echo SECRET > "$S/agent/.env"; echo 100 > "$S/pid"
  [ "$1" = 404 ] && touch "$S/404"; [ "$1" = crash ] && touch "$S/crash"
  printf '#!/bin/sh\necho 0\n' > "$S/bin/id"
  printf '#!/bin/sh\n[ -f %s/crash ] && { rm %s/crash; echo 101 > %s/pid; }\nexit 0\n' "$S" "$S" "$S" > "$S/bin/sleep"
  printf '#!/bin/sh\n[ -f %s/404 ] && exit 22\ncp "%s/deploymentovpn.sh" "$4"\n' "$S" "$REPO" > "$S/bin/curl"
  printf '#!/bin/sh\nexit 0\n' > "$S/bin/journalctl"
  cat > "$S/bin/systemctl" <<SC
#!/bin/sh
case "\$1" in
  cat|restart|is-active) exit 0 ;;
  show) case "\$3" in
    WorkingDirectory) echo $S/agent ;;
    ExecStart) echo "{ path=$S/venv/bin/python3 ; argv[]=$S/venv/bin/python3 $S/agent/main.py ; }" ;;
    MainPID) cat $S/pid ;; esac ;;
esac
SC
  chmod +x "$S"/bin/*
  PATH="$S/bin:$PATH" bash upgrade-agent.sh main >"$S/out" 2>&1; echo $? > "$S/rc"
}
run_real ok
[ "$(cat $D/ok/rc)" = 0 ] && grep -q AGENT_VERSION "$D/ok/agent/main.py" && ls "$D"/ok/agent/main.py.bak.* >/dev/null 2>&1 \
  && [ "$(cat $D/ok/agent/.env)" = SECRET ] && ok "real: success" || { bad "real: success"; cat "$D/ok/out"; }
run_real 404
[ "$(cat $D/404/rc)" != 0 ] && [ "$(cat $D/404/agent/main.py)" = OLD ] && ! ls "$D"/404/agent/main.py.bak.* >/dev/null 2>&1 \
  && ok "real: 404 untouched" || { bad "real: 404 untouched"; cat "$D/404/out"; }
run_real crash
[ "$(cat $D/crash/rc)" != 0 ] && [ "$(cat $D/crash/agent/main.py)" = OLD ] && grep -q "Rolled back" "$D/crash/out" \
  && ok "real: crash loop rolled back" || { bad "real: crash loop rolled back"; cat "$D/crash/out"; }
exit $fail
