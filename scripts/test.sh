#!/usr/bin/env bash
# Unit tests (`scripts/test.sh`). Humans and CI get the usual pytest output.
# Under a coding agent the full `pytest -v` output goes to .test-logs/ and only the
# totals, each failure (short traceback, captured output) and the log path are printed.
# Extra arguments go to pytest.
set -uo pipefail
cd "$(dirname "$0")/.."
if [ -z "${PYTHON:-}" ]; then PYTHON=python; [ -x .venv/bin/python ] && PYTHON=.venv/bin/python; fi

is_agent() {
  case "${AI_AGENT:-}" in 0|false|no|off) return 1 ;; "") ;; *) return 0 ;; esac
  [ -n "${CLAUDECODE:-}${CODEX_THREAD_ID:-}${CODEX_SANDBOX:-}${GEMINI_CLI:-}${CURSOR_AGENT:-}${OPENCODE:-}" ]
}

pytest=("$PYTHON" -m pytest tests)
if ! is_agent; then "${pytest[@]}" "$@"; exit $?; fi

export NO_COLOR=1
mkdir -p .test-logs
log=".test-logs/pytest-$(date +%Y%m%d-%H%M%S)-$$.log"
"${pytest[@]}" -v -o verbosity_assertions=2 -rfE --tb=short --color=no "$@" >"$log" 2>&1; rc=$?
if [ "$rc" -eq 0 ]; then
  tail -n 1 "$log"
elif grep -qE '^=+ (FAILURES|ERRORS) =+$' "$log"; then
  # failures, errors, short summary and totals; the warnings summary stays in the log
  awk '/^=+ (FAILURES|ERRORS) =+$/ {on=1} /^=+ warnings summary =+$/ {skip=1; next} skip && /^=+ / {skip=0} on && !skip' "$log" | head -n 200
else
  tail -n 30 "$log"
fi
echo "exit=$rc full log: $log"
exit "$rc"
