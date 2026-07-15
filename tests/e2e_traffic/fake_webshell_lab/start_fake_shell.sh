#!/usr/bin/env bash
# Start fake JSP webshell lab server (background).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST="${1:-0.0.0.0}"
PORT="${2:-8080}"
PID_FILE="${FAKE_SHELL_PID_FILE:-/tmp/fake_shelljsp_lab.pid}"
LOG_FILE="${FAKE_SHELL_LOG_FILE:-/tmp/fake_shelljsp_lab.log}"
PYTHON_BIN="${FAKE_SHELL_PYTHON:-python3}"

if [[ -f "$PID_FILE" ]]; then
  OLD_PID="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [[ -n "${OLD_PID:-}" ]] && kill -0 "$OLD_PID" 2>/dev/null; then
    echo "ERROR: fake shell already running pid=$OLD_PID (see $PID_FILE)" >&2
    echo "Stop with: $SCRIPT_DIR/stop_fake_shell.sh" >&2
    exit 1
  fi
  rm -f "$PID_FILE"
fi

# Fail fast if port is already in use.
if command -v ss >/dev/null 2>&1; then
  if ss -ltn "( sport = :$PORT )" 2>/dev/null | grep -q ":$PORT"; then
    echo "ERROR: port $PORT already in use" >&2
    exit 1
  fi
fi

: >"$LOG_FILE"
nohup "$PYTHON_BIN" "$SCRIPT_DIR/fake_shell_server.py" \
  --host "$HOST" \
  --port "$PORT" \
  >>"$LOG_FILE" 2>&1 &
PID=$!
echo "$PID" >"$PID_FILE"

# Wait for listen
READY=0
for _ in $(seq 1 30); do
  if ! kill -0 "$PID" 2>/dev/null; then
    echo "ERROR: fake shell exited immediately; see $LOG_FILE" >&2
    cat "$LOG_FILE" >&2 || true
    rm -f "$PID_FILE"
    exit 1
  fi
  if grep -q "FAKE_SHELL_STARTED" "$LOG_FILE" 2>/dev/null; then
    READY=1
    break
  fi
  sleep 0.1
done

if [[ "$READY" -ne 1 ]]; then
  echo "ERROR: fake shell did not report ready; see $LOG_FILE" >&2
  cat "$LOG_FILE" >&2 || true
  kill "$PID" 2>/dev/null || true
  rm -f "$PID_FILE"
  exit 1
fi

# Prefer a probeable URL for local checks.
PROBE_HOST="127.0.0.1"
if [[ "$HOST" != "0.0.0.0" && "$HOST" != "::" && "$HOST" != "[::]" ]]; then
  PROBE_HOST="$HOST"
fi
URL="http://${PROBE_HOST}:${PORT}/shell.jsp"
LAB_URL=""
if [[ "$HOST" == "0.0.0.0" ]]; then
  # Advertise lab IP when bound on all interfaces.
  LAB_IP="$(ip -4 -br addr show br0 2>/dev/null | awk '{print $3}' | cut -d/ -f1 || true)"
  if [[ -n "${LAB_IP:-}" ]]; then
    LAB_URL="http://${LAB_IP}:${PORT}/shell.jsp"
  fi
fi

echo "FAKE_SHELL_URL=$URL"
if [[ -n "$LAB_URL" ]]; then
  echo "FAKE_SHELL_LAB_URL=$LAB_URL"
fi
echo "FAKE_SHELL_PID=$PID"
echo "FAKE_SHELL_PID_FILE=$PID_FILE"
echo "FAKE_SHELL_LOG=$LOG_FILE"
exit 0
