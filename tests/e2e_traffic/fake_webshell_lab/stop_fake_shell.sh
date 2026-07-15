#!/usr/bin/env bash
# Stop fake JSP webshell lab server.
set -euo pipefail

PID_FILE="${FAKE_SHELL_PID_FILE:-/tmp/fake_shelljsp_lab.pid}"

if [[ ! -f "$PID_FILE" ]]; then
  echo "fake shell not running (no pid file: $PID_FILE)"
  exit 0
fi

PID="$(cat "$PID_FILE" 2>/dev/null || true)"
if [[ -z "${PID:-}" ]]; then
  rm -f "$PID_FILE"
  echo "fake shell pid file empty; removed"
  exit 0
fi

if ! kill -0 "$PID" 2>/dev/null; then
  rm -f "$PID_FILE"
  echo "fake shell already stopped (stale pid=$PID)"
  exit 0
fi

kill "$PID" 2>/dev/null || true
for _ in $(seq 1 20); do
  if ! kill -0 "$PID" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

if kill -0 "$PID" 2>/dev/null; then
  kill -9 "$PID" 2>/dev/null || true
fi

rm -f "$PID_FILE"
echo "FAKE_SHELL_STOPPED pid=$PID"
exit 0
