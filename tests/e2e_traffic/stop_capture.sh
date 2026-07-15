#!/usr/bin/env bash
# Stop tcpdump capture for DSP Traffic Regression E2E.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: stop_capture.sh --output-dir DIR

Reads DIR/tcpdump.pid, stops tcpdump, waits for pcap flush.
Safe if tcpdump already exited.
EOF
}

OUTPUT_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir|-o)
      OUTPUT_DIR="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -z "$OUTPUT_DIR" ]]; then
  echo "ERROR: --output-dir is required" >&2
  exit 1
fi

PID_PATH="$OUTPUT_DIR/tcpdump.pid"
PCAP_PATH="$OUTPUT_DIR/capture.pcap"

if [[ ! -f "$PID_PATH" ]]; then
  echo "CAPTURE_STOP: no pid file ($PID_PATH); treating as already stopped"
  exit 0
fi

TCPDUMP_PID="$(cat "$PID_PATH" 2>/dev/null || true)"
if [[ -z "${TCPDUMP_PID:-}" ]]; then
  echo "CAPTURE_STOP: empty pid file; treating as already stopped"
  rm -f "$PID_PATH"
  exit 0
fi

if kill -0 "$TCPDUMP_PID" 2>/dev/null; then
  # SIGINT lets tcpdump flush cleanly when possible.
  kill -INT "$TCPDUMP_PID" 2>/dev/null || kill "$TCPDUMP_PID" 2>/dev/null || true

  # Wait for process exit / pcap flush.
  for _ in $(seq 1 50); do
    if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done

  if kill -0 "$TCPDUMP_PID" 2>/dev/null; then
    kill -KILL "$TCPDUMP_PID" 2>/dev/null || true
    sleep 0.2
  fi
  echo "CAPTURE_STOPPED pid=$TCPDUMP_PID"
else
  echo "CAPTURE_STOP: pid $TCPDUMP_PID already exited"
fi

# Brief settle for filesystem flush.
sleep 0.5

if [[ -f "$PCAP_PATH" ]]; then
  SIZE="$(wc -c <"$PCAP_PATH" | tr -d ' ')"
  echo "CAPTURE_PCAP path=$PCAP_PATH bytes=$SIZE"
else
  echo "WARNING: pcap missing after stop: $PCAP_PATH" >&2
fi

rm -f "$PID_PATH"
exit 0
