#!/usr/bin/env bash
# Start tcpdump capture for DSP Traffic Regression E2E.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'EOF'
Usage: capture_traffic.sh --interface IFACE --output-dir DIR [--filter EXPR]

Starts tcpdump and writes:
  DIR/capture.pcap
  DIR/tcpdump.log
  DIR/tcpdump.pid

Default filter: tcp or udp or icmp
EOF
}

INTERFACE=""
OUTPUT_DIR=""
FILTER="tcp or udp or icmp"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --interface|-i)
      INTERFACE="${2:-}"
      shift 2
      ;;
    --output-dir|-o)
      OUTPUT_DIR="${2:-}"
      shift 2
      ;;
    --filter)
      FILTER="${2:-}"
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

if [[ -z "$INTERFACE" ]]; then
  echo "ERROR: --interface is required" >&2
  exit 1
fi
if [[ -z "$OUTPUT_DIR" ]]; then
  echo "ERROR: --output-dir is required" >&2
  exit 1
fi

if ! command -v tcpdump >/dev/null 2>&1; then
  echo "ERROR: tcpdump not found on PATH" >&2
  exit 1
fi

if ! ip link show "$INTERFACE" >/dev/null 2>&1; then
  echo "ERROR: interface not found: $INTERFACE" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"
PCAP_PATH="$OUTPUT_DIR/capture.pcap"
LOG_PATH="$OUTPUT_DIR/tcpdump.log"
PID_PATH="$OUTPUT_DIR/tcpdump.pid"

if [[ -f "$PID_PATH" ]]; then
  OLD_PID="$(cat "$PID_PATH" 2>/dev/null || true)"
  if [[ -n "${OLD_PID:-}" ]] && kill -0 "$OLD_PID" 2>/dev/null; then
    echo "ERROR: tcpdump already running with pid $OLD_PID (see $PID_PATH)" >&2
    exit 1
  fi
  rm -f "$PID_PATH"
fi

rm -f "$PCAP_PATH" "$LOG_PATH"

# Prefer capability/rootless capture; fall back to passwordless sudo (-n only).
# Never use interactive sudo (no password prompt / wait).
#
# Probe note: quiet interfaces may yield timeout (exit 124) with 0 packets.
# That is NOT a permission failure — only treat explicit permission errors as FAIL.
TCPDUMP_BIN="$(command -v tcpdump)"

_probe_permission_denied() {
  # stdin/arg: tcpdump stderr/stdout text
  echo "$1" | grep -qiE 'Operation not permitted|You don.t have permission|Permission denied'
}

_probe_opened_ok() {
  # Listening message means the capture socket opened successfully.
  echo "$1" | grep -qi 'listening on'
}

_can_capture_direct() {
  local out ec=0
  out="$(timeout 2 tcpdump -i "$INTERFACE" -c 1 -w /dev/null 2>&1)" || ec=$?
  PROBE_DIRECT_OUT="$out"
  if _probe_permission_denied "$out"; then
    return 1
  fi
  if _probe_opened_ok "$out"; then
    return 0
  fi
  # Got packet (0) or timed out waiting for packets (124) without perm error.
  [[ "$ec" -eq 0 || "$ec" -eq 124 ]]
}

_can_capture_sudo() {
  local out ec=0
  if ! command -v sudo >/dev/null 2>&1; then
    return 1
  fi
  out="$(sudo -n "$TCPDUMP_BIN" -i "$INTERFACE" -c 1 -w /dev/null 2>&1)" || ec=$?
  PROBE_SUDO_OUT="$out"
  if echo "$out" | grep -qi 'password is required'; then
    return 1
  fi
  if _probe_permission_denied "$out"; then
    return 1
  fi
  if _probe_opened_ok "$out"; then
    return 0
  fi
  [[ "$ec" -eq 0 || "$ec" -eq 124 ]]
}

run_tcpdump() {
  PROBE_DIRECT_OUT=""
  PROBE_SUDO_OUT=""

  # 1) Direct tcpdump (setcap / root / sufficient caps).
  if _can_capture_direct; then
    tcpdump -i "$INTERFACE" -nn -U -w "$PCAP_PATH" $FILTER >"$LOG_PATH" 2>&1 &
    echo $!
    return 0
  fi

  # 2) Passwordless sudo only (sudo -n). Prefer absolute path for sudoers matching.
  if _can_capture_sudo; then
    sudo -n "$TCPDUMP_BIN" -i "$INTERFACE" -nn -U -w "$PCAP_PATH" $FILTER >"$LOG_PATH" 2>&1 &
    echo $!
    return 0
  fi

  echo "ERROR: BLOCKED — insufficient permission to capture on $INTERFACE" >&2
  echo "direct_tcpdump: ${PROBE_DIRECT_OUT:-unknown}" >&2
  echo "sudo -n tcpdump: ${PROBE_SUDO_OUT:-unknown}" >&2
  echo >&2
  echo "Fix with one of:" >&2
  echo "  sudo setcap cap_net_raw,cap_net_admin=eip \"$TCPDUMP_BIN\"" >&2
  echo "  or configure passwordless sudo for tcpdump (sudo -n), with NOPASSWD" >&2
  echo "  AFTER any (ALL) ALL rule and allowing args:" >&2
  echo "    aella ALL=(root) NOPASSWD: $TCPDUMP_BIN, $TCPDUMP_BIN *" >&2
  echo "Then verify:" >&2
  echo "  tcpdump -i $INTERFACE -nn -c 3 'tcp or udp or icmp'" >&2
  return 1
}

if ! TCPDUMP_PID="$(run_tcpdump)"; then
  exit 1
fi
echo "$TCPDUMP_PID" >"$PID_PATH"

# Give tcpdump a moment to open the pcap and fail fast on permission errors.
sleep 1
if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
  echo "ERROR: tcpdump exited immediately; see $LOG_PATH" >&2
  if [[ -f "$LOG_PATH" ]]; then
    cat "$LOG_PATH" >&2 || true
  fi
  rm -f "$PID_PATH"
  exit 1
fi

# Ensure pcap file appears (tcpdump creates it on start with -w).
for _ in 1 2 3 4 5; do
  if [[ -f "$PCAP_PATH" ]]; then
    break
  fi
  sleep 0.2
done

if [[ ! -f "$PCAP_PATH" ]]; then
  echo "ERROR: pcap was not created: $PCAP_PATH" >&2
  kill "$TCPDUMP_PID" 2>/dev/null || true
  rm -f "$PID_PATH"
  exit 1
fi

echo "CAPTURE_STARTED pid=$TCPDUMP_PID interface=$INTERFACE pcap=$PCAP_PATH"
exit 0
