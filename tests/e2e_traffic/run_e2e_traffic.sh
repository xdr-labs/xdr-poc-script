#!/usr/bin/env bash
# DSP Traffic Regression E2E — full orchestration.
# Exit 0 on PASS, exit 1 on FAIL (or infrastructure failure).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

PROVIDER="local"
PROFILE="normal"
TARGET_NET="10.10.10.0/24"
INTERFACE=""
OUTPUT_DIR=""
WEBSHELL_URL=""
WEBSHELL_TYPE="jsp"
DSP_COMMAND=""
CONFIG_FILE=""

usage() {
  cat <<'EOF'
Usage: run_e2e_traffic.sh [options]

Options:
  --provider local|webshell
  --profile normal|high
  --target-net CIDR
  --interface IFACE
  --output-dir DIR
  --webshell-url URL
  --webshell-type jsp|php|aspx
  --dsp-command PATH_OR_CMD
  --config ENV_FILE
  -h, --help

This E2E test validates DSP traffic/evidence only.
It does NOT judge Stellar alerts, cases, or detection success.
EOF
}

load_config() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo "ERROR: config file not found: $file" >&2
    exit 1
  fi
  set -a
  # shellcheck disable=SC1090
  source "$file"
  set +a
  PROVIDER="${E2E_PROVIDER:-$PROVIDER}"
  PROFILE="${E2E_PROFILE:-$PROFILE}"
  TARGET_NET="${E2E_TARGET_NET:-$TARGET_NET}"
  INTERFACE="${E2E_INTERFACE:-$INTERFACE}"
  OUTPUT_DIR="${E2E_OUTPUT_DIR:-$OUTPUT_DIR}"
  WEBSHELL_URL="${E2E_WEBSHELL_URL:-$WEBSHELL_URL}"
  WEBSHELL_TYPE="${E2E_WEBSHELL_TYPE:-$WEBSHELL_TYPE}"
  DSP_COMMAND="${E2E_DSP_COMMAND:-$DSP_COMMAND}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --provider) PROVIDER="${2:-}"; shift 2 ;;
    --profile) PROFILE="${2:-}"; shift 2 ;;
    --target-net) TARGET_NET="${2:-}"; shift 2 ;;
    --interface) INTERFACE="${2:-}"; shift 2 ;;
    --output-dir) OUTPUT_DIR="${2:-}"; shift 2 ;;
    --webshell-url) WEBSHELL_URL="${2:-}"; shift 2 ;;
    --webshell-type) WEBSHELL_TYPE="${2:-}"; shift 2 ;;
    --dsp-command) DSP_COMMAND="${2:-}"; shift 2 ;;
    --config) CONFIG_FILE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -n "$CONFIG_FILE" ]]; then
  load_config "$CONFIG_FILE"
elif [[ -f "$SCRIPT_DIR/e2e_config.env" ]]; then
  load_config "$SCRIPT_DIR/e2e_config.env"
fi

if [[ -z "$INTERFACE" ]]; then
  # Prefer first non-loopback UP interface.
  INTERFACE="$(ip -br link | awk '$2 ~ /UP|UNKNOWN/ && $1 != "lo" {print $1; exit}')"
fi
if [[ -z "$INTERFACE" ]]; then
  echo "ERROR: --interface is required (no non-loopback interface detected)" >&2
  exit 1
fi

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="$SCRIPT_DIR/reports/run_${TIMESTAMP}_${PROVIDER}_${PROFILE}"
fi
mkdir -p "$OUTPUT_DIR"

if [[ -z "$DSP_COMMAND" ]]; then
  if [[ -x "$REPO_ROOT/.venv/bin/dsp" ]]; then
    DSP_COMMAND="$REPO_ROOT/.venv/bin/dsp"
  elif command -v dsp >/dev/null 2>&1; then
    DSP_COMMAND="$(command -v dsp)"
  else
    DSP_COMMAND="python3 -m dsp.runner.cli"
  fi
fi

if [[ "$PROVIDER" == "webshell" && -z "$WEBSHELL_URL" ]]; then
  echo "ERROR: --webshell-url is required when --provider webshell" >&2
  exit 1
fi

STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RUNS_ROOT="$OUTPUT_DIR/dsp_runs"
mkdir -p "$RUNS_ROOT"
export DSP_RUNS_DIR="$RUNS_ROOT"

LOG_FILE="$OUTPUT_DIR/e2e_run.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "=== DSP Traffic Regression E2E ==="
echo "provider=$PROVIDER profile=$PROFILE target_net=$TARGET_NET interface=$INTERFACE"
echo "output_dir=$OUTPUT_DIR"
echo "dsp_command=$DSP_COMMAND"
echo "dsp_runs_dir=$DSP_RUNS_DIR"

cleanup_capture() {
  "$SCRIPT_DIR/stop_capture.sh" --output-dir "$OUTPUT_DIR" || true
}
trap cleanup_capture EXIT

# 1) Start capture
"$SCRIPT_DIR/capture_traffic.sh" --interface "$INTERFACE" --output-dir "$OUTPUT_DIR"

# 2) Run DSP
DSP_ARGS=(run --profile "$PROFILE" --target-net "$TARGET_NET" --execution-provider "$PROVIDER")
if [[ "$PROVIDER" == "webshell" ]]; then
  DSP_ARGS+=(--webshell-family "$WEBSHELL_TYPE" --webshell-url "$WEBSHELL_URL")
fi

echo "=== Running DSP ==="
echo "NOTE: normal/high profiles include dns_tunnel and may take several minutes."
set +e
# shellcheck disable=SC2086
$DSP_COMMAND "${DSP_ARGS[@]}"
DSP_EXIT=$?
set -e
echo "DSP_EXIT=$DSP_EXIT"
echo "$DSP_EXIT" >"$OUTPUT_DIR/dsp_exit_code.txt"

# Locate run directory (latest under DSP_RUNS_DIR)
RUN_DIR="$(ls -1dt "$RUNS_ROOT"/*/ 2>/dev/null | head -n1 || true)"
if [[ -n "$RUN_DIR" ]]; then
  RUN_DIR="${RUN_DIR%/}"
  echo "$RUN_DIR" >"$OUTPUT_DIR/dsp_run_dir.txt"
  echo "DSP_RUN_DIR=$RUN_DIR"
else
  echo "WARNING: no DSP run directory found under $RUNS_ROOT" >&2
  echo "" >"$OUTPUT_DIR/dsp_run_dir.txt"
fi

# 3) Stop capture
trap - EXIT
"$SCRIPT_DIR/stop_capture.sh" --output-dir "$OUTPUT_DIR"

ENDED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# 4) Analyze pcap
python3 "$SCRIPT_DIR/analyze_pcap.py" \
  --pcap "$OUTPUT_DIR/capture.pcap" \
  --output "$OUTPUT_DIR/pcap_summary.json"

# 5) Collect evidence
EVIDENCE_ARGS=(
  --output "$OUTPUT_DIR/evidence_summary.json"
  --provider "$PROVIDER"
  --profile "$PROFILE"
  --runs-root "$RUNS_ROOT"
)
if [[ -n "${RUN_DIR:-}" && -d "${RUN_DIR:-}" ]]; then
  EVIDENCE_ARGS+=(--run-dir "$RUN_DIR")
fi
python3 "$SCRIPT_DIR/collect_dsp_evidence.py" "${EVIDENCE_ARGS[@]}"

# 6) Write run_info.json
python3 - <<PY
import json
from pathlib import Path
info = {
    "provider": "$PROVIDER",
    "profile": "$PROFILE",
    "target_net": "$TARGET_NET",
    "interface": "$INTERFACE",
    "webshell_type": "$WEBSHELL_TYPE" if "$PROVIDER" == "webshell" else "",
    "webshell_url": "$WEBSHELL_URL" if "$PROVIDER" == "webshell" else "",
    "dsp_command": "$DSP_COMMAND",
    "dsp_exit_code": int("$DSP_EXIT"),
    "started_at": "$STARTED_AT",
    "ended_at": "$ENDED_AT",
    "output_dir": "$OUTPUT_DIR",
    "dsp_run_dir": Path("$OUTPUT_DIR/dsp_run_dir.txt").read_text(encoding="utf-8").strip(),
    "dsp_runs_dir": "$RUNS_ROOT",
}
Path("$OUTPUT_DIR/run_info.json").write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")
print("Wrote $OUTPUT_DIR/run_info.json")
PY

# 7) Compare + report
set +e
python3 "$SCRIPT_DIR/compare_traffic_evidence.py" \
  --pcap-summary "$OUTPUT_DIR/pcap_summary.json" \
  --evidence-summary "$OUTPUT_DIR/evidence_summary.json" \
  --scenario-rules "$SCRIPT_DIR/scenario_packet_rules.yaml" \
  --expected-profiles "$SCRIPT_DIR/expected_profiles.yaml" \
  --gap-rules "$SCRIPT_DIR/regression_gap_rules.yaml" \
  --run-info "$OUTPUT_DIR/run_info.json" \
  --output-json "$OUTPUT_DIR/comparison_report.json" \
  --output-md "$OUTPUT_DIR/comparison_report.md"
COMPARE_EXIT=$?
set -e

# Also copy report into reports/ root alias for convenience
cp -f "$OUTPUT_DIR/comparison_report.md" "$OUTPUT_DIR/../comparison_report_latest.md" 2>/dev/null || true

echo "=== E2E complete ==="
echo "report: $OUTPUT_DIR/comparison_report.md"
echo "compare_exit=$COMPARE_EXIT dsp_exit=$DSP_EXIT"

# Traffic regression FAIL => exit 1. DSP non-zero alone does not override PASS
# unless comparison already failed. Infrastructure missing pcap/evidence fails compare.
if [[ "$COMPARE_EXIT" -ne 0 ]]; then
  exit 1
fi
exit 0
