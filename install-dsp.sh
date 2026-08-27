#!/usr/bin/env bash
# Bootstrap installer — clone/update DSP, create venv, install package, launch menu.
set -euo pipefail

RELEASE_BRANCH="${RELEASE_BRANCH:-${DSP_RELEASE_BRANCH:-release/v1.4.0-rc}}"
REPO_URL="${DSP_REPO_URL:-https://github.com/xdr-labs/xdr-poc-script.git}"
DSP_REPO_DIR="${DSP_REPO_DIR:-/home/aella/xdr-poc-script}"
DSP_NO_LAUNCH="${DSP_NO_LAUNCH:-0}"
DSP_PYTHON_BIN=""

log() {
  printf '[install-dsp] %s\n' "$*"
}

die() {
  printf '[install-dsp] ERROR: %s\n' "$*" >&2
  exit 1
}

# Retired line shipped stale normal volumes (HTTP 300 / DNS max_chunks 50 / DGA 15).
if [[ "${RELEASE_BRANCH}" == "release/v1.4.0" ]]; then
  die "release/v1.4.0 is retired; use release/v1.4.0-rc (unset DSP_RELEASE_BRANCH)"
fi

require_cmd() {
  local name="$1"
  command -v "$name" >/dev/null 2>&1 || die "missing required command: ${name}"
}

die_python311_required() {
  printf '[install-dsp] ERROR: DSP requires Python 3.11 or newer.\n' >&2
  printf '[install-dsp] Install Python 3.11+ and venv support, then rerun the installer.\n' >&2
  printf '[install-dsp] On Ubuntu 22.04:\n' >&2
  printf '  sudo apt update\n' >&2
  printf '  sudo apt install -y python3.11 python3.11-venv python3.11-dev\n' >&2
  exit 1
}

resolve_python311() {
  local candidate bin
  for candidate in python3.13 python3.12 python3.11 python3; do
    bin="$(command -v "${candidate}" 2>/dev/null || true)"
    if [[ -z "${bin}" ]]; then
      continue
    fi
    if ! "${bin}" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
      continue
    fi
    if ! "${bin}" -c 'import venv' 2>/dev/null; then
      continue
    fi
    printf '%s\n' "${bin}"
    return 0
  done
  return 1
}

select_python311() {
  local bin
  if ! bin="$(resolve_python311)"; then
    die_python311_required
  fi
  DSP_PYTHON_BIN="${bin}"
  log "selected python: ${DSP_PYTHON_BIN}"
  log "selected python version: $("${DSP_PYTHON_BIN}" --version 2>&1)"
}

check_prerequisites() {
  require_cmd git
  select_python311
}

ensure_dsp_state_dir() {
  # Preserve existing operator config and run artifacts.
  mkdir -p "${HOME}/.dsp"
  mkdir -p "${HOME}/.dsp/runs"
  if [[ -f "${HOME}/.dsp/config.env" ]]; then
    log "keeping existing config: ${HOME}/.dsp/config.env"
  fi
}

clone_or_update_repo() {
  if [[ -d "${DSP_REPO_DIR}/.git" ]]; then
    log "updating existing repository: ${DSP_REPO_DIR}"
    cd "${DSP_REPO_DIR}"
    git fetch origin
    git checkout "${RELEASE_BRANCH}"
    git pull origin "${RELEASE_BRANCH}"
  elif [[ -e "${DSP_REPO_DIR}" ]]; then
    die "${DSP_REPO_DIR} exists but is not a git repository"
  else
    log "cloning ${REPO_URL} (branch ${RELEASE_BRANCH}) -> ${DSP_REPO_DIR}"
    git clone -b "${RELEASE_BRANCH}" "${REPO_URL}" "${DSP_REPO_DIR}"
    cd "${DSP_REPO_DIR}"
  fi
}

ensure_venv() {
  local venv_dir="${DSP_REPO_DIR}/.venv"

  if [[ -d "${venv_dir}" ]]; then
    if ! "${venv_dir}/bin/python" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
      log "removing existing virtual environment (Python < 3.11): ${venv_dir}"
      rm -rf "${venv_dir}"
    fi
  fi

  if [[ ! -d "${venv_dir}" ]]; then
    log "creating virtual environment: ${venv_dir}"
    "${DSP_PYTHON_BIN}" -m venv "${venv_dir}"
  else
    log "using existing virtual environment: ${venv_dir}"
  fi

  if ! "${venv_dir}/bin/python" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
    die "virtual environment Python is older than 3.11 — remove ${venv_dir} and retry"
  fi
  log "venv python version: $("${venv_dir}/bin/python" --version 2>&1)"
}

setup_venv_and_package() {
  cd "${DSP_REPO_DIR}"

  ensure_venv

  .venv/bin/python -m pip install --upgrade pip
  .venv/bin/pip install -e .

  chmod +x dsp-menu.sh scripts/dsp-menu.sh 2>/dev/null || true
}

print_summary() {
  log "install complete"
  log "  repository: ${DSP_REPO_DIR}"
  log "  branch:     ${RELEASE_BRANCH}"
  log "  venv:       ${DSP_REPO_DIR}/.venv"
  log "  dsp:        ${DSP_REPO_DIR}/.venv/bin/dsp"
  log "  menu:       ${DSP_REPO_DIR}/dsp-menu.sh"
  if [[ -f "${DSP_REPO_DIR}/.venv/bin/dsp" ]]; then
    log "  version:    $("${DSP_REPO_DIR}/.venv/bin/dsp" --version 2>/dev/null || echo unknown)"
  fi
  log "rerun without menu: DSP_NO_LAUNCH=1 bash install-dsp.sh"
  log "launch menu:        ${DSP_REPO_DIR}/dsp-menu.sh"
}

main() {
  log "DSP bootstrap installer"
  log "  DSP_REPO_DIR=${DSP_REPO_DIR}"
  log "  RELEASE_BRANCH=${RELEASE_BRANCH}"

  check_prerequisites
  ensure_dsp_state_dir
  clone_or_update_repo
  setup_venv_and_package
  print_summary

  if [[ "${DSP_NO_LAUNCH}" == "1" ]]; then
    log "DSP_NO_LAUNCH=1 — skipping menu launch"
    exit 0
  fi

  log "launching DSP menu..."
  exec "${DSP_REPO_DIR}/dsp-menu.sh"
}

main "$@"
