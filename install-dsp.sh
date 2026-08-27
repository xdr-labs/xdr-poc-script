#!/usr/bin/env bash
# Bootstrap installer — clone/update DSP, create venv, install package, launch menu.
set -euo pipefail

RELEASE_BRANCH="${DSP_RELEASE_BRANCH:-release/v1.4.0-rc}"
REPO_URL="${DSP_REPO_URL:-https://github.com/xdr-labs/xdr-poc-script.git}"
DSP_REPO_DIR="${DSP_REPO_DIR:-/home/aella/xdr-poc-script}"
DSP_NO_LAUNCH="${DSP_NO_LAUNCH:-0}"

log() {
  printf '[install-dsp] %s\n' "$*"
}

die() {
  printf '[install-dsp] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  local name="$1"
  command -v "$name" >/dev/null 2>&1 || die "missing required command: ${name}"
}

check_prerequisites() {
  require_cmd git
  require_cmd python3

  if ! python3 -c 'import venv' 2>/dev/null; then
    die "python3 venv module not available — install python3-venv (e.g. apt install python3-venv)"
  fi

  if ! python3 -m pip --version >/dev/null 2>&1; then
    log "pip not found for system python3; trying ensurepip..."
    python3 -m ensurepip --upgrade >/dev/null 2>&1 || \
      die "pip is not available — install python3-pip or enable ensurepip"
  fi
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

setup_venv_and_package() {
  cd "${DSP_REPO_DIR}"

  if [[ ! -d .venv ]]; then
    log "creating virtual environment: ${DSP_REPO_DIR}/.venv"
    python3 -m venv .venv
  else
    log "using existing virtual environment: ${DSP_REPO_DIR}/.venv"
  fi

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
