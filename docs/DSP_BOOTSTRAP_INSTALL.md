# DSP Bootstrap Install

One-command install/update for a new host. Clones or updates the repository, creates a Python virtual environment, installs DSP, and opens the operator TUI menu.

## One-line install

```bash
curl -fsSL https://raw.githubusercontent.com/RickLee-kr/xdr-poc-script/release/v1.4.0-rc/install-dsp.sh | bash
```

Alternative:

```bash
wget -O install-dsp.sh https://raw.githubusercontent.com/RickLee-kr/xdr-poc-script/release/v1.4.0-rc/install-dsp.sh
bash install-dsp.sh
```

## What the installer does

1. Checks **git**, **python3**, **python3 venv** (`import venv`), and **pip** (or `ensurepip`)
2. Ensures `~/.dsp/` exists (does **not** overwrite `~/.dsp/config.env` if present)
3. Clones or updates `release/v1.4.0-rc` into the install directory
4. Creates `.venv` if missing
5. Runs `pip install -e .` in the venv
6. Makes `dsp-menu.sh` executable
7. Launches `./dsp-menu.sh` unless `DSP_NO_LAUNCH=1`

Existing run artifacts under `~/.dsp/runs/` are never deleted.

## Defaults

| Variable | Default |
|----------|---------|
| `DSP_REPO_DIR` | `/home/aella/xdr-poc-script` |
| `DSP_RELEASE_BRANCH` | `release/v1.4.0-rc` |
| `DSP_REPO_URL` | `https://github.com/RickLee-kr/xdr-poc-script.git` |
| `DSP_NO_LAUNCH` | `0` (launch menu after install) |

## Custom install path

```bash
DSP_REPO_DIR=/opt/xdr-poc-script bash install-dsp.sh
```

## Install without launching the menu

```bash
DSP_NO_LAUNCH=1 bash install-dsp.sh
```

Useful for CI, smoke checks, or rerunning the installer safely.

## Rerun / update

The script is **idempotent**. Run the same one-liner again to `git pull` and reinstall the package:

```bash
curl -fsSL https://raw.githubusercontent.com/RickLee-kr/xdr-poc-script/release/v1.4.0-rc/install-dsp.sh | bash
```

Or from an existing clone:

```bash
DSP_NO_LAUNCH=1 bash /home/aella/xdr-poc-script/install-dsp.sh
```

## After install

- Menu: `/home/aella/xdr-poc-script/dsp-menu.sh`
- CLI: `/home/aella/xdr-poc-script/.venv/bin/dsp`
- Operator config: `~/.dsp/config.env` (created by the menu on first use, not by the installer)
- Run artifacts: `~/.dsp/runs/`

See also [DSP_MENU.md](./DSP_MENU.md).

## Prerequisites (OS packages)

Debian/Ubuntu example:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip whiptail
```

`whiptail` is optional but recommended for the TUI menu.

## Syntax check

```bash
bash -n install-dsp.sh
```

## Scope

Installer and operator convenience only. Does not change DSP runtime, scenario, or detection logic.
