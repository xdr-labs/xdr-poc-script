# DSP Operator Menu

SSH-friendly launcher for updating, configuring, and running DSP without memorizing long CLI commands.

## Bootstrap install (new host)

Install or update DSP and launch this menu in one step:

```bash
curl -fsSL https://raw.githubusercontent.com/RickLee-kr/xdr-poc-script/release/v1.4.0-rc/install-dsp.sh | bash
```

Custom path, no menu launch:

```bash
DSP_REPO_DIR=/opt/xdr-poc-script DSP_NO_LAUNCH=1 bash install-dsp.sh
```

Details: [DSP_BOOTSTRAP_INSTALL.md](./DSP_BOOTSTRAP_INSTALL.md)

## Quick start

From the repository root:

```bash
./dsp-menu.sh
```

Or:

```bash
bash scripts/dsp-menu.sh
```

The menu uses **whiptail** when installed (common on Ubuntu/Debian). If whiptail is missing, a plain numbered prompt is used instead.

## Menu

| # | Action | Description |
|---|--------|-------------|
| 1 | Update latest patch | `git fetch`, checkout `release/v1.4.0-rc`, `git pull` |
| 2 | Configure environment | Save operator settings to `~/.dsp/config.env` |
| 3 | Run scenario | `dsp run` (local or webshell from config) |
| 4 | Show latest report | Latest run under `~/.dsp/runs/` |
| 5 | Show version/status | Git branch/commit, `dsp --version`, current config |
| 6 | Exit | Leave the menu |

## Configuration file

Path: `~/.dsp/config.env`

Created automatically on first run. Example:

```bash
DSP_REPO_DIR=/home/aella/xdr-poc-script
TARGET_NET=10.10.10.0/24
EXECUTION_MODE=local
PROFILE=normal
WEBSHELL_FAMILY=jsp
WEBSHELL_URL=http://10.10.10.50:8080/shell.jsp
REMOTE_WORK_DIR=/tmp/dsp
```

- **EXECUTION_MODE**: `local` or `webshell`
- **PROFILE**: `low`, `normal`, or `high`
- Webshell fields are prompted when mode is `webshell`

### Webshell validation status (Release 1.0)

| Family | Status |
|--------|--------|
| `jsp` | Validated — real Tomcat lab path |
| `php` | Validated — real Apache + PHP lab path |
| `aspx` | Preview only — not validated on Windows IIS; use for experimentation only |

When configuring webshell mode, prefer **jsp** or **php** for validated remote execution. See [Release 1.0 Summary](../RELEASE_1_0_SUMMARY.md).

## Run commands (equivalent)

**Local** (from config):

```bash
source ~/.dsp/config.env
source "$DSP_REPO_DIR/.venv/bin/activate"  # if present
dsp run --profile "$PROFILE" --target-net "$TARGET_NET"
```

**Webshell** (from config):

```bash
dsp run --profile "$PROFILE" \
  --execution-provider webshell \
  --webshell-family "$WEBSHELL_FAMILY" \
  --webshell-url "$WEBSHELL_URL" \
  --remote-work-dir "$REMOTE_WORK_DIR" \
  --target-net "$TARGET_NET"
```

## Prerequisites

- `bash`, `git`
- Python venv at `$DSP_REPO_DIR/.venv` (optional; menu activates it when present)
- `whiptail` (optional, for TUI)
- `dsp` on PATH after venv activation (`pip install -e .` in repo)

## Syntax check

```bash
bash -n scripts/dsp-menu.sh
bash -n dsp-menu.sh
```

## Scope

This script is an **operator convenience launcher** only. It does not change DSP runtime, scenario logic, or detection behavior.
