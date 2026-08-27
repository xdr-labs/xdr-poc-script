# Detection Scenario Platform (DSP)

**Release 1.4.0** — Generate realistic security-scenario traffic, collect structured events, and produce validation reports for lab and XDR testing.

DSP runs attack-simulation scenarios (port sweep, DNS tunnel, HTTP follow-up, SQL injection, SSH failure, and more) against a target network you define. Results land in a local run folder as events, reports, and evidence you can review or export.

---

## What it does

| | |
|---|---|
| **Runs scenarios** | Dispatches protocol traffic from this host (**local**) or via a **webshell** on a remote host |
| **Records events** | Append-only event store (`events.db` / `events.jsonl`) — single source of truth |
| **Produces reports** | `report.md`, `validation.json`, `traffic_summary.json` per run |
| **Profiles** | `low`, `normal`, or `high` traffic volume — no need to memorize CLI flags |

DSP validates **traffic and event generation**, not vendor alert firing.

---

## Quick Start

### Step 1 — Install once

Run this **once** on a new machine. It clones or updates the repo, creates `.venv`, installs DSP, and opens the menu.

```bash
curl -fsSL https://raw.githubusercontent.com/xdr-labs/xdr-poc-script/release/v1.4.0-rc/install-dsp.sh | bash
```

Install only (no menu): `DSP_NO_LAUNCH=1 bash install-dsp.sh`

### Step 2 — Use the menu every day

From the repository root:

```bash
cd /path/to/xdr-poc-script
./dsp-menu.sh
```

| Menu item | What it does |
|-----------|----------------|
| **Configure environment** | Target network (CIDR), profile, local vs webshell, webshell URL |
| **Run scenario** | Execute using saved settings |
| **Show latest report** | Open the most recent run under `~/.dsp/runs/` |
| **Update latest patch** | Pull `release/v1.4.0-rc` |
| **Show version/status** | Git state, `dsp --version`, current config |

**Config file:** `~/.dsp/config.env`  
**Run output:** `~/.dsp/runs/<run_id>/` (`report.md`, `events.db`, `validation.json`, …)

---

## Execution modes

| Mode | When to use |
|------|-------------|
| **local** | DSP runs scenarios from this machine into `--target-net` |
| **webshell** | Scenarios run on a remote host through a JSP / PHP / ASPX webshell endpoint |

Webshell configure hints (in the menu):

- **Family:** `jsp`, `php`, or `aspx` — must match the shell file type  
- **URL:** full HTTP(S) path, e.g. `http://10.10.10.50:8080/shell.jsp`  
- **Remote work dir:** writable path on the target, e.g. `/tmp/dsp`

---

## CLI (optional)

If you prefer the command line after `source .venv/bin/activate`:

```bash
# Local run
dsp run --profile normal --target-net 10.10.10.0/24

# Webshell run
dsp run --profile normal --target-net 10.10.10.0/24 \
  --execution-provider webshell \
  --webshell-family jsp \
  --webshell-url http://10.10.10.50:8080/shell.jsp \
  --remote-work-dir /tmp/dsp
```

---

## Requirements

- Python 3.11+
- `git`, `python3-venv`, `pip`
- `whiptail` (recommended for the TUI menu on Debian/Ubuntu)

---

## More documentation

- [Operator menu](./docs/DSP_MENU.md)
- [Bootstrap install](./docs/DSP_BOOTSTRAP_INSTALL.md)
- [Lab guide](./RELEASE_1_0_LAB_GUIDE.md)
