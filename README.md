# Detection Scenario Platform (DSP)

Generate realistic security traffic for XDR, SIEM, EDR, and lab validation.

**Release 1.4.0** — Generate realistic security-scenario traffic, collect structured events, and produce validation reports for lab and XDR testing.

DSP runs attack-simulation scenarios (port sweep, DNS tunnel, HTTP follow-up, SQL injection, SSH failure, and more) against a target network you define. Results land in a local run folder as events, reports, and evidence you can review or export.

---

## 🚀 Install & Run (30 Seconds)

**One command** — clone, install, and open the operator menu:

```bash
curl -fsSL https://raw.githubusercontent.com/RickLee-kr/xdr-poc-script/v1.4.0/install-dsp.sh | bash
```

Then in the menu:

| Step | Menu | Action |
|------|------|--------|
| 1 | *(install finishes)* | Menu opens automatically |
| 2 | **2 — Configure environment** | Set target network (CIDR), profile (`normal` / `high`), local vs webshell |
| 3 | **3 — Run scenario** | Execute using saved settings |

**Output:** `~/.dsp/runs/<run_id>/` (`report.md`, `events.db`, `validation.json`, …)  
**Config:** `~/.dsp/config.env`

Install only (no menu): `DSP_NO_LAUNCH=1 bash install-dsp.sh`  
Custom path: `DSP_REPO_DIR=/opt/xdr-poc-script bash install-dsp.sh`

---

## What it does

| | |
|---|---|
| **Runs scenarios** | Dispatches protocol traffic from this host (**local**) or via a **webshell** on a remote host |
| **Records events** | Append-only event store (`events.db` / `events.jsonl`) — single source of truth |
| **Produces reports** | `report.md`, `validation.json`, `traffic_summary.json` per run |
| **Profiles** | `normal` (default) or `high` — coverage expansion, not intensity |

DSP validates **traffic and event generation**, not vendor alert firing.

---

## Quick Start

### Step 1 — Install once

Run this **once** on a new machine. It clones or updates the repo, creates `.venv`, installs DSP, and opens the menu.

```bash
curl -fsSL https://raw.githubusercontent.com/RickLee-kr/xdr-poc-script/v1.4.0/install-dsp.sh | bash
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
| **Update latest patch** | Pull `release/v1.4.0` |
| **Show version/status** | Git state, `dsp --version`, current config |

**Config file:** `~/.dsp/config.env`  
**Run output:** `~/.dsp/runs/<run_id>/` (`report.md`, `events.db`, `validation.json`, …)

---

## Release Validation Status

Release 1.0 recommendation: **READY WITH KNOWN LIMITATIONS** (release **v1.4.0**).

| Status | Component |
|--------|-----------|
| Validated | Local Provider |
| Validated | JSP Webshell |
| Validated | PHP Webshell |
| Known limitation | ASPX Runtime Validation Pending |

DSP validates **traffic and event generation**, not vendor alert firing. See [Release 1.0 Summary](./RELEASE_1_0_SUMMARY.md) for scope and limitations.

---

## Validated Runtime Platforms

| Platform | Status | Notes |
|----------|--------|-------|
| **Linux** | Validated | Local provider; JSP (Tomcat) and PHP (Apache) webshell paths validated on lab host |
| **Windows** | Not yet validated | ASPX / IIS webshell execution path not validated in real environment |

---

## Validated Webshell Families

| Family | Status | Notes |
|--------|--------|-------|
| **JSP** | Validated | Real Tomcat + `shell.jsp` — 10/10 scenarios including `host_behavior_check` |
| **PHP** | Validated | Real Apache + PHP + `shell.php` — 10/10 scenarios including `host_behavior_check` |
| **ASPX** | Preview / not yet validated | Contract and HTTP transport exist; real Windows IIS execution has not been validated |

---

## Known Limitations

- ASPX runtime not validated on real Windows IIS
- Windows webshell execution path not validated (bundle runner, collector, and artifact handling are Linux-oriented today)
- ASPX should be considered **preview status** until Windows lab validation completes

Details: [`docs/validation/ASPX_REAL_WEBSHELL_VALIDATION_REPORT.md`](docs/validation/ASPX_REAL_WEBSHELL_VALIDATION_REPORT.md), [`docs/validation/RELEASE_DOCUMENTATION_AUDIT.md`](docs/validation/RELEASE_DOCUMENTATION_AUDIT.md)

---

## Execution modes

| Mode | When to use |
|------|-------------|
| **local** | DSP runs scenarios from this machine into `--target-net` |
| **webshell** | Scenarios run on a remote host through a webshell endpoint (**validated:** JSP, PHP; **preview:** ASPX) |

Webshell configure hints (in the menu):

- **Family:** `jsp` or `php` for validated remote execution; `aspx` is preview only (not yet validated on Windows IIS)  
- **URL:** full HTTP(S) path, e.g. `http://10.10.10.50:8080/shell.jsp`  
- **Remote work dir:** writable path on the target, e.g. `/tmp/dsp` (Linux validated paths)

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

- [Release 1.0 Summary](./RELEASE_1_0_SUMMARY.md)
- [Release notes](./RELEASE_NOTES.md)
- [Release documentation audit](./docs/validation/RELEASE_DOCUMENTATION_AUDIT.md)
- [Operator menu](./docs/DSP_MENU.md)
- [Bootstrap install](./docs/DSP_BOOTSTRAP_INSTALL.md)
- [Lab guide](./RELEASE_1_0_LAB_GUIDE.md)
