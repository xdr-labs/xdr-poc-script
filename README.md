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

## Fake JSP webshell lab (quick test)

Use this when you want to try **DSP webshell mode** without installing Tomcat. The script starts a small Flask app that mimics a JSP webshell at `/shell.jsp?cmd=...` — enough for connectivity checks and basic scenario runs in a **lab only**.

> **Warning:** This endpoint runs arbitrary shell commands. Use only on an isolated test machine. Never expose it to the public internet.

### What you need

| Item | Details |
|------|---------|
| OS | Debian/Ubuntu Linux (uses `apt`) |
| Network | Port **8080** free on the webshell host |
| DSP | Installed on the same machine **or** another host that can reach port 8080 |

### Step 1 — Run the setup script

From the repository root (or download the script from GitHub):

```bash
cd /path/to/xdr-poc-script
chmod +x scripts/setup_fake_shelljsp_lab.sh
./scripts/setup_fake_shelljsp_lab.sh
```

The script will:

1. Install `python3`, `python3-venv`, and `curl` (may ask for `sudo`)
2. Create `~/fake_shelljsp_lab/` with a Python virtual environment and Flask server
3. Start the fake webshell on **http://0.0.0.0:8080/shell.jsp**

Leave this terminal open while testing. Press **Ctrl+C** to stop the server.

**Start again later** (after setup):

```bash
cd ~/fake_shelljsp_lab && ./start.sh
```

### Step 2 — Verify the webshell works

Open a **second terminal** on the same machine:

```bash
cd ~/fake_shelljsp_lab
./test_local.sh
```

You should see output from `whoami`, `id`, and `hostname`. Manual check:

```bash
curl --get --data-urlencode "cmd=whoami" http://127.0.0.1:8080/shell.jsp
```

If another machine runs DSP, replace `127.0.0.1` with the webshell host IP (shown when setup finishes). If a firewall blocks access:

```bash
sudo ufw allow 8080/tcp
```

### Step 3 — Point DSP at the fake webshell

**Option A — Menu**

```bash
cd /path/to/xdr-poc-script
./dsp-menu.sh
```

1. **Configure environment**
2. Execution mode: **webshell**
3. Family: **jsp**
4. URL: `http://127.0.0.1:8080/shell.jsp` (same host) or `http://WEBSHELL_HOST_IP:8080/shell.jsp` (remote)
5. Remote work dir: `/tmp/dsp`
6. **Run scenario**

**Option B — CLI**

Same machine as the fake webshell:

```bash
source .venv/bin/activate
dsp run --profile low --target-net 10.10.10.0/24 \
  --execution-provider webshell \
  --webshell-family jsp \
  --webshell-url http://127.0.0.1:8080/shell.jsp \
  --remote-work-dir /tmp/dsp
```

DSP on a different machine (use the webshell host’s IP):

```bash
dsp run --profile low --target-net 10.10.10.0/24 \
  --execution-provider webshell \
  --webshell-family jsp \
  --webshell-url http://10.10.10.50:8080/shell.jsp \
  --remote-work-dir /tmp/dsp
```

### Lab files (after setup)

| Path | Purpose |
|------|---------|
| `~/fake_shelljsp_lab/shell_server.py` | Flask webshell server |
| `~/fake_shelljsp_lab/start.sh` | Start the server |
| `~/fake_shelljsp_lab/test_local.sh` | Quick curl smoke test |
| `scripts/setup_fake_shelljsp_lab.sh` | One-time setup (in this repo) |

### Fake vs real Tomcat

| | Fake lab (this script) | Real Tomcat (`shell.jsp`) |
|--|------------------------|---------------------------|
| Setup time | ~1 minute | Longer (Java/Tomcat install) |
| Best for | Quick DSP webshell smoke tests | Full Release 1.0 validation |
| Validated scenarios | Basic connectivity; not all bundle features | 10/10 scenarios validated |

For production-like validation, use a real Tomcat deployment — see [Lab guide](./RELEASE_1_0_LAB_GUIDE.md) and [JSP validation report](./docs/validation/JSP_REAL_WEBSHELL_VALIDATION_REPORT.md).

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
