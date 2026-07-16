# DSP v1.4.0 Release Notes

**Version:** 1.4.0  
**Date:** 2026-06-18 (UTC)  
**Tag:** `v1.4.0`  
**Release branch (historical):** `release/v1.4.0` (retired — use `release/v1.4.0-rc`)  
**Package:** `detection-scenario-platform` (`dsp`)

---

## Summary

DSP v1.4.0 completes Release 1.0 readiness documentation aligned with real-environment webshell validation. **Release recommendation: READY WITH KNOWN LIMITATIONS.**

Validated providers: **Local**, **JSP**, **PHP**. ASPX remains preview — contract and transport exist, but real Windows IIS execution has not been validated.

---

### Release 1.0 Status

| Area | Status |
|------|--------|
| Release scope (4 criteria) | Met via JSP + PHP real validation |
| Local Provider | Validated |
| JSP Webshell | Validated |
| PHP Webshell | Validated |
| ASPX Webshell | Not validated (preview) |

---

### Validation Milestone

- Real Tomcat + JSP validation completed — 10/10 scenarios on `victim-linux` ([`docs/validation/JSP_REAL_WEBSHELL_VALIDATION_REPORT.md`](docs/validation/JSP_REAL_WEBSHELL_VALIDATION_REPORT.md))
- Real Apache + PHP validation completed — 10/10 scenarios on `victim-linux` ([`docs/validation/PHP_REAL_WEBSHELL_VALIDATION_REPORT.md`](docs/validation/PHP_REAL_WEBSHELL_VALIDATION_REPORT.md))
- Host Behavior Check validation completed — full EDR lifecycle events on JSP and PHP
- Release 1.0 scope validated: remote execution, bundle collection, evidence export, manual verification workflow

---

### Known limitations (v1.4.0)

| Limitation | Detail |
|------------|--------|
| **ASPX runtime validation pending** | No reachable IIS/`shell.aspx` endpoint in lab; 0/10 real E2E scenarios |
| **Windows webshell execution path pending** | Bundle runner, collector, artifact handling, platform dispatch are Linux-oriented |
| **ASPX preview status** | Contract and HTTP transport exist; not recommended for production validation until Windows IIS validation completes |

See also: [`docs/validation/ASPX_REAL_WEBSHELL_VALIDATION_REPORT.md`](docs/validation/ASPX_REAL_WEBSHELL_VALIDATION_REPORT.md), [`docs/validation/ASPX_WINDOWS_COMPATIBILITY_AUDIT.md`](docs/validation/ASPX_WINDOWS_COMPATIBILITY_AUDIT.md), [`docs/validation/RELEASE_DOCUMENTATION_AUDIT.md`](docs/validation/RELEASE_DOCUMENTATION_AUDIT.md).

---

### Operator CLI (unchanged from v1.3.0)

```bash
# Local run
dsp run --target-net 10.10.10.0/24 --profile normal

# Webshell — validated families: jsp, php
dsp run --execution-provider webshell --webshell-family jsp \
  --webshell-url http://10.10.10.20:8080/shell.jsp \
  --target-net 10.10.10.0/24 --profile normal
```

---

# DSP v1.3.0 Release Notes

**Version:** 1.3.0  
**Date:** 2026-06-09 (UTC)  
**Package:** `detection-scenario-platform` (`dsp`)

---

## Summary

DSP v1.3.0 simplifies the operator CLI around three decisions: **where** to run (`local` / `webshell`), **which network** (`--target-net`), and **how intensively** (`--profile low|normal|high`). Discovery, host selection, protocol coverage, follow-up, and scenario ordering are handled internally.

### Operator CLI

```bash
# Default operational run (profile=normal)
dsp run --target-net 221.139.249.0/24 --profile normal

# Quick validation
dsp run --target-net 221.139.249.0/24 --profile low

# Maximum coverage
dsp run --target-net 221.139.249.0/24 --profile high

# Webshell — same UX
dsp run --execution-provider webshell --webshell-family jsp \
  --webshell-url http://server/shell.jsp \
  --target-net 221.139.249.0/24 --profile normal
```

### Changed Components

| Component | Change |
|-----------|--------|
| `dsp run` | `--profile` added; `--scenarios` now optional (advanced) |
| `operational_profiles.py` | Profile → scenario coverage + host limits |
| `traffic_profiles.py` | Renamed `balanced`→`normal`, `burst`→`high` (legacy aliases kept) |
| `console_output.py` | Progress + evidence summary on stdout |
| `RunManager` | Optional `on_progress` callback; `operational_profile` in run metadata |

### Profiles

| Profile | Scenarios | Host limit | Use case |
|---------|-----------|------------|----------|
| `low` | port_sweep, dns_tunnel, http_followup | 1 | Install / sensor check |
| `normal` | + dga, sql_injection, ldap, smb, ssh, kerberos | 2 | Demo / validation |
| `high` | same as normal | all discovered (capped) | Coverage / stress |

### Pre-release hardening (v1.3.0)

| Feature | Detail |
|---------|--------|
| Large CIDR guardrail | `--target-net` wider than `/24` blocked unless `--allow-large-target` **and** `--max-hosts` |
| `--max-hosts` | Caps CIDR expansion and per-scenario host selection (including `high`) |
| Progress counters | Per-scenario traffic metrics on completion (e.g. `queries_sent=100`) |
| Traffic Summary | Aggregated scenario counters before Evidence Summary |

```bash
# Blocked:
dsp run --target-net 10.0.0.0/16 --profile high

# Allowed:
dsp run --target-net 10.0.0.0/16 --profile high --allow-large-target --max-hosts 10
```

See [`docs/dsp-operational-cli-v1.3.0.md`](docs/dsp-operational-cli-v1.3.0.md).

---

# DSP v1.2.0 Release Notes

**Version:** 1.2.0  
**Date:** 2026-06-09 (UTC)  
**Package:** `detection-scenario-platform` (`dsp`)

---

## Summary

DSP v1.2.0 completes the webshell remote execution path on the standard `dsp run` entry point. Operators can run detection scenarios on a remote host via JSP/PHP/ASPX webshell (CLI supports all three families), collect event bundles, import them into the local Event Store, and receive validation, reporting, and evidence packages — without changing S2 exit codes or requiring Stellar API integration.

> **Note (v1.4.0):** Real runtime validation completed for **JSP** and **PHP** only. **ASPX** remains preview until Windows IIS validation completes. See v1.4.0 release notes above.

Live lab validation on `victim-linux` (`10.10.10.20`) confirmed real DNS, HTTP, and TCP traffic generation plus evidence export for the webshell path. See [`docs/remote-live-traffic-validation-report.md`](docs/remote-live-traffic-validation-report.md).

---

## Changed Components

### CLI (`dsp`)

| Change | Detail |
|--------|--------|
| `--execution-provider` | New choice: `local` (default) or `webshell` |
| `--webshell-family` | Required for webshell: `jsp`, `php`, `aspx` |
| `--webshell-url` | Required for webshell: endpoint URL |
| `--remote-work-dir` | Remote bundle directory (default: `/tmp/dsp`) |
| `--verify-tls` | Optional TLS verification for webshell HTTP transport |

### New entry point

| Script | Purpose |
|--------|---------|
| `dsp-remote-scenario` | Runs on the remote webshell target host; executes one scenario and writes `events.jsonl` bundle |

### RunManager

- Webshell provider selection and remote flow orchestration (`RemoteScenarioRunner` → `RemoteEventCollector` → Event Store import).
- Validation, reporting, and evidence export (`EvidenceExporter` + `ManualVerificationPackageGenerator`) on webshell runs (default `export_evidence=True`).

### Webshell runtime

- JSP artifact download fallback via `cat <path>` when `remote_path` GET is unavailable.
- Base64-encoded scenario payload transport (`encode_scenario_payload` / `decode_scenario_payload`) for shell-safe JSON delivery.

### Tests

- New: `test_remote_scenario_cli.py`, `test_remote_end_to_end.py`, `test_runmanager_webshell.py`
- Updated: remote scenario runner, e2e webshell flow, operational runner integration tests
- **Release gate:** 830 pytest tests passed

---

## Upgrade Steps

```bash
cd detection-scenario-platform
pip install -e ".[dev]"    # or: .venv/bin/pip install -e ".[dev]"
dsp --version              # expect: dsp 1.2.0
```

**Remote host prerequisite:** deploy `detection-scenario-platform` tree and install `dsp-remote-scenario` wrapper on the webshell target (see validation report §1).

**Example — local run (unchanged):**

```bash
dsp run --scenarios dns_tunnel --target-net 10.10.10.0/24
```

**Example — webshell remote run:**

```bash
dsp run \
  --scenarios dns_tunnel \
  --execution-provider webshell \
  --webshell-family jsp \
  --webshell-url http://10.10.10.20:8080/shell.jsp \
  --target-net 10.10.10.0/24
```

---

## Known Limitations (v1.2.0)

| Limitation | Detail | Workaround |
|------------|--------|------------|
| **`dsp run --profile low` not supported** | CLI has no `--profile` / `--traffic-profile` flag | Use `operational_runner --traffic-profile low`, or pass `scenario_params=build_scenario_params(id, "low")` programmatically |
| **`ssh_failure` live validation substituted** | Live session used `port_sweep` for TCP connect validation instead of `ssh_failure` | `port_sweep` exercises the same remote TCP transport path; SSH auth negotiation not validated in live report |
| **Remote install prerequisite** | Target host needs `dsp-remote-scenario` + platform tree | Deploy per [`docs/remote-live-traffic-validation-report.md`](docs/remote-live-traffic-validation-report.md) §1 |
| **JSP download fallback** | Lab JSP webshell lacks `remote_path` GET; bundle retrieved via `cat` | Automatic in `JspWebshellRuntime.download_artifact()` |
| **Detection confirmation (S3)** | Optional; does not affect S2 exit codes | `--confirm-detection` unchanged from v1.1.0 |

Additional gap analysis: [`docs/release-gap-analysis-v1.2.0.md`](docs/release-gap-analysis-v1.2.0.md).

---

## Validation References

- Live traffic report: [`docs/remote-live-traffic-validation-report.md`](docs/remote-live-traffic-validation-report.md)
- Release readiness revalidation: [`docs/release-readiness-revalidation.md`](docs/release-readiness-revalidation.md)
- Remote execution design: [`docs/remote-execution-completion-plan.md`](docs/remote-execution-completion-plan.md)

---

*DSP provides execution evidence only. Alert, case, and detection success are operator-verified in Stellar UI.*
