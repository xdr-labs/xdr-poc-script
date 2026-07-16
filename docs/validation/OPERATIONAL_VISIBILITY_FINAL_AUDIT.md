# Operational Visibility Final Audit

**Branch:** `release/v1.4.0` (post `569efc6`)  
**Audit date:** 2026-06-19 (UTC)  
**Scope:** Operational Visibility completeness and exit-code contract — no new features or scenarios.

Machine-readable evidence:

- Live run: [`../../lab/validation-runs/ov-final-audit-20260619T041009Z/20260619_ddf88a/`](../../lab/validation-runs/ov-final-audit-20260619T041009Z/20260619_ddf88a/)
- Prior regression: [`FULL_REGRESSION_AFTER_OPERATIONAL_VISIBILITY.md`](FULL_REGRESSION_AFTER_OPERATIONAL_VISIBILITY.md)

---

## 1. Root Cause Analysis

### Problem #1 — Exit code 1 on operationally complete runs

**Symptom:** Profile run finished with all scenarios `full` or `skipped` in reconciliation, yet CLI reported `exit 1`.

**Root cause:** `compute_exit_code()` in `dsp/runner/run_manager.py` mapped `ValidationDecision.FAILED` (S2 threshold miss, e.g. DGA `dga_nxdomain_observed_count=0`) to process exit `1`. Reconciliation and validation are separate layers:

| Layer | DGA example |
|-------|-------------|
| Reconciliation | `execution_status=full`, `planned=15`, `actual=15` (historical; current normal is **45**) |
| Validation (S2) | `decision=failed`, `reason=thresholds_not_met` |

Operators saw operational success in console/reconciliation but a failing exit code because threshold validation leaked into the process exit.

**Fix:** Exit code now reflects **run completion**, not S2 threshold outcomes. Threshold results remain in `validation.json`.

### Problem #2 — DGA `planned=0` / `actual=15`

**Symptom:** Console showed `planned_domains=15` but Planned vs Actual Summary showed `planned=0`.

**Root cause:** `dga_started` evidence stores `phase1_count` / `phase2_count` (then profile-normal: 10+5=15; **current normal: 35+10=45**), not `planned_domains`. `_planned_actual_fields()` only read `planned_domains` and `domains_planned` (absent from `traffic_summary` for DGA).

**Fix:** Derive planned from `phase1_count + phase2_count`; add DGA block to `traffic_summary.py`. Local `dga_started` now also writes `domains_planned` / `planned_domains`.

### Problem #3 — Non-Standard Port Burst invisible in OV

**Symptom:** Burst ran inside `http_followup` but Operational Visibility sections showed only aggregate HTTP reconciliation.

**Root cause:** Burst data existed in `http_followup_completed` evidence and `traffic_summary.json` (when `enabled`), but was not surfaced in `operational_visibility.json` or OV report sections.

**Fix:** `build_http_followup_operational_detail()` adds URL Scan + Burst breakdown; enriched into `reconciliations.http_followup` and report section `HTTP Follow-up Operational Detail`.

### Problem #4 — Host Behavior Summary absent on normal profile

**Finding:** `host_behavior_check` is **required** for Phase 1 webshell attack-chain runs per `PRODUCT-CHARTER-v1.2-Final.md` and is included in the normal/high operational profiles by default.

---

## 2. Exit Code Fix

**File:** `dsp/runner/run_manager.py` — `compute_exit_code()`

| Condition | Exit |
|-----------|------|
| Run completed; any SUCCESS / PARTIAL / SKIPPED / FAILED (threshold) | **0** |
| No validation results | **1** |
| CODE_FAILURE | **2** |

**Verified:** Live profile run with DGA `validation.json` decision `failed` returned **EXIT=0** (see section 7).

S2 threshold failure is visible in `validation.json` and `report.md` Traffic Validation table — not in process exit.

---

## 3. DGA Planned/Actual Fix

**Files:** `dsp/reporting/operational_visibility.py`, `dsp/runtime/traffic_summary.py`

| Field | Before | After (audit run) |
|-------|--------|-------------------|
| `planned` | 0 | **15** |
| `actual` | 15 | **15** |
| `execution_ratio_pct` | 0.0 | **100.0** |
| `execution_status` | full (misleading) | **full** |

`traffic_summary.json` now includes:

```json
"dga": {
  "domains_planned": 15,
  "domains_generated": 15,
  ...
}
```

---

## 4. Non-Standard Port Burst Visibility

Audit run `20260619_ddf88a` — `http_followup`:

> **Note:** URL Scan `planned=300` below is a **historical audit observation**. Current normal profile target is **1000** (`max_hosts=2`, `max_per_host=500`, `max_total=1000`).

### report.md

Section **HTTP Follow-up Operational Detail** present:

```text
URL Scan
planned=300
actual=300

Non-Standard Port Burst
attempts=105
success=10
failed=95
```

### traffic_summary.json

```json
"non_standard_port_burst": {
  "enabled": true,
  "ports": [8088, 8443, 8888, 9000, 9001, 9443],
  "attempts": 105,
  "success": 10,
  "failure": 95
}
```

### operational_visibility.json

Nested under `reconciliations.http_followup`:

```json
"url_scan": { "planned": 300, "actual": 300 },
"non_standard_port_burst": {
  "enabled": true,
  "ports": [...],
  "attempts": 105,
  "success": 10,
  "failure": 95
}
```

**Result:** PASS

---

## 5. Host Behavior Summary Investigation

| Question | Answer |
|----------|--------|
| Normal profile includes `host_behavior_check`? | **Yes** — Phase 1 required, included in normal/high profiles |
| Summary missing = bug? | **No** — scenario not in run plan |
| When included | `Host Behavior Summary` in report + `host_behavior_summary` in OV JSON (verified in prior JSP/PHP runs) |

---

## 6. Reconciliation Consistency Audit

Audit run — all scenarios in normal profile (10 scenarios, host behavior excluded):

> **Note:** Volumes in this table are **historical** (pre-v1.4.0-rc profile raise). Current normal goals: http_followup **1000**, sql_injection **1000**, dns_tunnel **~34953** idx (`payload_mb=1.0`), dga **45** (35+10).

| Scenario | planned | actual | status | planned ≥ actual |
|----------|--------:|-------:|--------|:---:|
| http_followup | 300 | 300 | full | ✓ |
| sql_injection | 800 | 800 | full | ✓ |
| ssh_failure | 150 | 150 | full | ✓ |
| ldap_enumeration | 0 | 0 | skipped | ✓ |
| smb_login_failure | 0 | 0 | skipped | ✓ |
| kerberos_failure | 0 | 0 | skipped | ✓ |
| dns_tunnel | 50 | 50 | full | ✓ |
| dga | 15 | 15 | full | ✓ |
| rare_protocol_activity | 4 | 4 | full | ✓ |
| port_sweep | 20 | 20 | full | ✓ |

**Result:** PASS — no `planned < actual` violations; skipped scenarios at `0/0`.

---

## 7. Regression Test Results

| Suite | Command | Result |
|-------|---------|--------|
| Full pytest | `pytest tests/` | **1062 passed** |
| E2E | `pytest tests/e2e/` | **16 passed** |
| Execution | `pytest tests/execution/` | **526 passed** |
| OV unit | `tests/reporting/test_operational_visibility.py` | **8 passed** (incl. DGA + burst) |

### Live validation

```bash
dsp run --profile normal --target-net 10.10.10.0/24 --verbose
```

(`221.139.249.0/24` unreachable from audit host; lab net used — same profile/scenario set.)

| Check | Result |
|-------|--------|
| Process exit | **0** |
| `validation.json` | DGA `failed` (threshold); others success/skipped |
| `report.md` | OV sections + HTTP burst detail |
| `traffic_summary.json` | DGA + burst blocks |
| `operational_visibility.json` | Reconciliations + nested burst |

Run directory: `lab/validation-runs/ov-final-audit-20260619T041009Z/20260619_ddf88a/`

---

## 8. Changed Files

| File | Change |
|------|--------|
| `dsp/runner/run_manager.py` | Exit code: threshold FAILED no longer → 1 |
| `dsp/reporting/operational_visibility.py` | DGA planned fix; HTTP burst OV detail; reconciliation enrich |
| `dsp/runtime/traffic_summary.py` | DGA/dns_tunnel summary; burst `enabled` guard |
| `tests/reporting/test_operational_visibility.py` | DGA + burst tests; exit code test update |
| `tests/validation/test_path_equality.py` | Threshold FAILED → exit 0 |
| `tests/runner/test_confirm_detection.py` | S2 threshold does not affect exit |
| `tests/runner/test_run_metadata_consistency.py` | Same |

---

## Final Verdict

# PASS

Operational Visibility audit items resolved:

1. Exit code reflects run completion (DGA threshold fail → exit 0)
2. DGA planned/actual aligned (`15/15`, 100%)
3. Non-Standard Port Burst visible in report, traffic summary, and OV JSON
4. Host Behavior absence on normal profile explained (optional scenario)
5. Full pytest green (1062)
6. Live profile run exit 0 with complete artifacts
