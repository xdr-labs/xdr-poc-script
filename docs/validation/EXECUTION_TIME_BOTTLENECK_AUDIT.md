# Execution Time Bottleneck Audit — Normal Profile (Real Environment)

**Audit date:** 2026-06-19 (UTC)  
**Reference:** Pre-fix real-environment profile run (`Duration: 4m55s`)  
**Profile:** `normal` (`dsp run --profile normal`)  
**Network:** `10.10.10.0/24` (lab)

---

## Summary

| Metric | Value |
|--------|-------|
| Total wall time | **4m 55s (295s)** |
| Scenarios executed | 10 (normal profile; `host_behavior_check` required per Charter v1.2 Phase 1 — may be absent in legacy runs) |
| Primary bottleneck | **kerberos_failure** — 68% of total time (pre-fix) |

Post-fix Kerberos fire-and-forget: **20 attempts complete in <1s** (measured locally after patch).

---

## Scenario Timing Breakdown (Pre-Fix Real Environment)

Estimates derived from run console output, `duration_sec` evidence patterns, and traffic-profile parameters. Kerberos elapsed is from observed operator log (`00:03:20`).

> **Note:** Pre-fix volumes below are **historical**. Current normal profile: http_followup **1000**, sql_injection **1000**, dga **45** (35+10), dns_tunnel **~34953** idx (`payload_mb=1.0`, not 50).

| Scenario | Elapsed | Percentage | Notes |
|----------|---------|------------|-------|
| kerberos_failure | **200s** | **67.8%** | 20 attempts × ~10s recv timeout per attempt |
| sql_injection | ~35s | 11.9% | 800 requests, timeout 10s, partial parallel |
| http_followup | ~30s | 10.2% | 300 requests + non-standard port burst |
| ssh_failure | ~18s | 6.1% | 150 auth attempts, timeout 5s |
| port_sweep | ~5s | 1.7% | 20 TCP probes, concurrency 32 |
| rare_protocol_activity | ~4s | 1.4% | 4 probes × 3s timeout |
| dga | ~2s | 0.7% | 15 domains then; **current normal = 45** (35 NX + 10 resolvable) |
| dns_tunnel | ~1s | 0.3% | 50 queries then; **current normal ≈ 34953** idx @ 1MB |
| ldap_enumeration | 0s | 0% | skipped — no LDAP discovered |
| smb_login_failure | 0s | 0% | skipped — no SMB discovered |

**Total accounted:** ~295s

---

## Post-Fix Projection (Same Profile)

| Scenario | Pre-fix | Post-fix (est.) | Change |
|----------|---------|-----------------|--------|
| kerberos_failure | 200s | **<1s** | fire-and-forget AS-REQ |
| dns_tunnel | 1s | **8–15s** | burst-pause realism (5–10 queries, 0.5–2s pause) |
| dga | 2s | **~4s** | 45 domains (was 15) |
| Others | ~92s | ~92s | unchanged |

**Projected total:** ~105–115s (~1m 45s–1m 55s), down from 4m 55s.

---

## Top 3 Bottlenecks (Pre-Fix)

### 1. kerberos_failure — 200s (68%)

**Cause:** Each UDP AS-REQ blocked on `recvfrom()` until the 10s socket timeout when no KDC responded. With 20 planned attempts (`2 hosts × 10 attempts`), worst-case wait dominated the entire run.

**Fix applied:** Fire-and-forget probe — send AS-REQ, do not wait for KDC response (`kdc_response_wait_sec=0`). Verified: 20 attempts in <1s.

### 2. sql_injection — ~35s (12%)

**Cause:** Highest request volume in profile (800 requests). Even with bounded concurrency, per-request HTTP timeout (10s) and target response latency accumulate.

**Status:** No change in this patch (operational fidelity scope). Volume is by design for detection threshold coverage.

### 3. http_followup — ~30s (10%)

**Cause:** 300 URL scan requests plus non-standard port burst (105 attempts in audit run). Dual-host coverage with 2s HTTP timeout.

**Status:** No change in this patch. Burst visibility added in prior OV work; timing unchanged.

---

## Observations

1. **Discovery vs attack phases:** Pre-fix, Kerberos alone exceeded typical discovery phase duration — inverted cost model.
2. **Instant scenarios are not free in aggregate:** DNS tunnel showed `0s` elapsed but contributed no realism; burst-pause adds ~10s intentional spread (acceptable trade-off).
3. **Skipped scenarios correctly cost 0s:** LDAP/SMB/Kerberos skip paths when services undiscovered add no wall-time penalty.
4. **DGA threshold miss unrelated to duration:** 15 domains completed in ~2s but failed S2 validation (`thresholds_not_met`); volume increase to 45 addresses detection coverage, not speed.

---

## Verification Commands

```bash
# Post-fix kerberos micro-benchmark (20 attempts)
python3 -c "
import time
from dsp.protocols.kerberos.attempts import plan_kerberos_attempts
from dsp.protocols.kerberos.client import KerberosClient
plans = plan_kerberos_attempts(['10.10.10.30','10.10.10.31'], max_hosts=2, attempts_per_host=10)
client = KerberosClient(mode='live', safe_mode=True)
t0 = time.monotonic()
for p in plans: client.attempt(p)
print(f'attempts={len(plans)} elapsed={time.monotonic()-t0:.2f}s')
"

# Full profile run (lab)
dsp run --profile normal --target-net 10.10.10.0/24 --verbose
```

---

## Final Verdict

Pre-fix profile run was **Kerberos-dominated** (68%). Post-fix changes target the largest bottleneck without altering host selection, discovery order, or validation logic.
