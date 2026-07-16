"""Normal-profile volume contract — single SoT for operator preflight and tests.

Prevents regressing to historical caps (HTTP 300, SQLi 800, DNS max_chunks 50,
DGA 15, abnormal_ua_ratio=0.10) that lived on the retired ``release/v1.4.0`` line.
"""

from __future__ import annotations

from typing import Any

from dsp.protocols.dns.tunnel import plan_chunk_count
from dsp.runtime.traffic_profiles import scenario_params_for_profile

# Operator release line — must match dsp-menu.sh / install-dsp.sh defaults.
OPERATOR_RELEASE_BRANCH = "release/v1.4.0-rc"

NORMAL_HTTP_MAX_TOTAL = 1000
NORMAL_HTTP_MAX_PER_HOST = 500
NORMAL_HTTP_MAX_HOSTS = 2
NORMAL_SQLI_MAX_TOTAL = 1000
NORMAL_SQLI_MAX_PER_HOST = 500
NORMAL_DNS_PAYLOAD_MB = 0.5
NORMAL_DNS_MAX_HOSTS = 1
NORMAL_DGA_PHASE1 = 35
NORMAL_DGA_PHASE2 = 10
NORMAL_DGA_TOTAL = NORMAL_DGA_PHASE1 + NORMAL_DGA_PHASE2
NORMAL_SSH_MAX_TOTAL = 150


def expected_dns_tunnel_idx_chunks() -> int:
    return plan_chunk_count(NORMAL_DNS_PAYLOAD_MB, 30)


def validate_normal_profile_templates() -> list[str]:
    """Return human-readable violations of the normal volume contract (empty = OK)."""
    errors: list[str] = []

    http = scenario_params_for_profile("http_followup", "normal")
    if int(http.get("max_total", 0)) != NORMAL_HTTP_MAX_TOTAL:
        errors.append(f"http_followup max_total={http.get('max_total')} (want {NORMAL_HTTP_MAX_TOTAL})")
    if int(http.get("max_per_host", 0)) != NORMAL_HTTP_MAX_PER_HOST:
        errors.append(
            f"http_followup max_per_host={http.get('max_per_host')} (want {NORMAL_HTTP_MAX_PER_HOST})"
        )
    if int(http.get("max_hosts", 0)) != NORMAL_HTTP_MAX_HOSTS:
        errors.append(f"http_followup max_hosts={http.get('max_hosts')} (want {NORMAL_HTTP_MAX_HOSTS})")
    if "abnormal_ua_ratio" in http:
        errors.append("http_followup must not set abnormal_ua_ratio (all-suspicious UA policy)")

    sqli = scenario_params_for_profile("sql_injection", "normal")
    if int(sqli.get("max_total", 0)) != NORMAL_SQLI_MAX_TOTAL:
        errors.append(f"sql_injection max_total={sqli.get('max_total')} (want {NORMAL_SQLI_MAX_TOTAL})")
    if int(sqli.get("max_per_host", 0)) != NORMAL_SQLI_MAX_PER_HOST:
        errors.append(
            f"sql_injection max_per_host={sqli.get('max_per_host')} (want {NORMAL_SQLI_MAX_PER_HOST})"
        )

    dns = scenario_params_for_profile("dns_tunnel", "normal")
    if float(dns.get("payload_mb", 0)) != NORMAL_DNS_PAYLOAD_MB:
        errors.append(f"dns_tunnel payload_mb={dns.get('payload_mb')} (want {NORMAL_DNS_PAYLOAD_MB})")
    if "max_chunks" in dns:
        errors.append(f"dns_tunnel must not set max_chunks (got {dns.get('max_chunks')})")
    if int(dns.get("max_hosts", 0)) != NORMAL_DNS_MAX_HOSTS:
        errors.append(f"dns_tunnel max_hosts={dns.get('max_hosts')} (want {NORMAL_DNS_MAX_HOSTS})")

    dga = scenario_params_for_profile("dga", "normal")
    phase1 = int(dga.get("phase1_count", 0))
    phase2 = int(dga.get("phase2_count", 0))
    if phase1 != NORMAL_DGA_PHASE1 or phase2 != NORMAL_DGA_PHASE2:
        errors.append(
            f"dga phases={phase1}+{phase2} (want {NORMAL_DGA_PHASE1}+{NORMAL_DGA_PHASE2}={NORMAL_DGA_TOTAL})"
        )

    ssh = scenario_params_for_profile("ssh_failure", "normal")
    if int(ssh.get("max_total", 0)) != NORMAL_SSH_MAX_TOTAL:
        errors.append(f"ssh_failure max_total={ssh.get('max_total')} (want {NORMAL_SSH_MAX_TOTAL})")

    return errors


def normal_profile_preflight_summary() -> dict[str, Any]:
    """Compact summary for operator logs."""
    return {
        "http_max_total": NORMAL_HTTP_MAX_TOTAL,
        "sqli_max_total": NORMAL_SQLI_MAX_TOTAL,
        "dns_idx_chunks": expected_dns_tunnel_idx_chunks(),
        "dga_total": NORMAL_DGA_TOTAL,
        "ssh_max_total": NORMAL_SSH_MAX_TOTAL,
        "operator_release_branch": OPERATOR_RELEASE_BRANCH,
    }


def assert_normal_profile_contract() -> None:
    errors = validate_normal_profile_templates()
    if errors:
        raise AssertionError("normal profile volume contract violated:\n- " + "\n- ".join(errors))
