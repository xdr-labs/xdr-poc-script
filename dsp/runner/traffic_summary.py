"""Map scenario validation metrics to operator-facing traffic counters."""

from __future__ import annotations

from typing import Any

# (display_label, metric_key) per scenario_id
_SCENARIO_TRAFFIC_LINES: dict[str, tuple[tuple[str, str], ...]] = {
    "dns_tunnel": (("queries_sent", "dns_tunnel_query_sent_count"),),
    "dga": (
        ("domains_generated", "dga_domain_generated_count"),
        ("queries_dispatched", "dga_query_dispatched_count"),
        ("nxdomain_observed", "dga_nxdomain_observed_count"),
        ("resolved_observed", "dga_resolved_observed_count"),
    ),
    "http_followup": (
        ("requests_sent", "http_request_sent_count"),
        ("responses_received", "http_response_received_count"),
    ),
    "sql_injection": (("requests_sent", "sql_request_sent_count"),),
    "port_sweep": (
        ("probes_sent", "port_probe_count"),
        ("success", "port_connection_success_count"),
        ("failed", "port_connection_failure_count"),
    ),
    "ssh_failure": (("attempts", "ssh_auth_attempt_count"),),
    "ldap_enumeration": (("attempts", "ldap_bind_or_search_attempt_count"),),
    "smb_login_failure": (("attempts", "smb_auth_attempt_count"),),
    "kerberos_failure": (("attempts", "kerberos_auth_attempt_count"),),
}


def traffic_lines_for_scenario(
    scenario_id: str,
    metrics: dict[str, Any],
) -> list[tuple[str, int | float | str]]:
    """Return display label/value pairs for a completed scenario."""
    spec = _SCENARIO_TRAFFIC_LINES.get(scenario_id)
    if not spec:
        return []

    lines: list[tuple[str, int | float | str]] = []
    for label, key in spec:
        if key not in metrics:
            continue
        lines.append((label, metrics[key]))
    return lines


def format_scenario_traffic_block(
    scenario_id: str,
    metrics: dict[str, Any],
) -> list[str]:
    """Format indented counter lines for stdout."""
    lines = traffic_lines_for_scenario(scenario_id, metrics)
    if not lines:
        return []
    result = [scenario_id]
    for label, value in lines:
        result.append(f"  {label}={value}")
    return result
