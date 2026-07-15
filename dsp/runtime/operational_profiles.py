"""Operational run profiles — scenario coverage and host selection for `dsp run --profile`."""

from __future__ import annotations

from typing import Any, Sequence

from dsp.engine.target_engine import expand_target_net_hosts
from dsp.runtime.traffic_profiles import (
    build_scenario_params,
    parse_traffic_profile,
    scenario_params_for_profile,
)

SUPPORTED_OPERATIONAL_PROFILES = frozenset({"normal", "high"})

DEFAULT_OPERATIONAL_PROFILE = "normal"

HOST_BEHAVIOR_CHECK_SCENARIO_ID = "host_behavior_check"

_PROFILE_ALIASES: dict[str, str] = {
    "balanced": "normal",
    "burst": "high",
    # Legacy: low removed — map to default normal.
    "low": "normal",
}

# Target-net execution order (after upfront discovery TCP prefetch):
# Phase 1 webshell-host telemetry → port_sweep → service follow-ups → dns_tunnel last.
DISCOVERY_FIRST_SCENARIO_ORDER: tuple[str, ...] = (
    HOST_BEHAVIOR_CHECK_SCENARIO_ID,
    "port_sweep",
    "http_followup",
    "sql_injection",
    "ssh_failure",
    "ldap_enumeration",
    "smb_login_failure",
    "kerberos_failure",
    "dga",
    "rare_protocol_activity",
    "dns_tunnel",
)

_PROFILE_SCENARIOS: dict[str, tuple[str, ...]] = {
    "normal": DISCOVERY_FIRST_SCENARIO_ORDER,
    "high": DISCOVERY_FIRST_SCENARIO_ORDER,
}

_PROFILE_MAX_HOSTS: dict[str, int | None] = {
    "normal": 2,
    "high": None,  # use all discovered hosts
}

_SCENARIO_LABELS: dict[str, str] = {
    "port_sweep": "Port Sweep",
    "dns_tunnel": "DNS Tunnel",
    "dga": "DGA",
    "http_followup": "HTTP Follow-up",
    "sql_injection": "SQL Injection",
    HOST_BEHAVIOR_CHECK_SCENARIO_ID: "Host Behavior Check",
    "ldap_enumeration": "LDAP Enumeration",
    "smb_login_failure": "SMB Login Failure",
    "ssh_failure": "SSH Failure",
    "kerberos_failure": "Kerberos Failure",
    "rare_protocol_activity": "Rare Protocol Activity",
    "dummy": "Dummy",
}


def parse_operational_profile(name: str) -> str:
    """Normalize and validate an operational profile name."""
    normalized = name.strip().lower()
    normalized = _PROFILE_ALIASES.get(normalized, normalized)
    if normalized not in SUPPORTED_OPERATIONAL_PROFILES:
        supported = ", ".join(sorted(SUPPORTED_OPERATIONAL_PROFILES))
        raise ValueError(
            f"unknown operational profile: {name!r}; choose from {supported}"
        )
    return normalized


def scenarios_for_profile(profile_name: str) -> list[str]:
    """Return ordered scenario IDs for an operational profile."""
    profile = parse_operational_profile(profile_name)
    return list(_PROFILE_SCENARIOS[profile])


def resolve_runnable_scenarios(
    profile_name: str,
    active_ids: Sequence[str],
) -> list[str]:
    """Filter profile scenarios to registry-active IDs, preserving order."""
    active = set(active_ids)
    return [sid for sid in scenarios_for_profile(profile_name) if sid in active]


def ensure_webshell_phase1_scenarios(
    scenario_ids: Sequence[str],
    *,
    active_ids: Sequence[str],
) -> list[str]:
    """Ensure Phase 1 host behavior check is scheduled for webshell attack-chain runs."""
    active = set(active_ids)
    if HOST_BEHAVIOR_CHECK_SCENARIO_ID not in active:
        return list(scenario_ids)
    if HOST_BEHAVIOR_CHECK_SCENARIO_ID in scenario_ids:
        return list(scenario_ids)
    return insert_host_behavior_check(scenario_ids)


def insert_host_behavior_check(scenario_ids: Sequence[str]) -> list[str]:
    """Insert host_behavior_check before target-net scenarios (Phase 1 webshell host)."""
    ordered = list(scenario_ids)
    if HOST_BEHAVIOR_CHECK_SCENARIO_ID in ordered:
        return ordered
    return [HOST_BEHAVIOR_CHECK_SCENARIO_ID, *ordered]


def discover_host_count(target_net: str, *, max_hosts: int | None = None) -> int:
    """Return usable host count from target_net CIDR (Target Discovery)."""
    net = (target_net or "").strip()
    if not net:
        raise ValueError(
            "target_net is required; refusing silent lab fallback"
        )
    cap = max_hosts if max_hosts is not None else 254
    return len(expand_target_net_hosts(net, max_hosts=cap))


def scenario_display_name(scenario_id: str) -> str:
    """Human-readable scenario label for progress output."""
    return _SCENARIO_LABELS.get(
        scenario_id,
        scenario_id.replace("_", " ").title(),
    )


def _host_limit_for_profile(
    profile: str,
    host_count: int,
    *,
    max_hosts_override: int | None = None,
) -> int:
    cap = _PROFILE_MAX_HOSTS[profile]
    if cap is None:
        limit = max(1, host_count)
    else:
        limit = max(1, min(cap, host_count))
    if max_hosts_override is not None:
        limit = min(limit, max_hosts_override)
    return max(1, limit)


def _scale_max_total_for_host_expansion(
    params: dict[str, Any],
    *,
    previous_max_hosts: int,
) -> dict[str, Any]:
    """When host coverage expands, keep per-host intensity and grow max_total."""
    merged = dict(params)
    if "max_per_host" not in merged or "max_total" not in merged:
        return merged
    new_hosts = int(merged.get("max_hosts", previous_max_hosts))
    if new_hosts <= previous_max_hosts:
        return merged
    per_host = int(merged["max_per_host"])
    merged["max_total"] = max(int(merged["max_total"]), per_host * new_hosts)
    return merged


def _apply_host_limit(
    params: dict[str, Any],
    profile: str,
    host_count: int,
    *,
    max_hosts_override: int | None = None,
) -> dict[str, Any]:
    merged = dict(params)
    previous_max_hosts = int(merged.get("max_hosts", 1))
    if merged.get("full_sweep") or merged.get("lock_max_hosts"):
        explicit = int(merged.get("max_hosts", host_count))
        limit = max(1, min(explicit, host_count))
        if max_hosts_override is not None:
            limit = min(limit, max_hosts_override)
        merged["max_hosts"] = max(1, limit)
        return merged
    limit = _host_limit_for_profile(
        profile,
        host_count,
        max_hosts_override=max_hosts_override,
    )
    merged["max_hosts"] = limit
    return _scale_max_total_for_host_expansion(
        merged,
        previous_max_hosts=previous_max_hosts,
    )


def build_operational_scenario_params(
    profile_name: str,
    scenario_ids: Sequence[str],
    *,
    target_net: str,
    max_hosts: int | None = None,
) -> dict[str, dict[str, Any]]:
    """Build RunManager scenario_params for an operational profile run."""
    profile = parse_operational_profile(profile_name)
    traffic_profile = parse_traffic_profile(profile)
    host_count = discover_host_count(target_net, max_hosts=max_hosts)

    params: dict[str, dict[str, Any]] = {}
    for scenario_id in scenario_ids:
        base = scenario_params_for_profile(scenario_id, traffic_profile)
        merged = _apply_host_limit(
            base,
            profile,
            host_count,
            max_hosts_override=max_hosts,
        )
        params[scenario_id] = merged
    return params


def build_explicit_scenario_params_with_profile(
    scenario_ids: Sequence[str],
    profile_name: str,
    *,
    target_net: str,
    max_hosts: int | None = None,
) -> dict[str, dict[str, Any]]:
    """Apply operational profile volume/host limits to explicit scenario IDs."""
    return build_operational_scenario_params(
        profile_name,
        scenario_ids,
        target_net=target_net,
        max_hosts=max_hosts,
    )
