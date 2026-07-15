"""Central traffic profile mapping — volume/timing only, no detection logic."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

SUPPORTED_TRAFFIC_PROFILES = frozenset({"normal", "high"})

_PROFILE_ALIASES: dict[str, str] = {
    "balanced": "normal",
    "burst": "high",
    # Legacy: low removed — map to default normal.
    "low": "normal",
}

# Profile-level DNS tunnel payload sizes (MB).
# high matches normal per-target payload; coverage expands via max_hosts only.
_PROFILE_DNS_TUNNEL_PAYLOAD_MB: dict[str, float] = {
    "normal": 1.0,
    "high": 1.0,
}

# DGA total domain counts (phase1 + phase2) per operational profile.
# high matches normal domain count; resolver selection remains one dns_host.
_DGA_DOMAIN_COUNTS: dict[str, dict[str, int]] = {
    "normal": {"phase1_count": 35, "phase2_count": 10},
    "high": {"phase1_count": 35, "phase2_count": 10},
}

# Shared normal-volume templates reused by high (coverage expands via host_cap).
_HTTP_FOLLOWUP_NORMAL: dict[str, Any] = {
    "max_hosts": 2,
    "max_per_host": 500,
    "max_total": 1000,
    "timeout": 2.0,
    "concurrency": 32,
    "include_attack_paths": True,
    "non_standard_burst_min": 50,
    "non_standard_burst_max": 200,
}
_SSH_FAILURE_NORMAL: dict[str, Any] = {
    "max_hosts": 2,
    "max_per_host": 150,
    "max_total": 150,
    "timeout": 5.0,
}
_SQL_INJECTION_NORMAL: dict[str, Any] = {
    "max_hosts": 2,
    "max_per_host": 500,
    "max_total": 1000,
    "timeout": 10.0,
}
_RARE_PROTOCOL_NORMAL: dict[str, Any] = {
    "max_hosts": 2,
    "timeout": 3.0,
    "rtp_burst_count": 8,
}
_KERBEROS_NORMAL: dict[str, Any] = {
    "max_hosts": 2,
    "attempts_per_host": 10,
    "timeout": 1.0,
}
_SMB_NORMAL: dict[str, Any] = {
    "max_hosts": 2,
    "attempts_per_host": 10,
    "timeout": 10.0,
}
_LDAP_NORMAL: dict[str, Any] = {
    "max_hosts": 2,
    "max_queries_per_host": 8,
    "timeout": 10.0,
}

# Per-scenario parameter templates keyed by operational profile name.
# Explicit scenario_params passed at run time always override these values.
# high = same per-target volume as normal; operational_profiles expands max_hosts.
_SCENARIO_PROFILE_PARAMS: dict[str, dict[str, dict[str, Any]]] = {
    "dummy": {
        "normal": {"action_count": 10},
        "high": {"action_count": 10},
    },
    "dns_tunnel": {
        "normal": {
            "volume_profile": "standard",
            "payload_mb": _PROFILE_DNS_TUNNEL_PAYLOAD_MB["normal"],
            "max_hosts": 1,
            "lock_max_hosts": True,
            "timeout": 0.05,
        },
        "high": {
            # Same per-target payload as normal; no lock — operational expands to all live hosts.
            "volume_profile": "standard",
            "payload_mb": _PROFILE_DNS_TUNNEL_PAYLOAD_MB["high"],
            "max_hosts": 1,
            "max_duration_sec": 120,
            "timeout": 0.05,
        },
    },
    "dga": {
        "normal": {**_DGA_DOMAIN_COUNTS["normal"], "timeout": 0.05},
        "high": {**_DGA_DOMAIN_COUNTS["high"], "timeout": 0.05},
    },
    "http_followup": {
        "normal": dict(_HTTP_FOLLOWUP_NORMAL),
        "high": dict(_HTTP_FOLLOWUP_NORMAL),
    },
    "ssh_failure": {
        "normal": dict(_SSH_FAILURE_NORMAL),
        "high": dict(_SSH_FAILURE_NORMAL),
    },
    "sql_injection": {
        "normal": dict(_SQL_INJECTION_NORMAL),
        "high": dict(_SQL_INJECTION_NORMAL),
    },
    "port_sweep": {
        "normal": {"max_hosts": 254, "max_ports": 10, "timeout": 0.5, "concurrency": 32},
        "high": {"max_hosts": 254, "max_ports": 10, "timeout": 0.5, "concurrency": 32},
    },
    "rare_protocol_activity": {
        "normal": dict(_RARE_PROTOCOL_NORMAL),
        "high": dict(_RARE_PROTOCOL_NORMAL),
    },
    "host_behavior_check": {
        "normal": {"timeout": 30.0},
        "high": {"timeout": 30.0},
    },
    "kerberos_failure": {
        "normal": dict(_KERBEROS_NORMAL),
        "high": dict(_KERBEROS_NORMAL),
    },
    "smb_login_failure": {
        "normal": dict(_SMB_NORMAL),
        "high": dict(_SMB_NORMAL),
    },
    "ldap_enumeration": {
        "normal": dict(_LDAP_NORMAL),
        "high": dict(_LDAP_NORMAL),
    },
    "dns_dummy": {
        "normal": {"query_count": 8},
        "high": {"query_count": 8},
    },
    "dns_transport_dummy": {
        "normal": {"query_count": 8},
        "high": {"query_count": 8},
    },
}

_PROFILE_META: dict[str, dict[str, Any]] = {
    "normal": {
        "description": (
            "Default profile — standard per-target traffic volume against limited "
            "representative targets (DNS Tunnel: 1 live host; others: up to 2)."
        ),
        "intensity": 1,
    },
    "high": {
        "description": (
            "Same per-target traffic volume as normal, applied to all discovered "
            "hosts/services (coverage expansion only)."
        ),
        "intensity": 2,
    },
}


@dataclass(frozen=True)
class TrafficProfile:
    """Operational traffic profile — controls generation volume and timing only."""

    name: str
    description: str
    intensity: int
    scenario_params: dict[str, Any]


def parse_traffic_profile(name: str) -> str:
    """Normalize and validate a traffic profile name."""
    normalized = name.strip().lower()
    normalized = _PROFILE_ALIASES.get(normalized, normalized)
    if normalized not in SUPPORTED_TRAFFIC_PROFILES:
        supported = ", ".join(sorted(SUPPORTED_TRAFFIC_PROFILES))
        raise ValueError(
            f"unknown traffic profile: {name!r}; choose from {supported}"
        )
    return normalized


def resolve_traffic_profile(name: str) -> TrafficProfile:
    """Return profile metadata without scenario-specific parameter mapping."""
    profile_name = parse_traffic_profile(name)
    meta = _PROFILE_META[profile_name]
    return TrafficProfile(
        name=profile_name,
        description=str(meta["description"]),
        intensity=int(meta["intensity"]),
        scenario_params={},
    )


def scenario_params_for_profile(scenario_id: str, profile_name: str) -> dict[str, Any]:
    """Map a traffic profile to scenario-specific execution parameters."""
    profile = parse_traffic_profile(profile_name)
    scenario_map = _SCENARIO_PROFILE_PARAMS.get(scenario_id)
    if scenario_map is None:
        return {"traffic_profile": profile}
    params = dict(scenario_map.get(profile, {}))
    params["traffic_profile"] = profile
    return params


def build_scenario_params(
    scenario_id: str,
    profile_name: str,
    *,
    overrides: dict[str, Any] | None = None,
) -> dict[str, dict[str, Any]]:
    """Build RunManager-compatible scenario_params for a single scenario."""
    params = scenario_params_for_profile(scenario_id, profile_name)
    if overrides:
        params = {**params, **overrides}
    return {scenario_id: params}


def profile_for_scenario(scenario_id: str, profile_name: str) -> TrafficProfile:
    """Return a TrafficProfile including scenario-specific parameter mapping."""
    base = resolve_traffic_profile(profile_name)
    params = scenario_params_for_profile(scenario_id, profile_name)
    return TrafficProfile(
        name=base.name,
        description=base.description,
        intensity=base.intensity,
        scenario_params=params,
    )


def per_target_volume_keys() -> tuple[str, ...]:
    """Parameter keys that must not increase on high vs normal (per-target volume)."""
    return (
        "max_per_host",
        "attempts_per_host",
        "max_queries_per_host",
        "rtp_burst_count",
        "payload_mb",
        "phase1_count",
        "phase2_count",
        "chunk_size",
        "action_count",
        "query_count",
        "non_standard_burst_min",
        "non_standard_burst_max",
    )


DEFAULT_TRAFFIC_PROFILE = "normal"
