"""Central traffic profile mapping — volume/timing only, no detection logic."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

SUPPORTED_TRAFFIC_PROFILES = frozenset({"low", "normal", "high"})

_PROFILE_ALIASES: dict[str, str] = {
    "balanced": "normal",
    "burst": "high",
}

# Per-scenario parameter templates keyed by operational profile name.
# Explicit scenario_params passed at run time always override these values.
_SCENARIO_PROFILE_PARAMS: dict[str, dict[str, dict[str, Any]]] = {
    "dummy": {
        "low": {"action_count": 3},
        "normal": {"action_count": 10},
        "high": {"action_count": 25},
    },
    # DNS Tunnel operational volumes follow RC 0.5 MB file-exfil model.
    # Do not reintroduce baseline max_chunks caps (e.g. normal=50).
    "dns_tunnel": {
        "low": {
            "volume_profile": "demo",
            "payload_mb": 0.5,
            "max_hosts": 1,
            "timeout": 0.1,
        },
        "normal": {
            "volume_profile": "standard",
            "payload_mb": 0.5,
            "max_hosts": 1,
            "lock_max_hosts": True,
            "timeout": 0.05,
        },
        "high": {
            "volume_profile": "standard",
            "payload_mb": 0.5,
            "max_hosts": 1,
            "max_duration_sec": 120,
            "timeout": 0.05,
        },
    },
    "dga": {
        "low": {"phase1_count": 3, "phase2_count": 2, "timeout": 0.1},
        "normal": {"phase1_count": 10, "phase2_count": 5, "timeout": 0.05},
        "high": {"phase1_count": 30, "phase2_count": 15, "timeout": 0.05},
    },
    "http_followup": {
        "low": {
            "max_hosts": 1,
            "max_per_host": 40,
            "max_total": 40,
            "timeout": 2.0,
            "concurrency": 32,
            "include_attack_paths": True,
        },
        "normal": {
            "max_hosts": 2,
            "max_per_host": 150,
            "max_total": 300,
            "timeout": 2.0,
            "concurrency": 32,
            "include_attack_paths": True,
            "abnormal_ua_ratio": 0.10,
        },
        "high": {
            "max_hosts": 1,
            "max_per_host": 300,
            "max_total": 300,
            "timeout": 2.0,
            "concurrency": 32,
            "include_attack_paths": True,
        },
    },
    "ssh_failure": {
        "low": {"max_hosts": 1, "max_per_host": 30, "max_total": 30, "timeout": 5.0},
        "normal": {"max_hosts": 2, "max_per_host": 150, "max_total": 150, "timeout": 5.0},
        "high": {"max_hosts": 2, "max_per_host": 300, "max_total": 300, "timeout": 5.0},
    },
    "sql_injection": {
        "low": {"max_hosts": 1, "max_per_host": 3, "max_total": 5, "timeout": 15.0},
        "normal": {"max_hosts": 2, "max_per_host": 400, "max_total": 800, "timeout": 10.0},
        "high": {"max_hosts": 3, "max_per_host": 25, "max_total": 50, "timeout": 5.0},
    },
    "port_sweep": {
        "low": {"max_hosts": 1, "max_ports": 10, "timeout": 0.5, "concurrency": 32},
        "normal": {"max_hosts": 254, "max_ports": 10, "timeout": 0.5, "concurrency": 32},
        "high": {"max_hosts": 254, "max_ports": 10, "timeout": 0.5, "concurrency": 32},
    },
    "host_behavior_check": {
        "low": {"timeout": 30.0},
        "normal": {"timeout": 30.0},
        "high": {"timeout": 30.0},
    },
    "kerberos_failure": {
        "low": {"max_hosts": 1, "attempts_per_host": 3, "timeout": 15.0},
        "normal": {"max_hosts": 2, "attempts_per_host": 10, "timeout": 10.0},
        "high": {"max_hosts": 2, "attempts_per_host": 25, "timeout": 5.0},
    },
    "smb_login_failure": {
        "low": {"max_hosts": 1, "attempts_per_host": 3, "timeout": 15.0},
        "normal": {"max_hosts": 2, "attempts_per_host": 10, "timeout": 10.0},
        "high": {"max_hosts": 2, "attempts_per_host": 25, "timeout": 5.0},
    },
    "ldap_enumeration": {
        "low": {"max_hosts": 1, "max_queries_per_host": 3, "timeout": 15.0},
        "normal": {"max_hosts": 2, "max_queries_per_host": 8, "timeout": 10.0},
        "high": {"max_hosts": 2, "max_queries_per_host": 20, "timeout": 5.0},
    },
    "dns_dummy": {
        "low": {"query_count": 3},
        "normal": {"query_count": 8},
        "high": {"query_count": 20},
    },
    "dns_transport_dummy": {
        "low": {"query_count": 3},
        "normal": {"query_count": 8},
        "high": {"query_count": 20},
    },
}

_PROFILE_META: dict[str, dict[str, Any]] = {
    "low": {
        "description": "Conservative traffic volume for first connectivity checks.",
        "intensity": 1,
    },
    "normal": {
        "description": "Moderate traffic volume — default operational test profile.",
        "intensity": 2,
    },
    "high": {
        "description": "High traffic volume — maximum coverage with bounded duration.",
        "intensity": 3,
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
