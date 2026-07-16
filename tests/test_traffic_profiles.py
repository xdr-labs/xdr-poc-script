"""Tests for dsp.runtime.traffic_profiles."""

from __future__ import annotations

import pytest

from dsp.runtime.traffic_profiles import (
    DEFAULT_TRAFFIC_PROFILE,
    SUPPORTED_TRAFFIC_PROFILES,
    build_scenario_params,
    parse_traffic_profile,
    per_target_volume_keys,
    profile_for_scenario,
    resolve_traffic_profile,
    scenario_params_for_profile,
)


@pytest.mark.parametrize("name", sorted(SUPPORTED_TRAFFIC_PROFILES))
def test_parse_traffic_profile_accepts_supported_names(name: str) -> None:
    assert parse_traffic_profile(name) == name
    assert parse_traffic_profile(name.upper()) == name


def test_supported_profiles_are_normal_and_high_only() -> None:
    assert SUPPORTED_TRAFFIC_PROFILES == frozenset({"normal", "high"})
    assert DEFAULT_TRAFFIC_PROFILE == "normal"


def test_parse_traffic_profile_rejects_invalid() -> None:
    with pytest.raises(ValueError, match="unknown traffic profile"):
        parse_traffic_profile("aggressive")


def test_resolve_traffic_profile_metadata() -> None:
    profile = resolve_traffic_profile("normal")
    assert profile.name == "normal"
    assert profile.intensity == 1
    assert "default" in profile.description.lower() or "representative" in profile.description.lower()


def test_parse_traffic_profile_accepts_legacy_aliases() -> None:
    assert parse_traffic_profile("balanced") == "normal"
    assert parse_traffic_profile("burst") == "high"
    assert parse_traffic_profile("low") == "normal"


def test_dns_tunnel_profile_payload_and_host_semantics() -> None:
    normal = scenario_params_for_profile("dns_tunnel", "normal")
    high = scenario_params_for_profile("dns_tunnel", "high")

    assert normal["payload_mb"] == high["payload_mb"] == 0.5
    assert normal["max_hosts"] == 1
    assert normal.get("lock_max_hosts") is True
    assert high.get("lock_max_hosts") is not True
    assert normal["traffic_profile"] == "normal"
    assert high["traffic_profile"] == "high"


def test_profile_dns_tunnel_payload_mb() -> None:
    assert scenario_params_for_profile("dns_tunnel", "normal")["payload_mb"] == 0.5
    assert scenario_params_for_profile("dns_tunnel", "high")["payload_mb"] == 0.5


def test_dns_tunnel_start_metadata_uses_payload_volume_not_fixed_cap() -> None:
    from dsp.engine.scenario_engine import TargetSet
    from dsp.protocols.dns.tunnel import CHUNK_SIZE_DEFAULT, plan_chunk_count
    from dsp.runner.target_selection import scenario_start_metadata

    alive = ["10.10.10.97", "10.10.10.98"]
    targets = TargetSet(
        target_net="10.10.10.0/24",
        hosts=alive,
        service_hosts={"dns_hosts": ["10.10.10.1"], "http_targets": alive},
        discovery_enabled=True,
        discovery_meta={"alive_hosts": alive},
    )
    params = scenario_params_for_profile("dns_tunnel", "normal")
    meta = scenario_start_metadata("dns_tunnel", targets, params)
    idx_per_host = plan_chunk_count(0.5, CHUNK_SIZE_DEFAULT)
    assert meta["payload_mb"] == 0.5
    assert meta["payload_bytes"] == int(0.5 * 1024 * 1024)
    assert meta["planned_queries"] == (idx_per_host + 2) * 1  # max_hosts=1
    assert meta["planned_queries"] != 50


def _dga_total_domains(params: dict) -> int:
    return int(params["phase1_count"]) + int(params["phase2_count"])


def test_dga_domain_counts_high_matches_normal() -> None:
    normal = scenario_params_for_profile("dga", "normal")
    high = scenario_params_for_profile("dga", "high")

    assert _dga_total_domains(normal) == 45
    assert _dga_total_domains(high) == 45


def test_high_per_target_volume_matches_normal() -> None:
    scenarios = [
        "http_followup",
        "sql_injection",
        "ssh_failure",
        "dga",
        "dns_tunnel",
        "rare_protocol_activity",
        "ldap_enumeration",
        "smb_login_failure",
        "kerberos_failure",
    ]
    keys = per_target_volume_keys()
    for sid in scenarios:
        normal = scenario_params_for_profile(sid, "normal")
        high = scenario_params_for_profile(sid, "high")
        for key in keys:
            if key in normal or key in high:
                assert high.get(key) == normal.get(key), f"{sid}.{key}"


def test_build_scenario_params_wraps_scenario_id() -> None:
    params = build_scenario_params("dummy", "normal")
    assert "dummy" in params
    assert params["dummy"]["action_count"] == 10


def test_build_scenario_params_applies_overrides() -> None:
    params = build_scenario_params("dummy", "normal", overrides={"action_count": 2})
    assert params["dummy"]["action_count"] == 2


def test_profile_for_scenario_includes_scenario_params() -> None:
    profile = profile_for_scenario("http_followup", "high")
    assert profile.name == "high"
    assert profile.scenario_params["max_total"] == 1000
    assert profile.scenario_params["max_per_host"] == 500


def test_normal_profile_http_followup_dual_target_v139() -> None:
    params = scenario_params_for_profile("http_followup", "normal")
    assert params.get("include_attack_paths") is True
    assert params["max_hosts"] == 2
    assert params["max_total"] == 1000
    assert params["max_per_host"] == 500
    assert "abnormal_ua_ratio" not in params


def test_normal_profile_sql_injection_1000_requests_v139() -> None:
    params = scenario_params_for_profile("sql_injection", "normal")
    assert params["max_total"] == 1000
    assert params["max_per_host"] == 500
    assert params["max_hosts"] == 2
