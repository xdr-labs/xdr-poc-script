"""Tests for dsp.runtime.operational_profiles."""

from __future__ import annotations

import pytest

from dsp.runtime.operational_profiles import (
    DEFAULT_OPERATIONAL_PROFILE,
    HOST_BEHAVIOR_CHECK_SCENARIO_ID,
    SUPPORTED_OPERATIONAL_PROFILES,
    build_operational_scenario_params,
    discover_host_count,
    parse_operational_profile,
    resolve_runnable_scenarios,
    scenarios_for_profile,
)


@pytest.mark.parametrize("name", sorted(SUPPORTED_OPERATIONAL_PROFILES))
def test_parse_operational_profile_accepts_supported_names(name: str) -> None:
    assert parse_operational_profile(name) == name


def test_supported_profiles_are_normal_and_high_only() -> None:
    assert SUPPORTED_OPERATIONAL_PROFILES == frozenset({"normal", "high"})
    assert DEFAULT_OPERATIONAL_PROFILE == "normal"


def test_parse_operational_profile_accepts_legacy_aliases() -> None:
    assert parse_operational_profile("balanced") == "normal"
    assert parse_operational_profile("burst") == "high"
    assert parse_operational_profile("low") == "normal"


def test_legacy_low_alias_uses_normal_scenario_coverage() -> None:
    assert scenarios_for_profile("low") == scenarios_for_profile("normal")


def test_normal_profile_includes_host_behavior_check() -> None:
    scenarios = scenarios_for_profile("normal")
    assert HOST_BEHAVIOR_CHECK_SCENARIO_ID in scenarios
    assert scenarios.index(HOST_BEHAVIOR_CHECK_SCENARIO_ID) == 0


def test_normal_profile_target_net_execution_order() -> None:
    scenarios = scenarios_for_profile("normal")
    assert scenarios.index("port_sweep") < scenarios.index("http_followup")
    assert scenarios.index("http_followup") < scenarios.index("sql_injection")
    assert scenarios.index("sql_injection") < scenarios.index("ssh_failure")
    assert scenarios.index("ldap_enumeration") < scenarios.index("smb_login_failure")
    assert scenarios.index("smb_login_failure") < scenarios.index("kerberos_failure")
    assert scenarios.index("kerberos_failure") < scenarios.index("dga")
    assert scenarios.index("dga") < scenarios.index("dns_tunnel")
    assert scenarios[-1] == "dns_tunnel"


def test_normal_profile_discovery_first_order() -> None:
    test_normal_profile_target_net_execution_order()


def test_normal_profile_includes_auth_and_protocol_scenarios() -> None:
    scenarios = scenarios_for_profile("normal")
    assert "ldap_enumeration" in scenarios
    assert "kerberos_failure" in scenarios
    assert scenarios.index("port_sweep") < scenarios.index("http_followup")
    assert scenarios.index("dns_tunnel") == len(scenarios) - 1


def test_high_profile_matches_normal_coverage() -> None:
    assert scenarios_for_profile("high") == scenarios_for_profile("normal")


def test_resolve_runnable_scenarios_filters_inactive() -> None:
    resolved = resolve_runnable_scenarios(
        "normal",
        ["dns_tunnel", "missing_scenario", "http_followup"],
    )
    assert resolved == ["http_followup", "dns_tunnel"]


def test_discover_host_count_expands_cidr() -> None:
    assert discover_host_count("192.168.55.0/30") == 2


def test_build_operational_scenario_params_caps_hosts_for_normal() -> None:
    params = build_operational_scenario_params(
        "normal",
        ["http_followup", "dns_tunnel"],
        target_net="10.10.10.0/24",
    )
    assert params["http_followup"]["max_hosts"] == 2
    assert params["http_followup"]["max_per_host"] == 500
    assert params["http_followup"]["max_total"] == 1000
    assert "abnormal_ua_ratio" not in params["http_followup"]
    assert params["dns_tunnel"]["traffic_profile"] == "normal"
    assert params["dns_tunnel"]["payload_mb"] == 0.5
    assert params["dns_tunnel"]["max_hosts"] == 1
    assert "max_chunks" not in params["dns_tunnel"]


def test_build_operational_scenario_params_uses_all_hosts_for_high() -> None:
    params = build_operational_scenario_params(
        "high",
        ["http_followup"],
        target_net="192.168.55.0/30",
    )
    assert params["http_followup"]["max_hosts"] == 2
    assert params["http_followup"]["max_per_host"] == 500
    assert params["http_followup"]["traffic_profile"] == "high"


def test_build_operational_scenario_params_normal_port_sweep_respects_profile_cap() -> None:
    params = build_operational_scenario_params(
        "normal",
        ["port_sweep"],
        target_net="10.10.10.0/24",
    )
    assert params["port_sweep"]["max_hosts"] == 2


def test_build_operational_scenario_params_high_port_sweep_allows_full_sweep() -> None:
    params = build_operational_scenario_params(
        "high",
        ["port_sweep"],
        target_net="10.10.10.0/24",
    )
    assert params["port_sweep"]["max_hosts"] == 254


def test_apply_host_limit_honors_explicit_full_sweep_flag() -> None:
    from dsp.runtime.operational_profiles import _apply_host_limit
    from dsp.runtime.traffic_profiles import scenario_params_for_profile

    base = scenario_params_for_profile("port_sweep", "high")
    base["full_sweep"] = True
    merged = _apply_host_limit(base, "normal", host_count=254)
    assert merged["max_hosts"] == 254
    assert merged["full_sweep"] is True


def test_build_operational_scenario_params_high_dns_tunnel_all_live_hosts() -> None:
    params = build_operational_scenario_params(
        "high",
        ["dns_tunnel"],
        target_net="192.168.55.0/30",
    )
    assert params["dns_tunnel"]["payload_mb"] == 0.5
    assert params["dns_tunnel"]["max_hosts"] == 2
    assert "max_chunks" not in params["dns_tunnel"]
    params = build_operational_scenario_params(
        "high",
        ["dns_tunnel"],
        target_net="10.10.10.0/24",
    )
    assert params["dns_tunnel"]["max_hosts"] == 254
    assert params["dns_tunnel"]["payload_mb"] == 0.5


def test_high_scales_max_total_when_hosts_expand() -> None:
    params = build_operational_scenario_params(
        "high",
        ["ssh_failure", "http_followup"],
        target_net="10.10.10.0/24",
    )
    assert params["ssh_failure"]["max_per_host"] == 150
    assert params["ssh_failure"]["max_hosts"] == 254
    assert params["ssh_failure"]["max_total"] == 150 * 254
    assert params["http_followup"]["max_per_host"] == 500
    assert params["http_followup"]["max_total"] == 500 * 254
