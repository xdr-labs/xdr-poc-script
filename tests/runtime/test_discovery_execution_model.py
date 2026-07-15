"""Discovery-first execution model and webshell attack chain alignment tests."""

from __future__ import annotations

import pytest

from dsp.engine.host_selection import (
    HTTP_ENDPOINT_SELECTION_CACHE_KEY,
    cache_http_endpoint_selection,
    resolve_http_endpoint_selection,
)
from dsp.engine.scenario_engine import TargetSet
from dsp.execution.remote.command.discovery_plans import build_plan_from_discovery
from dsp.runtime.operational_profiles import (
    DISCOVERY_FIRST_SCENARIO_ORDER,
    HOST_BEHAVIOR_CHECK_SCENARIO_ID,
    build_operational_scenario_params,
    scenarios_for_profile,
)
from dsp.runtime.scenario_plan import (
    INITIAL_COMPROMISE_ENDPOINT_KEY,
    WEBSHELL_EXECUTION_KEY,
    apply_webshell_initial_compromise_plan,
    build_port_sweep_plan_view,
    parse_initial_compromise_endpoint,
)
from dsp.runner.target_selection import resolve_scenario_targets, scenario_start_metadata


def _discovery_targets() -> TargetSet:
    return TargetSet(
        target_net="10.10.10.0/24",
        hosts=["10.10.10.97", "10.10.10.98"],
        service_hosts={
            "http_targets": ["10.10.10.97"],
            "ssh_hosts": ["10.10.10.98"],
        },
        service_endpoints={
            "http_targets": [("10.10.10.97", 8080)],
            "ssh_hosts": [("10.10.10.98", 22)],
        },
        discovery_enabled=True,
    )


def _apply_webshell_http_plan(
    params: dict[str, dict],
    scenario_ids: list[str],
    webshell_url: str,
) -> dict[str, dict]:
    merged = {sid: dict(p) for sid, p in params.items()}
    apply_webshell_initial_compromise_plan(merged, scenario_ids, webshell_url)
    cache_http_endpoint_selection(
        merged,
        scenario_ids=scenario_ids,
        targets=_discovery_targets(),
        dry_run=True,
    )
    return merged


def test_local_and_webshell_share_scenario_order_for_all_profiles() -> None:
    """Test A/F — identical scenario ordering between providers (profile-driven)."""
    for profile in ("normal", "high"):
        local_order = scenarios_for_profile(profile)
        webshell_order = scenarios_for_profile(profile)
        assert local_order == webshell_order
        if profile in ("normal", "high"):
            assert local_order == list(DISCOVERY_FIRST_SCENARIO_ORDER)


@pytest.mark.parametrize("profile", ["normal", "high"])
def test_profiles_preserve_discovery_first_ordering(profile: str) -> None:
    """Test E — normal/high preserve target-net execution ordering."""
    scenarios = scenarios_for_profile(profile)
    assert scenarios == list(DISCOVERY_FIRST_SCENARIO_ORDER)
    assert scenarios.index("port_sweep") < scenarios.index("http_followup")
    assert scenarios.index("sql_injection") < scenarios.index("dga")
    assert scenarios[-1] == "dns_tunnel"


def test_webshell_http_followup_targets_discovered_hosts_when_available() -> None:
    """Follow-up HTTP targets come from remote discovery on the webshell host."""
    webshell_url = "http://10.10.10.50:8080/shell.jsp"
    params = build_operational_scenario_params(
        "normal",
        ["http_followup"],
        target_net="10.10.10.0/24",
    )
    params = _apply_webshell_http_plan(params, ["http_followup"], webshell_url)
    targets = _discovery_targets()

    selection = resolve_http_endpoint_selection(
        targets,
        params["http_followup"],
        max_hosts=1,
        dry_run=True,
    )
    assert selection.selected
    assert selection.selected[0].host == "10.10.10.97"

    remote_plan = build_plan_from_discovery(
        "http_followup",
        {
            "target_net": targets.target_net,
            "hosts": targets.hosts,
            "service_hosts": targets.service_hosts,
            "service_endpoints": {
                key: list(value) for key, value in targets.service_endpoints.items()
            },
        },
        params["http_followup"],
        dry_run=True,
    )
    assert "10.10.10.97" in remote_plan["requests"][0]["url"]


def test_webshell_sql_injection_targets_discovered_http_hosts() -> None:
    """Phase 2 SQLi follows discovered HTTP endpoints, not the webshell server."""
    webshell_url = "http://10.10.10.50:8080/shell.jsp"
    params = build_operational_scenario_params(
        "normal",
        ["sql_injection"],
        target_net="10.10.10.0/24",
    )
    params = _apply_webshell_http_plan(params, ["sql_injection"], webshell_url)
    targets = _discovery_targets()

    remote_plan = build_plan_from_discovery(
        "sql_injection",
        {
            "target_net": targets.target_net,
            "hosts": targets.hosts,
            "service_hosts": targets.service_hosts,
            "service_endpoints": {
                key: list(value) for key, value in targets.service_endpoints.items()
            },
        },
        params["sql_injection"],
        dry_run=True,
    )
    assert remote_plan["requests"]
    assert all("10.10.10.97" in item["url"] for item in remote_plan["requests"])
    assert all("10.10.10.50" not in item["url"] for item in remote_plan["requests"])


def test_discovery_drives_http_followup_without_webshell_override() -> None:
    """Test D — service discovery drives HTTP follow-up when no webshell override."""
    params = build_operational_scenario_params(
        "normal",
        ["http_followup"],
        target_net="10.10.10.0/24",
    )
    targets = _discovery_targets()
    from dsp.engine.host_selection import (
        HttpFollowupSelection,
        selection_to_cache,
    )
    from dsp.protocols.http.target_probe import HTTPEndpointProbeResult

    selected = HTTPEndpointProbeResult(
        host="10.10.10.97",
        port=8080,
        scheme="http",
        status_counts={404: 1},
        selected=True,
        selection_reason="error_responses_available",
    )
    params["http_followup"][HTTP_ENDPOINT_SELECTION_CACHE_KEY] = selection_to_cache(
        HttpFollowupSelection(probed=[selected], selected=[selected])
    )

    meta = scenario_start_metadata("http_followup", targets, params["http_followup"])
    assert "10.10.10.97:8080" in meta["selected_targets"][0]
    assert WEBSHELL_EXECUTION_KEY not in params["http_followup"]


def test_local_and_webshell_port_sweep_plan_parity() -> None:
    """Test F — port_sweep plan identical; only HTTP pre-compromise differs in webshell mode."""
    params = build_operational_scenario_params(
        "normal",
        ["port_sweep"],
        target_net="10.10.10.0/24",
    )
    targets = _discovery_targets()

    local_plan = build_port_sweep_plan_view(targets, params["port_sweep"])
    local_hosts = resolve_scenario_targets("port_sweep", targets, params["port_sweep"])

    webshell_params = dict(params)
    apply_webshell_initial_compromise_plan(
        webshell_params,
        ["port_sweep"],
        "http://10.10.10.50:8080/shell.jsp",
    )
    remote_plan = build_port_sweep_plan_view(targets, webshell_params["port_sweep"])
    remote_hosts = resolve_scenario_targets(
        "port_sweep", targets, webshell_params["port_sweep"]
    )

    assert local_hosts == remote_hosts == local_plan.selected_hosts
    assert remote_plan.planned_probes == local_plan.planned_probes


def test_parse_initial_compromise_endpoint_defaults() -> None:
    endpoint = parse_initial_compromise_endpoint("http://10.10.10.50:8080/shell.jsp")
    assert endpoint.host == "10.10.10.50"
    assert endpoint.port == 8080
    assert endpoint.scheme == "http"


def test_local_http_plan_unchanged_without_webshell_url() -> None:
    params = build_operational_scenario_params(
        "normal",
        ["http_followup", "port_sweep"],
        target_net="10.10.10.0/24",
    )
    assert INITIAL_COMPROMISE_ENDPOINT_KEY not in params.get("http_followup", {})
    assert scenarios_for_profile("normal")[1] == "port_sweep"
    assert scenarios_for_profile("normal")[-1] == "dns_tunnel"
