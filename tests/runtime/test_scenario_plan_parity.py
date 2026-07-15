"""Provider-independent scenario planning parity and bash regression tests."""

from __future__ import annotations

import json

from dsp.engine.host_selection import cache_http_endpoint_selection
from dsp.engine.scenario_engine import TargetSet
from dsp.engine.target_engine import resolve_targets
from dsp.execution.remote.command.discovery_plans import build_plan_from_discovery
from dsp.execution.remote.command.scenario_plans import _plan_http_followup, _plan_port_sweep, _plan_sql_injection
from dsp.runner.target_selection import resolve_scenario_targets, scenario_start_metadata
from dsp.runtime.operational_profiles import build_operational_scenario_params, scenarios_for_profile
from dsp.runtime.scenario_plan import (
    build_scenario_execution_plan,
    build_port_sweep_plan_view,
    scenario_plan_parity_view,
)


def _lab_discovery_targets() -> TargetSet:
    """Lab-style discovery snapshot — same buckets for local and webshell planning."""
    return TargetSet(
        target_net="221.139.249.0/24",
        hosts=[
            "221.139.249.110",
            "221.139.249.113",
            "221.139.249.118",
        ],
        service_hosts={
            "http_targets": [
                "221.139.249.110",
                "221.139.249.113",
                "221.139.249.118",
            ],
            "ssh_hosts": ["221.139.249.110"],
            "dns_hosts": ["221.139.249.110"],
        },
        service_endpoints={
            "http_targets": [
                ("221.139.249.110", 80),
                ("221.139.249.110", 8080),
                ("221.139.249.113", 80),
                ("221.139.249.118", 8080),
            ],
            "ssh_hosts": [("221.139.249.110", 22)],
            "dns_hosts": [("221.139.249.110", 53)],
        },
        discovery_enabled=True,
        discovery_meta={
            "alive_hosts": [
                "221.139.249.110",
                "221.139.249.113",
                "221.139.249.118",
            ],
            "open_endpoints": 6,
        },
    )


def _targets_dict(targets: TargetSet) -> dict:
    return {
        "target_net": targets.target_net,
        "hosts": targets.hosts,
        "service_hosts": targets.service_hosts,
        "service_endpoints": {
            key: list(value) for key, value in targets.service_endpoints.items()
        },
        "discovery_enabled": targets.discovery_enabled,
        "discovery_meta": targets.discovery_meta,
    }


def _prepare_shared_params(
    profile: str,
    *,
    webshell: bool,
) -> tuple[list[str], dict[str, dict]]:
    scenario_ids = scenarios_for_profile(profile)
    params = build_operational_scenario_params(
        profile,
        scenario_ids,
        target_net="221.139.249.0/24",
    )
    targets = _lab_discovery_targets()
    if webshell:
        from dsp.runtime.scenario_plan import apply_webshell_initial_compromise_plan

        apply_webshell_initial_compromise_plan(
            params,
            scenario_ids,
            "http://10.10.10.50:8080/shell.jsp",
        )
    cache_http_endpoint_selection(
        params,
        scenario_ids=scenario_ids,
        targets=targets,
        dry_run=True,
        webshell_mode=webshell,
    )
    return scenario_ids, params


def _local_plan(scenario_id: str, targets: TargetSet, params: dict) -> dict:
    return build_scenario_execution_plan(scenario_id, targets, params, dry_run=True)


def _webshell_plan(scenario_id: str, targets: TargetSet, params: dict) -> dict:
    return build_plan_from_discovery(
        scenario_id,
        _targets_dict(targets),
        params,
        dry_run=True,
    )


def test_local_and_webshell_scenario_plan_parity_normal_profile() -> None:
    """Same discovery result must yield identical plans for local and webshell."""
    targets = _lab_discovery_targets()
    local_ids, local_params = _prepare_shared_params("normal", webshell=False)
    _, webshell_params = _prepare_shared_params("normal", webshell=True)
    assert local_ids == scenarios_for_profile("normal")

    parity_checks = {
        "port_sweep": "Recon",
        "dns_tunnel": "DNS",
        "dga": "DNS",
        "http_followup": "HTTP",
        "sql_injection": "HTTP",
        "ssh_failure": "SSH",
        "rare_protocol_activity": "Rare",
    }

    local_plans: dict[str, dict] = {}
    webshell_plans: dict[str, dict] = {}
    for scenario_id in parity_checks:
        sid_params = dict(local_params.get(scenario_id, {}))
        local_plans[scenario_id] = scenario_plan_parity_view(
            _local_plan(scenario_id, targets, sid_params)
        )
        webshell_plans[scenario_id] = scenario_plan_parity_view(
            _webshell_plan(scenario_id, targets, dict(webshell_params.get(scenario_id, {})))
        )

    assert local_plans == webshell_plans

    http_endpoints = local_plans["http_followup"]["endpoints"]
    assert "221.139.249.110" in http_endpoints
    assert "221.139.249.113" in http_endpoints
    assert local_plans["port_sweep"]["probe_count"] == webshell_plans["port_sweep"]["probe_count"]
    assert local_plans["port_sweep"]["probe_count"] == 20

    grouped_local = {}
    grouped_webshell = {}
    from dsp.runner.target_selection import resolve_selected_targets_by_protocol

    grouped_local = resolve_selected_targets_by_protocol(
        list(parity_checks),
        targets,
        local_params,
    )
    grouped_webshell = resolve_selected_targets_by_protocol(
        list(parity_checks),
        targets,
        webshell_params,
    )
    assert grouped_local == grouped_webshell

    # JSON round-trip sanity for operator plan diff workflows
    assert json.loads(json.dumps(local_plans)) == json.loads(json.dumps(webshell_plans))


def _targets_with_alive(*alive: str) -> TargetSet:
    return TargetSet(
        target_net="10.10.10.0/24",
        hosts=list(alive),
        discovery_enabled=True,
        discovery_meta={"alive_hosts": list(alive)},
    )


def test_normal_profile_port_sweep_does_not_scan_full_slash24() -> None:
    params = build_operational_scenario_params(
        "normal",
        ["port_sweep"],
        target_net="10.10.10.0/24",
    )
    assert params["port_sweep"]["max_hosts"] == 2

    targets = _targets_with_alive("10.10.10.97", "10.10.10.98", "10.10.10.99")
    plan = build_port_sweep_plan_view(targets, params["port_sweep"])
    assert plan.planned_probes == 20
    assert plan.selected_hosts == ["10.10.10.97", "10.10.10.98"]
    assert plan.selection_reason == "alive_hosts"
    assert plan.full_sweep_requested is False


def test_normal_profile_planned_probes_bounded_for_webshell_execution() -> None:
    params = build_operational_scenario_params(
        "normal",
        ["port_sweep"],
        target_net="10.10.10.0/24",
    )
    targets = resolve_targets("10.10.10.0/24", max_hosts=254, discovery=False, dry_run=True)
    plan = build_port_sweep_plan_view(targets, params["port_sweep"])
    assert plan.planned_probes <= 20


def test_high_profile_allows_intentional_full_sweep() -> None:
    params = build_operational_scenario_params(
        "high",
        ["port_sweep"],
        target_net="10.10.10.0/24",
    )
    assert params["port_sweep"]["max_hosts"] == 254
    targets = resolve_targets("10.10.10.0/24", max_hosts=254, discovery=False, dry_run=True)
    plan = build_port_sweep_plan_view(targets, params["port_sweep"])
    assert plan.planned_probes == 2540
    assert plan.full_sweep_requested is False


def test_explicit_full_sweep_params_bypass_profile_host_cap() -> None:
    params = build_operational_scenario_params(
        "normal",
        ["port_sweep"],
        target_net="10.10.10.0/24",
    )
    params["port_sweep"]["full_sweep"] = True
    params["port_sweep"]["max_hosts"] = 254
    targets = resolve_targets("10.10.10.0/24", max_hosts=254, discovery=False, dry_run=True)
    plan = build_port_sweep_plan_view(targets, params["port_sweep"])
    assert plan.full_sweep_requested is True
    assert plan.planned_probes == 2540


def test_local_and_webshell_port_sweep_plan_parity() -> None:
    params = build_operational_scenario_params(
        "normal",
        ["port_sweep"],
        target_net="10.10.10.0/24",
    )
    targets = _targets_with_alive("10.10.10.97", "10.10.10.98")

    local_plan = build_port_sweep_plan_view(targets, params["port_sweep"])
    local_hosts = resolve_scenario_targets("port_sweep", targets, params["port_sweep"])
    remote_plan = _plan_port_sweep(targets, params["port_sweep"], dry_run=False)

    assert local_hosts == local_plan.selected_hosts
    assert len(remote_plan["probes"]) == local_plan.planned_probes


def test_local_and_webshell_http_followup_endpoint_parity() -> None:
    from dsp.engine.host_selection import (
        HTTP_ENDPOINT_SELECTION_CACHE_KEY,
        HttpFollowupSelection,
        selection_to_cache,
    )
    from dsp.protocols.http.target_probe import HTTPEndpointProbeResult

    params = build_operational_scenario_params(
        "normal",
        ["http_followup"],
        target_net="10.10.10.0/24",
    )
    targets = TargetSet(
        target_net="10.10.10.0/24",
        hosts=["10.10.10.97"],
        service_hosts={"http_targets": ["10.10.10.97"]},
        service_endpoints={"http_targets": [("10.10.10.97", 8080)]},
        discovery_enabled=True,
    )
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

    local_meta = scenario_start_metadata("http_followup", targets, params["http_followup"])
    remote_plan = _plan_http_followup(targets, params["http_followup"], dry_run=False)

    assert local_meta["selected_targets"] == ["10.10.10.97:8080 (error_responses_available)"]
    assert remote_plan["requests"]
    assert remote_plan["requests"][0]["url"].startswith("http://10.10.10.97:8080")


def test_local_and_webshell_sql_injection_endpoint_parity() -> None:
    from dsp.engine.host_selection import (
        HTTP_ENDPOINT_SELECTION_CACHE_KEY,
        HttpFollowupSelection,
        selection_to_cache,
    )
    from dsp.protocols.http.target_probe import HTTPEndpointProbeResult

    params = build_operational_scenario_params(
        "normal",
        ["sql_injection"],
        target_net="10.10.10.0/24",
    )
    targets = TargetSet(
        target_net="10.10.10.0/24",
        hosts=["10.10.10.97"],
        service_hosts={"http_targets": ["10.10.10.97"]},
        service_endpoints={"http_targets": [("10.10.10.97", 8080)]},
        discovery_enabled=True,
    )
    selected = HTTPEndpointProbeResult(
        host="10.10.10.97",
        port=8080,
        scheme="http",
        status_counts={500: 1},
        selected=True,
        selection_reason="error_responses_available",
    )
    params["sql_injection"][HTTP_ENDPOINT_SELECTION_CACHE_KEY] = selection_to_cache(
        HttpFollowupSelection(probed=[selected], selected=[selected])
    )

    local_meta = scenario_start_metadata("sql_injection", targets, params["sql_injection"])
    remote_plan = _plan_sql_injection(targets, params["sql_injection"], dry_run=False)

    assert local_meta["selected_targets"] == ["10.10.10.97:8080 (error_responses_available)"]
    assert remote_plan["requests"]


def test_bash_parity_low_profile_metadata_documents_bounded_selection() -> None:
    params = build_operational_scenario_params(
        "normal",
        ["port_sweep"],
        target_net="10.10.10.0/24",
    )
    targets = _targets_with_alive("10.10.10.97")
    meta = scenario_start_metadata(
        "port_sweep",
        targets,
        params["port_sweep"],
        profile="normal",
    )
    assert meta["profile"] == "normal"
    assert meta["targets"] == 1
    assert meta["planned_probes"] == 10
    assert meta["selection_reason"] == "alive_hosts"
    assert meta["full_sweep_requested"] is False


def test_remote_timeout_regression_low_profile_probe_count(tmp_path) -> None:
    """Low profile must stay bounded so short webshell timeouts can still succeed."""
    from tests.e2e.fixtures.webshell_test_server import WebshellTestServer
    from dsp.runner.run_manager import RunManager

    server = WebshellTestServer(
        storage_dir=tmp_path / "storage",
        script_stdout_mode="command_timeout",
    )
    server.start()
    manager = RunManager(runs_dir=tmp_path / "runs")
    try:
        _, run_dir, exit_code = manager.run(
            scenario_ids=["port_sweep"],
            target_net="10.10.10.0/24",
            dry_run=False,
            operational_profile="normal",
            execution_provider="webshell",
            webshell_family="jsp",
            webshell_url=server.webshell_url,
            remote_work_dir=str(tmp_path / "remote-work"),
        )
        assert exit_code == 0
        meta = scenario_start_metadata(
            "port_sweep",
            _targets_with_alive("10.10.10.97"),
            build_operational_scenario_params(
                "normal",
                ["port_sweep"],
                target_net="10.10.10.0/24",
            )["port_sweep"],
            profile="normal",
        )
        assert meta["planned_probes"] <= 10
        assert (run_dir / "events.jsonl").is_file()
    finally:
        server.stop()
