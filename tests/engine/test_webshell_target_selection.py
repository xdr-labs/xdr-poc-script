"""Webshell attack chain alignment — Phase 1, discovery origin, and target selection."""

from __future__ import annotations

import io
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dsp.engine.scenario_engine import TargetSet
from dsp.execution.remote.command.discovery_plans import (
    build_plan_from_discovery,
    resolve_remote_discovery_plan,
)
from dsp.execution.remote.command.scenario_plans import _build_plan, _plan_remote_discovery_execute
from dsp.execution.remote.models import ScenarioExecutionRequest
from dsp.protocols.ssh.attempts import plan_ssh_attempts
from dsp.runtime.scenario_plan import (
    WEBSHELL_EXECUTION_KEY,
    apply_webshell_initial_compromise_plan,
    build_scenario_execution_plan,
    parse_initial_compromise_endpoint,
    webshell_server_endpoint,
)
from dsp.execution.webshell_provider import WebshellExecutionProvider
from dsp.runner import RunManager
from dsp.runner.console_output import OperationalConsole


def _webshell_provider_mock() -> MagicMock:
    provider = MagicMock()
    provider.__class__ = WebshellExecutionProvider
    provider.provider_type = "webshell"
    return provider


def _lab_targets() -> TargetSet:
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
        },
        service_endpoints={
            "http_targets": [
                ("221.139.249.110", 80),
                ("221.139.249.113", 80),
                ("221.139.249.118", 9000),
            ],
            "ssh_hosts": [("221.139.249.110", 22)],
        },
        discovery_enabled=True,
    )


def _discovery_dict() -> dict:
    return {
        "target_net": "10.10.10.0/24",
        "hosts": ["10.10.10.97", "10.10.10.98"],
        "service_hosts": {
            "http_targets": ["10.10.10.97"],
            "https_targets": [],
            "ssh_hosts": ["10.10.10.98"],
            "dns_hosts": ["10.10.10.97"],
            "ldap_hosts": ["10.10.10.98"],
            "smb_hosts": ["10.10.10.98"],
            "kerberos_hosts": ["10.10.10.98"],
        },
        "service_endpoints": {
            "http_targets": [("10.10.10.97", 8080)],
            "ssh_hosts": [("10.10.10.98", 22)],
            "dns_hosts": [("10.10.10.97", 53)],
            "ldap_hosts": [("10.10.10.98", 389)],
            "smb_hosts": [("10.10.10.98", 445)],
            "kerberos_hosts": [("10.10.10.98", 88)],
        },
        "discovery_enabled": True,
        "discovery_meta": {"discovery_origin": "webshell_host"},
    }


def test_prepare_runs_before_prefetch() -> None:
    call_order: list[str] = []

    def _prepare(_ctx):
        call_order.append("prepare")

    def _prefetch(*_args, **_kwargs):
        call_order.append("prefetch")
        return {
            "target_net": "10.10.10.0/24",
            "hosts": [],
            "service_hosts": {},
            "service_endpoints": {},
            "discovery_enabled": True,
            "discovery_meta": {"alive_hosts": [], "open_endpoints": 0, "probed_hosts": 0},
        }

    tmpdir = Path(tempfile.mkdtemp())
    with patch(
        "dsp.runner.run_manager.prefetch_webshell_target_net_discovery",
        side_effect=_prefetch,
    ):
        with patch.object(RunManager, "_create_execution_provider") as create_provider:
            provider = _webshell_provider_mock()
            provider.prepare.side_effect = _prepare
            provider.execute.return_value = None
            provider.cleanup.return_value = None
            create_provider.return_value = provider

            manager = RunManager(runs_dir=tmpdir / "runs")
            manager.run(
                scenario_ids=["http_followup"],
                target_net="10.10.10.0/24",
                dry_run=True,
                execution_provider="webshell",
                webshell_url="http://10.10.10.50:8080/shell.jsp",
                webshell_family="jsp",
            )

    assert call_order[:2] == ["prepare", "prefetch"]


def test_webshell_server_endpoint_from_user_url() -> None:
    params: dict[str, dict] = {}
    apply_webshell_initial_compromise_plan(
        params,
        ["ssh_failure"],
        "http://10.10.10.50:8080/shell.jsp",
    )
    endpoint = webshell_server_endpoint(params["ssh_failure"])
    assert endpoint is not None
    assert endpoint.host == "10.10.10.50"
    assert endpoint.port == 8080


def test_phase1_ssh_targets_webshell_host() -> None:
    endpoint = parse_initial_compromise_endpoint("http://10.10.10.20/shell.jsp")
    plans = plan_ssh_attempts([endpoint.host], max_hosts=1, max_per_host=3, max_total=3)
    assert plans
    assert all(plan.host == "10.10.10.20" for plan in plans)
    assert all(plan.port == 22 for plan in plans)


def test_webshell_discovery_runs_remote() -> None:
    request = ScenarioExecutionRequest(
        scenario_id="http_followup",
        scenario_params={"max_hosts": 2},
        execution_metadata={"traffic_origin_host": "remote"},
        run_id="test-run",
        target_net="10.10.10.0/24",
        dry_run=True,
    )
    plan = _plan_remote_discovery_execute(request, dry_run=True)
    assert plan["type"] == "remote_discovery_execute"
    assert plan["discovery"]["origin"] == "webshell_host"
    assert plan["discovery"]["max_hosts"] == 254

    with patch(
        "dsp.execution.remote.command.discovery_plans._tcp_probe",
        return_value=True,
    ):
        resolved = resolve_remote_discovery_plan(plan)
    assert resolved["type"] == "http_followup"
    assert resolved.get("discovery_result", {}).get("discovery_origin") == "webshell_host"


def test_webshell_target_selection_uses_remote_discovery() -> None:
    targets = _discovery_dict()
    params = {"max_hosts": 2, "max_total": 4, "max_per_host": 2}
    plan = build_plan_from_discovery("http_followup", targets, params, dry_run=True)
    assert plan["requests"]
    assert all("10.10.10.97" in item["url"] for item in plan["requests"])
    assert all("10.10.10.50" not in item["url"] for item in plan["requests"])


def test_local_and_webshell_have_same_behavior_different_origin() -> None:
    from dsp.engine.host_selection import cache_http_endpoint_selection

    targets = TargetSet(
        target_net="10.10.10.0/24",
        hosts=["10.10.10.97"],
        service_hosts={"http_targets": ["10.10.10.97"]},
        service_endpoints={"http_targets": [("10.10.10.97", 8080)]},
        discovery_enabled=True,
    )
    params: dict[str, dict] = {
        "http_followup": {"max_hosts": 1, "max_total": 4, "max_per_host": 2, "timeout": 2.0},
    }
    cache_http_endpoint_selection(
        params,
        scenario_ids=["http_followup"],
        targets=targets,
        dry_run=True,
        webshell_mode=False,
    )
    local_plan = build_scenario_execution_plan(
        "http_followup",
        targets,
        params["http_followup"],
        dry_run=True,
    )
    remote_plan = build_plan_from_discovery(
        "http_followup",
        {
            "target_net": targets.target_net,
            "hosts": targets.hosts,
            "service_hosts": targets.service_hosts,
            "service_endpoints": {
                key: list(value) for key, value in targets.service_endpoints.items()
            },
            "discovery_enabled": True,
        },
        params["http_followup"],
        dry_run=True,
    )

    local_hosts = {
        item["url"].split("://", 1)[1].split(":", 1)[0].split("/", 1)[0]
        for item in local_plan["requests"]
    }
    remote_hosts = {
        item["url"].split("://", 1)[1].split(":", 1)[0].split("/", 1)[0]
        for item in remote_plan["requests"]
    }
    assert local_hosts
    assert local_hosts == remote_hosts


def test_webshell_attack_chain_order(tmp_path: Path) -> None:
    events: list[str] = []

    def _track(event: str, _payload: dict) -> None:
        events.append(event)

    prepare_calls: list[str] = []

    with patch.object(RunManager, "_create_execution_provider") as create_provider:
        provider = _webshell_provider_mock()

        def _prepare(ctx):
            prepare_calls.append("prepare")
            ctx.execution_metadata["traffic_origin_host"] = "remote"

        provider.prepare.side_effect = _prepare
        provider.execute.return_value = None
        provider.cleanup.return_value = None
        create_provider.return_value = provider

        manager = RunManager(runs_dir=tmp_path / "runs")
        with patch(
            "dsp.execution.remote.command.runner.CommandScenarioRunner.run",
            return_value=MagicMock(to_dict=lambda: {"remote_execution_id": "r1"}),
        ):
            manager.run(
                scenario_ids=["http_followup"],
                target_net="10.10.10.0/24",
                dry_run=True,
                execution_provider="webshell",
                webshell_url="http://10.10.10.50:8080/shell.jsp",
                webshell_family="jsp",
                on_progress=_track,
            )

    assert prepare_calls == ["prepare"]
    assert "discovery_deferred" in events
    assert "phase1_webshell_attack_completed" not in events


def test_webshell_http_followup_targets_discovered_hosts_after_remote_discovery() -> None:
    targets = _discovery_dict()
    plan = build_plan_from_discovery(
        "http_followup",
        targets,
        {"max_hosts": 1, "max_total": 2, "max_per_host": 2},
        dry_run=True,
    )
    assert "10.10.10.97" in plan["requests"][0]["url"]
    assert "10.10.10.50" not in plan["requests"][0]["url"]


def test_webshell_planner_emits_remote_discovery_execute_plan() -> None:
    request = ScenarioExecutionRequest(
        scenario_id="sql_injection",
        scenario_params={"max_hosts": 2},
        execution_metadata={"traffic_origin_host": "remote"},
        run_id="run-1",
        target_net="221.139.249.0/24",
        dry_run=False,
    )
    plan = _build_plan(request, TargetSet(target_net="221.139.249.0/24"))
    assert plan["type"] == "remote_discovery_execute"
    assert plan["scenario_id"] == "sql_injection"


def test_host_behavior_uses_webshell_server_from_user_url() -> None:
    params: dict[str, dict] = {}
    apply_webshell_initial_compromise_plan(
        params,
        ["host_behavior_check"],
        "http://10.10.10.50:8080/shell.jsp",
    )
    ctx = params["host_behavior_check"][WEBSHELL_EXECUTION_KEY]
    assert ctx["webshell_url"] == "http://10.10.10.50:8080/shell.jsp"
    assert ctx["endpoint"]["host"] == "10.10.10.50"
    assert ctx["endpoint"]["port"] == 8080


def test_webshell_ssh_failure_targets_discovered_ssh_hosts() -> None:
    params: dict[str, dict] = {}
    apply_webshell_initial_compromise_plan(
        params,
        ["ssh_failure"],
        "http://10.10.10.50:8080/shell.jsp",
    )
    plan = build_plan_from_discovery(
        "ssh_failure",
        _discovery_dict(),
        params["ssh_failure"] | {"max_hosts": 1, "max_per_host": 3, "max_total": 3},
        dry_run=True,
    )
    assert plan["attempts"]
    assert all(item["host"] == "10.10.10.98" for item in plan["attempts"])
    assert all("10.10.10.50" not in item["host"] for item in plan["attempts"])


def test_webshell_ssh_failure_skipped_without_discovered_ssh() -> None:
    targets = {
        "target_net": "10.10.10.0/24",
        "hosts": ["10.10.10.97"],
        "service_hosts": {"http_targets": ["10.10.10.97"]},
        "service_endpoints": {"http_targets": [("10.10.10.97", 8080)]},
        "discovery_enabled": True,
    }
    plan = build_plan_from_discovery("ssh_failure", targets, {"max_hosts": 1}, dry_run=True)
    assert plan["mode"] == "skip"
    assert plan["reason"] == "no_ssh_hosts"


@pytest.mark.parametrize(
    "scenario_id,missing_capability",
    [
        ("http_followup", "http_targets"),
        ("sql_injection", "http_targets"),
        ("ssh_failure", "ssh_hosts"),
        ("dga", "dns_hosts"),
        ("ldap_enumeration", "ldap_hosts"),
        ("smb_login_failure", "smb_hosts"),
        ("kerberos_failure", "kerberos_hosts"),
    ],
)
def test_followup_skipped_when_discovery_capability_missing(
    scenario_id: str,
    missing_capability: str,
) -> None:
    base = _discovery_dict()
    base["service_hosts"][missing_capability] = []
    base["service_endpoints"][missing_capability] = []
    plan = build_plan_from_discovery(
        scenario_id,
        base,
        {"max_hosts": 1, "max_total": 2, "max_per_host": 2, "phase1_count": 1, "phase2_count": 0},
        dry_run=True,
    )
    assert plan.get("mode") == "skip"


def test_port_sweep_skips_when_no_alive_hosts() -> None:
    plan = build_plan_from_discovery(
        "port_sweep",
        {
            "target_net": "10.10.10.0/24",
            "hosts": [],
            "service_hosts": {},
            "service_endpoints": {},
            "discovery_enabled": True,
            "discovery_meta": {"alive_hosts": []},
        },
        {"max_hosts": 1, "max_ports": 1},
        dry_run=True,
    )
    assert plan["mode"] == "skip"
    assert plan["reason"] == "no_alive_hosts"


def test_dns_tunnel_uses_alive_hosts_when_no_dns_server() -> None:
    targets = {
        "target_net": "10.10.10.0/24",
        "hosts": ["10.10.10.97", "10.10.10.98"],
        "service_hosts": {"http_targets": ["10.10.10.97"]},
        "service_endpoints": {},
        "discovery_enabled": True,
    }
    plan = build_plan_from_discovery(
        "dns_tunnel",
        targets,
        {"max_hosts": 2, "max_chunks": 1},
        dry_run=True,
    )
    assert plan.get("mode") != "skip"
    query_hosts = {item["target"] for item in plan["queries"]}
    assert query_hosts == {"10.10.10.97", "10.10.10.98"}


def test_dns_tunnel_ignores_dns_hosts_when_present() -> None:
    targets = {
        "target_net": "10.10.10.0/24",
        "hosts": ["10.10.10.97", "10.10.10.98"],
        "service_hosts": {
            "http_targets": ["10.10.10.97"],
            "dns_hosts": ["10.10.10.20"],
        },
        "service_endpoints": {"dns_hosts": [("10.10.10.20", 53)]},
        "discovery_enabled": True,
    }
    plan = build_plan_from_discovery(
        "dns_tunnel",
        targets,
        {"max_hosts": 2, "max_chunks": 1},
        dry_run=True,
    )
    assert plan.get("mode") != "skip"
    query_hosts = {item["target"] for item in plan["queries"]}
    assert query_hosts == {"10.10.10.97", "10.10.10.98"}
    assert "10.10.10.20" not in query_hosts


def test_dga_skipped_without_discovered_dns_hosts() -> None:
    targets = {
        "target_net": "10.10.10.0/24",
        "hosts": ["10.10.10.97"],
        "service_hosts": {"http_targets": ["10.10.10.97"]},
        "service_endpoints": {},
        "discovery_enabled": True,
    }
    plan = build_plan_from_discovery(
        "dga",
        targets,
        {"phase1_count": 1, "phase2_count": 0},
        dry_run=True,
    )
    assert plan["mode"] == "skip"
    assert plan["reason"] == "no_dns_hosts"


def test_rare_protocol_uses_fallback_without_discovered_endpoints() -> None:
    targets = {
        "target_net": "10.10.10.0/24",
        "hosts": ["10.10.10.97"],
        "service_hosts": {"http_targets": ["10.10.10.97"]},
        "service_endpoints": {"http_targets": [("10.10.10.97", 8080)]},
        "discovery_enabled": True,
    }
    plan = build_plan_from_discovery(
        "rare_protocol_activity",
        targets,
        {"timeout": 3.0},
        dry_run=True,
    )
    assert plan["mode"] == "mock"
    assert len(plan["probes"]) == 4
    assert {probe["protocol"] for probe in plan["probes"]} == {
        "TELNET",
        "RTSP",
        "SIP",
        "RTP",
    }
    assert all(probe["host"] == "10.10.10.97" for probe in plan["probes"])


def test_webshell_sql_injection_targets_discovered_http_hosts() -> None:
    params: dict[str, dict] = {}
    apply_webshell_initial_compromise_plan(
        params,
        ["sql_injection"],
        "http://10.10.10.50:8080/shell.jsp",
    )
    plan = build_plan_from_discovery(
        "sql_injection",
        _discovery_dict(),
        params["sql_injection"] | {"max_hosts": 1, "max_total": 2},
        dry_run=True,
    )
    assert plan["requests"]
    assert all("10.10.10.97" in item["url"] for item in plan["requests"])
    assert all("10.10.10.50" not in item["url"] for item in plan["requests"])


def test_phase2_http_followup_attaches_abnormal_user_agents() -> None:
    plan = build_plan_from_discovery(
        "http_followup",
        _discovery_dict(),
        {"max_hosts": 1, "max_total": 4, "max_per_host": 4},
        dry_run=True,
    )
    from dsp.protocols.http.user_agents import is_abnormal_user_agent

    assert plan["requests"]
    assert all(is_abnormal_user_agent(item["user_agent"]) for item in plan["requests"])


def test_console_output_separates_execution_host_and_attack_target_net() -> None:
    stream = io.StringIO()
    console = OperationalConsole(stream=stream)
    console.handle_progress(
        "targets_selected",
        {
            "execution_host": {
                "host": "10.10.10.50",
                "port": 8080,
                "path": "/shell.jsp",
            },
            "webshell_url": "http://10.10.10.50:8080/shell.jsp",
            "attack_target_net": "221.139.249.0/24",
            "groups": {},
        },
    )
    output = stream.getvalue()
    assert "Execution Host:" in output
    assert "10.10.10.50:8080/shell.jsp" in output
    assert "Attack Target Net: 221.139.249.0/24" in output


def test_run_manager_skips_dsp_discovery_for_webshell(tmp_path: Path) -> None:
    with patch("dsp.runner.run_manager.resolve_targets") as resolve_targets:
        resolve_targets.return_value = TargetSet(target_net="10.10.10.0/24")
        with patch.object(RunManager, "_create_execution_provider") as create_provider:
            provider = _webshell_provider_mock()
            provider.prepare.return_value = None
            provider.execute.return_value = None
            provider.cleanup.return_value = None
            create_provider.return_value = provider

            manager = RunManager(runs_dir=tmp_path / "runs")
            manager.run(
                scenario_ids=["http_followup"],
                target_net="10.10.10.0/24",
                dry_run=True,
                execution_provider="webshell",
                webshell_url="http://10.10.10.50/shell.jsp",
                webshell_family="jsp",
            )

    resolve_targets.assert_called_once()
    assert resolve_targets.call_args.kwargs.get("discovery") is False


@pytest.mark.parametrize(
    "scenario_id,capability",
    [
        ("http_followup", "http_targets"),
        ("sql_injection", "http_targets"),
    ],
)
def test_remote_discovery_plan_selects_service_hosts(scenario_id: str, capability: str) -> None:
    targets = _discovery_dict()
    plan = build_plan_from_discovery(
        scenario_id,
        targets,
        {"max_hosts": 2, "max_total": 4, "max_per_host": 2},
        dry_run=True,
    )
    if capability == "http_targets":
        assert plan["requests"]
    if capability == "ssh_hosts" and scenario_id == "ssh_failure":
        assert plan["attempts"]
