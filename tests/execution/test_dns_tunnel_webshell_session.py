"""Webshell DNS tunnel session dispatch tests."""

from __future__ import annotations

import base64
import re
from unittest.mock import MagicMock

import pytest

from dsp.engine import RunConfig, RunContext
from dsp.engine.scenario_engine import TargetSet
from dsp.event_store import EventQuery, EventStore
from dsp.execution.remote.command import execute as execute_mod
from dsp.execution.remote.command.execute import execute_command_plan
from dsp.execution.remote.command.models import DNS_QUERY_METHOD_PYTHON_SOCKET_UDP53
from dsp.execution.remote.command.planner import _plan_dns_tunnel
from dsp.execution.remote.models import ScenarioExecutionRequest
from dsp.protocols.dns.tunnel import (
    CHUNK_SIZE_DEFAULT,
    MOCK_PAYLOAD_FILENAME,
    PAYLOAD_MB_DEFAULT,
    TUNNEL_DOMAIN_DEFAULT,
    build_tunnel_end_fqdn,
    build_tunnel_start_fqdn,
    plan_chunk_count,
    plan_dns_tunnel,
)


@pytest.fixture(autouse=True)
def _fast_detached_dns_tunnel_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(execute_mod, "DNS_TUNNEL_POLL_INTERVAL_SEC", 0.0)
    monkeypatch.setattr(execute_mod.time, "sleep", lambda _s: None)


def _targets() -> TargetSet:
    return TargetSet(
        target_net="10.10.10.0/24",
        hosts=["10.10.10.97"],
        service_hosts={"dns_hosts": [], "http_targets": ["10.10.10.97"]},
        discovery_enabled=True,
        discovery_meta={"alive_hosts": ["10.10.10.97"]},
    )


def _mock_dns_tunnel_markers(provider: MagicMock, marker_text: str) -> None:
    provider.run_remote_command.side_effect = [
        b"DNS_TUNNEL_LAUNCHED:1\n",
        b"1\n",
    ]
    provider.fetch_remote_file_via_cat.return_value = marker_text.encode("utf-8")


def test_webshell_dns_tunnel_one_http_dispatch_per_target(tmp_path) -> None:
    store = EventStore(tmp_path / "events.db")
    store.open_run("run-session")
    ctx = RunContext(
        run_id="run-session",
        target_net="10.10.10.0/24",
        event_store=store,
        config=RunConfig(dry_run=False),
        dry_run=False,
    )
    params = {
        "payload_mb": 0.0001,
        "max_chunks": 3,
        "domain": TUNNEL_DOMAIN_DEFAULT,
        "max_hosts": 1,
        "plan_seed": 42,
    }
    plan = plan_dns_tunnel(_targets(), params, dry_run=False)
    provider = MagicMock()
    queries = plan["queries"]
    session_output = "\n".join(
        [f"DNS_TUNNEL_SENT:{item['fqdn']}" for item in queries]
        + ["DNS_TUNNEL_SESSION_DONE"]
    )
    # Launch returns quickly; first poll reports SESSION_DONE count.
    provider.run_remote_command.side_effect = [
        b"DNS_TUNNEL_LAUNCHED:12345\n",
        b"1\n",
    ]
    provider.fetch_remote_file_via_cat.return_value = session_output.encode("utf-8")

    http_calls = execute_command_plan(
        plan,
        provider,
        ctx,
        ScenarioExecutionRequest(
            run_id="run-session",
            scenario_id="dns_tunnel",
            target_net="10.10.10.0/24",
            dry_run=False,
            scenario_params={},
            execution_metadata={},
        ),
    )

    assert http_calls >= 1
    # Detached session: launch + at least one poll, then marker cat.
    assert provider.run_remote_command.call_count >= 2
    assert provider.fetch_remote_file_via_cat.call_count == 1
    remote_command = provider.run_remote_command.call_args_list[0][0][0]
    assert "python3 -c" in remote_command
    assert "nohup" in remote_command
    assert "DNS_TUNNEL_LAUNCHED" in remote_command
    assert ".sent" in remote_command

    candidates = re.findall(r"[A-Za-z0-9+/=]{100,}", remote_command)
    assert candidates
    payload = max(candidates, key=len)
    script = base64.b64decode(payload.encode("ascii")).decode("utf-8")
    assert "DNS_TUNNEL_SENT:" in script
    assert "MARKER" in script
    assert "04d" in script
    assert "sendto" in script
    assert "recvfrom" not in script
    compile(script, "<dns_tunnel_remote_python>", "exec")

    dispatched = store.count(
        EventQuery(run_id="run-session", scenario_id="dns_tunnel", event="webshell_command_dispatched")
    )
    assert dispatched == 1

    idx_events = [
        e
        for e in store.list_events("run-session", "dns_tunnel")
        if e.event == "dns_tunnel_query_sent"
        and (e.evidence or {}).get("query_role") == "idx_chunk"
    ]
    assert len(idx_events) == 3
    assert all(str(e.evidence.get("fqdn", "")).startswith("idx-") for e in idx_events)
    assert any(
        str(e.evidence.get("fqdn", "")).startswith("idx-0000-") for e in idx_events
    )

    roles = {
        str((e.evidence or {}).get("query_role"))
        for e in store.list_events("run-session", "dns_tunnel")
        if e.event == "dns_tunnel_query_sent"
    }
    assert "session_start" in roles
    assert "session_end" in roles
    assert "idx_chunk" in roles

    end_fqdn = build_tunnel_end_fqdn(TUNNEL_DOMAIN_DEFAULT)
    strt_fqdn = build_tunnel_start_fqdn(MOCK_PAYLOAD_FILENAME, TUNNEL_DOMAIN_DEFAULT)
    fqdns = {str(e.evidence.get("fqdn")) for e in store.list_events("run-session", "dns_tunnel")}
    assert end_fqdn in fqdns
    assert strt_fqdn in fqdns


def test_local_webshell_planner_fqdn_parity() -> None:
    params = {
        "payload_mb": 0.0001,
        "max_chunks": 2,
        "domain": TUNNEL_DOMAIN_DEFAULT,
        "max_hosts": 1,
        "plan_seed": 7,
    }
    targets = _targets()
    local = plan_dns_tunnel(targets, params, dry_run=False)
    webshell = _plan_dns_tunnel(
        {
            "target_net": targets.target_net,
            "hosts": targets.hosts,
            "service_hosts": targets.service_hosts,
            "discovery_meta": targets.discovery_meta,
        },
        params,
        dry_run=False,
    )
    assert [q["fqdn"] for q in local["queries"]] == [q["fqdn"] for q in webshell["queries"]]
    idx_fqdns = [
        q["fqdn"] for q in local["queries"] if q.get("query_role") == "idx_chunk"
    ]
    assert idx_fqdns[0].startswith("idx-0000-")


def test_one_mb_plan_idx_count() -> None:
    total = plan_chunk_count(1.0, CHUNK_SIZE_DEFAULT)
    assert total == (1 * 1024 * 1024 + CHUNK_SIZE_DEFAULT - 1) // CHUNK_SIZE_DEFAULT
    assert total == 34953


def test_half_mb_plan_idx_count() -> None:
    total = plan_chunk_count(0.5, CHUNK_SIZE_DEFAULT)
    assert total == (512 * 1024 + CHUNK_SIZE_DEFAULT - 1) // CHUNK_SIZE_DEFAULT
    assert total == 17477


def test_normal_profile_payload_mb_drives_full_volume() -> None:
    """Operational normal profile must not cap chunks; payload_mb=0.5 sets volume."""
    from dsp.runtime.traffic_profiles import scenario_params_for_profile

    params = scenario_params_for_profile("dns_tunnel", "normal")
    plan = plan_dns_tunnel(_targets(), params, dry_run=False)
    expected_idx = plan_chunk_count(0.5, CHUNK_SIZE_DEFAULT)
    assert params.get("payload_mb") == 0.5
    assert plan.get("max_chunks") is None
    idx_count = sum(1 for q in plan["queries"] if q.get("query_role") == "idx_chunk")
    assert idx_count == expected_idx
    assert len(plan["queries"]) == expected_idx + 2


def test_webshell_high_profile_payload_mb_drives_volume() -> None:
    """Operational high profile uses same per-target payload as normal (0.5 MB)."""
    from dsp.runtime.traffic_profiles import scenario_params_for_profile

    alive = [f"221.139.249.{h}" for h in (101, 102, 103, 110, 113, 116, 118, 122, 126)]
    targets = TargetSet(
        target_net="221.139.249.0/24",
        hosts=alive,
        service_hosts={"dns_hosts": [], "http_targets": alive[:1]},
        discovery_enabled=True,
        discovery_meta={"alive_hosts": alive},
    )
    params = scenario_params_for_profile("dns_tunnel", "high")
    plan = plan_dns_tunnel(targets, params, dry_run=False)
    expected_idx = plan_chunk_count(0.5, CHUNK_SIZE_DEFAULT)
    assert params.get("payload_mb") == 0.5
    assert plan.get("max_chunks") is None
    idx_count = sum(1 for q in plan["queries"] if q.get("query_role") == "idx_chunk")
    assert idx_count == expected_idx


def test_webshell_high_profile_queries_sent_nonzero(tmp_path) -> None:
    """SESSION_DONE + DSP plan records queries_sent without DNS_TUNNEL_SENT lines."""
    from dsp.runtime.traffic_profiles import scenario_params_for_profile
    from dsp.runtime.traffic_summary import build_traffic_summary

    alive = [f"221.139.249.{h}" for h in (101, 102, 103, 110, 113, 116, 118, 122, 126)]
    targets = TargetSet(
        target_net="221.139.249.0/24",
        hosts=alive,
        service_hosts={"dns_hosts": [], "http_targets": alive[:1]},
        discovery_enabled=True,
        discovery_meta={"alive_hosts": alive},
    )
    params = {
        **scenario_params_for_profile("dns_tunnel", "high"),
        "payload_mb": 0.0001,
        "max_chunks": 3,
    }
    plan = plan_dns_tunnel(targets, params, dry_run=False)
    assert plan.get("max_chunks") == 3
    assert len(plan["queries"]) == 5

    store = EventStore(tmp_path / "events.db")
    store.open_run("run-high")
    ctx = RunContext(
        run_id="run-high",
        target_net="221.139.249.0/24",
        event_store=store,
        config=RunConfig(dry_run=False),
        dry_run=False,
    )
    provider = MagicMock()
    # Metric SoT is SESSION_DONE — SENT markers intentionally omitted.
    _mock_dns_tunnel_markers(provider, "DNS_TUNNEL_SESSION_DONE\n")

    execute_command_plan(
        plan,
        provider,
        ctx,
        ScenarioExecutionRequest(
            run_id="run-high",
            scenario_id="dns_tunnel",
            target_net="221.139.249.0/24",
            dry_run=False,
            scenario_params={"dns_tunnel": params},
            execution_metadata={},
        ),
    )

    summary = build_traffic_summary(
        store,
        run_id="run-high",
        scenario_ids=["dns_tunnel"],
        targets=targets,
        traffic_profile="high",
    )
    dns = summary["scenarios"]["dns_tunnel"]
    assert dns["queries_sent"] == 5
    assert dns["planned_queries"] == 5
    assert dns["dispatched_queries"] == 5
    assert dns["observed_queries"] == 5


def test_webshell_session_done_without_sent_markers_records_plan(tmp_path) -> None:
    """Wire traffic may succeed while SENT markers are lost; SESSION_DONE still counts."""
    store = EventStore(tmp_path / "events.db")
    store.open_run("run-no-sent")
    ctx = RunContext(
        run_id="run-no-sent",
        target_net="10.10.10.0/24",
        event_store=store,
        config=RunConfig(dry_run=False),
        dry_run=False,
    )
    params = {
        "payload_mb": 0.0001,
        "max_chunks": 2,
        "domain": TUNNEL_DOMAIN_DEFAULT,
        "max_hosts": 1,
        "plan_seed": 1,
    }
    plan = plan_dns_tunnel(_targets(), params, dry_run=False)
    provider = MagicMock()
    _mock_dns_tunnel_markers(provider, "DNS_TUNNEL_SESSION_DONE\n")

    execute_command_plan(
        plan,
        provider,
        ctx,
        ScenarioExecutionRequest(
            run_id="run-no-sent",
            scenario_id="dns_tunnel",
            target_net="10.10.10.0/24",
            dry_run=False,
            scenario_params={},
            execution_metadata={},
        ),
    )

    completed = [
        e
        for e in store.list_events("run-no-sent", "dns_tunnel")
        if e.event == "dns_tunnel_completed"
    ][0]
    assert completed.evidence["planned_queries"] == len(plan["queries"])
    assert completed.evidence["dispatched_queries"] == len(plan["queries"])
    assert completed.evidence["observed_queries"] == len(plan["queries"])
    assert completed.evidence["queries_sent"] == len(plan["queries"])
    assert completed.evidence["metric_source"] == "dsp_plan_session_done"

    sent = store.count(
        EventQuery(run_id="run-no-sent", scenario_id="dns_tunnel", event="dns_tunnel_query_sent")
    )
    assert sent == len(plan["queries"])


def test_webshell_without_session_done_records_zero_observed(tmp_path) -> None:
    """Do not invent success when SESSION_DONE is missing."""
    store = EventStore(tmp_path / "events.db")
    store.open_run("run-no-done")
    ctx = RunContext(
        run_id="run-no-done",
        target_net="10.10.10.0/24",
        event_store=store,
        config=RunConfig(dry_run=False),
        dry_run=False,
    )
    params = {
        "payload_mb": 0.0001,
        "max_chunks": 2,
        "domain": TUNNEL_DOMAIN_DEFAULT,
        "max_hosts": 1,
    }
    plan = plan_dns_tunnel(_targets(), params, dry_run=False)
    provider = MagicMock()
    provider.run_remote_command.side_effect = [
        b"DNS_TUNNEL_LAUNCHED:1\n",
        b"0\n",
    ]
    provider.fetch_remote_file_via_cat.return_value = b""

    # Bound poll loop for the unit test.
    execute_mod.DNS_TUNNEL_POLL_INTERVAL_SEC = 0.0
    original_timeout = execute_mod.compute_dns_tunnel_session_timeout_sec
    execute_mod.compute_dns_tunnel_session_timeout_sec = lambda *a, **k: 0  # type: ignore[assignment]
    try:
        execute_command_plan(
            plan,
            provider,
            ctx,
            ScenarioExecutionRequest(
                run_id="run-no-done",
                scenario_id="dns_tunnel",
                target_net="10.10.10.0/24",
                dry_run=False,
                scenario_params={},
                execution_metadata={},
            ),
        )
    finally:
        execute_mod.compute_dns_tunnel_session_timeout_sec = original_timeout

    completed = [
        e
        for e in store.list_events("run-no-done", "dns_tunnel")
        if e.event == "dns_tunnel_completed"
    ][0]
    assert completed.evidence["planned_queries"] == len(plan["queries"])
    assert completed.evidence["dispatched_queries"] == len(plan["queries"])
    assert completed.evidence["observed_queries"] == 0
    assert completed.evidence["queries_sent"] == 0
    assert (
        store.count(
            EventQuery(
                run_id="run-no-done",
                scenario_id="dns_tunnel",
                event="dns_tunnel_query_sent",
            )
        )
        == 0
    )
