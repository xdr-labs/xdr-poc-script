"""Tests for DSP v1.3.1 Runtime Activity Console."""

from __future__ import annotations

import io
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dsp.engine.scenario_engine import RunContext, TargetSet, emit_activity
from dsp.engine.target_engine import resolve_targets
from dsp.event_store import EventStore
from dsp.runner.cli import main
from dsp.runner.console_output import OperationalConsole, format_elapsed
from dsp.runner.progress_emitter import ProgressEmitter
from dsp.runner.run_manager import RunManager
from dsp.runner.target_selection import (
    resolve_selected_targets_by_protocol,
    scenario_start_metadata,
)
from dsp.runtime.operational_profiles import build_operational_scenario_params


def test_selected_targets_output() -> None:
    from dsp.engine.host_selection import (
        HTTP_ENDPOINT_SELECTION_CACHE_KEY,
        HttpFollowupSelection,
        selection_to_cache,
    )
    from dsp.protocols.http.target_probe import HTTPEndpointProbeResult

    targets = TargetSet(
        target_net="221.139.249.0/24",
        hosts=["221.139.249.101", "221.139.249.110", "221.139.249.113"],
        discovery_enabled=True,
        service_hosts={
            "http_targets": ["221.139.249.110"],
            "https_targets": ["221.139.249.113"],
            "dns_hosts": ["221.139.249.1"],
            "ldap_hosts": ["221.139.249.102"],
        },
        service_endpoints={
            "http_targets": [("221.139.249.110", 80)],
            "ldap_hosts": [("221.139.249.102", 389)],
        },
    )
    scenario_ids = ["port_sweep", "dns_tunnel", "http_followup", "ldap_enumeration"]
    params = build_operational_scenario_params(
        "normal",
        scenario_ids,
        target_net="221.139.249.0/24",
    )
    selected = HTTPEndpointProbeResult(
        host="221.139.249.110",
        port=80,
        scheme="http",
        status_counts={404: 1},
        selected=True,
        selection_reason="error_responses_available",
    )
    params.setdefault("http_followup", {})[HTTP_ENDPOINT_SELECTION_CACHE_KEY] = selection_to_cache(
        HttpFollowupSelection(probed=[selected], selected=[selected])
    )
    groups = resolve_selected_targets_by_protocol(scenario_ids, targets, params)
    buf = io.StringIO()
    console = OperationalConsole(stream=buf)
    console.handle_progress("targets_selected", {"groups": groups})

    output = buf.getvalue()
    assert "Selected Targets" in output
    assert "DNS:" in output
    assert "HTTP:" in output
    assert "LDAP:" in output
    for host in targets.hosts[:2]:
        assert host in output


def test_scenario_started_output() -> None:
    buf = io.StringIO()
    console = OperationalConsole(stream=buf)
    console.handle_progress(
        "scenario_started",
        {
            "scenario_id": "port_sweep",
            "index": 1,
            "total": 9,
            "metadata": {"targets": 2, "ports": 13},
        },
    )
    output = buf.getvalue()
    assert "[1/9] port_sweep STARTED" in output
    assert "targets=2" in output
    assert "ports=13" in output


def test_runtime_activity_output() -> None:
    buf = io.StringIO()
    console = OperationalConsole(stream=buf)
    console.handle_progress(
        "activity",
        {
            "scenario_id": "port_sweep",
            "target": "221.139.249.4",
            "port": 80,
            "action": "probe",
        },
    )
    console.handle_progress(
        "activity",
        {
            "scenario_id": "port_sweep",
            "target": "221.139.249.4",
            "port": 80,
            "result": "timeout",
        },
    )
    output = buf.getvalue()
    assert "[port_sweep]" in output
    assert "target=221.139.249.4" in output
    assert "port=80" in output
    assert "action=probe" in output
    assert "result=timeout" in output


def test_heartbeat_output() -> None:
    buf = io.StringIO()
    console = OperationalConsole(stream=buf)
    console.handle_progress(
        "heartbeat",
        {
            "scenario_id": "dns_tunnel",
            "elapsed_sec": 15.0,
            "counters": {"queries_sent": 40},
        },
    )
    output = buf.getvalue()
    assert "[dns_tunnel]" in output
    assert "running" in output
    assert "elapsed=00:00:15" in output
    assert "queries_sent=40" in output


def test_scenario_completed_summary_preserved() -> None:
    buf = io.StringIO()
    console = OperationalConsole(stream=buf)
    console.handle_progress(
        "scenario_completed",
        {
            "scenario_id": "port_sweep",
            "metrics": {
                "port_probe_count": 120,
                "port_connection_success_count": 4,
                "port_connection_failure_count": 116,
            },
        },
    )
    output = buf.getvalue()
    assert "Port Sweep Completed" in output
    assert "probes_sent=120" in output
    assert "success=4" in output
    assert "failed=116" in output


def test_traffic_summary_preserved() -> None:
    buf = io.StringIO()
    console = OperationalConsole(stream=buf)
    console.handle_progress(
        "run_completed",
        {
            "duration_sec": 60,
            "event_count": 100,
            "summaries": {
                "dns_tunnel": {
                    "metrics": {"dns_tunnel_query_sent_count": 100},
                },
            },
        },
    )
    console.print_traffic_summary()
    output = buf.getvalue()
    assert "Traffic Summary" in output
    assert "dns_tunnel" in output
    assert "queries_sent=100" in output


def test_progress_emitter_activity_and_heartbeat() -> None:
    phases: list[tuple[str, dict]] = []

    def capture(phase: str, data: dict) -> None:
        phases.append((phase, data))

    emitter = ProgressEmitter(capture)
    emitter.on_scenario_started("dns_tunnel")
    emitter.emit_activity("dns_tunnel", target="10.0.0.1", query="a.example.com", action="send")
    time.sleep(0.05)
    emitter.on_scenario_completed()

    activity_phases = [p for p, _ in phases if p == "activity"]
    assert len(activity_phases) == 1
    assert phases[0][1]["action"] == "send"


def test_emit_activity_from_run_context(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "events.db")
    phases: list[dict] = []
    ctx = RunContext(
        run_id="test",
        target_net="10.10.10.0/24",
        event_store=store,
        config=MagicMock(),
        activity_emitter=lambda scenario_id, **fields: phases.append(
            {"scenario_id": scenario_id, **fields}
        ),
    )
    emit_activity(ctx, "http_followup", target="10.10.10.20", url="http://x/login", action="request")
    assert phases[0]["action"] == "request"
    store.close()


def test_scenario_start_metadata() -> None:
    targets = resolve_targets("10.10.10.0/24", max_hosts=2)
    meta = scenario_start_metadata(
        "port_sweep",
        targets,
        {"max_hosts": 2, "max_ports": 10},
    )
    assert meta["targets"] == 2
    assert meta["ports"] == 10
    assert meta["planned_probes"] == 20
    assert meta["selection_reason"] == "discovered_hosts"


def test_format_elapsed() -> None:
    assert format_elapsed(8) == "00:00:08"
    assert format_elapsed(3661) == "01:01:01"


def test_cli_activity_console_integration(tmp_path: Path, capsys) -> None:
    run_dir = tmp_path / "20260610_act001"
    run_dir.mkdir()
    run_mock = MagicMock()
    run_mock.run_id = "20260610_act001"
    run_mock.status.value = "completed"

    def fake_run(*, on_progress=None, **kwargs):
        if on_progress:
            emitter = ProgressEmitter(on_progress)
            emitter.emit(
                "run_started",
                {
                    "provider": "local",
                    "target_net": kwargs.get("target_net"),
                    "profile": kwargs.get("operational_profile"),
                },
            )
            emitter.emit("discovery_started", {})
            emitter.emit("discovery_completed", {"hosts_found": 2})
            emitter.emit(
                "targets_selected",
                {
                    "groups": {
                        "DNS": ["221.139.249.4"],
                        "HTTP": ["221.139.249.20"],
                    },
                },
            )
            emitter.emit(
                "scenario_started",
                {
                    "scenario_id": "port_sweep",
                    "index": 1,
                    "total": 3,
                    "metadata": {"targets": 2, "ports": 13},
                },
            )
            emitter.on_scenario_started("port_sweep")
            emitter.emit_activity(
                "port_sweep",
                target="221.139.249.4",
                port=80,
                action="probe",
            )
            emitter.emit(
                "heartbeat",
                {
                    "scenario_id": "port_sweep",
                    "elapsed_sec": 8.0,
                    "counters": {"probes_sent": 5},
                },
            )
            emitter.on_scenario_completed()
            emitter.emit(
                "scenario_completed",
                {
                    "scenario_id": "port_sweep",
                    "metrics": {
                        "port_probe_count": 13,
                        "port_connection_success_count": 2,
                        "port_connection_failure_count": 11,
                    },
                },
            )
            emitter.emit("evidence_generated", {})
            emitter.emit(
                "run_completed",
                {
                    "duration_sec": 30,
                    "event_count": 50,
                    "summaries": {
                        "port_sweep": {
                            "metrics": {
                                "port_probe_count": 13,
                                "port_connection_success_count": 2,
                                "port_connection_failure_count": 11,
                            },
                        },
                    },
                },
            )
        return run_mock, run_dir, 0

    with patch.object(RunManager, "run", side_effect=fake_run):
        exit_code = main(
            [
                "run",
                "--profile",
                "normal",
                "--target-net",
                "221.139.249.0/24",
                "--dry-run",
            ]
        )

    captured = capsys.readouterr().out
    assert exit_code == 0
    assert "Selected Targets" in captured
    assert "DNS:" in captured
    assert "[1/3] port_sweep STARTED" in captured
    assert "action=probe" in captured
    assert "running" in captured
    assert "probes_sent=5" in captured
    assert "Port Sweep Completed" in captured
    assert "Traffic Summary" in captured


def test_http_probe_diagnostics_uses_refactored_selection_model() -> None:
    buf = io.StringIO()
    console = OperationalConsole(stream=buf)
    console.handle_progress(
        "http_probe_diagnostics",
        {
            "discovery_http_hosts": ["221.139.249.110"],
            "target_probe": [
                {
                    "host": "221.139.249.110",
                    "port": 8080,
                    "scheme": "http",
                    "probe_400": 2,
                    "probe_403": 0,
                    "probe_404": 0,
                    "probe_success": 0,
                    "probe_timeout": 0,
                    "probe_error": 0,
                    "redirect_only": 0,
                    "detection_score": 2000,
                    "selected": True,
                    "rejection_reason": "",
                    "selection_reason": "error_responses_available",
                    "http_versions": {"1.1": 2},
                }
            ],
        },
    )
    output = buf.getvalue()
    assert "HTTP endpoint probe diagnostics:" in output
    assert "221.139.249.110:8080" in output
    assert "selected" in output
    assert "error_responses_available" in output
