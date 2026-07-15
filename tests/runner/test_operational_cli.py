"""Tests for operational `dsp run --profile` CLI."""

from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dsp.runner.cli import _resolve_run_plan, main
from dsp.runner.console_output import OperationalConsole, format_duration
from dsp.runner.run_manager import RunManager
from dsp.runtime.target_net_guard import LARGE_TARGET_ERROR


def test_resolve_run_plan_profile_normal_selects_coverage(tmp_path: Path) -> None:
    manager = RunManager(runs_dir=tmp_path)
    scenario_ids, params, profile = _resolve_run_plan(
        manager,
        scenarios_arg=None,
        profile_arg="normal",
        target_net="10.10.10.0/24",
    )
    assert profile == "normal"
    assert "port_sweep" in scenario_ids
    assert "kerberos_failure" in scenario_ids
    assert params is not None
    assert params["http_followup"]["max_hosts"] == 2
    assert params["http_followup"]["max_per_host"] == 500
    assert params["http_followup"]["max_total"] == 1000


def test_resolve_run_plan_explicit_scenarios_without_profile() -> None:
    manager = MagicMock()
    manager.registry.active_ids.return_value = ["dummy"]
    scenario_ids, params, profile = _resolve_run_plan(
        manager,
        scenarios_arg="dummy,dns_tunnel",
        profile_arg=None,
        target_net="10.10.10.0/24",
    )
    assert scenario_ids == ["dummy", "dns_tunnel"]
    assert params is None
    assert profile is None


def test_resolve_run_plan_explicit_scenarios_with_profile_applies_params() -> None:
    manager = MagicMock()
    scenario_ids, params, profile = _resolve_run_plan(
        manager,
        scenarios_arg="dns_tunnel",
        profile_arg="normal",
        target_net="10.10.10.0/24",
    )
    assert scenario_ids == ["dns_tunnel"]
    assert profile == "normal"
    assert params["dns_tunnel"]["max_hosts"] == 1


def test_cli_profile_run_prints_progress_and_evidence(tmp_path: Path, capsys) -> None:
    run_dir = tmp_path / "20260610_abc123"
    run_dir.mkdir()
    run_mock = MagicMock()
    run_mock.run_id = "20260610_abc123"
    run_mock.status.value = "completed"

    def fake_run(*, on_progress=None, **kwargs):
        if on_progress:
            on_progress(
                "run_started",
                {
                    "provider": kwargs.get("execution_provider", "local"),
                    "target_net": kwargs.get("target_net"),
                    "profile": kwargs.get("operational_profile"),
                },
            )
            on_progress("discovery_started", {})
            on_progress("discovery_completed", {"hosts_found": 4})
            on_progress(
                "targets_selected",
                {"groups": {"DNS": ["221.139.249.4"], "HTTP": ["221.139.249.20"]}},
            )
            on_progress(
                "scenario_started",
                {
                    "scenario_id": "port_sweep",
                    "index": 1,
                    "total": 9,
                    "metadata": {"targets": 2, "ports": 13},
                },
            )
            on_progress(
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
            on_progress("evidence_generated", {})
            on_progress(
                "run_completed",
                {
                    "duration_sec": 192,
                    "event_count": 517,
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
    assert "DSP Run Started" in captured
    assert "Provider: local" in captured
    assert "Target Net: 221.139.249.0/24" in captured
    assert "Profile: normal" in captured
    assert "Discovery Completed" in captured
    assert "Hosts Found: 4" in captured
    assert "Selected Targets" in captured
    assert "[1/9] port_sweep STARTED" in captured
    assert "Duration: 0:03:12" in captured
    assert "Events Generated: 517" in captured
    assert "Port Sweep Completed" in captured
    assert "probes_sent=13" in captured
    assert "Traffic Summary" in captured
    assert "Evidence Summary" in captured
    assert "events.jsonl" in captured
    assert "validation.json" in captured


def test_cli_explicit_scenarios_still_supported(tmp_path: Path) -> None:
    run_dir = tmp_path / "explicit"
    run_dir.mkdir()
    run_mock = MagicMock()
    run_mock.run_id = "explicit"
    run_mock.status.value = "completed"

    with patch.object(RunManager, "run", return_value=(run_mock, run_dir, 0)) as run_fn:
        exit_code = main(
            [
                "run",
                "--scenarios",
                "dummy",
                "--dry-run",
                "--quiet",
            ]
        )

    assert exit_code == 0
    assert run_fn.call_args.kwargs["scenario_ids"] == ["dummy"]
    assert run_fn.call_args.kwargs["operational_profile"] is None


def test_operational_console_format_duration() -> None:
    assert format_duration(192) == "0:03:12"


def test_cli_high_large_target_blocked(capsys) -> None:
    exit_code = main(
        [
            "run",
            "--target-net",
            "10.0.0.0/16",
            "--profile",
            "high",
            "--dry-run",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "ERROR:" in captured.err
    assert LARGE_TARGET_ERROR in captured.err


def test_cli_high_large_target_allowed_with_opts(tmp_path: Path) -> None:
    run_dir = tmp_path / "large"
    run_dir.mkdir()
    run_mock = MagicMock()
    run_mock.run_id = "large"
    run_mock.status.value = "completed"

    with patch.object(RunManager, "run", return_value=(run_mock, run_dir, 0)) as run_fn:
        exit_code = main(
            [
                "run",
                "--target-net",
                "10.0.0.0/16",
                "--profile",
                "high",
                "--allow-large-target",
                "--max-hosts",
                "5",
                "--dry-run",
                "--quiet",
            ]
        )

    assert exit_code == 0
    assert run_fn.call_args.kwargs["max_hosts"] == 5


def test_cli_profile_run_real_runmanager(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DSP_RUNS_DIR", str(tmp_path))
    exit_code = main(
        [
            "run",
            "--profile",
            "normal",
            "--dry-run",
            "--quiet",
        ]
    )
    assert exit_code == 0


def test_operational_console_emits_scenario_labels() -> None:
    buf = io.StringIO()
    console = OperationalConsole(
        provider="webshell",
        target_net="221.139.249.0/24",
        profile="normal",
        stream=buf,
    )
    console.handle_progress("run_started", {})
    console.handle_progress("discovery_started", {})
    console.handle_progress("discovery_completed", {"hosts_found": 2})
    console.handle_progress(
        "scenario_completed",
        {
            "scenario_id": "dns_tunnel",
            "metrics": {"dns_tunnel_query_sent_count": 42},
        },
    )
    output = buf.getvalue()
    assert "Provider: webshell" in output
    assert "DNS Tunnel Completed" in output
    assert "queries_sent=42" in output
