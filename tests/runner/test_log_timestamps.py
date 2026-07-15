"""Tests for UTC timestamp logging and run metadata enrichment."""

from __future__ import annotations

import io
import json
import re
from datetime import datetime, timezone
from unittest.mock import patch

from dsp.event_store import Run, RunStatus
from dsp.runner.console_output import OperationalConsole
from dsp.runner.log_timestamps import (
    apply_run_timing_metadata,
    collect_git_info,
    format_utc_timestamp,
)
from dsp.runner.run_manager import RunManager


def test_format_utc_timestamp() -> None:
    dt = datetime(2026, 6, 23, 1, 22, 33, tzinfo=timezone.utc)
    assert format_utc_timestamp(dt) == "2026-06-23T01:22:33Z"
    assert format_utc_timestamp("2026-06-23T01:22:33+00:00") == "2026-06-23T01:22:33Z"


def test_collect_git_info_from_repo() -> None:
    info = collect_git_info()
    assert info["git_commit"]
    assert info["git_branch"]


def test_apply_run_timing_metadata() -> None:
    started = datetime(2026, 6, 23, 1, 22, 33, tzinfo=timezone.utc)
    ended = datetime(2026, 6, 23, 1, 25, 20, tzinfo=timezone.utc)
    run = Run(run_id="r1", started_at=started, ended_at=ended, status=RunStatus.COMPLETED)
    apply_run_timing_metadata(run, started_at=started, ended_at=ended)
    assert run.started_at_utc == "2026-06-23T01:22:33Z"
    assert run.completed_at_utc == "2026-06-23T01:25:20Z"
    assert run.duration_seconds == 167.0


def test_console_timestamps_on_key_events() -> None:
    started = datetime(2026, 6, 23, 1, 22, 33, tzinfo=timezone.utc)
    completed = datetime(2026, 6, 23, 1, 25, 20, tzinfo=timezone.utc)
    buf = io.StringIO()
    console = OperationalConsole(stream=buf)

    console.handle_progress(
        "run_started",
        {"provider": "webshell", "target_net": "10.10.10.0/24", "started_at": started},
    )
    console.handle_progress(
        "scenario_started",
        {"scenario_id": "sql_injection", "index": 4, "total": 11, "metadata": {}},
    )
    console.handle_progress(
        "activity",
        {"scenario_id": "dns_tunnel", "kind": "progress", "sent": 102, "total": 200},
    )
    console.handle_progress(
        "scenario_completed",
        {"scenario_id": "sql_injection", "metrics": {"sql_injection_request_sent_count": 1000}},
    )
    console.handle_progress(
        "scenario_skipped",
        {"scenario_id": "ldap_enumeration", "reason": "no_ldap_hosts"},
    )
    with patch("dsp.runner.console_output.OperationalConsole._utc_now", return_value=completed):
        console.handle_progress(
            "run_completed",
            {
                "duration_sec": 167,
                "event_count": 100,
                "started_at": started,
                "completed_at": completed,
                "git_commit": "3b3d319",
                "git_branch": "release/v1.4.0-rc",
            },
        )

    output = buf.getvalue()
    ts_pattern = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z \| ")
    assert ts_pattern.search(output)
    assert "2026-06-23T01:22:33Z | DSP Run Started" in output
    assert re.search(r"T\d{2}:\d{2}:\d{2}Z \| \[4/11\] sql_injection STARTED", output)
    assert re.search(r"T\d{2}:\d{2}:\d{2}Z \| \[dns_tunnel\] progress", output)
    assert re.search(r"T\d{2}:\d{2}:\d{2}Z \| SQL Injection Completed", output)
    assert re.search(r"T\d{2}:\d{2}:\d{2}Z \| LDAP Enumeration SKIPPED", output)
    assert "Git Commit: 3b3d319" in output
    assert "Git Branch: release/v1.4.0-rc" in output
    assert "2026-06-23T01:25:20Z | Run Completed" in output
    assert "Started At: 2026-06-23T01:22:33Z" in output
    assert "Completed At: 2026-06-23T01:25:20Z" in output
    assert "Duration: 0:02:47" in output


def test_run_json_includes_git_and_timing_fields(tmp_runs_dir) -> None:
    manager = RunManager(runs_dir=tmp_runs_dir)
    _, run_dir, exit_code = manager.run(scenario_ids=["dummy"], dry_run=True)
    assert exit_code == 0

    run_json = json.loads((run_dir / "run.json").read_text())
    assert run_json["git_commit"]
    assert run_json["git_branch"]
    assert run_json["started_at_utc"].endswith("Z")
    assert run_json["completed_at_utc"].endswith("Z")
    assert isinstance(run_json["duration_seconds"], (int, float))
    assert run_json["duration_seconds"] >= 0
