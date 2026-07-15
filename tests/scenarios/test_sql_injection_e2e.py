"""SQL injection scenario E2E tests."""

from __future__ import annotations

import json

import pytest

from dsp.runner import RunManager

from dsp.protocols.http.sqli_payloads import SQLI_REQUESTS_PER_HOST

SQLI_TEST_PARAMS = {
    "sql_injection": {
        "endpoints": [["10.10.10.20", 8080]],
        "max_hosts": 1,
    }
}


def test_sql_injection_dry_run_e2e(tmp_runs_dir):
    manager = RunManager(runs_dir=tmp_runs_dir)
    run, run_dir, exit_code = manager.run(
        scenario_ids=["sql_injection"],
        target_net="10.10.10.0/24",
        dry_run=True,
        scenario_params=SQLI_TEST_PARAMS,
    )

    assert run.status.value == "completed"
    assert exit_code == 0
    assert (run_dir / "events.db").exists()
    assert (run_dir / "validation.json").exists()
    assert (run_dir / "report.md").exists()

    validation = json.loads((run_dir / "validation.json").read_text())
    result = validation["results"][0]
    assert result["scenario_id"] == "sql_injection"
    assert result["decision"] == "success"
    assert result["metrics"]["sql_payload_generated_count"] == SQLI_REQUESTS_PER_HOST
    assert result["metrics"]["sql_request_sent_count"] == SQLI_REQUESTS_PER_HOST

    report = (run_dir / "report.md").read_text()
    assert "## SQL Injection Details" in report
    assert "sql_payload_generated_count" in report
    # Sample URLs come from the first planned requests (path pool cycles from the start).
    assert any(
        token in report
        for token in ("WEB-INF", "shell.jsp", "/login", "dvwa", "raygun4wp", "suspected_query")
    )


def test_sql_injection_live_e2e(tmp_runs_dir, mock_curl_http):
    manager = RunManager(runs_dir=tmp_runs_dir)
    run, run_dir, exit_code = manager.run(
        scenario_ids=["sql_injection"],
        target_net="10.10.10.0/24",
        dry_run=False,
        scenario_params=SQLI_TEST_PARAMS,
    )

    assert run.status.value == "completed"
    assert exit_code == 0

    validation = json.loads((run_dir / "validation.json").read_text())
    result = validation["results"][0]
    assert result["decision"] == "success"
    assert result["metrics"]["sql_request_sent_count"] == SQLI_REQUESTS_PER_HOST


def test_sql_injection_plugins_list():
    from dsp.plugins import PluginLoader, PluginStatus

    registry = PluginLoader().discover_and_load()
    record = registry.get("sql_injection")
    assert record is not None
    assert record.status == PluginStatus.ACTIVE
