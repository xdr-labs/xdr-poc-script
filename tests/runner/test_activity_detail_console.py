"""Runtime activity detail console tests for v1.3.5."""

from __future__ import annotations

import io
from pathlib import Path

from dsp.runner.console_output import OperationalConsole


def test_http_followup_request_detail_output() -> None:
    buf = io.StringIO()
    console = OperationalConsole(stream=buf)
    console.handle_progress(
        "activity",
        {
            "scenario_id": "http_followup",
            "kind": "detail",
            "seq": 1,
            "total": 1000,
            "action": "request",
            "target": "221.139.249.110:80",
            "method": "GET",
            "url": "http://221.139.249.110/WEB-INF/web.xml?file=%2e%2e%2fweb.xml",
            "path": "/WEB-INF/web.xml",
            "query": "?file=%2e%2e%2fweb.xml",
            "user_agent": "ThreatHunterAgent/8.2",
            "response_code": 301,
        },
    )
    output = buf.getvalue()
    assert "[http_followup] request 1/1000" in output
    assert "url=http://221.139.249.110/WEB-INF/web.xml" in output
    assert 'user_agent="ThreatHunterAgent/8.2"' in output
    assert "response_code=301" in output


def test_http_followup_completed_shows_evidence_file() -> None:
    buf = io.StringIO()
    console = OperationalConsole(stream=buf)
    console.handle_progress(
        "scenario_completed",
        {
            "scenario_id": "http_followup",
            "metrics": {
                "http_request_sent_count": 1000,
                "http_response_received_count": 1000,
            },
            "extras": {
                "unique_paths": 16,
                "unique_user_agents": 47,
                "malicious_rare_ua_count": 1000,
                "response_tracking": "disabled_webshell_mode",
            },
            "artifacts": {
                "evidence_file": "/tmp/run/http_followup_requests.jsonl",
                "request_dump": "/tmp/run/http_request_dump.json",
            },
        },
    )
    output = buf.getvalue()
    assert "HTTP Follow-up Completed" in output
    assert "evidence_file=/tmp/run/http_followup_requests.jsonl" in output
    assert "request_dump=/tmp/run/http_request_dump.json" in output
    assert "response_tracking=disabled_webshell_mode" in output
    assert "unique_paths=16" in output


def test_port_sweep_progress_output() -> None:
    buf = io.StringIO()
    console = OperationalConsole(stream=buf)
    console.handle_progress(
        "activity",
        {
            "scenario_id": "port_sweep",
            "kind": "progress",
            "sent": 320,
            "total": 2540,
            "open": 4,
            "failed": 316,
            "current": "221.139.249.32:80",
            "elapsed_sec": 5.0,
            "rate": 64.0,
        },
    )
    output = buf.getvalue()
    assert "[port_sweep] progress" in output
    assert "sent=320/2540" in output
    assert "open=4" in output
    assert "failed=316" in output
    assert "current=221.139.249.32:80" in output
    assert "rate=64.0 probes/sec" in output


def test_dns_tunnel_and_dga_progress_output() -> None:
    buf = io.StringIO()
    console = OperationalConsole(stream=buf)
    console.handle_progress(
        "activity",
        {
            "scenario_id": "dns_tunnel",
            "kind": "progress",
            "sent": 30,
            "total": 50,
            "target": "221.139.249.101",
            "sample_query": "idx-000030-xxxx.dns-tunnel.com",
            "elapsed_sec": 3.0,
            "rate": 10.0,
        },
    )
    console.handle_progress(
        "activity",
        {
            "scenario_id": "dga",
            "kind": "progress",
            "sent": 10,
            "total": 15,
            "sample_domain": "abc123.xdr.ooo",
            "elapsed_sec": 2.0,
            "rate": 5.0,
        },
    )
    output = buf.getvalue()
    assert "queries_sent=30/50" in output
    assert "sample_query=idx-000030-xxxx.dns-tunnel.com" in output
    assert "domains_generated=10/15" in output
    assert "sample_domain=abc123.xdr.ooo" in output


def test_ssh_failure_progress_output() -> None:
    buf = io.StringIO()
    console = OperationalConsole(stream=buf)
    console.handle_progress(
        "activity",
        {
            "scenario_id": "ssh_failure",
            "kind": "detail",
            "seq": 10,
            "total": 150,
            "action": "auth_attempt",
            "target": "221.139.249.101",
            "username": "invaliduser",
            "result": "auth_failed",
        },
    )
    console.handle_progress(
        "activity",
        {
            "scenario_id": "ssh_failure",
            "kind": "progress",
            "sent": 100,
            "total": 150,
            "auth_failed": 100,
            "timeouts": 0,
            "elapsed_sec": 12.0,
            "rate": 8.3,
        },
    )
    output = buf.getvalue()
    assert "[ssh_failure] attempt 10/150" in output
    assert "username=invaliduser" in output
    assert "attempts=100/150" in output
    assert "auth_failed=100" in output


def test_evidence_summary_lists_http_jsonl(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "events.jsonl").write_text("{}\n", encoding="utf-8")
    (run_dir / "http_followup_requests.jsonl").write_text("{}\n", encoding="utf-8")
    (run_dir / "traffic_summary.json").write_text("{}", encoding="utf-8")

    buf = io.StringIO()
    console = OperationalConsole(stream=buf)
    console.print_evidence_summary(run_dir)

    output = buf.getvalue()
    assert "Evidence Summary" in output
    assert "HTTP Evidence:" in output
    assert "http_followup_requests.jsonl" in output
    assert "traffic_summary.json" in output
