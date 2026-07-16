"""Command-only executors must emit validation-aligned DNS/DGA/Rare events."""

from __future__ import annotations

import base64
import re
from unittest.mock import MagicMock

import pytest

from dsp.engine import RunConfig, RunContext
from dsp.event_store import EventStore
from dsp.execution.remote.command import execute as execute_mod
from dsp.execution.remote.command.execute import execute_command_plan
from dsp.execution.remote.command.models import DNS_QUERY_METHOD_PYTHON_SOCKET_UDP53
from dsp.execution.remote.models import ScenarioExecutionRequest


@pytest.fixture(autouse=True)
def _fast_detached_dns_tunnel_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(execute_mod, "DNS_TUNNEL_POLL_INTERVAL_SEC", 0.0)
    monkeypatch.setattr(execute_mod.time, "sleep", lambda _s: None)


def _ctx(tmp_path) -> RunContext:
    store = EventStore(tmp_path / "events.db")
    store.open_run("run-val")
    return RunContext(
        run_id="run-val",
        target_net="10.10.10.0/24",
        event_store=store,
        config=RunConfig(dry_run=False),
        dry_run=False,
    )


def _request(scenario_id: str) -> ScenarioExecutionRequest:
    return ScenarioExecutionRequest(
        run_id="run-val",
        scenario_id=scenario_id,
        target_net="10.10.10.0/24",
        dry_run=False,
        scenario_params={},
        execution_metadata={},
    )


def _mock_dns_tunnel_markers(provider: MagicMock, marker_text: str) -> None:
    # Detached session: launch ACK, then poll reports SESSION_DONE count.
    provider.run_remote_command.side_effect = [
        b"DNS_TUNNEL_LAUNCHED:1\n",
        b"1\n",
    ]
    provider.fetch_remote_file_via_cat.return_value = marker_text.encode("utf-8")


def test_dns_tunnel_command_evidence_includes_python_socket_method(tmp_path) -> None:
    ctx = _ctx(tmp_path)
    provider = MagicMock()
    fqdn = "idx-0000-abc.dns-tunnel.com"
    _mock_dns_tunnel_markers(
        provider,
        f"DNS_TUNNEL_SENT:{fqdn}\nDNS_TUNNEL_SESSION_DONE\n",
    )
    plan = {
        "type": "dns_tunnel",
        "mode": "live",
        "payload_mb": 0.0001,
        "chunk_size": 30,
        "domain": "dns-tunnel.com",
        "mock_filename": "mock_exfil.dat",
        "send_interval_sec": 0.01,
        "session_id": "sess01",
        "queries": [
            {
                "target": "10.10.10.20",
                "fqdn": "idx-0000-abc.dns-tunnel.com",
                "seq": 0,
                "query_role": "idx_chunk",
                "protocol": "dns_udp",
                "port": 53,
            },
        ],
    }
    http_calls = execute_command_plan(plan, provider, ctx, _request("dns_tunnel"))
    events = ctx.event_store.list_events("run-val")
    completed = next(e for e in events if e.event == "dns_tunnel_completed")
    assert completed.evidence.get("dns_query_method") == DNS_QUERY_METHOD_PYTHON_SOCKET_UDP53
    assert completed.evidence.get("dns_tunnel_query_sent_count") == 1
    assert completed.evidence.get("webshell_http_dispatches") == 1
    assert http_calls == 1
    assert provider.run_remote_command.call_count >= 2
    dispatched = next(e for e in events if e.event == "webshell_command_dispatched")
    remote_command = str(dispatched.evidence.get("remote_command"))
    assert "python3 -c" in remote_command
    assert "nohup" in remote_command

    payload = _extract_b64_python_payload(remote_command)
    script = base64.b64decode(payload.encode("ascii")).decode("utf-8")
    assert "DNS_TUNNEL_SENT:" in script
    assert "MARKER" in script
    assert "sendto" in script
    assert "recvfrom" not in script
    assert "DNS_TUNNEL_SESSION_DONE" in script
    assert provider.fetch_remote_file_via_cat.call_count == 1


def test_dns_tunnel_dispatch_without_sendto_emits_no_query_sent(tmp_path) -> None:
    ctx = _ctx(tmp_path)
    provider = MagicMock()
    _mock_dns_tunnel_markers(provider, "DNS_TUNNEL_SESSION_DONE\n")
    plan = {
        "type": "dns_tunnel",
        "mode": "live",
        "payload_mb": 0.0001,
        "chunk_size": 30,
        "domain": "dns-tunnel.com",
        "mock_filename": "mock_exfil.dat",
        "send_interval_sec": 0.01,
        "session_id": "sess01",
        "queries": [
            {
                "target": "10.10.10.20",
                "fqdn": "idx-0000-abc.dns-tunnel.com",
                "seq": 0,
                "query_role": "idx_chunk",
                "protocol": "dns_udp",
                "port": 53,
            },
        ],
    }
    execute_command_plan(plan, provider, ctx, _request("dns_tunnel"))
    events = ctx.event_store.list_events("run-val")
    assert any(e.event == "dns_tunnel_dispatch_completed" for e in events)
    assert not any(e.event == "dns_tunnel_query_sent" for e in events)
    completed = next(e for e in events if e.event == "dns_tunnel_completed")
    assert completed.evidence.get("dns_tunnel_query_sent_count") == 0


def test_dns_tunnel_html_wrapped_markers_are_parsed(tmp_path) -> None:
    ctx = _ctx(tmp_path)
    provider = MagicMock()
    fqdn = "idx-0000-abc.dns-tunnel.com"
    _mock_dns_tunnel_markers(
        provider,
        f"<pre>DNS_TUNNEL_SENT:{fqdn}\nDNS_TUNNEL_SESSION_DONE</pre>",
    )
    plan = {
        "type": "dns_tunnel",
        "mode": "live",
        "payload_mb": 0.0001,
        "chunk_size": 30,
        "domain": "dns-tunnel.com",
        "mock_filename": "mock_exfil.dat",
        "send_interval_sec": 0.01,
        "session_id": "sess01",
        "max_chunks": 1,
        "queries": [
            {
                "target": "10.10.10.20",
                "fqdn": fqdn,
                "seq": 0,
                "query_role": "idx_chunk",
                "protocol": "dns_udp",
                "port": 53,
            },
        ],
    }
    execute_command_plan(plan, provider, ctx, _request("dns_tunnel"))
    completed = next(
        e for e in ctx.event_store.list_events("run-val") if e.event == "dns_tunnel_completed"
    )
    assert completed.evidence.get("dns_tunnel_query_sent_count") == 1


def test_dns_tunnel_session_timeout_still_reads_marker_file(tmp_path) -> None:
    ctx = _ctx(tmp_path)
    provider = MagicMock()
    fqdn = "idx-0000-abc.dns-tunnel.com"
    provider.run_remote_command.side_effect = TimeoutError("session timed out")
    provider.fetch_remote_file_via_cat.return_value = f"DNS_TUNNEL_SENT:{fqdn}\n".encode("utf-8")
    plan = {
        "type": "dns_tunnel",
        "mode": "live",
        "payload_mb": 0.0001,
        "chunk_size": 30,
        "domain": "dns-tunnel.com",
        "mock_filename": "mock_exfil.dat",
        "send_interval_sec": 0.01,
        "session_id": "sess01",
        "queries": [
            {
                "target": "10.10.10.20",
                "fqdn": fqdn,
                "seq": 0,
                "query_role": "idx_chunk",
                "protocol": "dns_udp",
                "port": 53,
            },
        ],
    }
    execute_command_plan(plan, provider, ctx, _request("dns_tunnel"))
    completed = next(
        e for e in ctx.event_store.list_events("run-val") if e.event == "dns_tunnel_completed"
    )
    assert completed.evidence.get("dns_tunnel_query_sent_count") == 1
    assert provider.fetch_remote_file_via_cat.call_count == 1


def test_dga_command_emits_validation_status_events(tmp_path) -> None:
    ctx = _ctx(tmp_path)
    provider = MagicMock()
    provider.run_remote_command.return_value = b"DGA_SENT:abcd1234567890.xdr.ooo\nDGA_SENT:abcd1234567890.live.xdr.ooo\n"
    plan = {
        "type": "dga",
        "mode": "live",
        "resolver": "10.10.10.20",
        "timeout": 1.0,
        "domains": [
            {"fqdn": "abcd1234567890.xdr.ooo", "phase": 1, "phase_name": "nxdomain", "seq": 1},
            {"fqdn": "abcd1234567890.live.xdr.ooo", "phase": 2, "phase_name": "resolvable", "seq": 2},
        ],
    }
    execute_command_plan(plan, provider, ctx, _request("dga"))
    events = ctx.event_store.list_events("run-val")
    nx = [e for e in events if e.event == "dga_nxdomain_observed"]
    resolved = [e for e in events if e.event == "dga_resolved_observed"]
    assert len(nx) == 1
    assert nx[0].status == "nxdomain"
    assert len(resolved) == 1
    assert resolved[0].status == "response"


def test_dga_http_transport_ok_but_no_marker_emits_zero_observed(tmp_path) -> None:
    ctx = _ctx(tmp_path)
    provider = MagicMock()
    provider.run_remote_command.return_value = b"SyntaxError: invalid syntax\n"
    plan = {
        "type": "dga",
        "mode": "live",
        "resolver": "10.10.10.20",
        "timeout": 1.0,
        "domains": [
            {"fqdn": "abcd1234567890.xdr.ooo", "phase": 1, "phase_name": "nxdomain", "seq": 1},
            {"fqdn": "abcd1234567890.live.xdr.ooo", "phase": 2, "phase_name": "resolvable", "seq": 2},
        ],
    }
    execute_command_plan(plan, provider, ctx, _request("dga"))
    events = ctx.event_store.list_events("run-val")
    assert not any(e.event == "dga_nxdomain_observed" for e in events)
    assert not any(e.event == "dga_resolved_observed" for e in events)


def _extract_b64_python_payload(command: str) -> str:
    # command is shell-quoted; shlex.quote may introduce '"'"' sequences.
    # Instead of trying to parse quotes, extract the longest base64-ish token.
    candidates = re.findall(r"[A-Za-z0-9+/=]{100,}", command)
    assert candidates, command
    return max(candidates, key=len)


def test_dga_generated_python_compiles(tmp_path) -> None:
    ctx = _ctx(tmp_path)
    provider = MagicMock()
    provider.run_remote_command.return_value = b""
    plan = {
        "type": "dga",
        "mode": "live",
        "resolver": "10.10.10.20",
        "timeout": 1.0,
        "domains": [
            {"fqdn": "abcd1234567890.xdr.ooo", "phase": 1, "phase_name": "nxdomain", "seq": 1},
        ],
    }
    execute_command_plan(plan, provider, ctx, _request("dga"))
    dispatched = next(e for e in ctx.event_store.list_events("run-val") if e.event == "webshell_command_dispatched")
    remote_command = str((dispatched.evidence or {}).get("remote_command") or "")
    payload = _extract_b64_python_payload(remote_command)
    script = base64.b64decode(payload.encode("ascii")).decode("utf-8")
    compile(script, "<dga_remote_python>", "exec")


def test_rare_protocol_command_emits_probe_attempt_events(tmp_path) -> None:
    ctx = _ctx(tmp_path)
    provider = MagicMock()
    provider.execute_command.return_value = MagicMock(status=MagicMock(value="completed"))
    plan = {
        "type": "rare_protocol_activity",
        "mode": "live",
        "timeout": 3.0,
        "probes": [
            {
                "host": "10.10.10.97",
                "port": 23,
                "protocol": "TELNET",
                "transport": "tcp",
                "artifact": "10.10.10.97:23:TELNET",
            },
        ],
    }
    execute_command_plan(plan, provider, ctx, _request("rare_protocol_activity"))
    events = ctx.event_store.list_events("run-val")
    attempts = [e for e in events if e.event == "rare_protocol_probe_attempt"]
    assert len(attempts) == 1
    assert attempts[0].status == "sent"


def test_rare_protocol_skip_plan_emits_skipped_events(tmp_path) -> None:
    ctx = _ctx(tmp_path)
    provider = MagicMock()
    plan = {
        "type": "rare_protocol_activity",
        "mode": "skip",
        "reason": "no_probe_plans",
    }
    dispatched = execute_command_plan(plan, provider, ctx, _request("rare_protocol_activity"))
    assert dispatched == 0
    provider.execute_command.assert_not_called()
    events = [e.event for e in ctx.event_store.list_events("run-val")]
    assert "rare_protocol_activity_skipped" in events
    assert "rare_protocol_probe_attempt" not in events
