"""DNS Tunnel target selection, send parity, and local/webshell plan tests."""

from __future__ import annotations

import importlib.util
import struct
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from dsp.engine.scenario_engine import RunContext, TargetSet
from dsp.event_store import EventQuery, EventStore
from dsp.execution.remote.bundle.planner import _plan_dns_tunnel
from dsp.protocols.dns.client import build_query, encode_qname
from dsp.protocols.dns.tunnel import select_tunnel_targets


def _targets(*, alive: list[str], dns_hosts: list[str] | None = None) -> TargetSet:
    return TargetSet(
        target_net="10.10.10.0/24",
        hosts=list(alive),
        service_hosts={
            "dns_hosts": dns_hosts or [],
            "http_targets": ["10.10.10.97"],
        },
        discovery_enabled=True,
        discovery_meta={"alive_hosts": list(alive)},
    )


def test_select_tunnel_targets_uses_alive_hosts_not_dns_hosts() -> None:
    targets = _targets(alive=["10.10.10.97", "10.10.10.98"], dns_hosts=["10.10.10.20"])
    selected = select_tunnel_targets(targets, {}, max_hosts=2)
    assert selected == ["10.10.10.97", "10.10.10.98"]
    assert "10.10.10.20" not in selected


def test_select_tunnel_targets_runs_without_discovered_port_53() -> None:
    targets = _targets(alive=["10.10.10.50", "10.10.10.51"], dns_hosts=[])
    assert select_tunnel_targets(targets, {}, max_hosts=2) == [
        "10.10.10.50",
        "10.10.10.51",
    ]


def test_local_and_webshell_dns_tunnel_plans_match() -> None:
    targets = _targets(alive=["10.10.10.97", "10.10.10.98"])
    params = {
        "payload_mb": 0.0001,
        "max_chunks": 3,
        "domain": "dns-tunnel.com",
        "max_hosts": 2,
        "plan_seed": 11,
    }
    plan = _plan_dns_tunnel(targets, params, dry_run=False)
    assert plan["type"] == "dns_tunnel"
    # 2 hosts × (strt + 3 idx + end)
    assert len(plan["queries"]) == 10
    hosts = {item["target"] for item in plan["queries"]}
    assert hosts == {"10.10.10.97", "10.10.10.98"}
    idx = [q for q in plan["queries"] if q.get("query_role") == "idx_chunk"]
    assert len(idx) == 6
    for item in idx:
        assert item["fqdn"].startswith("idx-")
        assert item["fqdn"].endswith(".dns-tunnel.com")


def test_live_executor_sends_udp_for_every_planned_query(tmp_path) -> None:
    sent_packets: list[tuple[bytes, tuple[str, int]]] = []

    def capture_sendto(data, addr):
        sent_packets.append((bytes(data), addr))

    mock_sock = MagicMock()
    mock_sock.sendto.side_effect = capture_sendto

    store = EventStore(tmp_path / "events.db")
    store.open_run("tunnel_send_run")
    ctx = RunContext(
        run_id="tunnel_send_run",
        target_net="10.10.10.0/24",
        event_store=store,
        config=MagicMock(scenario_params={"dns_tunnel": {}}),
        dry_run=False,
    )
    targets = _targets(alive=["10.10.10.97"])

    executor_path = Path(__file__).resolve().parents[2] / "scenarios" / "dns_tunnel" / "executor.py"
    spec = importlib.util.spec_from_file_location("dns_tunnel_executor", executor_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    params = {
        "payload_mb": 0.0001,
        "max_chunks": 3,
        "domain": "dns-tunnel.com",
        "max_hosts": 1,
    }

    with patch("dsp.protocols.dns.client.socket.socket", return_value=mock_sock):
        module.run(ctx, targets, params)

    # strt + 3 idx + end
    assert len(sent_packets) == 5
    for packet, (host, port) in sent_packets:
        assert host == "10.10.10.97"
        assert port == 53
        assert len(packet) >= 12

    query_sent = store.count(
        EventQuery(run_id="tunnel_send_run", scenario_id="dns_tunnel", event="dns_tunnel_query_sent")
    )
    dns_sent = store.count(
        EventQuery(run_id="tunnel_send_run", scenario_id="dns_tunnel", event="dns_query_sent")
    )
    assert query_sent == 5
    assert dns_sent == 5


def test_sendto_error_does_not_count_as_sent(tmp_path) -> None:
    mock_sock = MagicMock()
    mock_sock.sendto.side_effect = OSError("network unreachable")

    store = EventStore(tmp_path / "events.db")
    store.open_run("tunnel_err_run")
    ctx = RunContext(
        run_id="tunnel_err_run",
        target_net="10.10.10.0/24",
        event_store=store,
        config=MagicMock(scenario_params={"dns_tunnel": {}}),
        dry_run=False,
    )
    targets = _targets(alive=["10.10.10.97"])

    executor_path = Path(__file__).resolve().parents[2] / "scenarios" / "dns_tunnel" / "executor.py"
    spec = importlib.util.spec_from_file_location("dns_tunnel_executor_err", executor_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    with patch("dsp.protocols.dns.client.socket.socket", return_value=mock_sock):
        module.run(
            ctx,
            targets,
            {"payload_mb": 0.0001, "max_chunks": 2, "domain": "dns-tunnel.com", "max_hosts": 1},
        )

    assert store.count(
        EventQuery(run_id="tunnel_err_run", scenario_id="dns_tunnel", event="dns_tunnel_query_sent")
    ) == 0
    assert store.count(
        EventQuery(run_id="tunnel_err_run", scenario_id="dns_tunnel", event="dns_query_sent")
    ) == 0


def test_remote_runner_encodes_full_tunnel_fqdn() -> None:
    runner_path = (
        Path(__file__).resolve().parents[2]
        / "dsp"
        / "execution"
        / "remote"
        / "bundle"
        / "assets"
        / "run_scenario.py"
    )
    spec = importlib.util.spec_from_file_location("run_scenario_asset", runner_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    fqdn = "idx-000001-mfrggzdfmy.dns-tunnel.com"
    _txn_id, packet = module._build_dns_query_packet(fqdn)
    expected_txn, expected_packet = build_query(fqdn, 1)
    assert packet[2:] == expected_packet[2:]
    question = encode_qname(fqdn) + struct.pack("!HH", 1, 1)
    assert question in packet


def test_remote_runner_emits_dns_query_sent_per_query(tmp_path) -> None:
    runner_path = (
        Path(__file__).resolve().parents[2]
        / "dsp"
        / "execution"
        / "remote"
        / "bundle"
        / "assets"
        / "run_scenario.py"
    )
    spec = importlib.util.spec_from_file_location("run_scenario_events", runner_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    log = module.EventLog(
        run_id="r1",
        scenario_id="dns_tunnel",
        scenario_version="1.0.0",
        schema_version="1.0.0",
    )
    plan = {
        "mode": "mock",
        "domain": "dns-tunnel.com",
        "queries": [
            {"target": "10.10.10.97", "seq": 1, "fqdn": "idx-000001-abc.dns-tunnel.com"},
            {"target": "10.10.10.97", "seq": 2, "fqdn": "idx-000002-def.dns-tunnel.com"},
        ],
    }
    module._run_dns_tunnel(log, plan)
    events = [e["event"] for e in log.events]
    assert events.count("dns_tunnel_query_sent") == 2
    assert events.count("dns_query_sent") == 2
