"""DNS Tunnel scenario E2E tests."""

from __future__ import annotations

import json
import socket
import struct
from unittest.mock import MagicMock, patch

import pytest

from dsp.protocols.dns.client import encode_qname
from dsp.runner import RunManager

TUNNEL_TEST_PARAMS = {
    "dns_tunnel": {
        "payload_mb": 0.0001,
        "max_chunks": 3,
        "domain": "dns-tunnel.com",
        "targets": ["10.10.10.20"],
    }
}


def _build_dns_response(txn_id: int, *, rcode: int = 0, ancount: int = 1) -> bytes:
    flags = 0x8180 | rcode
    header = struct.pack("!HHHHHH", txn_id, flags, 1, ancount, 0, 0)
    question = encode_qname("idx-000001-test.dns-tunnel.com") + struct.pack("!HH", 1, 1)
    answer = b""
    if ancount:
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([10, 10, 10, 1])
    return header + question + answer


@pytest.fixture
def mock_dns_socket():
    response_holder: dict[str, int] = {}

    def make_socket(*args, **kwargs):
        sock = MagicMock()

        def sendto(data, addr):
            response_holder["txn_id"] = struct.unpack("!H", data[:2])[0]

        def recvfrom(size):
            txn_id = response_holder.get("txn_id", 0)
            return (_build_dns_response(txn_id), ("10.10.10.20", 53))

        sock.sendto.side_effect = sendto
        sock.recvfrom.side_effect = recvfrom
        return sock

    with patch("socket.socket", side_effect=make_socket):
        yield


def test_dns_tunnel_dry_run_e2e(tmp_runs_dir):
    manager = RunManager(runs_dir=tmp_runs_dir)
    run, run_dir, exit_code = manager.run(
        scenario_ids=["dns_tunnel"],
        target_net="10.10.10.0/24",
        dry_run=True,
        scenario_params=TUNNEL_TEST_PARAMS,
    )

    assert run.status.value == "completed"
    assert exit_code == 0
    assert (run_dir / "events.db").exists()
    assert (run_dir / "validation.json").exists()
    assert (run_dir / "report.md").exists()

    validation = json.loads((run_dir / "validation.json").read_text())
    result = validation["results"][0]
    assert result["scenario_id"] == "dns_tunnel"
    assert result["decision"] == "success"
    assert result["metrics"]["dns_tunnel_query_sent_count"] >= 1
    assert result["metrics"]["dns_tunnel_chunk_created_count"] >= 1

    report = (run_dir / "report.md").read_text()
    assert "## DNS Tunnel Details" in report
    assert "dns_tunnel_query_sent_count" in report
    assert "idx-0000-" in report


def test_dns_tunnel_live_e2e(tmp_runs_dir, mock_dns_socket):
    manager = RunManager(runs_dir=tmp_runs_dir)
    run, run_dir, exit_code = manager.run(
        scenario_ids=["dns_tunnel"],
        target_net="10.10.10.0/24",
        dry_run=False,
        scenario_params=TUNNEL_TEST_PARAMS,
    )

    assert run.status.value == "completed"
    assert exit_code == 0

    validation = json.loads((run_dir / "validation.json").read_text())
    result = validation["results"][0]
    assert result["decision"] == "success"
    # strt + 3 idx + end
    assert result["metrics"]["dns_tunnel_query_sent_count"] == 5
    assert result["metrics"]["dns_tunnel_chunk_created_count"] == 5


def test_dns_tunnel_plugins_list():
    from dsp.plugins import PluginLoader, PluginStatus

    registry = PluginLoader().discover_and_load()
    record = registry.get("dns_tunnel")
    assert record is not None
    assert record.status == PluginStatus.ACTIVE
