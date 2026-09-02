"""DNS Tunnel encoder and FQDN format unit tests."""

from __future__ import annotations

import base64

import pytest

from dsp.protocols.base import DnsProtocolError
from dsp.protocols.dns.tunnel import (
    CHUNK_SIZE_DEFAULT,
    MOCK_PAYLOAD_FILENAME,
    MOCK_PAYLOAD_PATTERN,
    build_dns_tunnel_queries,
    build_tunnel_end_fqdn,
    build_tunnel_fqdn,
    build_tunnel_start_fqdn,
    chunk_to_b32_label,
    dns_tunnel_session_script_completed,
    generate_mock_payload_bytes,
    is_valid_tunnel_fqdn,
    iter_payload_chunks,
    parse_dns_tunnel_session_sent_fqdns,
    plan_burst_schedule,
    plan_chunk_count,
    write_mock_payload_file,
)


def test_chunk_to_b32_label():
    chunk = b"hello-world-payload-30bytes!!"
    label = chunk_to_b32_label(chunk[:30])
    assert label == base64.b32encode(chunk[:30]).decode("ascii").lower().rstrip("=")
    assert "=" not in label


def test_plan_chunk_count_2mb():
    count = plan_chunk_count(2.0, CHUNK_SIZE_DEFAULT)
    assert count == (2 * 1024 * 1024 + CHUNK_SIZE_DEFAULT - 1) // CHUNK_SIZE_DEFAULT

def test_iter_payload_chunks_sizes():
    chunks = list(iter_payload_chunks(0.0001, chunk_size=30))
    assert len(chunks) >= 1
    assert all(len(c) <= 30 for c in chunks)
    assert sum(len(c) for c in chunks) >= 30


def test_mock_payload_is_deterministic_and_non_random():
    first = generate_mock_payload_bytes(0.001)
    second = generate_mock_payload_bytes(0.001)
    assert first == second
    assert first.startswith(MOCK_PAYLOAD_PATTERN)


def test_build_tunnel_fqdn_format():
    fqdn = build_tunnel_fqdn(0, "mfrggzdfmy", "dns-tunnel.com")
    assert fqdn == "idx-0000-mfrggzdfmy.dns-tunnel.com"
    assert is_valid_tunnel_fqdn(fqdn)


def test_build_tunnel_fqdn_sequence_padding():
    fqdn = build_tunnel_fqdn(42, "abc", "lab.example")
    assert fqdn.startswith("idx-0042-")


def test_session_marker_fqdns():
    start = build_tunnel_start_fqdn(MOCK_PAYLOAD_FILENAME, "dns-tunnel.com")
    assert start.startswith("strt-")
    assert start.endswith(".dns-tunnel.com")
    assert build_tunnel_end_fqdn("dns-tunnel.com") == "end-0.dns-tunnel.com"


def test_build_dns_tunnel_queries_include_session_markers():
    queries, _sid = build_dns_tunnel_queries(
        ["10.0.0.1"],
        payload_mb=0.0001,
        max_chunks=2,
        plan_seed=42,
    )
    roles = [q["query_role"] for q in queries]
    assert roles[0] == "session_start"
    assert roles[-1] == "session_end"
    assert queries[1]["fqdn"].startswith("idx-")


def test_plan_burst_schedule_covers_total():
    schedule = plan_burst_schedule(50)
    assert sum(schedule) == 50
    assert all(1 <= size <= 10 for size in schedule)
    assert len(schedule) >= 5


def test_invalid_tunnel_fqdn_rejected():
    assert not is_valid_tunnel_fqdn("strt-session.dns-tunnel.com")
    assert not is_valid_tunnel_fqdn("idx-1-abc.dns-tunnel.com")
    assert not is_valid_tunnel_fqdn("0001.chunk.dns-tunnel.com")


def test_build_tunnel_fqdn_label_too_long():
    with pytest.raises(DnsProtocolError, match="exceeds 63"):
        build_tunnel_fqdn(1, "a" * 60, "dns-tunnel.com")


def test_write_mock_payload_file(tmp_path):
    path = write_mock_payload_file(tmp_path / "mock.dat", 0.0001)
    assert path.is_file()
    assert path.stat().st_size >= CHUNK_SIZE_DEFAULT


def test_parse_dns_tunnel_session_sent_fqdns():
    text = (
        "DNS_TUNNEL_SENT:strt-mock.dns-tunnel.com\n"
        "DNS_TUNNEL_SENT:idx-0000-abc.dns-tunnel.com\n"
        "DNS_TUNNEL_SESSION_DONE\n"
    )
    assert parse_dns_tunnel_session_sent_fqdns(text) == frozenset(
        {"strt-mock.dns-tunnel.com", "idx-0000-abc.dns-tunnel.com"}
    )
    assert dns_tunnel_session_script_completed(text)
