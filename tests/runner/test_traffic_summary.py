"""Tests for scenario traffic summary formatting."""

from __future__ import annotations

from dsp.runner.traffic_summary import format_scenario_traffic_block, traffic_lines_for_scenario


def test_dns_tunnel_counters() -> None:
    lines = traffic_lines_for_scenario(
        "dns_tunnel",
        {"dns_tunnel_query_sent_count": 100},
    )
    assert lines == [("queries_sent", 100)]


def test_port_sweep_counters() -> None:
    block = format_scenario_traffic_block(
        "port_sweep",
        {
            "port_probe_count": 13,
            "port_connection_success_count": 2,
            "port_connection_failure_count": 11,
        },
    )
    assert block == [
        "port_sweep",
        "  probes_sent=13",
        "  success=2",
        "  failed=11",
    ]


def test_dga_queries_sent_equals_domains_generated() -> None:
    lines = traffic_lines_for_scenario(
        "dga",
        {
            "dga_domain_generated_count": 45,
            "dga_nxdomain_observed_count": 32,
            "dga_resolved_observed_count": 0,
        },
    )
    assert ("domains_generated", 45) in lines
    assert ("queries_sent", 45) in lines
    assert ("nxdomain_observed", 32) in lines
    assert ("resolved_observed", 0) not in lines
