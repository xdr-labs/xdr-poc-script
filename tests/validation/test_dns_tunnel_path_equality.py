"""DNS Tunnel Path Equality tests — Store-only validation and reporting."""

from __future__ import annotations

from datetime import datetime, timezone

from dsp.event_store import Event, EventStore, ValidationDecision
from dsp.plugins import PluginLoader
from dsp.protocols.dns.tunnel_events import (
    build_tunnel_chunk_created_event,
    build_tunnel_query_sent_event,
)
from dsp.reporting import ReportingEngine
from dsp.validation import ValidationEngine


def _append_lifecycle(store: EventStore, run_id: str, scenario_id: str) -> None:
    now = datetime.now(timezone.utc)
    for event_name in ("scenario_started", "scenario_completed"):
        store.append(
            Event(
                run_id=run_id,
                scenario_id=scenario_id,
                timestamp=now,
                stage="executor",
                event=event_name,
                status="info",
                source="runner",
            )
        )


def test_dns_tunnel_path_equality():
    store = EventStore(":memory:")
    run_id = "dns_tunnel_pe_run"
    store.open_run(run_id)
    _append_lifecycle(store, run_id, "dns_tunnel")

    fqdn = "idx-0000-mfrggzdfmy.dns-tunnel.com"
    target = "10.10.10.20"
    for seq in (0, 1, 2):
        evidence = {
            "target": target,
            "resolver": target,
            "fqdn": fqdn,
            "query": fqdn,
            "protocol": "dns_udp",
            "port": 53,
            "idx_pattern": True,
            "seq": seq,
        }
        store.append(
            build_tunnel_chunk_created_event(
                run_id=run_id,
                scenario_id="dns_tunnel",
                target=target,
                fqdn=fqdn,
                source="dry_run",
                evidence=evidence,
            )
        )
        store.append(
            build_tunnel_query_sent_event(
                run_id=run_id,
                scenario_id="dns_tunnel",
                target=target,
                fqdn=fqdn,
                source="dry_run",
                evidence=evidence,
            )
        )

    loader = PluginLoader()
    registry = loader.discover_and_load()
    validator = ValidationEngine(store, registry)
    result = validator.validate(run_id, "dns_tunnel")

    reporter = ReportingEngine(store, registry)
    report = reporter.generate(run_id, [result])
    table = reporter.build_primary_table_rows([result])

    assert result.decision == ValidationDecision.SUCCESS
    assert result.metrics["dns_tunnel_query_sent_count"] == 3
    assert result.metrics["dns_tunnel_chunk_created_count"] == 3
    assert table[0]["metrics"] == result.metrics
    assert report.traffic_validation[0].metrics == result.metrics


def test_dns_tunnel_empty_traffic_code_failure():
    store = EventStore(":memory:")
    run_id = "dns_tunnel_empty"
    store.open_run(run_id)
    _append_lifecycle(store, run_id, "dns_tunnel")

    loader = PluginLoader()
    registry = loader.discover_and_load()
    result = ValidationEngine(store, registry).validate(run_id, "dns_tunnel")

    assert result.decision == ValidationDecision.CODE_FAILURE
    assert "SOT_EMPTY_AFTER_EXECUTE" in result.fail_fast_codes
