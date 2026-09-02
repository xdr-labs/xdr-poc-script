"""DNS Tunnel planned vs dispatched validation."""

from __future__ import annotations

from datetime import datetime, timezone

from dsp.event_store import Event, EventStore, ValidationDecision
from dsp.plugins import PluginLoader
from dsp.protocols.dns.tunnel_events import (
    build_tunnel_chunk_created_event,
    build_tunnel_completed_event,
    build_tunnel_query_sent_event,
    build_tunnel_started_event,
)
from dsp.validation import ValidationEngine


def _lifecycle(store: EventStore, run_id: str) -> None:
    now = datetime.now(timezone.utc)
    for event_name in ("scenario_started", "scenario_completed"):
        store.append(
            Event(
                run_id=run_id,
                scenario_id="dns_tunnel",
                timestamp=now,
                stage="executor",
                event=event_name,
                status="info",
                source="runner",
            )
        )


def test_dns_tunnel_dispatch_shortfall_fails() -> None:
    store = EventStore(":memory:")
    run_id = "dns_tunnel_shortfall"
    store.open_run(run_id)
    _lifecycle(store, run_id)
    target = "10.1.3.80"
    planned = 17479
    store.append(
        build_tunnel_started_event(
            run_id=run_id,
            scenario_id="dns_tunnel",
            target=target,
            source="local",
            evidence={
                "planned_queries": planned,
                "total_planned_queries": planned,
                "payload_bytes": 524288,
            },
        )
    )
    for seq in range(50):
        fqdn = f"idx-{seq:04d}-mfrggzdfmy.dns-tunnel.com"
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
                source="local",
                evidence=evidence,
            )
        )
        store.append(
            build_tunnel_query_sent_event(
                run_id=run_id,
                scenario_id="dns_tunnel",
                target=target,
                fqdn=fqdn,
                source="local",
                evidence=evidence,
            )
        )
    store.append(
        build_tunnel_completed_event(
            run_id=run_id,
            scenario_id="dns_tunnel",
            target=target,
            source="local",
            evidence={
                "planned_queries": planned,
                "total_planned_queries": planned,
                "dispatched_queries": 50,
                "observed_queries": 50,
                "payload_bytes": 524288,
            },
        )
    )

    registry = PluginLoader().discover_and_load()
    result = ValidationEngine(store, registry).validate(run_id, "dns_tunnel")
    assert result.decision == ValidationDecision.CODE_FAILURE
    assert "DNS_TUNNEL_DISPATCH_SHORTFALL" in result.fail_fast_codes


def test_skip_reason_propagates_from_event_store() -> None:
    store = EventStore(":memory:")
    run_id = "smb_skip_reason"
    store.open_run(run_id)
    store.append(
        Event(
            run_id=run_id,
            scenario_id="smb_login_failure",
            timestamp=datetime.now(timezone.utc),
            stage="executor",
            event="smb_scenario_skipped",
            status="info",
            source="local",
            evidence={"reason": "No SMB service discovered"},
        )
    )
    registry = PluginLoader().discover_and_load()
    result = ValidationEngine(store, registry).validate(run_id, "smb_login_failure")
    assert result.decision == ValidationDecision.SKIPPED
    assert result.reason == "No SMB service discovered"
