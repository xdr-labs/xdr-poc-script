"""DGA Path Equality tests — Store-only validation and reporting."""

from __future__ import annotations

from datetime import datetime, timezone

from dsp.event_store import Event, EventStore, ValidationDecision
from dsp.plugins import PluginLoader
from dsp.protocols.dns.dga_events import (
    build_dga_domain_generated_event,
    build_dga_nxdomain_observed_event,
    build_dga_resolved_observed_event,
)
from dsp.protocols.dns.events import DNS_QUERY_SENT
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


def test_dga_path_equality():
    store = EventStore(":memory:")
    run_id = "dga_pe_run"
    store.open_run(run_id)
    _append_lifecycle(store, run_id, "dga")

    nx_fqdn = "rf2xh8lxoxv.xdr.ooo"
    res_fqdn = "a8fj3kq9xy.live.xdr.ooo"
    for fqdn, phase in ((nx_fqdn, 1), (res_fqdn, 2)):
        store.append(
            build_dga_domain_generated_event(
                run_id=run_id,
                scenario_id="dga",
                target="10.10.10.20",
                fqdn=fqdn,
                source="dry_run",
                evidence={"phase": phase},
            )
        )
        store.append(
            Event(
                run_id=run_id,
                scenario_id="dga",
                timestamp=datetime.now(timezone.utc),
                stage="executor",
                event=DNS_QUERY_SENT,
                status="sent",
                target="10.10.10.20",
                artifact=fqdn,
                source="dry_run",
                evidence={"phase": phase},
            )
        )
    store.append(
        build_dga_nxdomain_observed_event(
            run_id=run_id,
            scenario_id="dga",
            target="10.10.10.20",
            fqdn=nx_fqdn,
            source="dry_run",
            evidence={"phase": 1},
        )
    )
    store.append(
        build_dga_resolved_observed_event(
            run_id=run_id,
            scenario_id="dga",
            target="10.10.10.20",
            fqdn=res_fqdn,
            source="dry_run",
            evidence={"phase": 2},
        )
    )

    loader = PluginLoader()
    registry = loader.discover_and_load()
    validator = ValidationEngine(store, registry)
    result = validator.validate(run_id, "dga")

    reporter = ReportingEngine(store, registry)
    report = reporter.generate(run_id, [result])
    table = reporter.build_primary_table_rows([result])

    assert result.decision == ValidationDecision.SUCCESS
    assert result.metrics["dga_domain_generated_count"] == 2
    assert result.metrics["dga_query_dispatched_count"] == 2
    assert result.metrics["dga_nxdomain_observed_count"] == 1
    assert result.metrics["dga_resolved_observed_count"] == 1
    assert table[0]["metrics"] == result.metrics
    assert report.traffic_validation[0].metrics == result.metrics


def test_dga_empty_traffic_code_failure():
    store = EventStore(":memory:")
    run_id = "dga_empty"
    store.open_run(run_id)
    _append_lifecycle(store, run_id, "dga")

    loader = PluginLoader()
    registry = loader.discover_and_load()
    result = ValidationEngine(store, registry).validate(run_id, "dga")

    assert result.decision == ValidationDecision.CODE_FAILURE
    assert "SOT_EMPTY_AFTER_EXECUTE" in result.fail_fast_codes
