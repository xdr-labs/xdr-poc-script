"""Event Store append helpers for webshell command-only execution."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from dsp.event_store import Event, EventStore
from dsp.execution.remote.command.models import DISCOVERY_ORIGIN_WEBSHELL, EVENT_SOURCE_WEBSHELL


def _now() -> datetime:
    return datetime.now(timezone.utc)


def append_event(
    store: EventStore,
    *,
    run_id: str,
    scenario_id: str,
    event: str,
    status: str,
    evidence: dict[str, Any] | None = None,
    target: str = "",
    artifact: str = "",
    stage: str = "executor",
) -> None:
    store.append(
        Event(
            run_id=run_id,
            scenario_id=scenario_id,
            timestamp=_now(),
            stage=stage,
            event=event,
            status=status,
            target=target,
            artifact=artifact,
            evidence={
                **dict(evidence or {}),
                "origin": DISCOVERY_ORIGIN_WEBSHELL,
                "remote_execution_mode": "command",
            },
            source=EVENT_SOURCE_WEBSHELL,
        )
    )


def append_scenario_lifecycle(
    store: EventStore,
    *,
    run_id: str,
    scenario_id: str,
    event: str,
    evidence: dict[str, Any] | None = None,
) -> None:
    append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event=event,
        status="info",
        evidence=evidence,
        stage="executor",
    )


def append_scenario_skipped(
    store: EventStore,
    *,
    run_id: str,
    scenario_id: str,
    reason: str,
    evidence: dict[str, Any] | None = None,
) -> None:
    payload = {"reason": reason, **dict(evidence or {})}
    append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event=f"{scenario_id}_skipped",
        status="info",
        evidence=payload,
    )
    append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="scenario_skipped",
        status="info",
        evidence=payload,
        stage="prepare",
    )


def append_command_dispatched(
    store: EventStore,
    *,
    run_id: str,
    scenario_id: str,
    command_category: str,
    target: str,
    protocol: str,
    dispatch_status: str,
    evidence: dict[str, Any] | None = None,
    artifact: str = "",
    traffic_event: str | None = None,
    traffic_status: str = "sent",
) -> None:
    base = {
        "command_category": command_category,
        "protocol": protocol,
        "dispatch_status": dispatch_status,
        "origin": DISCOVERY_ORIGIN_WEBSHELL,
        **dict(evidence or {}),
    }
    append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="webshell_command_dispatched",
        status="info",
        target=target,
        artifact=artifact,
        evidence=base,
    )
    if traffic_event:
        append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event=traffic_event,
            status=traffic_status,
            target=target,
            artifact=artifact,
            evidence=base,
        )


def append_discovery_events(
    store: EventStore,
    *,
    run_id: str,
    scenario_id: str,
    target_net: str,
    probe_specs: list[dict[str, Any]],
    dispatch_status: str,
    discovery_result: dict[str, Any] | None = None,
    batch_results: list[tuple[list[dict[str, Any]], set[tuple[str, int]]]] | None = None,
) -> None:
    append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="remote_discovery_started",
        status="info",
        evidence={
            "target_net": target_net,
            "discovery_origin": DISCOVERY_ORIGIN_WEBSHELL,
            "planned_probes": len(probe_specs),
        },
    )
    seq = 0
    if batch_results is not None:
        for batch_specs, open_endpoints in batch_results:
            for spec in batch_specs:
                seq += 1
                _append_discovery_probe_event(
                    store,
                    run_id=run_id,
                    scenario_id=scenario_id,
                    spec=spec,
                    seq=seq,
                    dispatch_status=dispatch_status,
                    open=(str(spec["host"]), int(spec["port"])) in open_endpoints,
                )
    elif dispatch_status == "mock":
        for spec in probe_specs:
            seq += 1
            _append_discovery_probe_event(
                store,
                run_id=run_id,
                scenario_id=scenario_id,
                spec=spec,
                seq=seq,
                dispatch_status=dispatch_status,
                open=False,
            )
    completed_evidence: dict[str, Any] = {
        "target_net": target_net,
        "discovery_origin": DISCOVERY_ORIGIN_WEBSHELL,
        "probes_dispatched": seq or len(probe_specs),
        "planned_only": False,
    }
    if discovery_result is not None:
        completed_evidence.update(
            {
                "alive_hosts": discovery_result.get("alive_hosts", []),
                "open_endpoints": discovery_result.get("open_endpoints", 0),
                "probed_hosts": discovery_result.get("probed_hosts", len(probe_specs)),
                "discovery_method": discovery_result.get("discovery_method"),
                "command_delivery": discovery_result.get("command_delivery"),
                "runner_upload": discovery_result.get("runner_upload"),
                "probe_batches": discovery_result.get("probe_batches"),
                "output_preview": discovery_result.get("first_batch_output_preview"),
                "service_hosts": discovery_result.get("service_hosts"),
                "timed_out_batches": discovery_result.get("timed_out_batches"),
            }
        )
    append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="remote_discovery_completed",
        status="info",
        evidence=completed_evidence,
    )


def _append_discovery_probe_event(
    store: EventStore,
    *,
    run_id: str,
    scenario_id: str,
    spec: dict[str, Any],
    seq: int,
    dispatch_status: str,
    open: bool,
) -> None:
    host = str(spec["host"])
    port = int(spec["port"])
    artifact = f"{host}:{port}"
    append_command_dispatched(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        command_category="discovery_probe",
        target=host,
        protocol="tcp",
        dispatch_status=dispatch_status,
        artifact=artifact,
        traffic_event="port_probe_sent",
        evidence={
            "seq": seq,
            "host": host,
            "port": port,
            "capability": spec.get("capability"),
            "probe_open": open,
        },
    )
    append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="port_connection_failed" if not open else "port_probe_open",
        status="sent",
        target=host,
        artifact=artifact,
        evidence={
            "host": host,
            "port": port,
            "outcome": "open" if open else "closed",
            "origin": DISCOVERY_ORIGIN_WEBSHELL,
        },
    )
