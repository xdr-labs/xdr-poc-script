"""Port sweep event definitions and Event Store mapping."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from dsp.event_store import Event
from dsp.protocols.types import PortProbe, PortProbeResult

PORT_SWEEP_STARTED = "port_sweep_started"
PORT_PROBE_SENT = "port_probe_sent"
PORT_CONNECTION_OPENED = "port_connection_opened"
PORT_CONNECTION_FAILED = "port_connection_failed"
PORT_SWEEP_COMPLETED = "port_sweep_completed"
PORT_SWEEP_SKIPPED = "port_sweep_skipped"

PORT_SWEEP_TRAFFIC_EVENTS = frozenset(
    {
        PORT_PROBE_SENT,
        PORT_CONNECTION_OPENED,
        PORT_CONNECTION_FAILED,
    }
)

CONNECTION_ERROR_STATUSES = frozenset({"error", "timeout", "connection_refused"})


def build_port_sweep_started_event(
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    source: str,
    evidence: dict[str, Any],
) -> Event:
    return Event(
        run_id=run_id,
        scenario_id=scenario_id,
        timestamp=datetime.now(timezone.utc),
        stage="executor",
        event=PORT_SWEEP_STARTED,
        status="info",
        target=target,
        artifact="port_sweep_session",
        evidence=dict(evidence),
        source=source,
    )


def build_port_sweep_skipped_event(
    *,
    run_id: str,
    scenario_id: str,
    source: str,
    evidence: dict[str, Any],
) -> Event:
    return Event(
        run_id=run_id,
        scenario_id=scenario_id,
        timestamp=datetime.now(timezone.utc),
        stage="executor",
        event=PORT_SWEEP_SKIPPED,
        status="info",
        artifact="port_sweep_session",
        evidence=dict(evidence),
        source=source,
    )


def build_port_probe_sent_event(
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    artifact: str,
    source: str,
    evidence: dict[str, Any],
) -> Event:
    return Event(
        run_id=run_id,
        scenario_id=scenario_id,
        timestamp=datetime.now(timezone.utc),
        stage="executor",
        event=PORT_PROBE_SENT,
        status="sent",
        target=target,
        artifact=artifact,
        evidence=dict(evidence),
        source=source,
    )


def build_port_connection_opened_event(
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    artifact: str,
    source: str,
    evidence: dict[str, Any],
) -> Event:
    return Event(
        run_id=run_id,
        scenario_id=scenario_id,
        timestamp=datetime.now(timezone.utc),
        stage="executor",
        event=PORT_CONNECTION_OPENED,
        status="sent",
        target=target,
        artifact=artifact,
        evidence=dict(evidence),
        source=source,
    )


def build_port_connection_failed_event(
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    artifact: str,
    source: str,
    evidence: dict[str, Any],
    status: str = "connection_refused",
) -> Event:
    return Event(
        run_id=run_id,
        scenario_id=scenario_id,
        timestamp=datetime.now(timezone.utc),
        stage="executor",
        event=PORT_CONNECTION_FAILED,
        status=status,
        target=target,
        artifact=artifact,
        evidence=dict(evidence),
        source=source,
    )


def build_port_sweep_completed_event(
    *,
    run_id: str,
    scenario_id: str,
    target: str,
    source: str,
    evidence: dict[str, Any],
) -> Event:
    return Event(
        run_id=run_id,
        scenario_id=scenario_id,
        timestamp=datetime.now(timezone.utc),
        stage="executor",
        event=PORT_SWEEP_COMPLETED,
        status="info",
        target=target,
        artifact="port_sweep_session",
        evidence=dict(evidence),
        source=source,
    )


def append_outcome_events(
    *,
    run_id: str,
    scenario_id: str,
    probe: PortProbe,
    result: PortProbeResult,
    source: str,
) -> list[Event]:
    """Build connection outcome events from a port probe result."""
    events: list[Event] = []
    base_evidence: dict[str, Any] = {
        "host": probe.host,
        "port": probe.port,
        "probe_id": result.probe_id,
        "outcome": result.outcome,
        "dry_run": result.dry_run,
        "safe_mode": probe.safe_mode,
    }
    if result.evidence:
        base_evidence.update(result.evidence)

    artifact = f"{probe.host}:{probe.port}"

    if result.connection_opened:
        events.append(
            build_port_connection_opened_event(
                run_id=run_id,
                scenario_id=scenario_id,
                target=probe.host,
                artifact=artifact,
                source=source,
                evidence=dict(base_evidence),
            )
        )
    else:
        status = result.outcome if result.outcome in CONNECTION_ERROR_STATUSES else "error"
        events.append(
            build_port_connection_failed_event(
                run_id=run_id,
                scenario_id=scenario_id,
                target=probe.host,
                artifact=artifact,
                source=source,
                evidence=dict(base_evidence),
                status=status,
            )
        )

    return events
