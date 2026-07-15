"""Port sweep executor — planned TCP connection probes."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from dsp.engine.scenario_engine import RunContext, ScenarioSkipError, TargetSet
from dsp.protocols.recon import (
    DEFAULT_PORTS,
    MAX_HOSTS_DEFAULT,
    MAX_PORTS_DEFAULT,
    PortSweepClient,
    PlannedPortProbe,
    append_outcome_events,
    build_port_probe_sent_event,
    build_port_sweep_completed_event,
    build_port_sweep_skipped_event,
    build_port_sweep_started_event,
    plan_port_sweep,
)
from dsp.protocols.types import PortProbeResult
from dsp.runner.activity_reporter import ActivityReporter
from dsp.runtime.scenario_plan import select_port_sweep_hosts as _select_port_sweep_hosts

# stellar_poc.sh / fast-safe FALLBACK_SCAN_PARALLELISM
DEFAULT_CONCURRENCY = 32


def select_port_sweep_hosts(
    targets: TargetSet,
    config: dict,
    *,
    max_hosts: int = MAX_HOSTS_DEFAULT,
) -> list[str]:
    """Select hosts for horizontal sweep — provider-independent planning."""
    hosts, _reason = _select_port_sweep_hosts(targets, config, max_hosts=max_hosts)
    return hosts


def _resolve_ports(config: dict, max_ports: int) -> tuple[int, ...]:
    raw = config.get("ports")
    if raw is None:
        return DEFAULT_PORTS[:max_ports]
    return tuple(int(p) for p in raw)[:max_ports]


def _run_probe(
    *,
    plan: PlannedPortProbe,
    client: PortSweepClient,
    mode: str,
) -> PortProbeResult:
    if mode == "mock":
        return client.probe(plan, mock_outcome="connection_refused")
    return client.probe(plan)


def run(
    ctx: RunContext,
    targets: TargetSet,
    config: dict | None = None,
    scenario_id: str = "port_sweep",
) -> None:
    """Plan and execute port sweep probes; append events to Event Store."""
    params = config or {}
    max_hosts = int(params.get("max_hosts", MAX_HOSTS_DEFAULT))
    max_ports = int(params.get("max_ports", MAX_PORTS_DEFAULT))
    safe_mode = bool(params.get("safe_mode", True))
    concurrency = max(1, int(params.get("concurrency", DEFAULT_CONCURRENCY)))
    source = "dry_run" if ctx.dry_run else "local"
    mode = "mock" if ctx.dry_run else "live"
    client = PortSweepClient(
        mode=mode,
        timeout=float(params.get("timeout", 3.0)),
        safe_mode=safe_mode,
    )

    hosts, selection_reason = _select_port_sweep_hosts(targets, params, max_hosts=max_hosts)
    if not hosts or selection_reason == "no_alive_hosts":
        reason = "no_alive_hosts"
        ctx.event_store.append(
            build_port_sweep_skipped_event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                source=source,
                evidence={
                    "reason": reason,
                    "selection_reason": selection_reason,
                    "hosts": [],
                    "discovery": targets.discovery_enabled,
                },
            )
        )
        raise ScenarioSkipError(reason)

    ports = _resolve_ports(params, max_ports)
    plans = plan_port_sweep(
        hosts,
        max_hosts=max_hosts,
        ports=ports,
        max_ports=max_ports,
        safe_mode=safe_mode,
    )

    probe_count = 0
    success_count = 0
    failure_count = 0
    t0 = time.monotonic()

    ctx.event_store.append(
        build_port_sweep_started_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=hosts[0],
            source=source,
            evidence={
                "hosts": hosts,
                "ports": list(ports),
                "planned_probes": len(plans),
                "probes_planned": len(plans),
                "max_ports": max_ports,
                "concurrency": concurrency,
                "mode": mode,
                "safe_mode": safe_mode,
                "discovery": targets.discovery_enabled,
                "selection_reason": selection_reason,
            },
        )
    )

    activity = ActivityReporter(ctx, scenario_id, total=len(plans))
    worker_count = min(concurrency, len(plans)) if plans else 1
    pending = list(enumerate(plans, start=1))
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        future_map = {
            pool.submit(_run_probe, plan=plan, client=client, mode=mode): (seq, plan)
            for seq, plan in pending
        }
        for future in as_completed(future_map):
            if ctx.cancelled:
                break
            seq, plan = future_map[future]
            try:
                result = future.result()
            except Exception:
                result = PortProbeResult(
                    host=plan.host,
                    port=plan.port,
                    outcome="error",
                    probe_id="error",
                    dry_run=mode == "mock",
                    connection_opened=False,
                    evidence={"host": plan.host, "port": plan.port},
                )

            probe = client.make_probe(plan)
            artifact = plan.artifact
            probe_evidence = {
                "seq": seq,
                "host": plan.host,
                "port": plan.port,
                "safe_mode": plan.safe_mode,
            }
            ctx.event_store.append(
                build_port_probe_sent_event(
                    run_id=ctx.run_id,
                    scenario_id=scenario_id,
                    target=plan.host,
                    artifact=artifact,
                    source=source,
                    evidence=probe_evidence,
                )
            )
            probe_count += 1

            for outcome_event in append_outcome_events(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                probe=probe,
                result=result,
                source=source,
            ):
                ctx.event_store.append(outcome_event)

            if result.connection_opened:
                success_count += 1
                activity.emit_open(target=plan.host, port=plan.port)
            else:
                failure_count += 1

            activity.update(
                open=success_count,
                failed=failure_count,
                current=f"{plan.host}:{plan.port}",
            )
            activity.record(
                action="probe",
                target=plan.host,
                port=plan.port,
                result=result.outcome,
            )

    activity.emit_final_progress()
    elapsed = round(time.monotonic() - t0, 3)
    probes_per_second = round(probe_count / elapsed, 2) if elapsed > 0 else 0.0
    ctx.event_store.append(
        build_port_sweep_completed_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=hosts[0],
            source=source,
            evidence={
                "targets": hosts,
                "hosts": hosts,
                "ports": list(ports),
                "probe_count": probe_count,
                "probes_sent": probe_count,
                "connection_success_count": success_count,
                "connections_open": success_count,
                "connection_failure_count": failure_count,
                "duration_sec": elapsed,
                "concurrency": concurrency,
                "probes_per_second": probes_per_second,
                "safe_mode": safe_mode,
                "selection_reason": selection_reason,
            },
        )
    )
