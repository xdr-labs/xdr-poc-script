"""SMB login failure executor — discovery smb_hosts only; no fake auth counts."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from dsp.engine.host_selection import select_hosts_for_capability
from dsp.engine.scenario_engine import RunContext, TargetSet
from dsp.runner.activity_reporter import ActivityReporter
from dsp.event_store import Event
from dsp.protocols.smb import (
    ATTEMPTS_PER_HOST_DEFAULT,
    MAX_HOSTS_DEFAULT,
    SMB_PORT_DEFAULT,
    SmbClient,
    append_outcome_events,
    build_smb_auth_attempt_event,
    build_smb_scenario_completed_event,
    build_smb_scenario_started_event,
    plan_smb_attempts,
)


def select_smb_hosts(targets: TargetSet, config: dict, *, max_hosts: int = MAX_HOSTS_DEFAULT) -> list[str]:
    return select_hosts_for_capability(targets, config, capability="smb_hosts", max_hosts=max_hosts)


def run(
    ctx: RunContext,
    targets: TargetSet,
    config: dict | None = None,
    scenario_id: str = "smb_login_failure",
) -> None:
    """TCP probe SMB port 445 on discovery smb_hosts; skip when none open."""
    params = config or {}
    max_hosts = int(params.get("max_hosts", MAX_HOSTS_DEFAULT))
    attempts_per_host = int(params.get("attempts_per_host", ATTEMPTS_PER_HOST_DEFAULT))
    port = int(params.get("port", SMB_PORT_DEFAULT))
    safe_mode = bool(params.get("safe_mode", True))
    source = "dry_run" if ctx.dry_run else "local"
    mode = "mock" if ctx.dry_run else "live"

    hosts = select_smb_hosts(targets, params, max_hosts=max_hosts)
    if not hosts:
        ActivityReporter(ctx, scenario_id).emit_skipped(
            reason="No SMB service discovered",
            auth_attempts=0,
        )
        ctx.event_store.append(
            Event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                timestamp=datetime.now(timezone.utc),
                stage="executor",
                event="smb_scenario_skipped",
                status="info",
                source=source,
                evidence={
                    "reason": "No SMB service discovered",
                    "skipped_no_open_service": True,
                    "attempts_planned": 0,
                    "tcp_connect_attempts": 0,
                    "auth_attempts": 0,
                    "auth_failed": 0,
                },
            )
        )
        ctx.event_store.append(
            build_smb_scenario_completed_event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                target=targets.target_net,
                source=source,
                evidence={
                    "targets": [],
                    "hosts": [],
                    "port": port,
                    "skipped_no_open_service": True,
                    "attempts_planned": 0,
                    "tcp_connect_attempts": 0,
                    "tcp_connect_open": 0,
                    "tcp_connect_failed": 0,
                    "auth_attempts": 0,
                    "auth_failed": 0,
                    "duration_sec": 0.0,
                },
            )
        )
        return

    client = SmbClient(
        mode=mode,
        timeout=float(params.get("timeout", 10.0)),
        safe_mode=safe_mode,
    )
    plans = plan_smb_attempts(
        hosts,
        max_hosts=max_hosts,
        attempts_per_host=attempts_per_host,
        port=port,
        safe_mode=safe_mode,
    )

    tcp_attempts = 0
    tcp_open = 0
    tcp_failed = 0
    t0 = time.monotonic()
    activity = ActivityReporter(ctx, scenario_id, total=len(plans))

    ctx.event_store.append(
        build_smb_scenario_started_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=hosts[0],
            source=source,
            evidence={
                "hosts": hosts,
                "planned_attempts": len(plans),
                "attempts_planned": len(plans),
                "attempts_per_host": attempts_per_host,
                "port": port,
                "mode": mode,
                "safe_mode": safe_mode,
                "discovery": targets.discovery_enabled,
                "note": "tcp_connect_only_no_smb_auth",
            },
        )
    )

    for seq, plan in enumerate(plans, start=1):
        if ctx.cancelled:
            break

        attempt = client.make_attempt(plan)
        artifact = f"{plan.username}@{plan.host}:{plan.port}"
        attempt_evidence = {
            "seq": seq,
            "host": plan.host,
            "port": plan.port,
            "username": plan.username,
            "password_label": plan.password_label,
            "safe_mode": plan.safe_mode,
            "note": "tcp_connect_only_no_credentials",
        }
        ctx.event_store.append(
            build_smb_auth_attempt_event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                target=plan.host,
                artifact=artifact,
                source=source,
                evidence=attempt_evidence,
            )
        )
        tcp_attempts += 1

        if mode == "mock":
            result = client.attempt(plan, mock_outcome="auth_failed")
        else:
            result = client.attempt(plan)

        for outcome_event in append_outcome_events(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            attempt=attempt,
            result=result,
            source=source,
            password_label=plan.password_label,
        ):
            ctx.event_store.append(outcome_event)

        if result.connection_opened:
            tcp_open += 1
        else:
            tcp_failed += 1

        activity.record(
            action="auth_attempt",
            target=plan.host,
            port=plan.port,
            user=plan.username,
            result=result.outcome,
        )

    activity.emit_final_progress()
    elapsed = round(time.monotonic() - t0, 3)
    ctx.event_store.append(
        build_smb_scenario_completed_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=hosts[0],
            source=source,
            evidence={
                "targets": hosts,
                "hosts": hosts,
                "port": port,
                "attempts_planned": len(plans),
                "tcp_connect_attempts": tcp_attempts,
                "tcp_connect_open": tcp_open,
                "tcp_connect_failed": tcp_failed,
                "auth_attempts": 0,
                "auth_failed": 0,
                "duration_sec": elapsed,
                "safe_mode": safe_mode,
                "note": "tcp_connect_only_no_smb_auth",
            },
        )
    )
