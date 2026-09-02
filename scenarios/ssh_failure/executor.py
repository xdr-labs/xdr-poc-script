"""SSH login failure executor — discovery ssh_hosts + invaliduser burst."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from dsp.engine.host_selection import select_hosts_for_capability
from dsp.engine.scenario_engine import RunContext, TargetSet
from dsp.runner.activity_reporter import ActivityReporter
from dsp.event_store import Event
from dsp.protocols.ssh import (
    MAX_ATTEMPTS_PER_HOST_DEFAULT,
    MAX_ATTEMPTS_TOTAL_DEFAULT,
    MAX_HOSTS_DEFAULT,
    SSH_PORT_DEFAULT,
    SshClient,
    append_outcome_event,
    build_ssh_auth_attempt_event,
    build_ssh_failure_completed_event,
    build_ssh_failure_started_event,
    plan_ssh_attempts,
)


def select_ssh_hosts(targets: TargetSet, config: dict, *, max_hosts: int = MAX_HOSTS_DEFAULT) -> list[str]:
    return select_hosts_for_capability(targets, config, capability="ssh_hosts", max_hosts=max_hosts)


def run(
    ctx: RunContext,
    targets: TargetSet,
    config: dict | None = None,
    scenario_id: str = "ssh_failure",
) -> None:
    """Plan and execute SSH auth-failure attempts; append events to Event Store."""
    params = config or {}
    max_hosts = int(params.get("max_hosts", MAX_HOSTS_DEFAULT))
    max_per_host = int(params.get("max_per_host", MAX_ATTEMPTS_PER_HOST_DEFAULT))
    max_total = int(params.get("max_total", MAX_ATTEMPTS_TOTAL_DEFAULT))
    port = int(params.get("port", SSH_PORT_DEFAULT))
    source = "dry_run" if ctx.dry_run else "local"
    mode = "mock" if ctx.dry_run else "live"
    client = SshClient(mode=mode, timeout=float(params.get("timeout", 5.0)))

    hosts = select_ssh_hosts(targets, params, max_hosts=max_hosts)
    if not hosts:
        ctx.event_store.append(
            Event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                timestamp=datetime.now(timezone.utc),
                stage="executor",
                event="ssh_failure_skipped",
                status="info",
                source=source,
                evidence={
                    "reason": "No SSH service discovered",
                    "skipped_no_open_service": True,
                    "auth_attempts_planned": 0,
                    "auth_attempts": 0,
                },
            )
        )
        return

    plans = plan_ssh_attempts(
        hosts,
        max_hosts=max_hosts,
        max_per_host=max_per_host,
        max_total=max_total,
        port=port,
    )

    sample_usernames: list[str] = []
    attempt_count = 0
    failure_count = 0
    timeout_count = 0
    t0 = time.monotonic()
    activity = ActivityReporter(ctx, scenario_id, total=len(plans))

    ctx.event_store.append(
        build_ssh_failure_started_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=hosts[0],
            source=source,
            evidence={
                "hosts": hosts,
                "planned_attempts": len(plans),
                "auth_attempts_planned": len(plans),
                "max_total": max_total,
                "port": port,
                "mode": mode,
                "discovery": targets.discovery_enabled,
            },
        )
    )

    for seq, plan in enumerate(plans, start=1):
        if ctx.cancelled:
            break

        attempt = client.make_attempt(plan)
        artifact = f"{plan.username}@{plan.host}:{plan.port}"
        if plan.username not in sample_usernames and len(sample_usernames) < 5:
            sample_usernames.append(plan.username)

        attempt_evidence = {
            "seq": seq,
            "host": plan.host,
            "port": plan.port,
            "username": plan.username,
            "password_label": plan.password_label,
        }
        ctx.event_store.append(
            build_ssh_auth_attempt_event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                target=plan.host,
                artifact=artifact,
                source=source,
                evidence=attempt_evidence,
            )
        )
        attempt_count += 1

        if mode == "mock":
            result = client.attempt(plan, mock_outcome="auth_failed")
        else:
            result = client.attempt(plan)

        ctx.event_store.append(
            append_outcome_event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                attempt=attempt,
                result=result,
                source=source,
                password_label=plan.password_label,
            )
        )
        if result.outcome == "auth_failed":
            failure_count += 1
        elif result.outcome == "timeout":
            timeout_count += 1

        activity.update(auth_failed=failure_count, timeouts=timeout_count)
        activity.record(
            action="auth_attempt",
            target=plan.host,
            username=plan.username,
            result=result.outcome,
        )

    activity.emit_final_progress()
    elapsed = round(time.monotonic() - t0, 3)
    ctx.event_store.append(
        build_ssh_failure_completed_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=hosts[0],
            source=source,
            evidence={
                "targets": hosts,
                "port": port,
                "attempt_count": attempt_count,
                "auth_attempts": attempt_count,
                "failure_count": failure_count,
                "auth_failed": failure_count,
                "timeouts": timeout_count,
                "duration_sec": elapsed,
                "sample_usernames": sample_usernames,
            },
        )
    )
