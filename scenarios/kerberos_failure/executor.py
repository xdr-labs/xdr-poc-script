"""Kerberos failure executor — planned auth-failure attempts."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from dsp.engine.host_selection import select_hosts_for_capability
from dsp.engine.scenario_engine import RunContext, TargetSet
from dsp.event_store import Event
from dsp.runner.activity_reporter import ActivityReporter
from dsp.protocols.kerberos import (
    ATTEMPTS_PER_HOST_DEFAULT,
    DEFAULT_REALM,
    KERBEROS_PORT_DEFAULT,
    MAX_HOSTS_DEFAULT,
    KerberosClient,
    append_outcome_events,
    build_kerberos_auth_attempt_event,
    build_kerberos_connection_attempt_event,
    build_kerberos_scenario_completed_event,
    build_kerberos_scenario_started_event,
    plan_kerberos_attempts,
)


def select_kerberos_hosts(
    targets: TargetSet,
    config: dict,
    *,
    max_hosts: int = MAX_HOSTS_DEFAULT,
) -> list[str]:
    """Select Kerberos targets from discovery kerberos_hosts bucket."""
    return select_hosts_for_capability(
        targets,
        config,
        capability="kerberos_hosts",
        max_hosts=max_hosts,
    )


def run(
    ctx: RunContext,
    targets: TargetSet,
    config: dict | None = None,
    scenario_id: str = "kerberos_failure",
) -> None:
    """Plan and execute Kerberos auth-failure attempts; append events to Event Store."""
    params = config or {}
    max_hosts = int(params.get("max_hosts", MAX_HOSTS_DEFAULT))
    attempts_per_host = int(params.get("attempts_per_host", ATTEMPTS_PER_HOST_DEFAULT))
    port = int(params.get("port", KERBEROS_PORT_DEFAULT))
    realm = str(params.get("realm", DEFAULT_REALM))
    safe_mode = bool(params.get("safe_mode", True))
    source = "dry_run" if ctx.dry_run else "local"
    mode = "mock" if ctx.dry_run else "live"
    client = KerberosClient(
        mode=mode,
        timeout=float(params.get("timeout", 10.0)),
        safe_mode=safe_mode,
    )

    hosts = select_kerberos_hosts(targets, params, max_hosts=max_hosts)
    if not hosts:
        # Discovery-first: empty kerberos_hosts bucket => skip (do not abort).
        ActivityReporter(ctx, scenario_id).emit_skipped(reason="no_kerberos_hosts")
        ctx.event_store.append(
            Event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                timestamp=datetime.now(timezone.utc),
                stage="executor",
                event="kerberos_failure_skipped",
                status="info",
                source=source,
                evidence={
                    "reason": "skipped_no_open_service: no kerberos_hosts from discovery",
                    "skipped_no_open_service": True,
                    "hosts": [],
                    "port": port,
                    "attempt_count": 0,
                    "failure_count": 0,
                },
            )
        )
        ctx.event_store.append(
            build_kerberos_scenario_completed_event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                target=targets.target_net,
                source=source,
                evidence={
                    "targets": [],
                    "hosts": [],
                    "port": port,
                    "realm": realm,
                    "attempt_count": 0,
                    "failure_count": 0,
                    "duration_sec": 0.0,
                    "sample_usernames": [],
                    "safe_mode": safe_mode,
                    "skipped_no_open_service": True,
                },
            )
        )
        return

    plans = plan_kerberos_attempts(
        hosts,
        max_hosts=max_hosts,
        attempts_per_host=attempts_per_host,
        port=port,
        realm=realm,
        safe_mode=safe_mode,
    )

    sample_usernames: list[str] = []
    attempt_count = 0
    failure_count = 0
    t0 = time.monotonic()
    activity = ActivityReporter(ctx, scenario_id, total=len(plans))

    ctx.event_store.append(
        build_kerberos_scenario_started_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=hosts[0],
            source=source,
            evidence={
                "hosts": hosts,
                "planned_attempts": len(plans),
                "attempts_per_host": attempts_per_host,
                "port": port,
                "realm": realm,
                "mode": mode,
                "safe_mode": safe_mode,
            },
        )
    )

    for seq, plan in enumerate(plans, start=1):
        if ctx.cancelled:
            break

        attempt = client.make_attempt(plan)
        artifact = f"{plan.username}@{plan.realm}@{plan.host}:{plan.port}"
        if plan.username not in sample_usernames and len(sample_usernames) < 5:
            sample_usernames.append(plan.username)

        attempt_evidence = {
            "seq": seq,
            "host": plan.host,
            "port": plan.port,
            "username": plan.username,
            "realm": plan.realm,
            "safe_mode": plan.safe_mode,
        }

        ctx.event_store.append(
            build_kerberos_connection_attempt_event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                target=plan.host,
                artifact=artifact,
                source=source,
                evidence=attempt_evidence,
            )
        )

        ctx.event_store.append(
            build_kerberos_auth_attempt_event(
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

        for outcome_event in append_outcome_events(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            attempt=attempt,
            result=result,
            source=source,
        ):
            ctx.event_store.append(outcome_event)

        if result.outcome == "auth_failed":
            failure_count += 1

        activity.record(
            action="auth_attempt",
            target=plan.host,
            user=plan.username,
            result=result.outcome,
        )

    activity.emit_final_progress()
    elapsed = round(time.monotonic() - t0, 3)
    ctx.event_store.append(
        build_kerberos_scenario_completed_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=hosts[0],
            source=source,
            evidence={
                "targets": hosts,
                "hosts": hosts,
                "port": port,
                "realm": realm,
                "attempt_count": attempt_count,
                "failure_count": failure_count,
                "duration_sec": elapsed,
                "sample_usernames": sample_usernames,
                "safe_mode": safe_mode,
            },
        )
    )
