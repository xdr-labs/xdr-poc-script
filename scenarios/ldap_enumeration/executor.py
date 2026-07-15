"""LDAP enumeration executor — planned safe bind/search attempts."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from dsp.engine.host_selection import select_hosts_for_capability
from dsp.engine.scenario_engine import RunContext, TargetSet
from dsp.event_store import Event
from dsp.runner.activity_reporter import ActivityReporter
from dsp.protocols.ldap import (
    DEFAULT_SAFE_FILTERS,
    LDAP_PORT_DEFAULT,
    MAX_HOSTS_DEFAULT,
    MAX_QUERIES_PER_HOST_DEFAULT,
    LdapClient,
    append_outcome_events,
    build_attempt_event,
    build_ldap_enum_completed_event,
    build_ldap_enum_started_event,
    plan_ldap_enumeration,
)


def select_ldap_hosts(
    targets: TargetSet,
    config: dict,
    *,
    max_hosts: int = MAX_HOSTS_DEFAULT,
) -> list[str]:
    """Select LDAP targets from discovery ldap_hosts bucket."""
    return select_hosts_for_capability(
        targets,
        config,
        capability="ldap_hosts",
        max_hosts=max_hosts,
    )


def _resolve_ports(config: dict) -> tuple[int, ...]:
    raw = config.get("ports")
    if raw is None:
        return (LDAP_PORT_DEFAULT,)
    return tuple(int(p) for p in raw)


def run(
    ctx: RunContext,
    targets: TargetSet,
    config: dict | None = None,
    scenario_id: str = "ldap_enumeration",
) -> None:
    """Plan and execute LDAP enumeration actions; append events to Event Store."""
    params = config or {}
    max_hosts = int(params.get("max_hosts", MAX_HOSTS_DEFAULT))
    max_queries = int(params.get("max_queries_per_host", MAX_QUERIES_PER_HOST_DEFAULT))
    safe_mode = bool(params.get("safe_mode", True))
    source = "dry_run" if ctx.dry_run else "local"
    mode = "mock" if ctx.dry_run else "live"
    client = LdapClient(
        mode=mode,
        timeout=float(params.get("timeout", 5.0)),
        safe_mode=safe_mode,
    )

    hosts = select_ldap_hosts(targets, params, max_hosts=max_hosts)
    ports = _resolve_ports(params)
    if not hosts:
        # Discovery-first: empty ldap_hosts bucket => skip (do not abort).
        ActivityReporter(ctx, scenario_id).emit_skipped(reason="no_ldap_hosts")
        ctx.event_store.append(
            Event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                timestamp=datetime.now(timezone.utc),
                stage="executor",
                event="ldap_enumeration_skipped",
                status="info",
                source=source,
                evidence={
                    "reason": "skipped_no_open_service: no ldap_hosts from discovery",
                    "skipped_no_open_service": True,
                    "hosts": [],
                    "ports": list(ports),
                    "connection_attempt_count": 0,
                    "bind_attempt_count": 0,
                    "search_attempt_count": 0,
                },
            )
        )
        ctx.event_store.append(
            build_ldap_enum_completed_event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                target=targets.target_net,
                source=source,
                evidence={
                    "targets": [],
                    "hosts": [],
                    "ports": list(ports),
                    "connection_attempt_count": 0,
                    "bind_attempt_count": 0,
                    "search_attempt_count": 0,
                    "sample_filters": [],
                    "duration_sec": 0.0,
                    "safe_mode": safe_mode,
                    "skipped_no_open_service": True,
                },
            )
        )
        return

    plans = plan_ldap_enumeration(
        hosts,
        max_hosts=max_hosts,
        max_queries_per_host=max_queries,
        ports=ports,
        safe_mode=safe_mode,
    )

    connection_count = 0
    bind_count = 0
    search_count = 0
    sample_filters: list[str] = []
    t0 = time.monotonic()
    activity = ActivityReporter(ctx, scenario_id, total=len(plans))

    ctx.event_store.append(
        build_ldap_enum_started_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=hosts[0],
            source=source,
            evidence={
                "hosts": hosts,
                "ports": list(ports),
                "planned_actions": len(plans),
                "max_queries_per_host": max_queries,
                "mode": mode,
                "safe_mode": safe_mode,
            },
        )
    )

    for seq, plan in enumerate(plans, start=1):
        if ctx.cancelled:
            break

        action = client.make_action(plan)
        attempt_evidence = {
            "seq": seq,
            "host": plan.host,
            "port": plan.port,
            "action_type": plan.action_type,
            "safe_mode": plan.safe_mode,
        }
        if plan.search_filter:
            attempt_evidence["filter"] = plan.search_filter
            if plan.search_filter not in sample_filters and len(sample_filters) < 4:
                sample_filters.append(plan.search_filter)

        ctx.event_store.append(
            build_attempt_event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                action=action,
                source=source,
                evidence=attempt_evidence,
            )
        )

        if plan.action_type == "connection":
            connection_count += 1
        elif plan.action_type == "bind":
            bind_count += 1
        elif plan.action_type == "search":
            search_count += 1

        if mode == "mock":
            mock_outcome = None
            if plan.action_type == "bind":
                mock_outcome = "auth_failed"
            elif plan.action_type == "search":
                mock_outcome = "error"
            result = client.execute(plan, mock_outcome=mock_outcome)
        else:
            result = client.execute(plan)

        if plan.action_type == "bind":
            activity.record(
                action="bind_attempt",
                target=plan.host,
                user="administrator",
                result=result.outcome,
            )
        elif plan.action_type == "search":
            activity.record(
                action="search",
                target=plan.host,
                result=result.outcome,
            )

        for outcome_event in append_outcome_events(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            action=action,
            result=result,
            source=source,
        ):
            ctx.event_store.append(outcome_event)

    activity.emit_final_progress()
    elapsed = round(time.monotonic() - t0, 3)
    ctx.event_store.append(
        build_ldap_enum_completed_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=hosts[0],
            source=source,
            evidence={
                "targets": hosts,
                "hosts": hosts,
                "ports": list(ports),
                "connection_attempt_count": connection_count,
                "bind_attempt_count": bind_count,
                "search_attempt_count": search_count,
                "sample_filters": sample_filters or list(DEFAULT_SAFE_FILTERS[:4]),
                "duration_sec": elapsed,
                "safe_mode": safe_mode,
            },
        )
    )
