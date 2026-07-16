"""DGA executor — domain generation and UDP/53 query execution."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from dsp.engine.host_selection import select_hosts_for_capability
from dsp.event_store import Event
from dsp.engine.scenario_engine import RunContext, TargetSet
from dsp.runner.activity_reporter import ActivityReporter
from dsp.protocols.dns import DnsClient, build_dns_events
from dsp.protocols.dns.dga import (
    EFFECTIVE_TLD_DEFAULT,
    PHASE1_COUNT_DEFAULT,
    PHASE2_COUNT_DEFAULT,
    generate_nxdomain_fqdn,
    generate_resolvable_fqdn,
)
from dsp.protocols.dns.dga_events import (
    build_dga_completed_event,
    build_dga_domain_generated_event,
    build_dga_nxdomain_observed_event,
    build_dga_resolved_observed_event,
    build_dga_started_event,
)


def select_dga_resolver(targets: TargetSet, config: dict) -> str | None:
    """Select DNS resolver from discovery dns_hosts bucket (discovery-only)."""
    if config.get("resolver"):
        return str(config["resolver"])
    dns_hosts = select_hosts_for_capability(
        targets,
        config,
        capability="dns_hosts",
        max_hosts=1,
    )
    if dns_hosts:
        return dns_hosts[0]
    return None


def run(
    ctx: RunContext,
    targets: TargetSet,
    config: dict | None = None,
    scenario_id: str = "dga",
) -> None:
    """Execute DGA phases, transmit DNS queries, append events to Event Store."""
    params = config or {}
    effective_tld = str(params.get("effective_tld", EFFECTIVE_TLD_DEFAULT))
    phase1_count = int(params.get("phase1_count", PHASE1_COUNT_DEFAULT))
    phase2_count = int(params.get("phase2_count", PHASE2_COUNT_DEFAULT))
    resolver = select_dga_resolver(targets, params)
    source = "dry_run" if ctx.dry_run else "local"
    if resolver is None:
        ctx.event_store.append(
            Event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                timestamp=datetime.now(timezone.utc),
                stage="executor",
                event="dga_skipped",
                status="info",
                source=source,
                evidence={
                    "reason": "skipped_no_open_service: no dns_hosts from discovery",
                    "skipped_no_open_service": True,
                    "no_dns_hosts": True,
                },
            )
        )
        return

    mode = "mock" if ctx.dry_run else "live"
    client = DnsClient(mode=mode, timeout=0.05)

    sample_domains: list[str] = []
    nx_observed = 0
    resolved_observed = 0
    domains_generated = 0
    t0 = time.monotonic()
    total_domains = phase1_count + phase2_count
    activity = ActivityReporter(ctx, scenario_id, total=total_domains)

    ctx.event_store.append(
        build_dga_started_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=resolver,
            source=source,
            evidence={
                "effective_tld": effective_tld,
                "phase1_count": phase1_count,
                "phase2_count": phase2_count,
                "domains_planned": total_domains,
                "planned_domains": total_domains,
                "mode": mode,
            },
        )
    )

    for phase, count, generator, mock_outcome, phase_name in (
        (1, phase1_count, generate_nxdomain_fqdn, "nxdomain", "nxdomain"),
        (2, phase2_count, generate_resolvable_fqdn, "response", "resolvable"),
    ):
        for seq in range(1, count + 1):
            if ctx.cancelled:
                break

            fqdn = generator(effective_tld)
            if len(sample_domains) < 5:
                sample_domains.append(fqdn)

            gen_evidence = {
                "phase": phase,
                "seq": seq,
                "effective_tld": effective_tld,
                "phase_name": phase_name,
            }
            ctx.event_store.append(
                build_dga_domain_generated_event(
                    run_id=ctx.run_id,
                    scenario_id=scenario_id,
                    target=resolver,
                    fqdn=fqdn,
                    source=source,
                    evidence=gen_evidence,
                )
            )
            domains_generated += 1

            query = client.make_query(resolver, fqdn)
            activity.update(sample_domain=fqdn)
            activity.record(action="send", target=resolver, query=fqdn)
            if mode == "mock":
                result = client.query(resolver, fqdn, mock_outcome=mock_outcome)
            else:
                result = client.query(resolver, fqdn)

            observe_evidence = {
                "phase": phase,
                "seq": seq,
                "effective_tld": effective_tld,
                "outcome": result.outcome,
                "query_id": result.query_id,
            }
            if result.outcome == "nxdomain":
                ctx.event_store.append(
                    build_dga_nxdomain_observed_event(
                        run_id=ctx.run_id,
                        scenario_id=scenario_id,
                        target=resolver,
                        fqdn=fqdn,
                        source=source,
                        evidence=observe_evidence,
                    )
                )
                nx_observed += 1
            elif result.outcome == "response":
                ctx.event_store.append(
                    build_dga_resolved_observed_event(
                        run_id=ctx.run_id,
                        scenario_id=scenario_id,
                        target=resolver,
                        fqdn=fqdn,
                        source=source,
                        evidence=observe_evidence,
                    )
                )
                resolved_observed += 1

            for event in build_dns_events(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                query=query,
                result=result,
                source=source,
                include_created=False,
            ):
                ctx.event_store.append(event)

    activity.emit_final_progress()
    elapsed = round(time.monotonic() - t0, 3)
    ctx.event_store.append(
        build_dga_completed_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=resolver,
            source=source,
            evidence={
                "effective_tld": effective_tld,
                "domains_generated": domains_generated,
                "nxdomain_observed": nx_observed,
                "resolved_observed": resolved_observed,
                "duration_sec": elapsed,
                "sample_domains": sample_domains,
                "resolver": resolver,
            },
        )
    )
