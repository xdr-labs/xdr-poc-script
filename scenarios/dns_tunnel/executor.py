"""DNS Tunnel executor — chunk generation, FQDN encoding, UDP/53 transmission."""

from __future__ import annotations

import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dsp.engine.scenario_engine import RunContext, TargetSet
from dsp.event_store import Event
from dsp.runner.activity_reporter import ActivityReporter
from dsp.protocols.dns import DnsClient, build_dns_events
from dsp.protocols.dns.tunnel import (
    MOCK_PAYLOAD_FILENAME,
    PAYLOAD_MB_DEFAULT,
    RECV_TIMEOUT_SEC,
    SEND_INTERVAL_SEC,
    TUNNEL_DOMAIN_DEFAULT,
    CHUNK_SIZE_DEFAULT,
    DnsTunnelTransmitter,
    dns_tunnel_query_evidence,
    plan_dns_tunnel,
    select_tunnel_targets,
    write_mock_payload_file,
)
from dsp.protocols.dns.tunnel_events import (
    build_tunnel_chunk_created_event,
    build_tunnel_completed_event,
    build_tunnel_query_sent_event,
    build_tunnel_started_event,
)
from dsp.protocols.dns.volume_profiles import apply_volume_profile


def run(
    ctx: RunContext,
    targets: TargetSet,
    config: dict | None = None,
    scenario_id: str = "dns_tunnel",
) -> None:
    """Generate tunnel chunks, transmit DNS queries, append events to Event Store."""
    params = apply_volume_profile(config or {}, dry_run=ctx.dry_run)
    plan = plan_dns_tunnel(targets, params, dry_run=ctx.dry_run)
    source = "dry_run" if ctx.dry_run else "local"
    if plan.get("mode") == "skip":
        reason = str(plan.get("reason") or "no_alive_hosts")
        ActivityReporter(ctx, scenario_id).emit_skipped(reason=reason)
        skip_evidence = {
            "reason": reason,
            "skip_reason": "No eligible target",
        }
        ctx.event_store.append(
            Event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                timestamp=datetime.now(timezone.utc),
                stage="executor",
                event="dns_tunnel_skipped",
                status="info",
                source=source,
                evidence=skip_evidence,
            )
        )
        ctx.event_store.append(
            Event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                timestamp=datetime.now(timezone.utc),
                stage="executor",
                event="scenario_skipped",
                status="info",
                source=source,
                evidence=skip_evidence,
            )
        )
        return

    payload_mb = float(plan.get("payload_mb", PAYLOAD_MB_DEFAULT))
    chunk_size = int(plan.get("chunk_size", CHUNK_SIZE_DEFAULT))
    domain = str(plan.get("domain", TUNNEL_DOMAIN_DEFAULT))
    mock_filename = str(plan.get("mock_filename", MOCK_PAYLOAD_FILENAME))
    send_interval = float(plan.get("send_interval_sec", SEND_INTERVAL_SEC))
    timeout = float(plan.get("timeout", RECV_TIMEOUT_SEC))
    mode = "mock" if ctx.dry_run else "live"
    client = DnsClient(mode=mode, timeout=timeout)
    provider = str(getattr(ctx, "execution_provider", None) or source)

    host_targets = select_tunnel_targets(targets, params, max_hosts=int(params.get("max_hosts", 1)))
    session_id = str(plan.get("session_id") or uuid.uuid4().hex[:6])
    queries = list(plan.get("queries") or [])
    sample_fqdns: list[str] = []
    unique_subdomains: set[str] = set()

    with tempfile.TemporaryDirectory(prefix="dsp-dns-tunnel-") as tmpdir:
        payload_path = write_mock_payload_file(
            Path(tmpdir) / mock_filename,
            payload_mb,
        )

        for target in host_targets:
            if ctx.cancelled:
                break

            target_queries = [q for q in queries if q["target"] == target]
            planned_queries = len(target_queries)
            planned_data = sum(
                1 for q in target_queries if q.get("query_role", "idx_chunk") == "idx_chunk"
            )
            session_start_n = sum(
                1 for q in target_queries if q.get("query_role") == "session_start"
            )
            session_end_n = sum(
                1 for q in target_queries if q.get("query_role") == "session_end"
            )
            payload_bytes = int(payload_mb * 1024 * 1024)
            start_time = datetime.now(timezone.utc)
            started_evidence = {
                "session_id": session_id,
                "payload_mb": payload_mb,
                "payload_bytes": payload_bytes,
                "chunk_size": chunk_size,
                "domain": domain,
                "planned_chunks": planned_data,
                "planned_data_queries": planned_data,
                "session_start_queries": session_start_n,
                "session_end_queries": session_end_n,
                "planned_queries": planned_queries,
                "total_planned_queries": planned_queries,
                "target_dns_server": target,
                "target_port": 53,
                "source_host": str(getattr(ctx, "source_host", "") or ""),
                "provider": provider,
                "start_time": start_time.isoformat().replace("+00:00", "Z"),
                "mock_payload_file": str(payload_path.name),
                "send_interval_sec": send_interval,
                "mode": mode,
            }
            ctx.event_store.append(
                build_tunnel_started_event(
                    run_id=ctx.run_id,
                    scenario_id=scenario_id,
                    target=target,
                    source=source,
                    evidence=started_evidence,
                )
            )

            chunks_sent = 0
            queries_dispatched = 0
            bytes_encoded = 0
            t0 = time.monotonic()
            activity = ActivityReporter(ctx, scenario_id, total=max(1, planned_queries))
            transmitter = DnsTunnelTransmitter(
                client,
                target,
                send_interval=send_interval,
            )

            for item in target_queries:
                if ctx.cancelled:
                    break
                fqdn = str(item["fqdn"])
                query_role = str(item.get("query_role") or "idx_chunk")
                seq = item.get("seq")
                unique_subdomains.add(fqdn.split(".", 1)[0] if "." in fqdn else fqdn)

                if query_role == "idx_chunk" and len(sample_fqdns) < 3:
                    sample_fqdns.append(fqdn)

                chunk_evidence = dns_tunnel_query_evidence(item)
                chunk_evidence.update(
                    {
                        "session_id": session_id,
                        "domain": domain,
                        "query_role": query_role,
                    }
                )
                if seq is not None:
                    chunk_evidence["seq"] = seq

                ctx.event_store.append(
                    build_tunnel_chunk_created_event(
                        run_id=ctx.run_id,
                        scenario_id=scenario_id,
                        target=target,
                        fqdn=fqdn,
                        source=source,
                        evidence=chunk_evidence,
                    )
                )

                query = client.make_query(target, fqdn)
                activity.update(target=target, sample_query=fqdn)
                activity.record(action="send", target=target, query=fqdn)
                result = transmitter.send(fqdn)

                query_evidence = dns_tunnel_query_evidence(item)
                query_evidence.update(
                    {
                        "session_id": session_id,
                        "qtype": query.qtype,
                        "query_id": result.query_id,
                        "outcome": result.outcome,
                    }
                )
                if result.evidence.get("bytes_sent") is not None:
                    query_evidence["bytes_sent"] = result.evidence["bytes_sent"]
                if result.outcome != "sent":
                    continue
                queries_dispatched += 1
                ctx.event_store.append(
                    build_tunnel_query_sent_event(
                        run_id=ctx.run_id,
                        scenario_id=scenario_id,
                        target=target,
                        fqdn=fqdn,
                        source=source,
                        evidence=query_evidence,
                    )
                )

                for event in build_dns_events(
                    run_id=ctx.run_id,
                    scenario_id=scenario_id,
                    query=query,
                    result=result,
                    source=source,
                    include_created=False,
                ):
                    ctx.event_store.append(event)

                if query_role == "idx_chunk":
                    chunks_sent += 1
                    bytes_encoded += int(item.get("chunk_bytes") or 0)

            activity.emit_final_progress()
            end_time = datetime.now(timezone.utc)
            elapsed = round(time.monotonic() - t0, 3)
            qps = round(queries_dispatched / elapsed, 3) if elapsed > 0 else 0.0
            completed_evidence = {
                "session_id": session_id,
                "chunks_sent": chunks_sent,
                "bytes_encoded": bytes_encoded,
                "payload_bytes": payload_bytes,
                "chunk_size": chunk_size,
                "planned_data_queries": planned_data,
                "session_start_queries": session_start_n,
                "session_end_queries": session_end_n,
                "planned_queries": planned_queries,
                "total_planned_queries": planned_queries,
                "dispatched_queries": queries_dispatched,
                "observed_queries": queries_dispatched,
                "queries_sent": queries_dispatched,
                "dns_tunnel_chunk_created_count": planned_queries,
                "target_dns_server": target,
                "target_port": 53,
                "source_host": str(getattr(ctx, "source_host", "") or ""),
                "provider": provider,
                "start_time": start_time.isoformat().replace("+00:00", "Z"),
                "end_time": end_time.isoformat().replace("+00:00", "Z"),
                "duration_sec": elapsed,
                "duration": elapsed,
                "queries_per_second": qps,
                "unique_subdomains": len(unique_subdomains),
                "targets": host_targets,
                "sample_fqdns": sample_fqdns,
                "domain": domain,
                "send_interval_sec": send_interval,
                "mock_payload_file": mock_filename,
            }
            ctx.event_store.append(
                build_tunnel_completed_event(
                    run_id=ctx.run_id,
                    scenario_id=scenario_id,
                    target=target,
                    source=source,
                    evidence=completed_evidence,
                )
            )
