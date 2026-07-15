"""DNS Tunnel executor — chunk generation, FQDN encoding, UDP/53 transmission."""

from __future__ import annotations

import tempfile
import time
import uuid
from pathlib import Path

from dsp.engine.scenario_engine import RunContext, TargetSet
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
    if plan.get("mode") == "skip":
        return

    payload_mb = float(plan.get("payload_mb", PAYLOAD_MB_DEFAULT))
    chunk_size = int(plan.get("chunk_size", CHUNK_SIZE_DEFAULT))
    domain = str(plan.get("domain", TUNNEL_DOMAIN_DEFAULT))
    mock_filename = str(plan.get("mock_filename", MOCK_PAYLOAD_FILENAME))
    send_interval = float(plan.get("send_interval_sec", SEND_INTERVAL_SEC))
    timeout = float(plan.get("timeout", RECV_TIMEOUT_SEC))
    source = "dry_run" if ctx.dry_run else "local"
    mode = "mock" if ctx.dry_run else "live"
    client = DnsClient(mode=mode, timeout=timeout)

    host_targets = select_tunnel_targets(targets, params, max_hosts=int(params.get("max_hosts", 1)))
    session_id = str(plan.get("session_id") or uuid.uuid4().hex[:6])
    queries = list(plan.get("queries") or [])
    idx_queries = [q for q in queries if q.get("query_role", "idx_chunk") == "idx_chunk"]
    total_planned = len(idx_queries)
    sample_fqdns: list[str] = []

    with tempfile.TemporaryDirectory(prefix="dsp-dns-tunnel-") as tmpdir:
        payload_path = write_mock_payload_file(
            Path(tmpdir) / mock_filename,
            payload_mb,
        )

        for target in host_targets:
            if ctx.cancelled:
                break

            target_queries = [q for q in queries if q["target"] == target]
            started_evidence = {
                "session_id": session_id,
                "payload_mb": payload_mb,
                "chunk_size": chunk_size,
                "domain": domain,
                "planned_chunks": total_planned,
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
            bytes_encoded = 0
            t0 = time.monotonic()
            activity = ActivityReporter(ctx, scenario_id, total=total_planned)
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
            elapsed = round(time.monotonic() - t0, 3)
            completed_evidence = {
                "session_id": session_id,
                "chunks_sent": chunks_sent,
                "bytes_encoded": bytes_encoded,
                "duration_sec": elapsed,
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
