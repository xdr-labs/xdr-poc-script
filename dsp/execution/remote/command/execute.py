"""DNS Tunnel command execution — webshell detached session + Event Store metrics.

Metric contract (Source of Truth = DSP plan + session completion, NOT stdout markers):

  planned_queries
      = len(target_queries) from plan_dns_tunnel (idx + session markers)

  dispatched_queries
      = planned_queries when the remote session was successfully launched
        (HTTP/command transport OK)

  observed_queries
      = planned_queries when SESSION_DONE is confirmed via poll/marker file;
        those planned FQDNs are recorded as dns_tunnel_query_sent

DNS_TUNNEL_SENT stdout/file lines are debug-only and must not gate Event Store.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from dsp.engine.scenario_engine import RunContext
from dsp.execution.providers.runtime.command import CommandRequest, CommandStatus
from dsp.execution.remote.command import events as cmd_events
from dsp.execution.remote.command.models import DNS_QUERY_METHOD_PYTHON_SOCKET_UDP53
from dsp.execution.remote.command.shell import (
    dns_tunnel_session_command_evidence,
    mock_noop_command,
)
from dsp.execution.remote.models import ScenarioExecutionRequest
from dsp.execution.webshell.event_sync.bundle_content import normalize_webshell_command_output
from dsp.protocols.dns.tunnel import (
    CHUNK_SIZE_DEFAULT,
    MOCK_PAYLOAD_FILENAME,
    PAYLOAD_MB_DEFAULT,
    SEND_INTERVAL_SEC,
    TUNNEL_DOMAIN_DEFAULT,
    compute_dns_tunnel_session_timeout_sec,
    dns_tunnel_query_evidence,
    dns_tunnel_session_script_completed,
)

if TYPE_CHECKING:
    from dsp.execution.webshell_provider import WebshellExecutionProvider

DNS_TUNNEL_LAUNCH_TIMEOUT_SEC = 20.0
DNS_TUNNEL_POLL_TIMEOUT_SEC = 10.0
DNS_TUNNEL_POLL_INTERVAL_SEC = 5.0


def _collect_dns_tunnel_marker_output(
    provider: WebshellExecutionProvider,
    marker_path: str,
) -> str:
    """Fetch remote marker file (SESSION_DONE / optional SENT lines)."""
    try:
        raw = provider.fetch_remote_file_via_cat(marker_path)
    except Exception:
        return ""
    return normalize_webshell_command_output(raw)


def _dns_tunnel_session_completed(session_output: str, marker_output: str) -> bool:
    combined = "\n".join(part for part in (session_output, marker_output) if part)
    return dns_tunnel_session_script_completed(combined)


def _dns_tunnel_poll_reports_done(poll_output: str) -> bool:
    """True when remote ``grep -c SESSION_DONE`` reports a positive count."""
    for token in normalize_webshell_command_output(poll_output).split():
        try:
            if int(token) > 0:
                return True
        except ValueError:
            continue
    return False


def _dispatch(
    provider: WebshellExecutionProvider,
    command: str,
    *,
    timeout_seconds: float,
) -> str:
    result = provider.execute_command(
        CommandRequest(command=command),
        timeout_seconds=int(max(1, timeout_seconds)),
    )
    return result.status.value


def execute_command_plan(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    """Execute a command plan; currently DNS Tunnel only."""
    plan_type = str(plan.get("type") or "")
    if plan_type != "dns_tunnel":
        return 0
    return _execute_dns_tunnel(plan, provider, ctx, request)


def _execute_dns_tunnel(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    store = ctx.event_store
    run_id = str(request.run_id)
    scenario_id = request.scenario_id
    queries = plan.get("queries") or []
    mock = plan.get("mode") == "mock"
    payload_mb = float(plan.get("payload_mb", PAYLOAD_MB_DEFAULT))
    chunk_size = int(plan.get("chunk_size", CHUNK_SIZE_DEFAULT))
    domain = str(plan.get("domain", TUNNEL_DOMAIN_DEFAULT))
    mock_filename = str(plan.get("mock_filename", MOCK_PAYLOAD_FILENAME))
    send_interval = float(plan.get("send_interval_sec", SEND_INTERVAL_SEC))
    session_id = plan.get("session_id")
    max_chunks = plan.get("max_chunks")

    by_target: dict[str, list[dict[str, Any]]] = {}
    for item in queries:
        by_target.setdefault(str(item["target"]), []).append(item)

    http_dispatches = 0
    command_sample: str | None = None
    t0 = time.monotonic()

    for target, target_queries in by_target.items():
        planned_queries = len(target_queries)
        idx_count = sum(
            1 for q in target_queries if q.get("query_role", "idx_chunk") == "idx_chunk"
        )
        session_meta = dns_tunnel_session_command_evidence(
            target,
            payload_mb=payload_mb,
            chunk_size=chunk_size,
            domain=domain,
            mock_filename=mock_filename,
            send_interval=send_interval,
            suppress_errors=False,
            max_chunks=int(max_chunks) if max_chunks is not None else None,
            run_id=run_id,
        )
        dns_method = session_meta.get("dns_query_method", DNS_QUERY_METHOD_PYTHON_SOCKET_UDP53)
        if command_sample is None:
            command_sample = session_meta["remote_command"]

        payload_bytes = int(payload_mb * 1024 * 1024)
        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="dns_tunnel_started",
            status="info",
            target=target,
            evidence={
                "planned_chunks": idx_count,
                "planned_queries": planned_queries,
                "payload_bytes": payload_bytes,
                "payload_mb": payload_mb,
                "chunk_size": chunk_size,
                "mode": plan.get("mode", "live"),
                "dns_query_method": dns_method,
                "execution_mode": session_meta.get("execution_mode", "dns_tunnel_session_detached"),
                "session_id": session_id,
                "target": target,
                "target_dns_server": target,
                "target_port": 53,
                "target_selection": plan.get("target_selection", "alive_hosts"),
                "send_interval_sec": send_interval,
                "mock_filename": mock_filename,
            },
        )

        session_artifact = f"dns_tunnel_session:{target}"
        dispatch_payload = {
            **session_meta,
            "target": target,
            "dispatch_phase": "attempt",
            "session_id": session_id,
            "planned_queries": planned_queries,
        }
        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="dns_tunnel_dispatch_attempt",
            status="info",
            target=target,
            artifact=session_artifact,
            evidence=dispatch_payload,
        )

        if mock:
            command = mock_noop_command()
            timeout_seconds = 30
            poll_attempts = 0
            session_script_completed = True
            dispatch_status = _dispatch(provider, command, timeout_seconds=timeout_seconds)
            dispatch_transport_ok = dispatch_status == CommandStatus.COMPLETED.value
            session_output = ""
            marker_output = ""
        else:
            command = session_meta["remote_command"]
            poll_command = str(session_meta.get("poll_done_command") or "")
            timeout_seconds = compute_dns_tunnel_session_timeout_sec(
                payload_mb,
                chunk_size,
                send_interval,
                max_chunks=int(max_chunks) if max_chunks is not None else None,
            )
            dispatch_status = CommandStatus.FAILED.value
            dispatch_transport_ok = False
            session_output = ""
            marker_output = ""
            session_script_completed = False
            poll_attempts = 0
            try:
                raw_output = provider.run_remote_command(
                    command,
                    timeout_seconds=DNS_TUNNEL_LAUNCH_TIMEOUT_SEC,
                )
                dispatch_transport_ok = True
                dispatch_status = CommandStatus.COMPLETED.value
                session_output = normalize_webshell_command_output(raw_output)
            except Exception as exc:
                session_output = str(exc)

            if dispatch_transport_ok and poll_command:
                deadline = time.monotonic() + float(timeout_seconds)
                while time.monotonic() < deadline:
                    poll_attempts += 1
                    try:
                        poll_raw = provider.run_remote_command(
                            poll_command,
                            timeout_seconds=DNS_TUNNEL_POLL_TIMEOUT_SEC,
                        )
                        poll_text = normalize_webshell_command_output(poll_raw)
                        session_output = f"{session_output}\n{poll_text}".strip()
                        if _dns_tunnel_poll_reports_done(poll_text):
                            session_script_completed = True
                            break
                    except StopIteration:
                        break
                    except Exception as exc:
                        session_output = f"{session_output}\npoll_error:{exc}".strip()
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    time.sleep(min(DNS_TUNNEL_POLL_INTERVAL_SEC, max(0.0, remaining)))

            marker_output = _collect_dns_tunnel_marker_output(
                provider,
                session_meta["marker_output_path"],
            )
            if not session_script_completed:
                session_script_completed = _dns_tunnel_session_completed(
                    session_output,
                    marker_output,
                )

        # Metric SoT: DSP plan + session completion — not DNS_TUNNEL_SENT lines.
        dispatched_queries = planned_queries if dispatch_transport_ok else 0
        observed_queries = planned_queries if (dispatch_transport_ok and session_script_completed) else 0

        outcome_payload = {
            **dispatch_payload,
            "dispatch_phase": "completed" if dispatch_transport_ok else "failed",
            "dispatch_status": dispatch_status,
            "timeout_seconds": timeout_seconds,
            "planned_queries": planned_queries,
            "dispatched_queries": dispatched_queries,
            "observed_queries": observed_queries,
            "dns_tunnel_planned_queries": planned_queries,
            "dns_tunnel_session_script_completed": session_script_completed,
            "dns_tunnel_poll_attempts": poll_attempts,
            "marker_output_path": session_meta["marker_output_path"],
            "execution_mode": session_meta.get("execution_mode", "dns_tunnel_session"),
            "metric_source": "dsp_plan_session_done",
        }
        if session_output:
            outcome_payload["session_output_preview"] = session_output[:500]
        if marker_output:
            outcome_payload["marker_output_preview"] = marker_output[:500]
        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="dns_tunnel_dispatch_completed" if dispatch_transport_ok else "dns_tunnel_dispatch_failed",
            status="info" if dispatch_transport_ok else "error",
            target=target,
            artifact=session_artifact,
            evidence=outcome_payload,
        )
        cmd_events.append_command_dispatched(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            command_category="dns_tunnel_session",
            target=target,
            protocol="dns_udp",
            dispatch_status=dispatch_status,
            artifact=session_artifact,
            traffic_event="dns_tunnel_session_started",
            evidence={**outcome_payload, "remote_command": command},
        )
        http_dispatches += 1

        target_query_events = 0
        if observed_queries > 0:
            for item in target_queries:
                fqdn = str(item["fqdn"])
                traffic_evidence = dns_tunnel_query_evidence(item)
                query_payload = {
                    **traffic_evidence,
                    **session_meta,
                    "session_id": session_id,
                    "outcome": "dispatched",
                    "metric_kind": "observed",
                    "dispatch_status": dispatch_status,
                }
                cmd_events.append_event(
                    store,
                    run_id=run_id,
                    scenario_id=scenario_id,
                    event="dns_tunnel_chunk_created",
                    status="info",
                    target=target,
                    artifact=fqdn,
                    evidence=query_payload,
                )
                cmd_events.append_event(
                    store,
                    run_id=run_id,
                    scenario_id=scenario_id,
                    event="dns_tunnel_query_sent",
                    status="sent",
                    target=target,
                    artifact=fqdn,
                    evidence=query_payload,
                )
                target_query_events += 1

        duration_sec = round(time.monotonic() - t0, 3)
        qps = round(target_query_events / duration_sec, 3) if duration_sec > 0 else 0.0
        completed_evidence: dict[str, Any] = {
            "queries_sent": target_query_events,
            "planned_queries": planned_queries,
            "dispatched_queries": dispatched_queries,
            "observed_queries": observed_queries,
            "dns_tunnel_query_sent_count": target_query_events,
            "dns_tunnel_chunk_created_count": target_query_events,
            "dns_tunnel_planned_queries": planned_queries,
            "payload_bytes": payload_bytes,
            "webshell_http_dispatches": http_dispatches,
            "dns_query_method": dns_method,
            "execution_mode": session_meta.get("execution_mode", "dns_tunnel_session_detached"),
            "session_id": session_id,
            "target_dns_server": target,
            "target_port": 53,
            "target_selection": plan.get("target_selection", "alive_hosts"),
            "send_interval_sec": send_interval,
            "payload_mb": payload_mb,
            "duration_sec": duration_sec,
            "queries_per_second": qps,
            "dns_tunnel_session_script_completed": session_script_completed,
            "dns_tunnel_poll_attempts": poll_attempts,
            "metric_source": "dsp_plan_session_done",
        }
        if command_sample:
            completed_evidence["remote_command_sample"] = command_sample
        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="dns_tunnel_completed",
            status="info",
            target=target,
            evidence=completed_evidence,
        )

    return http_dispatches
