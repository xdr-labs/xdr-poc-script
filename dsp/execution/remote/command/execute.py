"""Execute scenario plans via webshell command dispatch and Event Store append."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from dsp.engine.scenario_engine import RunContext
from dsp.execution.providers.runtime.command import CommandRequest, CommandStatus
from dsp.execution.remote.command import events as cmd_events
from dsp.execution.remote.command.models import DNS_QUERY_METHOD_PYTHON_SOCKET_UDP53
from dsp.execution.remote.command.shell import (
    curl_request_command,
    dns_query_command_evidence,
    dns_tunnel_session_command_evidence,
    host_behavior_shell_command,
    kerberos_attempt_command,
    ldap_action_command,
    mock_noop_command,
    rare_protocol_probe_command,
    smb_probe_command,
    ssh_attempt_command,
    tcp_probe_command,
)
from dsp.execution.remote.models import ScenarioExecutionRequest
from dsp.execution.webshell.event_sync.bundle_content import normalize_webshell_command_output
from dsp.protocols.http.followup_evidence import (
    WEBSHELL_RESPONSE_TRACKING,
    build_dispatch_request_evidence,
    summarize_http_followup_evidence,
)
from dsp.protocols.http.user_agents import URL_SCAN_USER_AGENT_POLICY
from dsp.protocols.http.non_standard_port_burst import burst_connection_success
from dsp.protocols.dns.tunnel import (
    CHUNK_SIZE_DEFAULT,
    MOCK_PAYLOAD_FILENAME,
    PAYLOAD_MB_DEFAULT,
    SEND_INTERVAL_SEC,
    TUNNEL_DOMAIN_DEFAULT,
    compute_dns_tunnel_session_timeout_sec,
    dns_tunnel_query_evidence,
    dns_tunnel_session_script_completed,
    parse_dns_tunnel_session_sent_fqdns,
)

if TYPE_CHECKING:
    from dsp.execution.webshell_provider import WebshellExecutionProvider


DGA_SENT_LINE_PREFIX = "DGA_SENT:"


def _collect_dns_tunnel_marker_output(
    provider: WebshellExecutionProvider,
    marker_path: str,
) -> str:
    """Fetch file-backed DNS tunnel send markers from the remote host."""
    try:
        raw = provider.fetch_remote_file_via_cat(marker_path)
    except Exception:
        return ""
    return normalize_webshell_command_output(raw)


def _resolve_dns_tunnel_sent_fqdns(
    *,
    session_output: str,
    marker_output: str,
    mock: bool,
    target_queries: list[dict[str, Any]],
    dispatch_transport_ok: bool,
) -> frozenset[str]:
    """Merge session stdout and remote marker file into confirmed send FQDNs."""
    if mock:
        if not dispatch_transport_ok:
            return frozenset()
        return frozenset(str(item["fqdn"]) for item in target_queries)

    combined = "\n".join(part for part in (session_output, marker_output) if part)
    return parse_dns_tunnel_session_sent_fqdns(combined)


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


DNS_TUNNEL_LAUNCH_TIMEOUT_SEC = 20.0
DNS_TUNNEL_POLL_TIMEOUT_SEC = 10.0
DNS_TUNNEL_POLL_INTERVAL_SEC = 5.0


def _parse_dga_sent_marker(text: str) -> bool:
    for line in text.splitlines():
        if line.strip().startswith(DGA_SENT_LINE_PREFIX):
            return True
    return False


def execute_command_plan(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    """Dispatch plan commands through webshell and append Event Store evidence."""
    plan_type = str(plan.get("type") or "")
    handlers = {
        "port_sweep": _execute_port_sweep,
        "http_followup": _execute_http_followup,
        "sql_injection": _execute_sql_injection,
        "ssh_failure": _execute_ssh_failure,
        "dns_tunnel": _execute_dns_tunnel,
        "dga": _execute_dga,
        "ldap_enumeration": _execute_ldap_enumeration,
        "smb_login_failure": _execute_smb_login_failure,
        "kerberos_failure": _execute_kerberos_failure,
        "host_behavior_check": _execute_host_behavior_check,
        "rare_protocol_activity": _execute_rare_protocol_activity,
    }
    handler = handlers.get(plan_type)
    if handler is None:
        return 0
    return handler(plan, provider, ctx, request)


def _dispatch(
    provider: WebshellExecutionProvider,
    command: str,
    *,
    timeout_seconds: int = 300,
) -> str:
    result = provider.execute_command(
        CommandRequest.new(command, timeout_seconds=timeout_seconds)
    )
    return str(result.status.value)


def _dispatch_command_result(
    provider: WebshellExecutionProvider,
    command: str,
    *,
    timeout_seconds: int = 300,
):
    return provider.execute_command(
        CommandRequest.new(command, timeout_seconds=timeout_seconds)
    )


def _execute_port_sweep(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    store = ctx.event_store
    run_id = str(request.run_id)
    scenario_id = request.scenario_id
    probes = plan.get("probes") or []
    timeout = float(plan.get("timeout", 3.0))
    mock = plan.get("mode") == "mock"
    first_host = probes[0]["host"] if probes else ""
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="port_sweep_started",
        status="info",
        target=first_host,
        artifact="port_sweep_session",
        evidence={"planned_probes": len(probes), "mode": plan.get("mode", "live")},
    )
    dispatched = 0
    for index, probe in enumerate(probes, start=1):
        host = str(probe["host"])
        port = int(probe["port"])
        artifact = str(probe.get("artifact") or f"{host}:{port}")
        command = mock_noop_command() if mock else tcp_probe_command(host, port, timeout=timeout)
        status = _dispatch(provider, command, timeout_seconds=int(timeout) + 5)
        cmd_events.append_command_dispatched(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            command_category="port_probe",
            target=host,
            protocol="tcp",
            dispatch_status=status,
            artifact=artifact,
            traffic_event="port_probe_sent",
            evidence={"seq": index, "host": host, "port": port},
        )
        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="port_connection_failed",
            status="sent",
            target=host,
            artifact=artifact,
            evidence={"host": host, "port": port, "outcome": "command_dispatched"},
        )
        dispatched += 1
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="port_sweep_completed",
        status="info",
        target=first_host,
        artifact="port_sweep_session",
        evidence={"probe_count": len(probes), "commands_dispatched": dispatched},
    )
    return dispatched


def _plan_selection_fields(plan: dict[str, Any]) -> dict[str, Any]:
    """Extract HTTP endpoint selection metadata attached during planning."""
    keys = (
        "selected_targets",
        "target_count",
        "http_targets",
        "https_targets",
        "selected_http_target_reason",
        "probe_summaries",
        "target_probe",
        "rejected_targets",
        "redirect_only_candidates",
        "https_targets_skipped",
        "hosts",
        "endpoints",
    )
    return {key: plan[key] for key in keys if key in plan}


def _execute_non_standard_port_burst(
    burst_plan: dict[str, Any],
    *,
    provider: WebshellExecutionProvider,
    store: Any,
    run_id: str,
    scenario_id: str,
    primary_target: str,
    timeout: float,
    mock: bool,
) -> tuple[dict[str, Any], int]:
    """Dispatch non-standard port burst commands and append burst lifecycle events."""
    requests = list(burst_plan.get("requests") or [])
    if not burst_plan.get("enabled") or not requests:
        return {"enabled": False}, 0

    ports = list(burst_plan.get("ports") or [])
    targets = list(burst_plan.get("targets") or [])
    t0 = time.monotonic()
    mode = "mock" if mock else "live"

    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="non_standard_port_burst_started",
        status="info",
        target=primary_target,
        artifact="non_standard_port_burst",
        evidence={
            "attempts_planned": len(requests),
            "ports": ports,
            "targets": targets,
            "mode": mode,
        },
    )

    attempts = 0
    successes = 0
    failures = 0
    dispatched = 0

    for item in requests:
        host = str(item["host"])
        port = int(item["port"])
        url = str(item.get("url") or "")
        user_agent = str(item.get("user_agent") or "Mozilla/5.0")
        seq = item.get("seq")
        command = (
            mock_noop_command()
            if mock
            else curl_request_command(url, method="GET", user_agent=user_agent, timeout=timeout)
        )
        dispatch_status = _dispatch(provider, command, timeout_seconds=int(timeout) + 5)
        dispatched += 1

        if mock:
            outcome = "response"
            status_code = 200 if int(seq) % 3 else 404
        elif dispatch_status == "completed":
            outcome = "response"
            status_code = 200
        else:
            outcome = "error"
            status_code = None

        base_evidence = {
            "seq": seq,
            "host": host,
            "port": port,
            "url": url,
            "method": "GET",
            "user_agent": user_agent,
            "discovered": item.get("discovered"),
            "probe": item.get("probe"),
            "outcome": outcome,
            "dispatch_status": dispatch_status,
        }
        if status_code is not None:
            base_evidence["status_code"] = status_code

        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="non_standard_port_connection_attempt",
            status="info",
            target=host,
            artifact="non_standard_port_connection",
            evidence=dict(base_evidence),
        )
        attempts += 1

        if burst_connection_success(outcome, status_code):
            successes += 1
            cmd_events.append_event(
                store,
                run_id=run_id,
                scenario_id=scenario_id,
                event="non_standard_port_connection_success",
                status="info",
                target=host,
                artifact="non_standard_port_connection",
                evidence=dict(base_evidence),
            )
        else:
            failures += 1
            cmd_events.append_event(
                store,
                run_id=run_id,
                scenario_id=scenario_id,
                event="non_standard_port_connection_failure",
                status="error",
                target=host,
                artifact="non_standard_port_connection",
                evidence=dict(base_evidence),
            )

    elapsed = round(time.monotonic() - t0, 3)
    summary = {
        "enabled": True,
        "ports": ports,
        "targets": targets,
        "attempts": attempts,
        "success": successes,
        "failure": failures,
        "duration_sec": elapsed,
    }
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="non_standard_port_burst_completed",
        status="info",
        target=primary_target,
        artifact="non_standard_port_burst",
        evidence=dict(summary),
    )
    return summary, dispatched


def _execute_http_followup(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    store = ctx.event_store
    run_id = str(request.run_id)
    scenario_id = request.scenario_id
    requests_list = plan.get("requests") or []
    timeout = float(plan.get("timeout", 10.0))
    mock = plan.get("mode") == "mock"
    selection_fields = _plan_selection_fields(plan)
    primary_target = ""
    if selection_fields.get("hosts"):
        primary_target = str(selection_fields["hosts"][0])
    elif requests_list:
        primary_target = str(requests_list[0].get("url") or "")
    started_evidence = {
        "requests_planned": len(requests_list),
        "planned_requests": len(requests_list),
        "mode": plan.get("mode", "live"),
        "user_agent_policy": URL_SCAN_USER_AGENT_POLICY,
        **selection_fields,
    }
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="http_followup_started",
        status="info",
        target=primary_target,
        evidence=started_evidence,
    )
    dispatched = 0
    request_evidence: list[dict[str, Any]] = []
    for index, item in enumerate(requests_list, start=1):
        url = str(item["url"])
        method = str(item.get("method") or "GET")
        user_agent = str(item.get("user_agent") or "Mozilla/5.0")
        command = (
            mock_noop_command()
            if mock
            else curl_request_command(url, method=method, user_agent=user_agent, timeout=timeout)
        )
        status = _dispatch(provider, command, timeout_seconds=int(timeout) + 5)
        request_evidence.append(
            build_dispatch_request_evidence(
                url=url,
                method=method,
                user_agent=user_agent,
                dispatch_status=status,
                seq=index,
            )
        )
        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="http_request_created",
            status="info",
            target=url,
            evidence={"seq": index, "url": url, "method": method, "user_agent": user_agent},
        )
        cmd_events.append_command_dispatched(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            command_category="http_request",
            target=url,
            protocol="http",
            dispatch_status=status,
            traffic_event="http_request_sent",
            evidence={"url": url, "method": method, "user_agent": user_agent},
        )
        dispatched += 1
    burst_plan = dict(plan.get("non_standard_port_burst") or {})
    burst_summary, burst_dispatched = _execute_non_standard_port_burst(
        burst_plan,
        provider=provider,
        store=store,
        run_id=run_id,
        scenario_id=scenario_id,
        primary_target=primary_target,
        timeout=timeout,
        mock=mock,
    )
    requests_sent = len(request_evidence)
    dispatched += burst_dispatched
    request_dump, request_dump_summary = summarize_http_followup_evidence(
        request_evidence,
        response_tracking=WEBSHELL_RESPONSE_TRACKING,
    )
    abnormal_user_agents = int(request_dump_summary.get("abnormal_user_agents", 0))
    target_distribution = dict(request_dump_summary.get("target_distribution") or {})
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="http_followup_completed",
        status="info",
        target=primary_target,
        evidence={
            "requests_sent": requests_sent,
            "request_count": requests_sent,
            "request_evidence": request_evidence,
            "request_dump": request_dump,
            "request_dump_summary": request_dump_summary,
            "response_tracking": WEBSHELL_RESPONSE_TRACKING,
            "abnormal_user_agents": abnormal_user_agents,
            "normal_user_agents": int(request_dump_summary.get("normal_user_agents", 0)),
            "abnormal_user_agent_ratio": request_dump_summary.get("abnormal_user_agent_ratio", 0.0),
            "user_agent_policy": URL_SCAN_USER_AGENT_POLICY,
            "target_distribution": target_distribution,
            "target_count": len(target_distribution),
            "per_target_request_count": dict(target_distribution),
            "requests_per_target": dict(target_distribution),
            "expected_url_scan_distribution": dict(target_distribution),
            "non_standard_port_burst": burst_summary,
            **selection_fields,
        },
    )
    return dispatched


def _execute_sql_injection(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    store = ctx.event_store
    run_id = str(request.run_id)
    scenario_id = request.scenario_id
    requests_list = plan.get("requests") or []
    timeout = float(plan.get("timeout", 10.0))
    mock = plan.get("mode") == "mock"
    selection_fields = _plan_selection_fields(plan)
    primary_target = ""
    if selection_fields.get("hosts"):
        primary_target = str(selection_fields["hosts"][0])
    elif requests_list:
        primary_target = str(requests_list[0].get("url") or "")
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="sql_injection_started",
        status="info",
        target=primary_target,
        evidence={
            "requests_planned": len(requests_list),
            "planned_requests": len(requests_list),
            "mode": plan.get("mode", "live"),
            **selection_fields,
        },
    )
    dispatched = 0
    for index, item in enumerate(requests_list, start=1):
        url = str(item["url"])
        method = str(item.get("method") or "GET")
        command = (
            mock_noop_command()
            if mock
            else curl_request_command(
                url,
                method=method,
                timeout=timeout,
                body_b64=item.get("body_b64"),
                content_type=item.get("content_type"),
            )
        )
        status = _dispatch(provider, command, timeout_seconds=int(timeout) + 5)
        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="sql_payload_generated",
            status="info",
            target=url,
            evidence={
                "seq": index,
                "payload_category": item.get("payload_category"),
                "parameter": item.get("parameter"),
            },
        )
        cmd_events.append_command_dispatched(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            command_category="sql_request",
            target=url,
            protocol="http",
            dispatch_status=status,
            traffic_event="sql_request_sent",
            evidence={"url": url, "method": method},
        )
        dispatched += 1
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="sql_injection_completed",
        status="info",
        target=primary_target,
        evidence={
            "requests_sent": dispatched,
            "request_count": dispatched,
            **selection_fields,
        },
    )
    return dispatched


def _execute_ssh_failure(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    store = ctx.event_store
    run_id = str(request.run_id)
    scenario_id = request.scenario_id
    attempts = plan.get("attempts") or []
    timeout = float(plan.get("timeout", 5.0))
    mock = plan.get("mode") == "mock"
    first_host = attempts[0]["host"] if attempts else ""
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="ssh_failure_started",
        status="info",
        target=first_host,
        evidence={"auth_attempts_planned": len(attempts), "mode": plan.get("mode", "live")},
    )
    dispatched = 0
    for index, item in enumerate(attempts, start=1):
        host = str(item["host"])
        port = int(item["port"])
        username = str(item["username"])
        artifact = f"{username}@{host}:{port}"
        command = (
            mock_noop_command()
            if mock
            else ssh_attempt_command(host, port, username, timeout=timeout)
        )
        status = _dispatch(provider, command, timeout_seconds=int(timeout) + 5)
        cmd_events.append_command_dispatched(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            command_category="ssh_auth",
            target=host,
            protocol="ssh",
            dispatch_status=status,
            artifact=artifact,
            traffic_event="ssh_auth_attempt",
            evidence={"seq": index, "username": username, "port": port},
        )
        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="ssh_auth_failed",
            status="auth_failed",
            target=host,
            artifact=artifact,
            evidence={"username": username, "outcome": "command_dispatched"},
        )
        dispatched += 1
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="ssh_failure_completed",
        status="info",
        target=first_host,
        evidence={"auth_attempts": dispatched},
    )
    return dispatched


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
    first_target = str(queries[0]["target"]) if queries else ""

    by_target: dict[str, list[dict[str, Any]]] = {}
    for item in queries:
        by_target.setdefault(str(item["target"]), []).append(item)

    http_dispatches = 0
    command_sample: str | None = None

    for target, target_queries in by_target.items():
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
        dns_method = session_meta["dns_query_method"]
        if command_sample is None:
            command_sample = session_meta["remote_command"]

        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="dns_tunnel_started",
            status="info",
            target=target,
            evidence={
                "planned_chunks": idx_count,
                "mode": plan.get("mode", "live"),
                "dns_query_method": dns_method,
                "execution_mode": session_meta.get("execution_mode", "dns_tunnel_session_detached"),
                "session_id": session_id,
                "target": target,
                "target_selection": plan.get("target_selection", "alive_hosts"),
                "send_interval_sec": send_interval,
                "payload_mb": payload_mb,
                "chunk_size": chunk_size,
                "mock_filename": mock_filename,
            },
        )

        session_artifact = f"dns_tunnel_session:{target}"
        dispatch_payload = {
            **session_meta,
            "target": target,
            "dispatch_phase": "attempt",
            "session_id": session_id,
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
            sent_fqdns = _resolve_dns_tunnel_sent_fqdns(
                session_output=session_output,
                marker_output=marker_output,
                mock=True,
                target_queries=target_queries,
                dispatch_transport_ok=dispatch_transport_ok,
            )
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
            sent_fqdns = frozenset()
            session_script_completed = False
            poll_attempts = 0
            try:
                # Detached launch returns quickly; servlet ~30s envelopes must not host the send loop.
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
            sent_fqdns = _resolve_dns_tunnel_sent_fqdns(
                session_output=session_output,
                marker_output=marker_output,
                mock=False,
                target_queries=target_queries,
                dispatch_transport_ok=dispatch_transport_ok,
            )

        outcome_payload = {
            **dispatch_payload,
            "dispatch_phase": "completed" if dispatch_transport_ok else "failed",
            "dispatch_status": dispatch_status,
            "timeout_seconds": timeout_seconds,
            "dns_tunnel_sendto_success_count": len(sent_fqdns),
            "dns_tunnel_planned_queries": len(target_queries),
            "dns_tunnel_session_script_completed": session_script_completed,
            "dns_tunnel_poll_attempts": poll_attempts,
            "marker_output_path": session_meta["marker_output_path"],
            "execution_mode": session_meta.get("execution_mode", "dns_tunnel_session"),
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
        planned_by_fqdn = {str(item["fqdn"]): item for item in target_queries}
        for fqdn in sorted(sent_fqdns):
            item = planned_by_fqdn.get(
                fqdn,
                {
                    "target": target,
                    "fqdn": fqdn,
                    "query": fqdn,
                    "protocol": "dns_udp",
                    "port": 53,
                },
            )
            traffic_evidence = dns_tunnel_query_evidence(item)
            query_payload = {
                **traffic_evidence,
                **session_meta,
                "session_id": session_id,
                "outcome": "sendto_success",
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

        completed_evidence: dict[str, Any] = {
            "queries_sent": target_query_events,
            "dns_tunnel_query_sent_count": target_query_events,
            "dns_tunnel_chunk_created_count": target_query_events,
            "dns_tunnel_sendto_success_count": len(sent_fqdns),
            "dns_tunnel_planned_queries": len(target_queries),
            "webshell_http_dispatches": http_dispatches,
            "dns_query_method": dns_method,
            "execution_mode": session_meta.get("execution_mode", "dns_tunnel_session_detached"),
            "session_id": session_id,
            "target_selection": plan.get("target_selection", "alive_hosts"),
            "send_interval_sec": send_interval,
            "payload_mb": payload_mb,
            "dns_tunnel_session_script_completed": session_script_completed,
            "dns_tunnel_poll_attempts": poll_attempts,
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


def _execute_dga(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    store = ctx.event_store
    run_id = str(request.run_id)
    scenario_id = request.scenario_id
    domains = plan.get("domains") or []
    timeout = float(plan.get("timeout", 0.05))
    mock = plan.get("mode") == "mock"
    resolver = str(plan.get("resolver") or "")
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="dga_started",
        status="info",
        target=resolver,
        artifact="dga_session",
        evidence={"domains_planned": len(domains), "mode": plan.get("mode", "live")},
    )
    dispatched = 0
    nx_observed = 0
    resolved_observed = 0
    for item in domains:
        fqdn = str(item["fqdn"])
        target = str(item.get("resolver") or resolver)
        query_evidence = dns_query_command_evidence(
            target,
            fqdn,
            timeout=max(timeout, 1.0),
            sent_marker_prefix=DGA_SENT_LINE_PREFIX,
            suppress_errors=False,
        )
        command = (
            mock_noop_command()
            if mock
            else query_evidence["remote_command"]
        )
        dispatch_status = CommandStatus.FAILED.value
        dispatch_transport_ok = False
        command_output = ""
        marker_observed = False
        if mock:
            status = _dispatch(provider, command, timeout_seconds=10)
            dispatch_transport_ok = status == CommandStatus.COMPLETED.value
            dispatch_status = status
            marker_observed = dispatch_transport_ok
        else:
            try:
                raw_output = provider.run_remote_command(
                    command,
                    timeout_seconds=float(10),
                )
                dispatch_transport_ok = True
                dispatch_status = CommandStatus.COMPLETED.value
                command_output = raw_output.decode("utf-8", errors="replace")
                marker_observed = _parse_dga_sent_marker(command_output)
            except Exception as exc:
                command_output = str(exc)
        phase_name = str(item.get("phase_name") or "")
        domain_evidence = {
            "phase": item.get("phase"),
            "seq": item.get("seq"),
            "phase_name": phase_name,
            **query_evidence,
        }
        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="dga_domain_generated",
            status="info",
            target=target,
            artifact=fqdn,
            evidence=domain_evidence,
        )
        cmd_events.append_command_dispatched(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            command_category="dga_query",
            target=target,
            protocol="dns",
            dispatch_status=dispatch_status,
            artifact=fqdn,
            traffic_event=None,
            evidence={
                **domain_evidence,
                "dispatch_transport_ok": dispatch_transport_ok,
                "dga_sent_marker_observed": marker_observed,
                **(
                    {"command_output_preview": command_output[:500]}
                    if command_output and not marker_observed
                    else {}
                ),
            },
        )
        if not marker_observed:
            dispatched += 1
            continue
        if phase_name == "nxdomain":
            cmd_events.append_event(
                store,
                run_id=run_id,
                scenario_id=scenario_id,
                event="dga_nxdomain_observed",
                status="nxdomain",
                target=target,
                artifact=fqdn,
                evidence={**domain_evidence, "outcome": "command_dispatched"},
            )
            nx_observed += 1
        else:
            cmd_events.append_event(
                store,
                run_id=run_id,
                scenario_id=scenario_id,
                event="dga_resolved_observed",
                status="response",
                target=target,
                artifact=fqdn,
                evidence={**domain_evidence, "outcome": "command_dispatched"},
            )
            resolved_observed += 1
        dispatched += 1
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="dga_completed",
        status="info",
        target=resolver,
        artifact="dga_session",
        evidence={
            "domains_generated": dispatched,
            "nxdomain_observed": nx_observed,
            "resolved_observed": resolved_observed,
            "dns_query_method": DNS_QUERY_METHOD_PYTHON_SOCKET_UDP53,
        },
    )
    return dispatched


def _execute_ldap_enumeration(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    store = ctx.event_store
    run_id = str(request.run_id)
    scenario_id = request.scenario_id
    actions = plan.get("actions") or []
    timeout = float(plan.get("timeout", 5.0))
    mock = plan.get("mode") == "mock"
    first_host = actions[0]["host"] if actions else ""
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="ldap_enum_started",
        status="info",
        target=first_host,
        evidence={"planned_actions": len(actions), "mode": plan.get("mode", "live")},
    )
    dispatched = 0
    for index, item in enumerate(actions, start=1):
        host = str(item["host"])
        port = int(item["port"])
        action_type = str(item["action_type"])
        command = (
            mock_noop_command()
            if mock
            else ldap_action_command(
                host,
                port,
                action_type,
                search_filter=str(item.get("search_filter") or ""),
                timeout=timeout,
            )
        )
        status = _dispatch(provider, command, timeout_seconds=int(timeout) + 5)
        event_map = {
            "connection": "ldap_connection_attempt",
            "bind": "ldap_bind_attempt",
            "search": "ldap_search_attempt",
        }
        cmd_events.append_command_dispatched(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            command_category=f"ldap_{action_type}",
            target=host,
            protocol="ldap",
            dispatch_status=status,
            artifact=f"{host}:{port}:{action_type}",
            traffic_event=event_map.get(action_type, "ldap_connection_attempt"),
            evidence={"seq": index, "action_type": action_type, "port": port},
        )
        dispatched += 1
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="ldap_enum_completed",
        status="info",
        target=first_host,
        evidence={"actions_dispatched": dispatched},
    )
    return dispatched


def _execute_smb_login_failure(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    store = ctx.event_store
    run_id = str(request.run_id)
    scenario_id = request.scenario_id
    attempts = plan.get("attempts") or []
    timeout = float(plan.get("timeout", 5.0))
    mock = plan.get("mode") == "mock"
    first_host = attempts[0]["host"] if attempts else ""
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="smb_scenario_started",
        status="info",
        target=first_host,
        evidence={"attempts_planned": len(attempts), "mode": plan.get("mode", "live")},
    )
    dispatched = 0
    for index, item in enumerate(attempts, start=1):
        host = str(item["host"])
        port = int(item["port"])
        username = str(item["username"])
        artifact = f"{username}@{host}:{port}"
        command = mock_noop_command() if mock else smb_probe_command(host, port, timeout=timeout)
        status = _dispatch(provider, command, timeout_seconds=int(timeout) + 5)
        cmd_events.append_command_dispatched(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            command_category="smb_auth",
            target=host,
            protocol="smb",
            dispatch_status=status,
            artifact=artifact,
            traffic_event="smb_auth_attempt",
            evidence={"seq": index, "username": username, "port": port},
        )
        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="smb_auth_failed",
            status="auth_failed",
            target=host,
            artifact=artifact,
            evidence={"username": username, "outcome": "command_dispatched"},
        )
        dispatched += 1
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="smb_scenario_completed",
        status="info",
        target=first_host,
        evidence={"auth_attempts": dispatched},
    )
    return dispatched


def _execute_kerberos_failure(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    store = ctx.event_store
    run_id = str(request.run_id)
    scenario_id = request.scenario_id
    attempts = plan.get("attempts") or []
    timeout = float(plan.get("timeout", 10.0))
    mock = plan.get("mode") == "mock"
    first_host = attempts[0]["host"] if attempts else ""
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="kerberos_scenario_started",
        status="info",
        target=first_host,
        evidence={"attempts_planned": len(attempts), "mode": plan.get("mode", "live")},
    )
    dispatched = 0
    for index, item in enumerate(attempts, start=1):
        host = str(item["host"])
        port = int(item["port"])
        username = str(item["username"])
        realm = str(item.get("realm") or plan.get("realm") or "LOCAL.REALM")
        artifact = f"{username}@{realm}@{host}:{port}"
        command = (
            mock_noop_command()
            if mock
            else kerberos_attempt_command(host, port, username, realm, timeout=timeout)
        )
        status = _dispatch(provider, command, timeout_seconds=int(timeout) + 5)
        cmd_events.append_command_dispatched(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            command_category="kerberos_auth",
            target=host,
            protocol="kerberos",
            dispatch_status=status,
            artifact=artifact,
            traffic_event="kerberos_auth_attempt",
            evidence={"seq": index, "username": username, "realm": realm},
        )
        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="kerberos_auth_failed",
            status="auth_failed",
            target=host,
            artifact=artifact,
            evidence={"username": username, "outcome": "command_dispatched"},
        )
        dispatched += 1
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="kerberos_scenario_completed",
        status="info",
        target=first_host,
        evidence={"auth_attempts": dispatched},
    )
    return dispatched


def _execute_host_behavior_check(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    from dsp.protocols.host.behavior_executor import execute_host_behavior_plan

    store = ctx.event_store
    run_id = str(request.run_id)
    scenario_id = request.scenario_id
    target = plan.get("target_host")
    if not target:
        return 0
    timeout = float(plan.get("timeout", 30.0))
    mock = plan.get("mode") == "mock"

    def _dispatch_shell(shell: str) -> None:
        command = mock_noop_command() if mock else host_behavior_shell_command(shell)
        _dispatch(provider, command, timeout_seconds=int(timeout))

    completed = execute_host_behavior_plan(
        store,
        plan,
        run_id=run_id,
        scenario_id=scenario_id,
        source="remote",
        run_shell=None if mock else _dispatch_shell,
        timeout=timeout,
    )
    return int(completed.get("commands_dispatched", 0))


def _execute_rare_protocol_activity(
    plan: dict[str, Any],
    provider: WebshellExecutionProvider,
    ctx: RunContext,
    request: ScenarioExecutionRequest,
) -> int:
    store = ctx.event_store
    run_id = str(request.run_id)
    scenario_id = request.scenario_id
    if plan.get("mode") == "skip":
        cmd_events.append_scenario_skipped(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            reason=str(plan.get("reason") or "no_probe_plans"),
        )
        return 0
    probes = plan.get("probes") or []
    timeout = float(plan.get("timeout", 3.0))
    mock = plan.get("mode") == "mock"
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="rare_protocol_activity_started",
        status="info",
        evidence={"probes_planned": len(probes), "mode": plan.get("mode", "live")},
    )
    dispatched = 0
    attempt_count = 0
    for index, probe in enumerate(probes, start=1):
        host = str(probe["host"])
        port = int(probe["port"])
        protocol = str(probe.get("protocol") or "tcp")
        command = (
            mock_noop_command()
            if mock
            else rare_protocol_probe_command(host, port, protocol)
        )
        status = _dispatch(provider, command, timeout_seconds=int(timeout) + 5)
        probe_evidence = {
            "seq": index,
            "port": port,
            "transport": probe.get("transport"),
            "protocol": protocol,
            "remote_command": command if not mock else "true",
        }
        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="rare_protocol_probe_attempt",
            status="sent",
            target=host,
            artifact=str(probe.get("artifact") or f"{host}:{port}"),
            evidence=probe_evidence,
        )
        attempt_count += 1
        cmd_events.append_command_dispatched(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            command_category="rare_protocol",
            target=host,
            protocol=protocol,
            dispatch_status=status,
            artifact=str(probe.get("artifact") or f"{host}:{port}"),
            traffic_event=None,
            evidence=probe_evidence,
        )
        cmd_events.append_event(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="rare_protocol_probe_failure",
            status="connection_refused",
            target=host,
            artifact=str(probe.get("artifact") or f"{host}:{port}"),
            evidence={**probe_evidence, "outcome": "command_dispatched"},
        )
        dispatched += 1
    cmd_events.append_event(
        store,
        run_id=run_id,
        scenario_id=scenario_id,
        event="rare_protocol_activity_completed",
        status="info",
        evidence={
            "probes_dispatched": dispatched,
            "attempt_count": attempt_count,
            "failure_count": attempt_count,
        },
    )
    return dispatched
