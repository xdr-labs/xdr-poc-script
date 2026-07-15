"""SQL injection executor — planned payload URLs and HTTP requests."""

from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from typing import Any

from dsp.engine.host_selection import (
    HttpFollowupSelection,
    SKIP_REASON_HTTP_TARGETS_NOT_FOUND,
    format_selected_target_labels,
    resolve_http_endpoint_selection,
)
from dsp.engine.scenario_engine import RunContext, ScenarioSkipError, TargetSet
from dsp.event_store import Event
from dsp.protocols.http import HttpClient
from dsp.protocols.http.sqli_events import (
    append_sqli_outcome_event,
    build_sql_injection_completed_event,
    build_sql_injection_started_event,
    build_sql_payload_generated_event,
    build_sql_request_sent_event,
)
from dsp.protocols.http.sqli_payloads import (
    SQLI_PAYLOAD_CATEGORIES,
    SQLI_REQUESTS_PER_HOST,
    plan_sqli_requests,
)
from dsp.protocols.http.urls import (
    MAX_HOSTS_DEFAULT,
)
from dsp.protocols.types import HttpRequest


def select_sqli_endpoints(
    targets: TargetSet,
    config: dict,
    *,
    max_hosts: int,
    dry_run: bool = False,
    timeout: float = 10.0,
) -> HttpFollowupSelection:
    """Select HTTP-only endpoints that respond, using probe scoring when available."""
    return resolve_http_endpoint_selection(
        targets,
        config,
        max_hosts=max_hosts,
        dry_run=dry_run,
        timeout=timeout,
    )


def select_sqli_endpoint_targets(
    targets: TargetSet,
    config: dict,
    *,
    max_hosts: int = MAX_HOSTS_DEFAULT,
) -> list[str]:
    """Return host:port labels for selected SQLi HTTP endpoints."""
    selection = resolve_http_endpoint_selection(
        targets, config, max_hosts=max_hosts, dry_run=False, timeout=10.0
    )
    if not selection.selected:
        return []
    return [f"{ep.host}:{ep.port}" for ep in selection.selected]


def select_sqli_hosts(
    targets: TargetSet,
    config: dict,
    *,
    max_hosts: int = MAX_HOSTS_DEFAULT,
) -> list[str]:
    """Return host IPs for progress output — mirrors executor endpoint selection."""
    return [
        target.split(":", 1)[0]
        for target in select_sqli_endpoint_targets(targets, config, max_hosts=max_hosts)
    ]


def _emit_sqli_skipped(
    ctx: RunContext,
    *,
    reason: str,
    source: str,
    https_targets_skipped: list[str] | None = None,
    probe_summaries: list[dict[str, int | str | bool]] | None = None,
    rejected_targets: list[str] | None = None,
    selected_targets: list[str] | None = None,
) -> None:
    from datetime import datetime, timezone

    ctx.event_store.append(
        Event(
            run_id=ctx.run_id,
            scenario_id="sql_injection",
            timestamp=datetime.now(timezone.utc),
            stage="executor",
            event="sql_injection_skipped",
            status="info",
            source=source,
            evidence={
                "hosts": [],
                "reason": reason,
                "http_targets_not_found": reason == "HTTP_TARGETS_NOT_FOUND",
                "https_targets_skipped": https_targets_skipped or [],
                "requests_planned": 0,
                "requests_sent": 0,
                "probe_summaries": probe_summaries or [],
                "target_probe": probe_summaries or [],
                "rejected_targets": rejected_targets or [],
                "selected_targets": selected_targets or [],
            },
        )
    )


def _run_dir_from_store(ctx: RunContext) -> Path | None:
    db_path = getattr(ctx.event_store, "_db_path", ":memory:")
    if db_path == ":memory:":
        return None
    return Path(db_path).parent


def _write_sqli_request_log(ctx: RunContext, records: list[dict[str, Any]]) -> Path | None:
    run_dir = _run_dir_from_store(ctx)
    if run_dir is None:
        return None
    out_path = run_dir / "sql_injection_requests.jsonl"
    with out_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    return out_path


def _write_sqli_wire_evidence_log(ctx: RunContext, records: list[dict[str, Any]]) -> Path | None:
    run_dir = _run_dir_from_store(ctx)
    if run_dir is None:
        return None
    from dsp.protocols.http.wire_evidence import write_wire_evidence_jsonl

    out_path = run_dir / "sql_wire_evidence.jsonl"
    return write_wire_evidence_jsonl(out_path, records)


def _make_http_request(plan) -> HttpRequest:
    path = plan.path if not plan.query else f"{plan.path}?{plan.query}"
    headers: dict[str, str] = {"User-Agent": "dsp-sql-injection/1.0"}
    if plan.content_type:
        headers["Content-Type"] = plan.content_type
    return HttpRequest(
        url=plan.url,
        method=plan.method,
        host=plan.host,
        port=plan.port,
        path=path,
        headers=headers,
        body=plan.body,
        content_type=plan.content_type,
    )


def run(
    ctx: RunContext,
    targets: TargetSet,
    config: dict | None = None,
    scenario_id: str = "sql_injection",
) -> None:
    """Plan and execute SQL injection HTTP requests; append events to Event Store."""
    params = config or {}
    max_hosts = int(params.get("max_hosts", MAX_HOSTS_DEFAULT))
    max_per_host = int(params.get("max_per_host", SQLI_REQUESTS_PER_HOST))
    max_total = int(params.get("max_total", max_per_host * max(1, max_hosts)))
    write_wire_evidence = bool(params.get("write_wire_evidence", False))
    source = "dry_run" if ctx.dry_run else "local"
    mode = "mock" if ctx.dry_run else "live"
    client = HttpClient(mode=mode, timeout=float(params.get("timeout", 10.0)))

    selection = select_sqli_endpoints(
        targets,
        params,
        max_hosts=max_hosts,
        dry_run=ctx.dry_run,
        timeout=float(params.get("timeout", 10.0)),
    )
    if selection.skip_reason or not selection.selected:
        reason = selection.skip_reason or SKIP_REASON_HTTP_TARGETS_NOT_FOUND
        _emit_sqli_skipped(
            ctx,
            reason=reason,
            source=source,
            https_targets_skipped=selection.https_targets_skipped,
            probe_summaries=selection.probe_summaries,
            rejected_targets=selection.rejected_targets,
        )
        raise ScenarioSkipError(reason)

    endpoints = [(ep.host, ep.port) for ep in selection.selected]
    hosts = [ep.host for ep in selection.selected]
    selected_targets = format_selected_target_labels(selection.selected)
    plans = plan_sqli_requests(
        endpoints=endpoints,
        max_hosts=max_hosts,
        max_per_host=max_per_host,
        max_total=max_total,
    )

    ports_used = sorted({plan.port for plan in plans})
    schemes_used = sorted({plan.url.split("://", 1)[0] for plan in plans})
    sample_urls: list[str] = []
    sample_payloads: list[str] = []
    payload_count = 0
    sent_count = 0
    response_count = 0
    request_log: list[dict[str, Any]] = []
    wire_log: list[dict[str, Any]] = []
    category_counter: Counter[str] = Counter()
    transport_counter: Counter[str] = Counter()
    t0 = time.monotonic()

    ctx.event_store.append(
        build_sql_injection_started_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=hosts[0],
            source=source,
            evidence={
                "hosts": hosts,
                "endpoints": [
                    {
                        "host": ep.host,
                        "port": ep.port,
                        "scheme": ep.scheme,
                        "selection_reason": ep.selection_reason,
                    }
                    for ep in selection.selected
                ],
                "planned_requests": len(plans),
                "max_total": max_total,
                "mode": mode,
                "schemes_used": schemes_used,
                "https_targets_skipped": selection.https_targets_skipped,
                "selected_http_target_reason": selection.selected_http_target_reason,
                "probe_summaries": selection.probe_summaries,
                "target_probe": selection.probe_summaries,
                "rejected_targets": selection.rejected_targets,
                "selected_targets": selected_targets,
                "payload_categories": sorted(SQLI_PAYLOAD_CATEGORIES),
            },
        )
    )

    for seq, plan in enumerate(plans, start=1):
        if ctx.cancelled:
            break

        request = _make_http_request(plan)
        if len(sample_urls) < 5:
            sample_urls.append(request.url)
        if plan.payload not in sample_payloads and len(sample_payloads) < 5:
            sample_payloads.append(plan.payload)

        payload_evidence = {
            "seq": seq,
            "host": plan.host,
            "port": plan.port,
            "path": plan.path,
            "parameter": plan.parameter,
            "payload": plan.payload,
            "payload_category": plan.payload_category,
            "method": plan.method,
            "transport": plan.transport,
        }
        ctx.event_store.append(
            build_sql_payload_generated_event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                target=plan.host,
                url=request.url,
                source=source,
                evidence=payload_evidence,
            )
        )
        payload_count += 1

        ctx.event_store.append(
            build_sql_request_sent_event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                target=plan.host,
                url=request.url,
                source=source,
                evidence={
                    **payload_evidence,
                    "url": request.url,
                },
            )
        )
        sent_count += 1

        if mode == "mock":
            result = client.request(request, mock_outcome="response", mock_status_code=200)
        else:
            result = client.request(request)

        response_code = result.status_code
        request_log.append(
            {
                "seq": seq,
                "target": f"{plan.host}:{plan.port}",
                "method": plan.method,
                "url": request.url,
                "path": plan.path,
                "parameter": plan.parameter,
                "payload_category": plan.payload_category,
                "payload": plan.payload,
                "response_code": response_code,
                "transport": plan.transport,
            }
        )
        if write_wire_evidence:
            from dsp.protocols.http.wire_evidence import build_wire_record_from_request

            wire_log.append(
                build_wire_record_from_request(
                    request,
                    response_code=response_code,
                    target=f"{plan.host}:{plan.port}",
                )
            )
        category_counter[plan.payload_category] += 1
        transport_counter[plan.transport] += 1

        ctx.event_store.append(
            append_sqli_outcome_event(
                run_id=ctx.run_id,
                scenario_id=scenario_id,
                request=request,
                result=result,
                source=source,
                payload=plan.payload,
            )
        )
        if result.outcome == "response":
            response_count += 1

    if sent_count == 0:
        _emit_sqli_skipped(
            ctx,
            reason=SKIP_REASON_HTTP_TARGETS_NOT_FOUND,
            source=source,
            https_targets_skipped=selection.https_targets_skipped,
            probe_summaries=selection.probe_summaries,
            rejected_targets=selection.rejected_targets,
        )
        raise ScenarioSkipError(SKIP_REASON_HTTP_TARGETS_NOT_FOUND)

    request_log_path = _write_sqli_request_log(ctx, request_log)
    wire_log_path = _write_sqli_wire_evidence_log(ctx, wire_log) if write_wire_evidence else None
    elapsed = round(time.monotonic() - t0, 3)
    ctx.event_store.append(
        build_sql_injection_completed_event(
            run_id=ctx.run_id,
            scenario_id=scenario_id,
            target=hosts[0],
            source=source,
            evidence={
                "targets": hosts,
                "ports_used": ports_used,
                "schemes_used": schemes_used,
                "https_targets_skipped": selection.https_targets_skipped,
                "request_count": sent_count,
                "requests_sent": sent_count,
                "payload_count": payload_count,
                "response_count": response_count,
                "duration_sec": elapsed,
                "sample_urls": sample_urls,
                "sample_payloads": sample_payloads,
                "payload_category_distribution": dict(category_counter),
                "transport_distribution": dict(transport_counter),
                "selected_http_target_reason": selection.selected_http_target_reason,
                "probe_summaries": selection.probe_summaries,
                "target_probe": selection.probe_summaries,
                "rejected_targets": selection.rejected_targets,
                "selected_targets": selected_targets,
                "sql_injection_requests_jsonl": str(request_log_path) if request_log_path else "",
                "sql_wire_evidence_jsonl": str(wire_log_path) if wire_log_path else "",
            },
        )
    )
