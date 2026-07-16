"""Traffic summary — planned vs actual counters from Event Store."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from dsp.engine.scenario_engine import TargetSet
from dsp.event_store import Event, EventStore

if TYPE_CHECKING:
    from dsp.plugins.registry import PluginRegistry


def _normalize_event(event: Event | dict[str, Any]) -> dict[str, Any]:
    """Normalize Event objects, dicts, or to_dict()-capable records for summary."""
    if isinstance(event, dict):
        return {
            "scenario_id": event.get("scenario_id", ""),
            "event": event.get("event", ""),
            "evidence": event.get("evidence") or {},
            "target": event.get("target", ""),
        }
    to_dict = getattr(event, "to_dict", None)
    if callable(to_dict):
        data = to_dict()
        return {
            "scenario_id": data.get("scenario_id", ""),
            "event": data.get("event", ""),
            "evidence": data.get("evidence") or {},
            "target": data.get("target", ""),
        }
    return {
        "scenario_id": event.scenario_id,
        "event": event.event,
        "evidence": event.evidence or {},
        "target": event.target,
    }


def _event_dict(event: Event) -> dict[str, Any]:
    return _normalize_event(event)


def _is_phase1_webshell_evidence(evidence: dict[str, Any]) -> bool:
    return evidence.get("phase") == "phase1_webshell_attack"


def _last_evidence(
    events: list[dict[str, Any]],
    scenario_id: str,
    event_name: str,
    *,
    exclude_phase1: bool = False,
) -> dict[str, Any]:
    for e in reversed(events):
        if e.get("scenario_id") != scenario_id or e.get("event") != event_name:
            continue
        evidence = dict(e.get("evidence") or {})
        if exclude_phase1 and _is_phase1_webshell_evidence(evidence):
            continue
        return evidence
    return {}


def _last_scenario_evidence(
    events: list[dict[str, Any]],
    scenario_id: str,
    event_name: str,
    *,
    exclude_phase1: bool = True,
) -> dict[str, Any]:
    """Prefer non-phase1 lifecycle evidence; fall back to any matching event."""
    evidence = _last_evidence(events, scenario_id, event_name, exclude_phase1=exclude_phase1)
    if evidence or not exclude_phase1:
        return evidence
    return _last_evidence(events, scenario_id, event_name, exclude_phase1=False)


def _parse_request_url(url: str) -> tuple[str, int, str]:
    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    host = parsed.hostname or ""
    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80
    return host, int(port), scheme


def _endpoint_label(host: str, port: int, scheme: str = "http") -> str:
    default_port = 443 if scheme == "https" else 80
    if port and port != default_port:
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def _collect_http_request_metadata(
    events: list[dict[str, Any]],
    scenario_id: str,
    *,
    exclude_phase1: bool = True,
) -> dict[str, Any]:
    ports_used: set[int] = set()
    schemes_used: set[str] = set()
    target_ips: set[str] = set()
    per_target_request_count: dict[str, int] = {}
    payload_category_distribution: dict[str, int] = {}
    transport_distribution: dict[str, int] = {}

    request_events = (
        "http_request_sent",
        "sql_request_sent",
        "http_request_created",
        "sql_payload_generated",
    )
    for event in events:
        if event.get("scenario_id") != scenario_id:
            continue
        event_name = event.get("event")
        if event_name not in request_events:
            continue
        evidence = event.get("evidence") or {}
        if exclude_phase1 and _is_phase1_webshell_evidence(evidence):
            continue

        url = str(evidence.get("url") or event.get("artifact") or event.get("target") or "")
        host = str(evidence.get("host") or "")
        port_val = evidence.get("port")
        scheme = str(evidence.get("scheme") or "")

        if url.startswith(("http://", "https://")):
            host, port, scheme = _parse_request_url(url)
        elif host and port_val is not None:
            port = int(port_val)
            scheme = scheme or "http"
        else:
            continue

        if host:
            target_ips.add(host)
        if port:
            ports_used.add(port)
        if scheme:
            schemes_used.add(scheme)

        label = _endpoint_label(host, port, scheme or "http")
        per_target_request_count[label] = per_target_request_count.get(label, 0) + 1

        if event_name == "sql_payload_generated":
            category = str(evidence.get("payload_category") or "unknown")
            payload_category_distribution[category] = payload_category_distribution.get(category, 0) + 1
        if event_name == "sql_request_sent":
            transport = str(evidence.get("transport") or evidence.get("method") or "GET")
            transport_distribution[transport] = transport_distribution.get(transport, 0) + 1

    selected_targets = sorted(per_target_request_count.keys())
    return {
        "target_ips": sorted(target_ips),
        "ports_used": sorted(ports_used),
        "schemes_used": sorted(schemes_used),
        "selected_targets": selected_targets,
        "target_count": len(selected_targets),
        "per_target_request_count": per_target_request_count,
        "requests_per_target": dict(per_target_request_count),
        "payload_category_distribution": payload_category_distribution,
        "transport_distribution": transport_distribution,
    }


def _collect_port_sweep_metadata(
    events: list[dict[str, Any]],
    scenario_id: str,
) -> dict[str, Any]:
    ports: set[int] = set()
    target_ips: set[str] = set()
    probe_events = {"port_probe_sent", "port_connection_opened", "port_connection_failed"}
    for event in events:
        if event.get("scenario_id") != scenario_id:
            continue
        if event.get("event") not in probe_events:
            continue
        evidence = event.get("evidence") or {}
        host = str(evidence.get("host") or event.get("target") or "")
        port_val = evidence.get("port")
        if host:
            target_ips.add(host)
        if port_val is not None:
            ports.add(int(port_val))
    return {
        "ports": sorted(ports),
        "target_ips": sorted(target_ips),
    }


def _merge_nonempty_fields(scenario_summary: dict[str, Any], fields: dict[str, Any]) -> None:
    for key, value in fields.items():
        if value in (None, "", [], {}):
            continue
        if not scenario_summary.get(key):
            scenario_summary[key] = value


def _scenario_store_metrics(
    store: EventStore,
    registry: PluginRegistry | None,
    run_id: str,
    scenario_id: str,
) -> dict[str, int | float]:
    if registry is None:
        return {}
    from dsp.runtime.scenario_store_metrics import aggregate_scenario_metrics

    return aggregate_scenario_metrics(store, registry, run_id, scenario_id)


def _count_events(
    events: list[dict[str, Any]],
    scenario_id: str,
    event_name: str,
    *,
    exclude_phase1: bool = False,
) -> int:
    total = 0
    for e in events:
        if e.get("scenario_id") != scenario_id or e.get("event") != event_name:
            continue
        evidence = e.get("evidence") or {}
        if exclude_phase1 and _is_phase1_webshell_evidence(evidence):
            continue
        total += 1
    return total


def _http_scenario_fallback_fields(
    targets: TargetSet,
    scenario_params: dict[str, dict[str, Any]] | None,
    scenario_id: str,
) -> dict[str, Any]:
    if scenario_id not in ("http_followup", "sql_injection"):
        return {}
    params = (scenario_params or {}).get(scenario_id) or {}
    from dsp.engine.host_selection import (
        http_selection_summary_fields,
        resolve_discovery_http_selection,
    )

    selection = resolve_discovery_http_selection(
        targets,
        params,
        webshell_mode=True,
    )
    if not selection.selected:
        http_hosts = targets.hosts_for_capability("http_targets")
        if not http_hosts:
            return {}
        return {
            "http_targets": http_hosts,
            "https_targets": targets.hosts_for_capability("https_targets"),
            "selected_targets": [str(host) for host in http_hosts[: int(params.get("max_hosts", 2))]],
            "target_count": min(len(http_hosts), int(params.get("max_hosts", 2))),
        }
    return http_selection_summary_fields(selection, targets)


def _merge_http_summary_fields(
    scenario_summary: dict[str, Any],
    fallback: dict[str, Any],
) -> None:
    if not fallback:
        return
    for key in (
        "selected_targets",
        "target_count",
        "http_targets",
        "https_targets",
        "selected_http_target_reason",
        "probe_summaries",
        "target_probe",
        "rejected_targets",
    ):
        if not scenario_summary.get(key) and fallback.get(key):
            scenario_summary[key] = fallback[key]
    if not scenario_summary.get("target_count") and scenario_summary.get("selected_targets"):
        scenario_summary["target_count"] = len(scenario_summary["selected_targets"])


def build_traffic_summary(
    store: EventStore,
    *,
    run_id: str,
    scenario_ids: list[str],
    targets: TargetSet,
    traffic_profile: str,
    webshell_execution: dict[str, Any] | None = None,
    scenario_params: dict[str, dict[str, Any]] | None = None,
    registry: PluginRegistry | None = None,
) -> dict[str, Any]:
    """Build planned vs actual traffic summary for a run."""
    events = [_normalize_event(e) for e in store.list_events(run_id)]

    summary: dict[str, Any] = {
        "traffic_profile": traffic_profile,
        "target_net": targets.target_net,
        "attack_target_net": targets.target_net,
        "discovery": {
            "enabled": targets.discovery_enabled,
            **targets.discovery_meta,
        },
        "scenarios": {},
    }
    if webshell_execution:
        summary["execution_host"] = webshell_execution.get("execution_host")
        summary["webshell_url"] = webshell_execution.get("webshell_url")

    for sid in scenario_ids:
        exclude_phase1 = sid in ("http_followup", "sql_injection")
        started = _last_scenario_evidence(events, sid, f"{sid}_started", exclude_phase1=exclude_phase1)
        if not started:
            started = _last_scenario_evidence(events, sid, "host_behavior_check_started")
        if not started:
            started = _last_scenario_evidence(events, sid, "port_sweep_started")
        if not started:
            started = _last_scenario_evidence(events, sid, "http_followup_started")
        if not started:
            started = _last_scenario_evidence(events, sid, "ssh_failure_started")
        if not started:
            started = _last_scenario_evidence(events, sid, "dns_tunnel_started")
        if not started:
            started = _last_scenario_evidence(events, sid, "dga_started")
        if not started:
            started = _last_scenario_evidence(events, sid, "rare_protocol_activity_started")
        if not started:
            started = _last_scenario_evidence(events, sid, "smb_scenario_started")
        if not started:
            started = _last_scenario_evidence(events, sid, "sql_injection_started")

        completed = _last_scenario_evidence(events, sid, f"{sid}_completed", exclude_phase1=exclude_phase1)
        if not completed:
            completed = _last_scenario_evidence(events, sid, "host_behavior_check_completed")
        if not completed:
            completed = _last_scenario_evidence(events, sid, "port_sweep_completed")
        if not completed:
            completed = _last_scenario_evidence(events, sid, "http_followup_completed")
        if not completed:
            completed = _last_scenario_evidence(events, sid, "ssh_failure_completed")
        if not completed:
            completed = _last_scenario_evidence(events, sid, "dns_tunnel_completed")
        if not completed:
            completed = _last_scenario_evidence(events, sid, "dga_completed")
        if not completed:
            completed = _last_scenario_evidence(events, sid, "rare_protocol_activity_completed")
        if not completed:
            completed = _last_scenario_evidence(events, sid, "smb_scenario_completed")
        if not completed:
            completed = _last_scenario_evidence(events, sid, "sql_injection_completed")

        skipped = _last_evidence(events, sid, f"{sid}_skipped")
        if not skipped:
            skipped = _last_evidence(events, sid, "smb_scenario_skipped")
        if not skipped:
            skipped = _last_evidence(events, sid, "http_followup_skipped")
        if not skipped:
            skipped = _last_evidence(events, sid, "sql_injection_skipped")
        if not skipped:
            skipped = _last_evidence(events, sid, "ssh_failure_skipped")
        if not skipped:
            skipped = _last_evidence(events, sid, "rare_protocol_activity_skipped")
        if not skipped:
            skipped = _last_evidence(events, sid, "port_sweep_skipped")
        if not skipped:
            skipped = _last_evidence(events, sid, "ldap_enumeration_skipped")
        if not skipped:
            skipped = _last_evidence(events, sid, "kerberos_failure_skipped")

        store_metrics = _scenario_store_metrics(store, registry, run_id, sid)
        use_store_metrics = bool(store_metrics)
        scenario_summary: dict[str, Any] = {
            "target_ips": completed.get("targets") or started.get("hosts") or skipped.get("hosts") or [],
            "skipped": bool(skipped),
            "skip_reason": skipped.get("reason"),
        }

        if sid == "host_behavior_check":
            started = started or _last_evidence(events, sid, "host_behavior_check_started")
            completed = completed or _last_evidence(events, sid, "host_behavior_check_completed")
            scenario_summary.update({
                "commands_planned": started.get("commands_planned", 0),
                "commands_dispatched": completed.get("commands_dispatched", 0),
                "host_behavior": completed.get("host_behavior") or {},
            })
        elif sid == "port_sweep":
            port_meta = _collect_port_sweep_metadata(events, sid)
            if use_store_metrics:
                probes_sent = int(store_metrics.get("port_probe_count", 0))
                connections_open = int(store_metrics.get("port_connection_success_count", 0))
                connection_failures = int(store_metrics.get("port_connection_failure_count", 0))
            else:
                probes_sent = int(
                    completed.get("probe_count")
                    or _count_events(events, sid, "port_probe_sent")
                )
                connections_open = int(completed.get("connection_success_count", 0))
                connection_failures = int(
                    completed.get("connection_failure_count")
                    or _count_events(events, sid, "port_connection_failed")
                )
            scenario_summary.update({
                "probes_planned": started.get("planned_probes", 0),
                "probes_sent": probes_sent,
                "connections_open": connections_open,
                "connection_failures": connection_failures,
                "ports": started.get("ports") or port_meta.get("ports", []),
                "duration_sec": completed.get("duration_sec"),
                "probes_per_second": completed.get("probes_per_second"),
                "concurrency": started.get("concurrency") or completed.get("concurrency"),
            })
            _merge_nonempty_fields(scenario_summary, {"target_ips": port_meta.get("target_ips", [])})
        elif sid == "http_followup":
            request_metadata = _collect_http_request_metadata(events, sid, exclude_phase1=True)
            if use_store_metrics:
                requests_sent = int(store_metrics.get("http_request_sent_count", 0))
                responses_received = int(store_metrics.get("http_response_received_count", 0))
            else:
                requests_sent = int(
                    completed.get("request_count")
                    or completed.get("requests_sent")
                    or _count_events(events, sid, "http_request_sent", exclude_phase1=True)
                )
                responses_received = int(
                    completed.get("response_count")
                    or completed.get("responses_received")
                    or _count_events(events, sid, "http_response_received", exclude_phase1=True)
                )
            requests_planned = (
                started.get("planned_requests")
                or started.get("requests_planned")
                or _count_events(events, sid, "http_request_created", exclude_phase1=True)
                or 0
            )
            if skipped:
                requests_planned = 0
            scenario_summary.update({
                "requests_planned": requests_planned,
                "requests_sent": requests_sent,
                "responses_received": responses_received,
                "paths_sample": completed.get("paths_used") or started.get("paths_planned"),
                "user_agent_classes": completed.get("user_agent_classes", {}),
                "malicious_rare_ua_count": completed.get("malicious_rare_ua_count", 0),
                "ports_used": completed.get("ports_used", []),
                "schemes_used": completed.get("schemes_used", []),
                "scheme_by_port": completed.get("scheme_by_port", {}),
                "https_fallback": False,
                "https_targets_skipped": completed.get("https_targets_skipped")
                or started.get("https_targets_skipped")
                or skipped.get("https_targets_skipped", []),
                "http_targets": completed.get("http_targets") or started.get("http_targets", []),
                "https_targets": completed.get("https_targets") or started.get("https_targets", []),
                "skipped_no_http_service": skipped.get("skipped_no_http_service", False),
                "http_targets_not_found": skipped.get("http_targets_not_found", False)
                or skipped.get("reason") == "HTTP_TARGETS_NOT_FOUND",
                "duration_sec": completed.get("duration_sec"),
                "response_code_distribution": completed.get("response_code_distribution", {}),
                "selected_http_target_reason": completed.get("selected_http_target_reason")
                or started.get("selected_http_target_reason", ""),
                "redirect_only_warning": completed.get("redirect_only_warning", False),
                "probe_summaries": completed.get("probe_summaries")
                or started.get("probe_summaries")
                or skipped.get("probe_summaries", []),
                "target_probe": completed.get("target_probe")
                or started.get("target_probe")
                or skipped.get("target_probe")
                or completed.get("probe_summaries")
                or started.get("probe_summaries")
                or skipped.get("probe_summaries", []),
                "rejected_targets": completed.get("rejected_targets")
                or started.get("rejected_targets")
                or skipped.get("rejected_targets", []),
                "redirect_only_candidates": completed.get("redirect_only_candidates")
                or started.get("redirect_only_candidates", []),
                "target_count": completed.get("target_count", len(completed.get("target_distribution", {}))),
                "concentrated_target": completed.get("concentrated_target", ""),
                "target_distribution": completed.get("target_distribution", {}),
                "selected_targets": completed.get("selected_targets")
                or started.get("selected_targets", [])
                or skipped.get("selected_targets", []),
                "requests_per_target": (
                    completed.get("per_target_request_count")
                    or completed.get("target_distribution")
                    or completed.get("requests_per_target")
                    or started.get("requests_per_target", {})
                ),
                "per_target_request_count": (
                    completed.get("per_target_request_count")
                    or completed.get("target_distribution", {})
                ),
                "per_target_error_count": completed.get("per_target_error_count", {}),
                "abnormal_user_agents": completed.get("abnormal_user_agents", 0),
                "normal_user_agents": completed.get("normal_user_agents", 0),
                "abnormal_user_agent_ratio": completed.get("abnormal_user_agent_ratio", 0.0),
                "payload_only_ua": completed.get("payload_only_ua", 0),
                "user_agent_policy": completed.get("user_agent_policy")
                or started.get("user_agent_policy"),
                "expected_url_scan_distribution": (
                    completed.get("per_target_request_count")
                    or completed.get("target_distribution")
                    or completed.get("expected_url_scan_distribution")
                    or started.get("expected_url_scan_distribution", {})
                ),
            })
            burst = (
                completed.get("non_standard_port_burst")
                or _last_evidence(events, sid, "non_standard_port_burst_completed")
                or {}
            )
            if burst.get("enabled"):
                scenario_summary["non_standard_port_burst"] = {
                    "ports": burst.get("ports", []),
                    "attempts": burst.get("attempts", 0),
                    "success": burst.get("success", 0),
                    "failure": burst.get("failure", 0),
                }
            elif use_store_metrics and (
                store_metrics.get("non_standard_port_connection_attempt_count")
                or store_metrics.get("non_standard_port_connection_failure_count")
                or store_metrics.get("non_standard_port_connection_success_count")
            ):
                scenario_summary["non_standard_port_burst"] = {
                    "ports": burst.get("ports", []),
                    "attempts": int(store_metrics.get("non_standard_port_connection_attempt_count", 0)),
                    "success": int(store_metrics.get("non_standard_port_connection_success_count", 0)),
                    "failure": int(store_metrics.get("non_standard_port_connection_failure_count", 0)),
                }
            _merge_http_summary_fields(
                scenario_summary,
                _http_scenario_fallback_fields(targets, scenario_params, sid),
            )
            if completed.get("response_tracking"):
                scenario_summary["response_tracking"] = completed["response_tracking"]
            _merge_nonempty_fields(scenario_summary, request_metadata)
            if not scenario_summary.get("http_targets"):
                scenario_summary["http_targets"] = targets.hosts_for_capability("http_targets")
            if requests_sent > 0 and not scenario_summary.get("selected_targets"):
                scenario_summary["selected_targets"] = request_metadata.get("selected_targets", [])
                scenario_summary["target_count"] = len(scenario_summary["selected_targets"])
        elif sid == "ssh_failure":
            scenario_summary.update({
                "auth_attempts_planned": started.get("planned_attempts", 0),
                "auth_attempts": completed.get("attempt_count") or _count_events(events, sid, "ssh_auth_attempt"),
                "auth_failed": completed.get("failure_count") or _count_events(events, sid, "ssh_auth_failed"),
                "timeouts": _count_events(events, sid, "ssh_auth_timeout"),
                "sample_usernames": completed.get("sample_usernames", []),
            })
        elif sid == "dns_tunnel":
            dns_dispatch = _last_evidence(events, sid, "webshell_command_dispatched")
            if use_store_metrics:
                queries_sent = int(store_metrics.get("dns_tunnel_query_sent_count", 0))
                chunks_created = int(store_metrics.get("dns_tunnel_chunk_created_count", 0))
            else:
                queries_sent = _count_events(events, sid, "dns_tunnel_query_sent")
                chunks_created = _count_events(events, sid, "dns_tunnel_chunk_created")
            scenario_summary.update({
                "queries_planned": started.get("planned_chunks", 0),
                "dns_tunnel_query_sent_count": queries_sent,
                "dns_tunnel_chunk_created_count": chunks_created,
                "queries_sent": queries_sent,
                "dns_query_method": completed.get("dns_query_method")
                or started.get("dns_query_method")
                or dns_dispatch.get("dns_query_method"),
                "remote_command_sample": completed.get("remote_command_sample")
                or dns_dispatch.get("remote_command"),
                "target_selection": started.get("target_selection")
                or completed.get("target_selection", "alive_hosts"),
                "selected_target": started.get("target")
                or completed.get("target")
                or dns_dispatch.get("target"),
            })
        elif sid == "dga":
            phase1 = int(started.get("phase1_count") or 0)
            phase2 = int(started.get("phase2_count") or 0)
            domains_generated_count = _count_events(events, sid, "dga_domain_generated")
            domains_planned = int(
                started.get("domains_planned")
                or started.get("planned_domains")
                or (phase1 + phase2)
                or 0
            )
            domains_generated = int(
                completed.get("domains_generated")
                or domains_generated_count
                or 0
            )
            scenario_summary.update({
                "domains_planned": domains_planned,
                "domains_generated": domains_generated,
                "dga_domain_generated_count": domains_generated_count,
                "dga_nxdomain_observed_count": _count_events(events, sid, "dga_nxdomain_observed"),
                "dga_resolved_observed_count": _count_events(events, sid, "dga_resolved_observed"),
                "dns_query_method": completed.get("dns_query_method"),
            })
        elif sid == "rare_protocol_activity":
            scenario_summary.update({
                "probes_planned": started.get("planned_probes", 0),
                "attempts": completed.get("attempt_count")
                or _count_events(events, sid, "rare_protocol_probe_attempt"),
                "success": completed.get("success_count")
                or _count_events(events, sid, "rare_protocol_probe_success"),
                "failure": completed.get("failure_count")
                or _count_events(events, sid, "rare_protocol_probe_failure"),
                "protocols": completed.get("protocols") or started.get("protocols", []),
                "execution_host": completed.get("execution_host") or started.get("execution_host", ""),
                "duration_sec": completed.get("duration_sec"),
            })
        elif sid == "smb_login_failure":
            scenario_summary.update({
                "attempts_planned": started.get("planned_attempts", 0),
                "tcp_connect_attempts": completed.get("tcp_connect_attempts", 0),
                "tcp_connect_open": completed.get("tcp_connect_open", 0),
                "tcp_connect_failed": completed.get("tcp_connect_failed", 0),
                "skipped_no_open_service": completed.get("skipped_no_open_service", False),
                "auth_attempts": 0,
                "auth_failed": 0,
            })
        elif sid == "sql_injection":
            request_metadata = _collect_http_request_metadata(events, sid, exclude_phase1=True)
            if use_store_metrics:
                requests_sent = int(store_metrics.get("sql_request_sent_count", 0))
                payload_count = int(store_metrics.get("sql_payload_generated_count", 0))
            else:
                requests_sent = int(
                    completed.get("requests_sent")
                    or completed.get("request_count")
                    or _count_events(events, sid, "sql_request_sent", exclude_phase1=True)
                )
                payload_count = int(
                    completed.get("payload_count")
                    or _count_events(events, sid, "sql_payload_generated", exclude_phase1=True)
                )
            requests_planned = (
                started.get("planned_requests")
                or started.get("requests_planned")
                or payload_count
                or 0
            )
            if skipped:
                requests_planned = 0
            scenario_summary.update({
                "requests_planned": requests_planned,
                "requests_sent": requests_sent,
                "responses_received": int(store_metrics.get("sql_response_received_count", 0))
                or completed.get("response_count", 0),
                "payload_count": payload_count,
                "payload_category_distribution": completed.get("payload_category_distribution", {}),
                "transport_distribution": completed.get("transport_distribution", {}),
                "ports_used": completed.get("ports_used", started.get("ports_used", [])),
                "schemes_used": completed.get("schemes_used", started.get("schemes_used", [])),
                "https_targets_skipped": completed.get("https_targets_skipped")
                or started.get("https_targets_skipped")
                or skipped.get("https_targets_skipped", []),
                "http_targets_not_found": skipped.get("http_targets_not_found", False)
                or skipped.get("reason") == "HTTP_TARGETS_NOT_FOUND",
                "duration_sec": completed.get("duration_sec"),
                "selected_http_target_reason": completed.get("selected_http_target_reason")
                or started.get("selected_http_target_reason", ""),
                "probe_summaries": completed.get("probe_summaries")
                or started.get("probe_summaries")
                or skipped.get("probe_summaries", []),
                "target_probe": completed.get("target_probe")
                or started.get("target_probe")
                or skipped.get("target_probe")
                or completed.get("probe_summaries")
                or started.get("probe_summaries")
                or skipped.get("probe_summaries", []),
                "rejected_targets": completed.get("rejected_targets")
                or started.get("rejected_targets")
                or skipped.get("rejected_targets", []),
                "selected_targets": completed.get("selected_targets")
                or started.get("selected_targets", [])
                or skipped.get("selected_targets", []),
                "sql_injection_requests_jsonl": completed.get("sql_injection_requests_jsonl", ""),
            })
            _merge_http_summary_fields(
                scenario_summary,
                _http_scenario_fallback_fields(targets, scenario_params, sid),
            )
            _merge_nonempty_fields(scenario_summary, request_metadata)
            if not scenario_summary.get("payload_category_distribution"):
                scenario_summary["payload_category_distribution"] = request_metadata.get(
                    "payload_category_distribution",
                    {},
                )
            if not scenario_summary.get("transport_distribution"):
                scenario_summary["transport_distribution"] = request_metadata.get(
                    "transport_distribution",
                    {},
                )
            if not scenario_summary.get("http_targets"):
                scenario_summary["http_targets"] = targets.hosts_for_capability("http_targets")
            if requests_sent > 0 and not scenario_summary.get("selected_targets"):
                scenario_summary["selected_targets"] = request_metadata.get("selected_targets", [])
                scenario_summary["target_count"] = len(scenario_summary["selected_targets"])

        summary["scenarios"][sid] = scenario_summary

    from dsp.protocols.host.behavior_observability import (
        HOST_BEHAVIOR_SCENARIO_ID,
        build_host_behavior_checklist,
        host_behavior_report_payload,
    )

    if HOST_BEHAVIOR_SCENARIO_ID in scenario_ids:
        checklist = build_host_behavior_checklist(store, run_id, HOST_BEHAVIOR_SCENARIO_ID)
        payload = host_behavior_report_payload(checklist)
        summary["host_behavior"] = payload
        hb = summary["scenarios"].setdefault(HOST_BEHAVIOR_SCENARIO_ID, {})
        hb["host_behavior"] = payload

    for sid in ("http_followup", "sql_injection"):
        scenario_probe = summary["scenarios"].get(sid, {})
        target_probe = scenario_probe.get("target_probe")
        if target_probe:
            summary["target_probe"] = target_probe
            summary["selected_targets"] = scenario_probe.get("selected_targets", [])
            summary["selected_attack_targets"] = scenario_probe.get("selected_targets", [])
            summary["rejected_targets"] = scenario_probe.get("rejected_targets", [])
            summary["selected_target_reason"] = scenario_probe.get(
                "selected_http_target_reason", ""
            )
            if scenario_probe.get("skip_reason"):
                summary["http_endpoint_skip_reason"] = scenario_probe["skip_reason"]
            break

    return summary
