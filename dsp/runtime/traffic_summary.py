"""Traffic summary — planned vs actual counters from Event Store."""

from __future__ import annotations

from typing import Any

from dsp.engine.scenario_engine import TargetSet
from dsp.event_store import Event, EventStore
from dsp.runtime.discovery_report import (
    discovery_basis_for_scenario,
    normalize_discovery_meta,
)


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


def _count_events(events: list[dict[str, Any]], scenario_id: str, event_name: str) -> int:
    return sum(1 for e in events if e.get("scenario_id") == scenario_id and e.get("event") == event_name)


def _last_evidence(events: list[dict[str, Any]], scenario_id: str, event_name: str) -> dict[str, Any]:
    for e in reversed(events):
        if e.get("scenario_id") == scenario_id and e.get("event") == event_name:
            return dict(e.get("evidence") or {})
    return {}


def build_traffic_summary(
    store: EventStore,
    *,
    run_id: str,
    scenario_ids: list[str],
    targets: TargetSet,
    traffic_profile: str,
) -> dict[str, Any]:
    """Build planned vs actual traffic summary for a run."""
    events = [_normalize_event(e) for e in store.list_events(run_id)]
    discovery = normalize_discovery_meta(
        {
            "enabled": targets.discovery_enabled,
            **targets.discovery_meta,
        }
    )

    summary: dict[str, Any] = {
        "traffic_profile": traffic_profile,
        "target_net": targets.target_net,
        "discovery": discovery,
        "scenarios": {},
    }

    for sid in scenario_ids:
        started = _last_evidence(events, sid, f"{sid}_started")
        if not started:
            started = _last_evidence(events, sid, "port_sweep_started")
        if not started:
            started = _last_evidence(events, sid, "http_followup_started")
        if not started:
            started = _last_evidence(events, sid, "ssh_failure_started")
        if not started:
            started = _last_evidence(events, sid, "smb_scenario_started")
        if not started:
            started = _last_evidence(events, sid, "sql_injection_started")

        completed = _last_evidence(events, sid, f"{sid}_completed")
        if not completed:
            completed = _last_evidence(events, sid, "port_sweep_completed")
        if not completed:
            completed = _last_evidence(events, sid, "http_followup_completed")
        if not completed:
            completed = _last_evidence(events, sid, "ssh_failure_completed")
        if not completed:
            completed = _last_evidence(events, sid, "smb_scenario_completed")
        if not completed:
            completed = _last_evidence(events, sid, "sql_injection_completed")

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
            skipped = _last_evidence(events, sid, "kerberos_failure_skipped")
        if not skipped:
            skipped = _last_evidence(events, sid, "dns_tunnel_skipped")
        if not skipped:
            skipped = _last_evidence(events, sid, "scenario_skipped")

        scenario_summary: dict[str, Any] = {
            "target_ips": completed.get("targets") or started.get("hosts") or skipped.get("hosts") or [],
            "skipped": bool(skipped),
            "skip_reason": skipped.get("reason"),
            "discovery_basis": discovery_basis_for_scenario(sid, discovery),
            "planned": None,
            "dispatched": None,
            "observed": None,
        }

        if sid == "port_sweep":
            scenario_summary.update({
                "probes_planned": started.get("planned_probes", 0),
                "probes_sent": completed.get("probe_count") or _count_events(events, sid, "port_probe_sent"),
                "connections_open": completed.get("connection_success_count", 0),
                "connection_failures": completed.get("connection_failure_count", 0),
                "ports": started.get("ports", []),
                "duration_sec": completed.get("duration_sec"),
                "probes_per_second": completed.get("probes_per_second"),
                "concurrency": started.get("concurrency") or completed.get("concurrency"),
            })
        elif sid == "http_followup":
            scenario_summary.update({
                "requests_planned": 0 if skipped else started.get("planned_requests", 0),
                "requests_sent": completed.get("request_count") or _count_events(events, sid, "http_request_sent"),
                "responses_received": completed.get("response_count", 0),
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
                "requests_per_target": completed.get("requests_per_target")
                or started.get("requests_per_target", {}),
                "per_target_request_count": completed.get("per_target_request_count", {}),
                "per_target_error_count": completed.get("per_target_error_count", {}),
                "abnormal_user_agents": completed.get("abnormal_user_agents", 0),
                "normal_user_agents": completed.get("normal_user_agents", 0),
                "abnormal_user_agent_ratio": completed.get("abnormal_user_agent_ratio", 0.0),
                "payload_only_ua": completed.get("payload_only_ua", 0),
                "abnormal_ua_ratio": completed.get("abnormal_ua_ratio")
                or started.get("abnormal_ua_ratio", 0.0),
                "expected_url_scan_distribution": completed.get("expected_url_scan_distribution")
                or started.get("expected_url_scan_distribution", {}),
            })
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
            if not started:
                started = _last_evidence(events, sid, "dns_tunnel_started")
            if not completed:
                completed = _last_evidence(events, sid, "dns_tunnel_completed")
            queries_sent = int(
                completed.get("queries_sent")
                or completed.get("observed_queries")
                or _count_events(events, sid, "dns_tunnel_query_sent")
                or 0
            )
            chunks_created = int(
                completed.get("dns_tunnel_chunk_created_count")
                or _count_events(events, sid, "dns_tunnel_chunk_created")
                or 0
            )
            planned = int(
                completed.get("total_planned_queries")
                or completed.get("planned_queries")
                or started.get("total_planned_queries")
                or started.get("planned_queries")
                or started.get("planned_chunks")
                or 0
            )
            dispatched = int(
                completed.get("dispatched_queries")
                or dns_dispatch.get("dispatched_queries")
                or queries_sent
                or 0
            )
            observed = int(completed.get("observed_queries") or queries_sent)
            scenario_summary.update({
                "planned": planned,
                "dispatched": dispatched,
                "observed": observed,
                "queries_planned": planned,
                "planned_queries": planned,
                "planned_data_queries": int(
                    completed.get("planned_data_queries")
                    or started.get("planned_data_queries")
                    or 0
                ),
                "session_start_queries": int(
                    completed.get("session_start_queries")
                    or started.get("session_start_queries")
                    or 0
                ),
                "session_end_queries": int(
                    completed.get("session_end_queries")
                    or started.get("session_end_queries")
                    or 0
                ),
                "total_planned_queries": planned,
                "dispatched_queries": dispatched,
                "observed_queries": observed,
                "dns_tunnel_query_sent_count": queries_sent,
                "dns_tunnel_chunk_created_count": chunks_created,
                "queries_sent": queries_sent,
                "payload_bytes": completed.get("payload_bytes") or started.get("payload_bytes"),
                "chunk_size": completed.get("chunk_size") or started.get("chunk_size"),
                "target_dns_server": (
                    completed.get("target_dns_server")
                    or started.get("target_dns_server")
                    or started.get("target")
                    or dns_dispatch.get("target")
                ),
                "target_port": completed.get("target_port") or started.get("target_port") or 53,
                "source_host": completed.get("source_host") or started.get("source_host"),
                "provider": completed.get("provider") or started.get("provider"),
                "start_time": completed.get("start_time") or started.get("start_time"),
                "end_time": completed.get("end_time"),
                "duration_sec": completed.get("duration_sec") or completed.get("duration"),
                "duration": completed.get("duration_sec") or completed.get("duration"),
                "queries_per_second": completed.get("queries_per_second"),
                "unique_subdomains": completed.get("unique_subdomains"),
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
            if not started:
                started = _last_evidence(events, sid, "dga_started")
            if not completed:
                completed = _last_evidence(events, sid, "dga_completed")
            generated = int(
                completed.get("generated_domains")
                or completed.get("domains_generated")
                or _count_events(events, sid, "dga_domain_generated")
                or 0
            )
            dispatched = int(
                completed.get("dispatched_queries")
                or _count_events(events, sid, "dns_query_sent")
                or 0
            )
            planned = int(
                started.get("planned_domains")
                or (
                    int(started.get("phase1_count") or 0)
                    + int(started.get("phase2_count") or 0)
                )
                or generated
            )
            observed_nx = int(
                completed.get("observed_nxdomain")
                or completed.get("nxdomain_observed")
                or _count_events(events, sid, "dga_nxdomain_observed")
                or 0
            )
            observed_resolved = int(
                completed.get("observed_resolved")
                or completed.get("resolved_observed")
                or _count_events(events, sid, "dga_resolved_observed")
                or 0
            )
            scenario_summary.update({
                "planned": planned,
                "dispatched": dispatched,
                "observed": observed_nx + observed_resolved,
                "generated_domains": generated,
                "domains_generated": generated,
                "dispatched_queries": dispatched,
                "observed_nxdomain": observed_nx,
                "observed_resolved": observed_resolved,
                "nxdomain_observed": observed_nx,
                "resolved_observed": observed_resolved,
                "resolver": completed.get("resolver") or started.get("target"),
                "duration_sec": completed.get("duration_sec"),
                "sample_domains": completed.get("sample_domains", []),
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
            scenario_summary.update({
                "requests_planned": 0 if skipped else started.get("planned_requests", 0),
                "requests_sent": completed.get("requests_sent") or completed.get("request_count", 0),
                "responses_received": completed.get("response_count", 0),
                "payload_count": completed.get("payload_count", 0),
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

        summary["scenarios"][sid] = scenario_summary

    for sid in ("http_followup", "sql_injection"):
        scenario_probe = summary["scenarios"].get(sid, {})
        target_probe = scenario_probe.get("target_probe")
        if target_probe:
            summary["target_probe"] = target_probe
            summary["selected_targets"] = scenario_probe.get("selected_targets", [])
            summary["rejected_targets"] = scenario_probe.get("rejected_targets", [])
            if scenario_probe.get("skip_reason"):
                summary["http_endpoint_skip_reason"] = scenario_probe["skip_reason"]
            break

    return summary
