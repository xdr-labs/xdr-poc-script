"""Resolve per-scenario targets for operational progress output."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

from dsp.engine.scenario_engine import TargetSet
from dsp.runtime.scenario_plan import build_port_sweep_plan_view

_SCENARIOS_ROOT = Path(__file__).resolve().parents[2] / "scenarios"

_PROTOCOL_GROUPS: dict[str, str] = {
    "port_sweep": "Recon",
    "dns_tunnel": "DNS",
    "dga": "DNS",
    "http_followup": "HTTP",
    "sql_injection": "HTTP",
    "ldap_enumeration": "LDAP",
    "smb_login_failure": "SMB",
    "ssh_failure": "SSH",
    "kerberos_failure": "Kerberos",
    "rare_protocol_activity": "Rare",
}

_SELECTOR_SPECS: dict[str, tuple[str, bool]] = {
    "port_sweep": ("select_port_sweep_hosts", True),
    "dns_tunnel": ("select_tunnel_targets", True),
    "dga": ("select_dga_resolver", False),
    "http_followup": ("select_followup_endpoint_targets", True),
    "sql_injection": ("select_sqli_endpoint_targets", True),
    "ldap_enumeration": ("select_ldap_hosts", True),
    "smb_login_failure": ("select_smb_hosts", True),
    "ssh_failure": ("select_ssh_hosts", True),
    "kerberos_failure": ("select_kerberos_hosts", True),
}

_PROTOCOL_ORDER = ("Recon", "DNS", "HTTP", "LDAP", "SMB", "SSH", "Kerberos", "Rare")


def _load_executor_module(scenario_id: str):
    path = _SCENARIOS_ROOT / scenario_id / "executor.py"
    spec = importlib.util.spec_from_file_location(f"{scenario_id}_executor", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load executor for scenario {scenario_id!r}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def resolve_scenario_targets(
    scenario_id: str,
    targets: TargetSet,
    params: dict[str, Any],
) -> list[str]:
    """Return host IPs selected for a scenario using its executor selector."""
    max_hosts = int(params.get("max_hosts", 2))
    if scenario_id == "rare_protocol_activity":
        from dsp.protocols.rare.attempts import plan_rare_protocol_activity

        plans = plan_rare_protocol_activity(targets, params)
        if not plans:
            return []
        seen: set[str] = set()
        hosts: list[str] = []
        for plan in plans:
            host = str(plan.host)
            if host in seen:
                continue
            seen.add(host)
            hosts.append(host)
            if len(hosts) >= max_hosts:
                break
        return hosts
    spec = _SELECTOR_SPECS.get(scenario_id)
    if spec is None:
        return []
    func_name, is_list = spec
    module = _load_executor_module(scenario_id)
    selector = getattr(module, func_name)
    if is_list:
        return [str(h) for h in selector(targets, params, max_hosts=max_hosts)]
    result = selector(targets, params)
    if result is None:
        return []
    return [str(result)]


def resolve_selected_targets_by_protocol(
    scenario_ids: list[str],
    targets: TargetSet,
    scenario_params: dict[str, dict[str, Any]],
) -> dict[str, list[str]]:
    """Group selected scenario targets by protocol label for console output."""
    grouped: dict[str, set[str]] = {}
    for scenario_id in scenario_ids:
        protocol = _PROTOCOL_GROUPS.get(scenario_id)
        if protocol is None:
            continue
        params = scenario_params.get(scenario_id, {})
        hosts = resolve_scenario_targets(scenario_id, targets, params)
        if not hosts:
            continue
        bucket = grouped.setdefault(protocol, set())
        bucket.update(hosts)

    ordered: dict[str, list[str]] = {}
    for protocol in _PROTOCOL_ORDER:
        if protocol in grouped:
            ordered[protocol] = sorted(grouped[protocol])
    for protocol in sorted(grouped):
        if protocol not in ordered:
            ordered[protocol] = sorted(grouped[protocol])
    return ordered


def resolve_webshell_discovered_targets_by_protocol(
    scenario_ids: list[str],
    targets: TargetSet,
    scenario_params: dict[str, dict[str, Any]],
) -> dict[str, list[str]]:
    """Group discovery targets by protocol — same rules as local execution."""
    return resolve_selected_targets_by_protocol(scenario_ids, targets, scenario_params)


def scenario_start_metadata(
    scenario_id: str,
    targets: TargetSet,
    params: dict[str, Any],
    *,
    profile: str | None = None,
    webshell_mode: bool = False,
) -> dict[str, Any]:
    """Build metadata lines for scenario STARTED progress output."""
    hosts = resolve_scenario_targets(scenario_id, targets, params)
    meta: dict[str, Any] = {"targets": len(hosts)}
    if webshell_mode:
        meta["discovery_origin"] = "webshell_host"
        meta["target_net"] = targets.target_net
    if scenario_id == "port_sweep":
        plan = build_port_sweep_plan_view(targets, params)
        meta["targets"] = len(plan.selected_hosts)
        meta["ports"] = len(plan.selected_ports)
        meta["planned_probes"] = plan.planned_probes
        meta["concurrency"] = int(params.get("concurrency", 32))
        meta["selection_reason"] = plan.selection_reason
        meta["full_sweep_requested"] = plan.full_sweep_requested
        if profile:
            meta["profile"] = profile
    elif scenario_id == "http_followup":
        from dsp.engine.host_selection import (
            SKIP_REASON_HTTP_TARGETS_NOT_FOUND,
            format_selected_target_labels,
            resolve_http_endpoint_selection,
        )
        from dsp.protocols.http.curl_transport import curl_available
        from dsp.protocols.http.urls import compute_requests_per_target, plan_followup_requests

        max_hosts = int(params.get("max_hosts", 3))
        max_per_host = int(params.get("max_per_host", 500))
        max_total = int(params.get("max_total", 1000))
        min_requests_per_target = int(params.get("min_requests_per_target", 100))
        timeout = float(params.get("timeout", 2.0))
        selection = resolve_http_endpoint_selection(
            targets,
            params,
            max_hosts=max_hosts,
            dry_run=False,
            timeout=timeout,
        )
        meta["target_probe"] = selection.probe_summaries
        meta["probe_summaries"] = selection.probe_summaries
        meta["rejected_targets"] = selection.rejected_targets
        if not selection.selected:
            meta["skip_reason"] = selection.skip_reason or SKIP_REASON_HTTP_TARGETS_NOT_FOUND
            meta["selected_targets"] = []
        else:
            ep = selection.selected[0]
            meta["target"] = f"{ep.scheme}://{ep.host}:{ep.port}"
            meta["selected_http_target_reason"] = selection.selected_http_target_reason
            endpoint_tuples = [(e.host, e.port) for e in selection.selected]
            per_target = compute_requests_per_target(
                len(endpoint_tuples),
                max_total,
                min_per_target=min_requests_per_target,
            )
            planned = plan_followup_requests(
                endpoints=endpoint_tuples,
                max_hosts=max_hosts,
                max_per_host=min(max_per_host, per_target),
                max_total=max_total,
                include_attack_paths=bool(params.get("include_attack_paths", True)),
            )
            requests_per_target: dict[str, int] = {}
            for plan in planned:
                key = f"{plan.host}:{plan.port}"
                requests_per_target[key] = requests_per_target.get(key, 0) + 1
            meta["selected_targets"] = format_selected_target_labels(selection.selected)
            meta["requests_per_target"] = requests_per_target
            from dsp.protocols.http.user_agents import URL_SCAN_USER_AGENT_POLICY

            meta["user_agent_policy"] = URL_SCAN_USER_AGENT_POLICY
            meta["expected_url_scan_distribution"] = requests_per_target
            meta["targets"] = len(requests_per_target)
            meta["planned_requests"] = len(planned)
        meta["transport"] = "curl" if curl_available() else "urllib"
        meta["evidence"] = "http_followup_requests.jsonl"
    elif scenario_id == "dns_tunnel":
        from dsp.protocols.dns.tunnel import CHUNK_SIZE_DEFAULT, PAYLOAD_MB_DEFAULT, plan_chunk_count
        from dsp.protocols.dns.volume_profiles import apply_volume_profile

        tuned = apply_volume_profile(params, dry_run=False)
        payload_mb = float(tuned.get("payload_mb", PAYLOAD_MB_DEFAULT))
        chunk_size = int(tuned.get("chunk_size", CHUNK_SIZE_DEFAULT))
        max_chunks = tuned.get("max_chunks")
        include_markers = bool(tuned.get("include_session_markers", True))
        meta["payload_mb"] = payload_mb
        meta["payload_bytes"] = int(payload_mb * 1024 * 1024)
        meta["chunk_size"] = chunk_size
        if hosts:
            idx_per_host = plan_chunk_count(payload_mb, chunk_size)
            if max_chunks is not None:
                idx_per_host = min(idx_per_host, int(max_chunks))
            session_markers = 2 if include_markers else 0
            meta["planned_queries"] = (idx_per_host + session_markers) * len(hosts)
    elif scenario_id == "dga":
        meta["planned_domains"] = int(params.get("max_domains", params.get("max_total", 15)))
    elif scenario_id in ("ssh_failure", "ldap_enumeration", "kerberos_failure", "smb_login_failure"):
        meta["planned_attempts"] = int(params.get("max_total", 0)) or None
    elif scenario_id == "sql_injection":
        from dsp.engine.host_selection import (
            SKIP_REASON_HTTP_TARGETS_NOT_FOUND,
            format_selected_target_labels,
            resolve_http_endpoint_selection,
        )
        from dsp.protocols.http.urls import compute_requests_per_target, plan_followup_requests

        max_hosts = int(params.get("max_hosts", 2))
        max_total = int(params.get("max_total", params.get("max_payloads", 10)))
        timeout = float(params.get("timeout", 10.0))
        selection = resolve_http_endpoint_selection(
            targets,
            params,
            max_hosts=max_hosts,
            dry_run=False,
            timeout=timeout,
        )
        meta["target_probe"] = selection.probe_summaries
        meta["probe_summaries"] = selection.probe_summaries
        meta["rejected_targets"] = selection.rejected_targets
        if not selection.selected:
            meta["skip_reason"] = selection.skip_reason or SKIP_REASON_HTTP_TARGETS_NOT_FOUND
            meta["selected_targets"] = []
        else:
            meta["selected_targets"] = format_selected_target_labels(selection.selected)
            meta["selected_http_target_reason"] = selection.selected_http_target_reason
            meta["planned_requests"] = max_total
    return {k: v for k, v in meta.items() if v is not None}
