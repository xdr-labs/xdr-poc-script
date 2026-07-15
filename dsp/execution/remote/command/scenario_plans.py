"""Shared scenario plan builders for webshell command-only execution."""

from __future__ import annotations

from typing import Any

from dsp.discovery.legacy_bash import DISCOVERY_MAX_HOSTS, FAST_SAFE_DISCOVERY_PORTS
from dsp.engine.host_selection import resolve_http_endpoint_selection, select_hosts_for_capability
from dsp.engine.scenario_engine import TargetSet
from dsp.execution.remote.models import ScenarioExecutionRequest
from dsp.protocols.dns.tunnel import plan_dns_tunnel as build_dns_tunnel_plan
from dsp.protocols.host.behavior import build_host_behavior_plan
from dsp.protocols.http.non_standard_port_burst import plan_non_standard_port_burst
from dsp.protocols.http.sqli_payloads import plan_sqli_requests, sql_injection_request_items
from dsp.protocols.http.urls import plan_followup_requests
from dsp.protocols.http.user_agents import attach_followup_user_agents
from dsp.protocols.rare.attempts import plan_rare_protocol_activity as build_rare_protocol_plans
from dsp.protocols.recon import plan_port_sweep as build_port_sweep_plans
from dsp.protocols.ssh.attempts import SSH_PORT_DEFAULT, plan_ssh_attempts
from dsp.runtime.scenario_plan import build_port_sweep_plan_view


def uses_remote_discovery(request: ScenarioExecutionRequest) -> bool:
    """Webshell scenarios discover target_net on the remote host."""
    return request.execution_metadata.get("traffic_origin_host") == "remote"


def plan_remote_discovery_execute(
    request: ScenarioExecutionRequest,
    *,
    dry_run: bool,
) -> dict[str, Any]:
    params = dict(request.scenario_params)
    return {
        "type": "remote_discovery_execute",
        "scenario_id": request.scenario_id,
        "params": params,
        "discovery": {
            "target_net": request.target_net,
            "max_hosts": DISCOVERY_MAX_HOSTS,
            "ports": list(FAST_SAFE_DISCOVERY_PORTS),
            "origin": "webshell_host",
        },
        "mode": "mock" if dry_run else "live",
    }


def build_scenario_execution_plan(
    scenario_id: str,
    targets: TargetSet,
    params: dict[str, Any],
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Build provider-independent executable plan from discovery ``TargetSet`` only."""
    if scenario_id == "host_behavior_check":
        request = ScenarioExecutionRequest(
            scenario_id=scenario_id,
            scenario_params=dict(params),
            execution_metadata={},
            run_id=str(params.get("run_id") or "plan"),
            target_net=targets.target_net,
            dry_run=dry_run,
        )
        return plan_host_behavior_check(request, params, dry_run=dry_run)

    builders = {
        "port_sweep": lambda: plan_port_sweep(targets, params, dry_run=dry_run),
        "dns_tunnel": lambda: plan_dns_tunnel(targets, params, dry_run=dry_run),
        "http_followup": lambda: plan_http_followup(targets, params, dry_run=dry_run),
        "sql_injection": lambda: plan_sql_injection(targets, params, dry_run=dry_run),
        "ssh_failure": lambda: plan_ssh_failure(targets, params, dry_run=dry_run),
        "ldap_enumeration": lambda: _plan_ldap_enumeration(targets, params, dry_run=dry_run),
        "smb_login_failure": lambda: _plan_smb_login_failure(targets, params, dry_run=dry_run),
        "kerberos_failure": lambda: _plan_kerberos_failure(targets, params, dry_run=dry_run),
        "dga": lambda: _plan_dga(targets, params, dry_run=dry_run),
        "rare_protocol_activity": lambda: plan_rare_protocol_activity(
            targets, params, dry_run=dry_run
        ),
    }
    builder = builders.get(scenario_id)
    if builder is None:
        return {"type": "skip", "mode": "skip", "reason": f"unsupported_scenario:{scenario_id}"}
    return builder()


def _plan_ldap_enumeration(
    targets: TargetSet, params: dict[str, Any], *, dry_run: bool
) -> dict[str, Any]:
    from dsp.protocols.ldap.attempts import plan_ldap_enumeration

    max_hosts = int(params.get("max_hosts", 2))
    hosts = select_hosts_for_capability(
        targets, params, capability="ldap_hosts", max_hosts=max_hosts
    )
    if not hosts:
        return {"type": "ldap_enumeration", "mode": "skip", "reason": "no_ldap_hosts"}
    ports = tuple(int(p) for p in (params.get("ports") or (389,)))
    plans = plan_ldap_enumeration(
        hosts,
        max_hosts=max_hosts,
        max_queries_per_host=int(params.get("max_queries_per_host", 10)),
        ports=ports,
        safe_mode=bool(params.get("safe_mode", True)),
    )
    return {
        "type": "ldap_enumeration",
        "mode": "mock" if dry_run else "live",
        "timeout": float(params.get("timeout", 5.0)),
        "actions": [
            {
                "host": plan.host,
                "port": plan.port,
                "action_type": plan.action_type,
                "search_filter": plan.search_filter,
            }
            for plan in plans
        ],
    }


def _plan_smb_login_failure(
    targets: TargetSet, params: dict[str, Any], *, dry_run: bool
) -> dict[str, Any]:
    from dsp.protocols.smb.attempts import plan_smb_attempts

    max_hosts = int(params.get("max_hosts", 2))
    hosts = select_hosts_for_capability(
        targets, params, capability="smb_hosts", max_hosts=max_hosts
    )
    if not hosts:
        return {"type": "smb_login_failure", "mode": "skip", "reason": "no_smb_hosts"}
    port = int(params.get("port", 445))
    plans = plan_smb_attempts(
        hosts,
        max_hosts=max_hosts,
        attempts_per_host=int(params.get("attempts_per_host", 10)),
        port=port,
        safe_mode=bool(params.get("safe_mode", True)),
    )
    return {
        "type": "smb_login_failure",
        "mode": "mock" if dry_run else "live",
        "timeout": float(params.get("timeout", 5.0)),
        "attempts": [
            {
                "host": plan.host,
                "port": plan.port,
                "username": plan.username,
                "password_label": plan.password_label,
            }
            for plan in plans
        ],
    }


def _plan_kerberos_failure(
    targets: TargetSet, params: dict[str, Any], *, dry_run: bool
) -> dict[str, Any]:
    from dsp.protocols.kerberos.attempts import plan_kerberos_attempts

    max_hosts = int(params.get("max_hosts", 2))
    hosts = select_hosts_for_capability(
        targets, params, capability="kerberos_hosts", max_hosts=max_hosts
    )
    if not hosts:
        return {"type": "kerberos_failure", "mode": "skip", "reason": "no_kerberos_hosts"}
    port = int(params.get("port", 88))
    realm = str(params.get("realm", "LOCAL.REALM"))
    plans = plan_kerberos_attempts(
        hosts,
        max_hosts=max_hosts,
        attempts_per_host=int(params.get("attempts_per_host", 10)),
        port=port,
        realm=realm,
        safe_mode=bool(params.get("safe_mode", True)),
    )
    return {
        "type": "kerberos_failure",
        "mode": "mock" if dry_run else "live",
        "timeout": float(params.get("timeout", 10.0)),
        "realm": realm,
        "attempts": [
            {
                "host": plan.host,
                "port": plan.port,
                "username": plan.username,
                "realm": plan.realm,
            }
            for plan in plans
        ],
    }


def _plan_dga(targets: TargetSet, params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    from dsp.protocols.dns.dga import (
        EFFECTIVE_TLD_DEFAULT,
        PHASE1_COUNT_DEFAULT,
        PHASE2_COUNT_DEFAULT,
        generate_nxdomain_fqdn,
        generate_resolvable_fqdn,
    )

    effective_tld = str(params.get("effective_tld", EFFECTIVE_TLD_DEFAULT))
    phase1_count = int(params.get("phase1_count", PHASE1_COUNT_DEFAULT))
    phase2_count = int(params.get("phase2_count", PHASE2_COUNT_DEFAULT))
    dns_hosts = list(targets.service_hosts.get("dns_hosts") or [])
    if params.get("resolver"):
        resolver = str(params["resolver"])
    elif dns_hosts:
        resolver = dns_hosts[0]
    else:
        return {"type": "dga", "mode": "skip", "reason": "no_dns_hosts"}
    domains: list[dict[str, Any]] = []
    seq = 0
    for phase, count, generator, phase_name in (
        (1, phase1_count, generate_nxdomain_fqdn, "nxdomain"),
        (2, phase2_count, generate_resolvable_fqdn, "resolvable"),
    ):
        for _ in range(count):
            seq += 1
            fqdn = generator(effective_tld)
            domains.append(
                {
                    "seq": seq,
                    "phase": phase,
                    "phase_name": phase_name,
                    "fqdn": fqdn,
                    "resolver": resolver,
                }
            )
    if not domains:
        return {"type": "dga", "mode": "skip", "reason": "no_domains_planned"}
    return {
        "type": "dga",
        "mode": "mock" if dry_run else "live",
        "resolver": resolver,
        "effective_tld": effective_tld,
        "domains": domains,
        "timeout": float(params.get("timeout", 0.05)),
    }


def build_scenario_plan(request: ScenarioExecutionRequest, targets: TargetSet) -> dict[str, Any]:
    params = dict(request.scenario_params)
    scenario_id = request.scenario_id
    if (
        uses_remote_discovery(request)
        and scenario_id != "host_behavior_check"
        and not targets.discovery_enabled
        and not targets.hosts
    ):
        return plan_remote_discovery_execute(request, dry_run=request.dry_run)
    return build_scenario_execution_plan(
        scenario_id,
        targets,
        params,
        dry_run=request.dry_run,
    )


def plan_port_sweep(targets: TargetSet, params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    plan_view = build_port_sweep_plan_view(targets, params)
    if not plan_view.selected_hosts or plan_view.selection_reason == "no_alive_hosts":
        return {
            "type": "port_sweep",
            "mode": "skip",
            "reason": "no_alive_hosts",
            "selection_reason": plan_view.selection_reason,
        }
    plans = build_port_sweep_plans(
        plan_view.selected_hosts,
        max_hosts=plan_view.max_hosts,
        ports=plan_view.selected_ports,
        max_ports=plan_view.max_ports,
        safe_mode=bool(params.get("safe_mode", True)),
    )
    return {
        "type": "port_sweep",
        "mode": "mock" if dry_run else "live",
        "timeout": float(params.get("timeout", 3.0)),
        "concurrency": max(1, int(params.get("concurrency", 32))),
        "selection_reason": plan_view.selection_reason,
        "probes": [
            {"host": plan.host, "port": plan.port, "artifact": plan.artifact}
            for plan in plans
        ],
    }


def plan_dns_tunnel(targets: TargetSet, params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    return build_dns_tunnel_plan(targets, params, dry_run=dry_run)


def plan_http_followup(targets: TargetSet, params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    max_hosts = int(params.get("max_hosts", 2))
    selection = resolve_http_endpoint_selection(
        targets,
        params,
        max_hosts=max_hosts,
        dry_run=dry_run,
        timeout=float(params.get("timeout", 10.0)),
    )
    if not selection.selected:
        return {"type": "http_followup", "mode": "skip", "reason": "no_http_endpoints"}

    endpoints = [(ep.host, ep.port) for ep in selection.selected]
    followup_hosts = [host for host, _ in endpoints]
    plans = plan_followup_requests(
        endpoints=endpoints,
        max_hosts=max_hosts,
        max_per_host=int(params.get("max_per_host", 10)),
        max_total=int(params.get("max_total", 20)),
        include_attack_paths=bool(params.get("include_attack_paths", True)),
    )
    enriched_plans, _ = attach_followup_user_agents(plans)
    burst_plan = plan_non_standard_port_burst(targets, followup_hosts, params)
    return {
        "type": "http_followup",
        "mode": "mock" if dry_run else "live",
        "timeout": float(params.get("timeout", 10.0)),
        "requests": [
            {
                "url": plan.url,
                "method": plan.method,
                "user_agent": (plan.headers or {}).get("User-Agent", "Mozilla/5.0"),
            }
            for plan in enriched_plans
        ],
        "non_standard_port_burst": burst_plan,
    }


def plan_sql_injection(targets: TargetSet, params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    max_hosts = int(params.get("max_hosts", 2))
    selection = resolve_http_endpoint_selection(
        targets,
        params,
        max_hosts=max_hosts,
        dry_run=dry_run,
        timeout=float(params.get("timeout", 10.0)),
    )
    if not selection.selected:
        return {"type": "sql_injection", "mode": "skip", "reason": "no_http_endpoints"}

    endpoints = [(ep.host, ep.port) for ep in selection.selected]
    plans = plan_sqli_requests(endpoints=endpoints, max_hosts=max_hosts)
    requests = sql_injection_request_items(plans)
    return {
        "type": "sql_injection",
        "mode": "mock" if dry_run else "live",
        "timeout": float(params.get("timeout", 10.0)),
        "requests": requests,
    }


def plan_ssh_failure(targets: TargetSet, params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    max_hosts = int(params.get("max_hosts", 2))
    hosts = select_hosts_for_capability(
        targets, params, capability="ssh_hosts", max_hosts=max_hosts
    )
    if not hosts:
        return {"type": "ssh_failure", "mode": "skip", "reason": "no_ssh_hosts"}

    port = int(params.get("port", SSH_PORT_DEFAULT))
    plans = plan_ssh_attempts(
        hosts,
        max_hosts=max_hosts,
        max_per_host=int(params.get("max_per_host", 150)),
        max_total=int(params.get("max_total", 150)),
        port=port,
    )
    return {
        "type": "ssh_failure",
        "mode": "mock" if dry_run else "live",
        "timeout": float(params.get("timeout", 5.0)),
        "attempts": [
            {
                "host": plan.host,
                "port": plan.port,
                "username": plan.username,
                "password_label": plan.password_label,
            }
            for plan in plans
        ],
    }


def plan_host_behavior_check(
    request: ScenarioExecutionRequest,
    params: dict[str, Any],
    *,
    dry_run: bool,
) -> dict[str, Any]:
    family = params.get("webshell_family") or request.execution_metadata.get(
        "webshell_family"
    )
    merged = dict(params)
    if family:
        merged["webshell_family"] = family
    return build_host_behavior_plan(
        merged,
        run_id=str(request.run_id),
        dry_run=dry_run,
        webshell_family=str(family) if family else None,
    )


def plan_rare_protocol_activity(
    targets: TargetSet,
    params: dict[str, Any],
    *,
    dry_run: bool,
) -> dict[str, Any]:
    plans = build_rare_protocol_plans(targets, params)
    if not plans:
        return {
            "type": "rare_protocol_activity",
            "mode": "skip",
            "reason": "no_valid_target",
        }
    return {
        "type": "rare_protocol_activity",
        "mode": "mock" if dry_run else "live",
        "timeout": float(params.get("timeout", 3.0)),
        "probes": [
            {
                "protocol": plan.protocol,
                "host": plan.host,
                "port": plan.port,
                "transport": plan.transport,
                "artifact": plan.artifact,
                "rtp_packets": plan.rtp_packets,
            }
            for plan in plans
        ],
    }

_uses_remote_discovery = uses_remote_discovery
_plan_remote_discovery_execute = plan_remote_discovery_execute
_build_plan = build_scenario_plan
_build_scenario_execution_plan = build_scenario_execution_plan
_plan_port_sweep = plan_port_sweep
_plan_dns_tunnel = plan_dns_tunnel
_plan_http_followup = plan_http_followup
_plan_sql_injection = plan_sql_injection
_plan_ssh_failure = plan_ssh_failure
_plan_host_behavior_check = plan_host_behavior_check
_plan_rare_protocol_activity = plan_rare_protocol_activity
