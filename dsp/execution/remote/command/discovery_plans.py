"""Webshell command-only discovery-based scenario planning."""

from __future__ import annotations

import base64
import ipaddress
import random
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from dsp.protocols.http.urls import plan_followup_requests
from dsp.protocols.http.user_agents import attach_followup_user_agents
from dsp.protocols.dns.dga import (
    EFFECTIVE_TLD_DEFAULT,
    PHASE1_COUNT_DEFAULT,
    PHASE2_COUNT_DEFAULT,
    generate_nxdomain_fqdn,
    generate_resolvable_fqdn,
)
from dsp.protocols.kerberos.attempts import plan_kerberos_attempts
from dsp.protocols.ldap.attempts import plan_ldap_enumeration
from dsp.protocols.smb.attempts import plan_smb_attempts
from dsp.runtime.http_endpoint_selection import select_discovered_http_endpoint_tuples
from dsp.runtime.scenario_plan import webshell_server_endpoint

DISCOVERY_PORTS: tuple[int, ...] = (22, 53, 80, 88, 389, 443, 445, 636, 8080, 8443, 8888, 9000, 9090)
PORT_CAPABILITY_MAP: dict[int, str] = {
    443: "https_targets",
    8443: "https_targets",
    80: "http_targets",
    8080: "http_targets",
    8888: "http_targets",
    9000: "http_targets",
    9090: "http_targets",
    22: "ssh_hosts",
    53: "dns_hosts",
    88: "kerberos_hosts",
    389: "ldap_hosts",
    636: "ldap_hosts",
    445: "smb_hosts",
}
DEFAULT_PROBE_TIMEOUT = 0.5
DEFAULT_PROBE_WORKERS = 32
SSH_USERNAMES = ("invaliduser", "admin", "root")
DEFAULT_PORTS = (22, 80, 443, 445, 8080, 8443)


def expand_target_net_hosts(target_net: str, *, max_hosts: int = 254) -> list[str]:
    network = ipaddress.ip_network(target_net.strip(), strict=False)
    hosts: list[str] = []
    for addr in network.hosts():
        hosts.append(str(addr))
        if len(hosts) >= max_hosts:
            break
    return hosts


def _tcp_probe(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def discover_target_net(
    target_net: str,
    *,
    ports: tuple[int, ...] = DISCOVERY_PORTS,
    max_hosts: int = 254,
    timeout: float = DEFAULT_PROBE_TIMEOUT,
    workers: int = DEFAULT_PROBE_WORKERS,
) -> dict[str, Any]:
    """Live host + service discovery from the webshell host vantage point."""
    candidates = expand_target_net_hosts(target_net, max_hosts=max_hosts)
    service_hosts: dict[str, list[str]] = {
        "ssh_hosts": [],
        "dns_hosts": [],
        "kerberos_hosts": [],
        "ldap_hosts": [],
        "http_targets": [],
        "https_targets": [],
        "smb_hosts": [],
    }
    service_endpoints: dict[str, list[tuple[str, int]]] = {
        "ssh_hosts": [],
        "dns_hosts": [],
        "kerberos_hosts": [],
        "ldap_hosts": [],
        "http_targets": [],
        "https_targets": [],
        "smb_hosts": [],
    }
    alive: set[str] = set()
    open_endpoints = 0

    def _probe(host: str, port: int) -> tuple[str, int, str | None]:
        if not _tcp_probe(host, port, timeout):
            return host, port, None
        return host, port, PORT_CAPABILITY_MAP.get(port)

    tasks = [(host, port) for host in candidates for port in ports]
    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(tasks)))) as pool:
        futures = [pool.submit(_probe, host, port) for host, port in tasks]
        for future in as_completed(futures):
            host, port, capability = future.result()
            if capability is None:
                continue
            alive.add(host)
            open_endpoints += 1
            bucket = service_hosts.setdefault(capability, [])
            if host not in bucket:
                bucket.append(host)
            service_endpoints.setdefault(capability, []).append((host, port))

    for key in service_hosts:
        service_hosts[key] = sorted(service_hosts[key], key=lambda h: tuple(int(p) for p in h.split(".")))
    alive_hosts = sorted(alive, key=lambda h: tuple(int(p) for p in h.split(".")))
    return {
        "target_net": target_net,
        "hosts": alive_hosts,
        "service_hosts": service_hosts,
        "service_endpoints": service_endpoints,
        "discovery_enabled": True,
        "discovery_meta": {
            "probed_hosts": len(candidates),
            "alive_hosts": alive_hosts,
            "open_endpoints": open_endpoints,
            "service_hosts": service_hosts,
            "discovery_origin": "webshell_host",
        },
    }


def _hosts_for(targets: dict[str, Any], capability: str) -> list[str]:
    return list((targets.get("service_hosts") or {}).get(capability, []))


def _resolve_http_plan_endpoints(
    targets: dict[str, Any],
    params: dict[str, Any],
    *,
    dry_run: bool = False,
) -> tuple[list[tuple[str, int]], dict[str, object]]:
    from dsp.engine.host_selection import (
        http_selection_summary_fields,
        resolve_discovery_http_selection,
    )

    target_set = _targets_to_target_set(targets)
    max_hosts = int(params.get("max_hosts", 2))
    selection = resolve_discovery_http_selection(
        target_set,
        params,
        max_hosts=max_hosts,
        dry_run=dry_run,
        webshell_mode=True,
        timeout=float(params.get("timeout", 10.0)),
    )
    if selection.selected:
        endpoints = [(ep.host, ep.port) for ep in selection.selected]
        return endpoints, http_selection_summary_fields(selection, target_set)

    http_hosts = _hosts_for(targets, "http_targets")
    http_endpoints = list((targets.get("service_endpoints") or {}).get("http_targets", []))
    endpoints = select_discovered_http_endpoint_tuples(
        http_hosts=http_hosts,
        http_endpoints=http_endpoints,
        max_hosts=max_hosts,
        explicit_hosts=None,
        explicit_port=int(params.get("port", 80)),
    )
    return endpoints, http_selection_summary_fields(selection, target_set)


def _select_http_endpoints(
    targets: dict[str, Any],
    params: dict[str, Any],
    *,
    dry_run: bool = False,
) -> list[tuple[str, int]]:
    endpoints, _ = _resolve_http_plan_endpoints(targets, params, dry_run=dry_run)
    return endpoints


def _plan_http_followup(targets: dict[str, Any], params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    endpoints, selection_fields = _resolve_http_plan_endpoints(targets, params, dry_run=dry_run)
    if not endpoints:
        return {"type": "http_followup", "mode": "skip", "reason": "no_http_endpoints"}
    max_hosts = int(params.get("max_hosts", 2))
    plans = plan_followup_requests(
        endpoints=endpoints,
        max_hosts=max_hosts,
        max_per_host=int(params.get("max_per_host", 500)),
        max_total=int(params.get("max_total", 1000)),
        include_attack_paths=bool(params.get("include_attack_paths", True)),
    )
    enriched_plans, _ = attach_followup_user_agents(plans)
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
        "non_standard_port_burst": {"enabled": False},
        **selection_fields,
    }


def _plan_ssh_failure(targets: dict[str, Any], params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    max_hosts = int(params.get("max_hosts", 2))
    hosts = _hosts_for(targets, "ssh_hosts")[:max_hosts]
    if not hosts:
        return {"type": "ssh_failure", "mode": "skip", "reason": "no_ssh_hosts"}
    port = int(params.get("port", 22))
    max_total = int(params.get("max_total", 150))
    attempts: list[dict[str, Any]] = []
    for host in hosts:
        for index in range(min(int(params.get("max_per_host", 150)), max_total - len(attempts))):
            attempts.append(
                {
                    "host": host,
                    "port": port,
                    "username": SSH_USERNAMES[index % len(SSH_USERNAMES)],
                    "password_label": "Password123",
                }
            )
            if len(attempts) >= max_total:
                break
    return {
        "type": "ssh_failure",
        "mode": "mock" if dry_run else "live",
        "timeout": float(params.get("timeout", 5.0)),
        "attempts": attempts,
    }


def _plan_port_sweep(targets: dict[str, Any], params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    max_hosts = int(params.get("max_hosts", 2))
    hosts = list(targets.get("hosts") or [])[:max_hosts]
    if not hosts:
        return {"type": "port_sweep", "mode": "skip", "reason": "no_alive_hosts"}
    ports = tuple(int(p) for p in (params.get("ports") or DEFAULT_PORTS))
    max_ports = int(params.get("max_ports", len(ports)))
    selected_ports = ports[:max_ports]
    probes = [
        {"host": host, "port": port, "artifact": f"{host}:{port}"}
        for host in hosts
        for port in selected_ports
    ]
    return {
        "type": "port_sweep",
        "mode": "mock" if dry_run else "live",
        "timeout": float(params.get("timeout", 3.0)),
        "concurrency": max(1, int(params.get("concurrency", 32))),
        "probes": probes,
    }


def _targets_to_target_set(targets: dict[str, Any]) -> Any:
    from dsp.engine.scenario_engine import TargetSet

    return TargetSet(
        target_net=str(targets.get("target_net") or ""),
        hosts=list(targets.get("hosts") or []),
        service_hosts=dict(targets.get("service_hosts") or {}),
        service_endpoints={
            key: [tuple(item) for item in value]
            for key, value in (targets.get("service_endpoints") or {}).items()
        },
        discovery_enabled=bool(targets.get("discovery_enabled", True)),
        discovery_meta=dict(targets.get("discovery_meta") or {}),
    )


def _plan_dns_tunnel(targets: dict[str, Any], params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    from dsp.protocols.dns.tunnel import plan_dns_tunnel

    return plan_dns_tunnel(_targets_to_target_set(targets), params, dry_run=dry_run)


def _plan_dga(targets: dict[str, Any], params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    effective_tld = str(params.get("effective_tld", EFFECTIVE_TLD_DEFAULT))
    phase1_count = int(params.get("phase1_count", PHASE1_COUNT_DEFAULT))
    phase2_count = int(params.get("phase2_count", PHASE2_COUNT_DEFAULT))
    dns_hosts = _hosts_for(targets, "dns_hosts")
    if not dns_hosts:
        return {"type": "dga", "mode": "skip", "reason": "no_dns_hosts"}
    resolver = dns_hosts[0]
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


def _plan_ldap_enumeration(targets: dict[str, Any], params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    max_hosts = int(params.get("max_hosts", 2))
    hosts = _hosts_for(targets, "ldap_hosts")[:max_hosts]
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


def _plan_smb_login_failure(targets: dict[str, Any], params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    max_hosts = int(params.get("max_hosts", 2))
    hosts = _hosts_for(targets, "smb_hosts")[:max_hosts]
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


def _plan_kerberos_failure(targets: dict[str, Any], params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    max_hosts = int(params.get("max_hosts", 2))
    hosts = _hosts_for(targets, "kerberos_hosts")[:max_hosts]
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


def _plan_host_behavior_check(params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    from dsp.protocols.host.behavior import build_host_behavior_plan

    if webshell_server_endpoint(params) is None:
        return {
            "type": "host_behavior_check",
            "mode": "skip",
            "reason": "no_webshell_url",
        }
    return build_host_behavior_plan(
        params,
        run_id=str(params.get("run_id") or "remote"),
        dry_run=dry_run,
        webshell_family=params.get("webshell_family"),
    )


def _plan_rare_protocol_activity(targets: dict[str, Any], params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    from dsp.protocols.rare.attempts import plan_rare_protocol_activity

    plans = plan_rare_protocol_activity(_targets_to_target_set(targets), params)
    if not plans:
        return {"type": "rare_protocol_activity", "mode": "skip", "reason": "no_probe_plans"}
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


def build_plan_from_discovery(
    scenario_id: str,
    targets: dict[str, Any],
    params: dict[str, Any],
    *,
    dry_run: bool,
) -> dict[str, Any]:
    """Build an executable scenario plan from discovery results — provider-independent."""
    from dsp.execution.remote.command.scenario_plans import build_scenario_execution_plan

    target_set = _targets_to_target_set(targets)
    return build_scenario_execution_plan(
        scenario_id,
        target_set,
        params,
        dry_run=dry_run,
    )


def resolve_remote_discovery_plan(plan: dict[str, Any]) -> dict[str, Any]:
    """Run discovery on the webshell host and materialize the scenario plan."""
    discovery_cfg = dict(plan.get("discovery") or {})
    target_net = str(discovery_cfg.get("target_net") or "")
    max_hosts = int(discovery_cfg.get("max_hosts", 254))
    ports = tuple(int(p) for p in (discovery_cfg.get("ports") or DISCOVERY_PORTS))
    dry_run = plan.get("mode") == "mock"
    scenario_id = str(plan.get("scenario_id") or "")
    params = dict(plan.get("params") or {})
    targets = discover_target_net(target_net, ports=ports, max_hosts=max_hosts)
    executable = build_plan_from_discovery(scenario_id, targets, params, dry_run=dry_run)
    executable["discovery_result"] = targets.get("discovery_meta")
    return executable
