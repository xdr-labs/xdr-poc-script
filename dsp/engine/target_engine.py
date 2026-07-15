"""Target resolution from operator-supplied target_net CIDR."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable

from dsp.engine.scenario_engine import TargetSet

DEFAULT_LAB_TARGET_NET = "10.10.10.0/24"
DEFAULT_LAB_FALLBACK_HOST = "10.10.10.20"
MAX_EXPANDED_HOSTS = 32
DISCOVERY_MAX_HOSTS = 254


def expand_target_net_hosts(target_net: str, *, max_hosts: int = MAX_EXPANDED_HOSTS) -> list[str]:
    """Return usable host IPs from a CIDR (network/broadcast excluded for IPv4)."""
    network = ipaddress.ip_network(target_net.strip(), strict=False)
    hosts: list[str] = []
    for addr in network.hosts():
        hosts.append(str(addr))
        if len(hosts) >= max_hosts:
            break
    return hosts


def host_in_target_net(host: str, target_net: str) -> bool:
    """Return True when host is a member of target_net."""
    return ipaddress.ip_address(host) in ipaddress.ip_network(target_net.strip(), strict=False)


def resolve_targets(
    target_net: str,
    required_capabilities: list[str] | None = None,
    *,
    max_hosts: int | None = None,
    discovery: bool = False,
    dry_run: bool = False,
    on_discovery_progress: Callable[[dict[str, int]], None] | None = None,
) -> TargetSet:
    """Build TargetSet from target_net; optional bash-aligned TCP service discovery."""
    caps = {cap: True for cap in (required_capabilities or [])}
    caps.setdefault("alive_host", True)

    net = (target_net or "").strip()
    if not net:
        raise ValueError(
            "target_net is required; refusing silent lab fallback "
            f"(removed default {DEFAULT_LAB_FALLBACK_HOST})"
        )

    expand_limit = DISCOVERY_MAX_HOSTS if discovery else (max_hosts if max_hosts is not None else MAX_EXPANDED_HOSTS)
    hosts = expand_target_net_hosts(net, max_hosts=expand_limit)
    if not hosts:
        raise ValueError(f"target_net has no usable hosts: {net}")

    service_hosts: dict[str, list[str]] = {}
    service_endpoints: dict[str, list[tuple[str, int]]] = {}
    discovery_enabled = False
    discovery_meta: dict[str, object] = {}

    if discovery and not dry_run:
        from dsp.discovery.legacy_bash import discover_services

        result = discover_services(
            net,
            max_hosts=DISCOVERY_MAX_HOSTS,
            on_progress=on_discovery_progress,
        )
        service_hosts = result.service_hosts
        service_endpoints = result.service_endpoints
        discovery_enabled = True
        discovery_meta = {
            "probed_hosts": result.probed_hosts,
            "alive_hosts": result.alive_hosts,
            "open_endpoints": result.open_endpoints,
            "service_hosts": service_hosts,
            "service_endpoints": service_endpoints,
        }
        # Discovery-first: never keep CIDR expansion when discovery ran.
        hosts = list(result.alive_hosts)

    return TargetSet(
        target_net=net,
        hosts=hosts,
        capabilities=caps,
        service_hosts=service_hosts,
        service_endpoints=service_endpoints,
        discovery_enabled=discovery_enabled,
        discovery_meta=discovery_meta,
    )
