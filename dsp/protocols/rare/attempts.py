"""Rare protocol activity planning — discovery-first target selection."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Any

from dsp.engine.scenario_engine import TargetSet
from dsp.runtime.scenario_plan import INITIAL_COMPROMISE_ENDPOINT_KEY, WEBSHELL_EXECUTION_KEY

RARE_PROTOCOL_PORTS: dict[str, int] = {
    "TELNET": 23,
    "RTSP": 554,
    "SIP": 5060,
    "RTP": 5004,
}

DEFAULT_RTP_BURST = 8
MAX_RTP_BURST = 32

# Loopback / unresolved names that must never be invented as probe targets.
_FORBIDDEN_LOCALHOST = frozenset({"127.0.0.1", "::1", "localhost"})


@dataclass(frozen=True)
class PlannedRareProbe:
    """Single rare-protocol probe action."""

    protocol: str
    host: str
    port: int
    transport: str
    artifact: str
    rtp_packets: int = 0


def _local_interface_ips() -> set[str]:
    """IPs assigned to this host — probing them from local provider yields no br0 packets."""
    ips: set[str] = set(_FORBIDDEN_LOCALHOST)
    try:
        import fcntl
        import struct

        for _idx, name in socket.if_nameindex():
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    ifreq = struct.pack("256s", name.encode("utf-8")[:15])
                    res = fcntl.ioctl(s.fileno(), 0x8915, ifreq)
                    ips.add(socket.inet_ntoa(res[20:24]))
            except OSError:
                continue
    except OSError:
        pass
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            addr = info[4][0]
            if addr:
                ips.add(str(addr))
    except OSError:
        pass
    return ips


def _is_unusable_probe_host(host: str, *, local_ips: set[str] | None = None) -> bool:
    if host in _FORBIDDEN_LOCALHOST:
        return True
    blocked = local_ips if local_ips is not None else _local_interface_ips()
    return host in blocked


def _webshell_origin_host(params: dict[str, Any]) -> str:
    """Return webshell/initial-compromise origin host when present — never invents targets."""
    endpoint = params.get(INITIAL_COMPROMISE_ENDPOINT_KEY)
    if isinstance(endpoint, dict) and endpoint.get("host"):
        return str(endpoint["host"])
    ws_ctx = params.get(WEBSHELL_EXECUTION_KEY)
    if isinstance(ws_ctx, dict) and ws_ctx.get("execution_host"):
        return str(ws_ctx["execution_host"])
    if params.get("execution_host"):
        return str(params["execution_host"])
    return ""


def _discovered_rare_endpoints(targets: TargetSet) -> list[tuple[str, int, str]]:
    rare_ports = set(RARE_PROTOCOL_PORTS.values())
    port_to_protocol = {port: name for name, port in RARE_PROTOCOL_PORTS.items()}
    found: list[tuple[str, int, str]] = []
    seen: set[tuple[str, int]] = set()

    for endpoints in targets.service_endpoints.values():
        for host, port in endpoints:
            if port in rare_ports and (host, port) not in seen:
                seen.add((host, port))
                found.append((host, port, port_to_protocol[port]))

    meta = targets.discovery_meta or {}
    open_eps = meta.get("open_endpoints")
    if isinstance(open_eps, list):
        for item in open_eps:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                host, port = str(item[0]), int(item[1])
                if port in rare_ports and (host, port) not in seen:
                    seen.add((host, port))
                    found.append((host, port, port_to_protocol[port]))

    return found


def _alive_probe_hosts(targets: TargetSet, params: dict[str, Any]) -> list[str]:
    """Discovery alive hosts for rare-protocol fallback.

    Host fan-out follows ``max_hosts`` (normal: capped; high: all discovered).
    Excludes webshell origin and local interface IPs.
    """
    origin = _webshell_origin_host(params)
    local_ips = _local_interface_ips()
    meta = targets.discovery_meta or {}
    raw_alive = [str(h) for h in (meta.get("alive_hosts") or targets.hosts or [])]
    usable = [
        h
        for h in raw_alive
        if h != origin and not _is_unusable_probe_host(h, local_ips=local_ips)
    ]
    if not usable:
        return []
    cap = params.get("max_hosts")
    if cap is None:
        return usable[:1]
    limit = max(1, int(cap))
    return usable[:limit]


def _probe_fallback_hosts(targets: TargetSet, params: dict[str, Any]) -> list[str]:
    """Return explicit or discovery live hosts only — no localhost/CIDR/self-IP invention."""
    local_ips = _local_interface_ips()
    if params.get("probe_hosts"):
        return [
            str(h)
            for h in params["probe_hosts"]
            if not _is_unusable_probe_host(str(h), local_ips=local_ips)
        ]
    if params.get("hosts"):
        return [
            str(h)
            for h in params["hosts"]
            if not _is_unusable_probe_host(str(h), local_ips=local_ips)
        ]
    return _alive_probe_hosts(targets, params)


def _transport_for(protocol: str) -> str:
    if protocol == "RTP":
        return "udp"
    if protocol == "SIP":
        return "udp_tcp"
    return "tcp"


def plan_rare_protocol_activity(
    targets: TargetSet,
    params: dict[str, Any],
) -> list[PlannedRareProbe]:
    """Build rare-protocol probes — discovery endpoints first, live-host fallback.

    Returns an empty list (caller skips) when no rare-port endpoint and no valid
    live/explicit host exist. Never invents ``127.0.0.1``, CIDR hosts, or local
    interface IPs (self-target yields no observable br0 packets for local provider).
    """
    plans: list[PlannedRareProbe] = []
    seen: set[tuple[str, int, str]] = set()
    local_ips = _local_interface_ips()
    rtp_burst = min(
        MAX_RTP_BURST,
        max(1, int(params.get("rtp_burst_count", DEFAULT_RTP_BURST))),
    )

    explicit = params.get("targets") or []
    for item in explicit:
        protocol = str(item.get("protocol", "")).upper()
        host = str(item.get("host", ""))
        port = int(item.get("port", RARE_PROTOCOL_PORTS.get(protocol, 0)))
        if not protocol or not host or port <= 0:
            continue
        if _is_unusable_probe_host(host, local_ips=local_ips):
            continue
        key = (host, port, protocol)
        if key in seen:
            continue
        seen.add(key)
        plans.append(
            PlannedRareProbe(
                protocol=protocol,
                host=host,
                port=port,
                transport=_transport_for(protocol),
                artifact=f"{protocol.lower()}:{host}:{port}",
                rtp_packets=rtp_burst if protocol == "RTP" else 0,
            )
        )

    for host, port, protocol in _discovered_rare_endpoints(targets):
        if _is_unusable_probe_host(host, local_ips=local_ips):
            continue
        key = (host, port, protocol)
        if key in seen:
            continue
        seen.add(key)
        plans.append(
            PlannedRareProbe(
                protocol=protocol,
                host=host,
                port=port,
                transport=_transport_for(protocol),
                artifact=f"{protocol.lower()}:{host}:{port}",
                rtp_packets=rtp_burst if protocol == "RTP" else 0,
            )
        )

    protocols_needed = {p for p in RARE_PROTOCOL_PORTS if not any(pl.protocol == p for pl in plans)}
    if protocols_needed:
        for host in _probe_fallback_hosts(targets, params):
            if _is_unusable_probe_host(host, local_ips=local_ips):
                continue
            for protocol in sorted(protocols_needed):
                port = RARE_PROTOCOL_PORTS[protocol]
                key = (host, port, protocol)
                if key in seen:
                    continue
                seen.add(key)
                plans.append(
                    PlannedRareProbe(
                        protocol=protocol,
                        host=host,
                        port=port,
                        transport=_transport_for(protocol),
                        artifact=f"{protocol.lower()}:{host}:{port}",
                        rtp_packets=rtp_burst if protocol == "RTP" else 0,
                    )
                )

    return plans
