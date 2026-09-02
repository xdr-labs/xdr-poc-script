"""Discovery layer ported from stellar_poc_fast_safe.sh / stellar_poc.sh."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from dsp.engine.target_engine import expand_target_net_hosts, host_in_target_net

# stellar_poc_fast_safe.sh FAST_SAFE_DISCOVERY_PORTS
FAST_SAFE_DISCOVERY_PORTS: tuple[int, ...] = (
    22,
    53,
    80,
    88,
    389,
    443,
    445,
    636,
    8080,
    8443,
    8888,
    9000,
    9090,
)

# stellar_poc_fast_safe.sh fast_safe_discovery_port_target_file
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

DISCOVERY_MAX_HOSTS = 254
DEFAULT_PROBE_TIMEOUT_SEC = 0.5
DEFAULT_PROBE_WORKERS = 32


def port_capability_key(port: int) -> str | None:
    return PORT_CAPABILITY_MAP.get(port)


def probe_tcp_port(host: str, port: int, *, timeout: float = DEFAULT_PROBE_TIMEOUT_SEC) -> bool:
    """TCP connect probe — same intent as bash poc_port_probe (nc/bash /dev/tcp)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


HttpEndpoint = tuple[str, int]


@dataclass
class DiscoveryResult:
    """Service discovery output aligned with bash remote_hosts/*.txt files."""

    target_net: str
    service_hosts: dict[str, list[str]] = field(default_factory=dict)
    service_endpoints: dict[str, list[HttpEndpoint]] = field(default_factory=dict)
    alive_hosts: list[str] = field(default_factory=list)
    probed_hosts: int = 0
    open_endpoints: int = 0

    def hosts_for(self, capability: str) -> list[str]:
        return list(self.service_hosts.get(capability, []))

    def endpoints_for(self, capability: str) -> list[HttpEndpoint]:
        return list(self.service_endpoints.get(capability, []))

    def merged_http_hosts(self) -> list[str]:
        seen: set[str] = set()
        merged: list[str] = []
        for key in ("http_targets", "https_targets"):
            for host in self.hosts_for(key):
                if host not in seen:
                    seen.add(host)
                    merged.append(host)
        return merged


def discover_services(
    target_net: str,
    *,
    ports: tuple[int, ...] = FAST_SAFE_DISCOVERY_PORTS,
    max_hosts: int = DISCOVERY_MAX_HOSTS,
    timeout: float = DEFAULT_PROBE_TIMEOUT_SEC,
    workers: int = DEFAULT_PROBE_WORKERS,
) -> DiscoveryResult:
    """
    Probe target_net hosts on key ports (bash fast-safe service discovery).

    Scans expanded /24 hosts and maps open ports to capability host lists.
    """
    net = target_net.strip()
    candidates = expand_target_net_hosts(net, max_hosts=max_hosts)
    service_hosts: dict[str, list[str]] = {
        "ssh_hosts": [],
        "dns_hosts": [],
        "http_targets": [],
        "https_targets": [],
        "smb_hosts": [],
        "kerberos_hosts": [],
        "ldap_hosts": [],
    }
    service_endpoints: dict[str, list[HttpEndpoint]] = {
        "ssh_hosts": [],
        "dns_hosts": [],
        "http_targets": [],
        "https_targets": [],
        "smb_hosts": [],
        "kerberos_hosts": [],
        "ldap_hosts": [],
    }
    alive: set[str] = set()
    open_count = 0

    jobs: list[tuple[str, int, str]] = []
    for host in candidates:
        if not host_in_target_net(host, net):
            continue
        for port in ports:
            cap = port_capability_key(port)
            if cap is not None:
                jobs.append((host, port, cap))

    if not jobs:
        return DiscoveryResult(
            target_net=net,
            service_hosts=service_hosts,
            service_endpoints=service_endpoints,
            probed_hosts=0,
        )

    worker_count = max(1, min(workers, len(jobs)))
    with ThreadPoolExecutor(max_workers=worker_count) as pool:
        future_map = {
            pool.submit(probe_tcp_port, host, port, timeout=timeout): (host, port, cap)
            for host, port, cap in jobs
        }
        for future in as_completed(future_map):
            host, port, cap = future_map[future]
            try:
                if future.result():
                    open_count += 1
                    alive.add(host)
                    bucket = service_hosts.setdefault(cap, [])
                    if host not in bucket:
                        bucket.append(host)
                    ep_bucket = service_endpoints.setdefault(cap, [])
                    if (host, port) not in ep_bucket:
                        ep_bucket.append((host, port))
            except OSError:
                continue

    for cap in service_hosts:
        service_hosts[cap].sort(key=lambda h: tuple(int(p) for p in h.split(".")))
    for cap in service_endpoints:
        service_endpoints[cap].sort(key=lambda ep: (tuple(int(p) for p in ep[0].split(".")), ep[1]))

    return DiscoveryResult(
        target_net=net,
        service_hosts=service_hosts,
        service_endpoints=service_endpoints,
        alive_hosts=sorted(alive, key=lambda h: tuple(int(p) for p in h.split("."))),
        probed_hosts=len(candidates),
        open_endpoints=open_count,
    )
