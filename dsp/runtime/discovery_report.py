"""Discovery → scenario follow-up mapping for run reports."""

from __future__ import annotations

from typing import Any

# Port → (service label, transport) for human-readable discovery reports.
_PORT_SERVICE: dict[int, tuple[str, str]] = {
    22: ("SSH", "tcp"),
    53: ("DNS", "udp"),
    80: ("HTTP", "tcp"),
    88: ("Kerberos", "tcp"),
    389: ("LDAP", "tcp"),
    443: ("HTTPS", "tcp"),
    445: ("SMB", "tcp"),
    636: ("LDAPS", "tcp"),
    8080: ("HTTP", "tcp"),
    8443: ("HTTPS", "tcp"),
    8888: ("HTTP", "tcp"),
    9000: ("HTTP", "tcp"),
    9090: ("HTTP", "tcp"),
}

# Capability bucket → follow-up scenario ids (execution order hint).
CAPABILITY_FOLLOWUPS: dict[str, tuple[str, ...]] = {
    "ssh_hosts": ("ssh_failure",),
    "dns_hosts": ("dga", "dns_tunnel"),
    "http_targets": ("http_followup", "sql_injection"),
    "https_targets": ("http_followup", "sql_injection"),
    "smb_hosts": ("smb_login_failure",),
    "kerberos_hosts": ("kerberos_failure",),
    "ldap_hosts": ("ldap_enumeration",),
}


def normalize_discovery_meta(discovery_meta: dict[str, Any] | None) -> dict[str, Any]:
    """Normalize TargetSet.discovery_meta into JSON-friendly discovery report fields."""
    meta = dict(discovery_meta or {})
    service_hosts = dict(meta.get("service_hosts") or {})
    raw_endpoints = meta.get("service_endpoints") or {}
    service_endpoints: dict[str, list[dict[str, Any]]] = {}
    for cap, endpoints in dict(raw_endpoints).items():
        rows: list[dict[str, Any]] = []
        for item in endpoints or []:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                host, port = str(item[0]), int(item[1])
            elif isinstance(item, dict):
                host, port = str(item.get("host", "")), int(item.get("port", 0))
            else:
                continue
            service, protocol = _PORT_SERVICE.get(port, ("unknown", "tcp"))
            rows.append(
                {
                    "host": host,
                    "port": port,
                    "protocol": protocol,
                    "service": service,
                    "capability": cap,
                    "follow_up_scenarios": list(CAPABILITY_FOLLOWUPS.get(cap, ())),
                }
            )
        service_endpoints[cap] = rows

    hosts = _hosts_from_discovery(meta, service_hosts, service_endpoints)
    return {
        "enabled": bool(meta.get("enabled", False) or service_hosts or meta.get("alive_hosts")),
        "probed_hosts": int(meta.get("probed_hosts") or 0),
        "alive_hosts": list(meta.get("alive_hosts") or []),
        "open_endpoints": int(meta.get("open_endpoints") or 0),
        "service_hosts": service_hosts,
        "service_endpoints": service_endpoints,
        "hosts": hosts,
    }


def _hosts_from_discovery(
    meta: dict[str, Any],
    service_hosts: dict[str, list[str]],
    service_endpoints: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    by_host: dict[str, list[dict[str, Any]]] = {}
    for rows in service_endpoints.values():
        for row in rows:
            by_host.setdefault(row["host"], []).append(row)

    ordered_hosts = list(meta.get("alive_hosts") or [])
    for host in _flatten_hosts(service_hosts):
        if host not in ordered_hosts:
            ordered_hosts.append(host)

    hosts: list[dict[str, Any]] = []
    for host in ordered_hosts:
        services = by_host.get(host, [])
        if not services:
            hosts.append({"host": host, "services": []})
            continue
        # Deduplicate by port while preserving order.
        seen_ports: set[int] = set()
        unique: list[dict[str, Any]] = []
        for svc in services:
            port = int(svc["port"])
            if port in seen_ports:
                continue
            seen_ports.add(port)
            unique.append(svc)
        hosts.append({"host": host, "services": unique})
    return hosts


def _flatten_hosts(service_hosts: dict[str, list[str]]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for hosts in service_hosts.values():
        for host in hosts or []:
            if host not in seen:
                seen.add(host)
                out.append(str(host))
    return out


def format_discovery_report_lines(discovery: dict[str, Any]) -> list[str]:
    """Render markdown lines for Discovered Hosts section."""
    lines = [
        "## Discovered Hosts",
        "",
    ]
    if not discovery.get("enabled") and not discovery.get("hosts"):
        lines.extend(["_Discovery was not enabled or returned no hosts._", ""])
        return lines

    lines.append(f"- **Probed hosts:** {discovery.get('probed_hosts', 0)}")
    lines.append(f"- **Alive hosts:** {len(discovery.get('alive_hosts') or [])}")
    lines.append(f"- **Open endpoints:** {discovery.get('open_endpoints', 0)}")
    lines.append("")

    hosts = discovery.get("hosts") or []
    if not hosts:
        lines.extend(["_No discovered services._", ""])
        return lines

    for entry in hosts:
        host = entry.get("host", "")
        lines.append(f"### {host}")
        lines.append("")
        services = entry.get("services") or []
        if not services:
            lines.append("- _(alive, no mapped service ports)_")
            lines.append("")
            continue
        for svc in services:
            label = svc.get("service", "unknown")
            protocol = svc.get("protocol", "tcp")
            port = svc.get("port", "?")
            followups = svc.get("follow_up_scenarios") or []
            follow = ", ".join(followups) if followups else "(none)"
            lines.append(f"- {label} {protocol}/{port}")
            lines.append(f"  - follow-up: {follow}")
        lines.append("")
    return lines


def discovery_basis_for_scenario(
    scenario_id: str,
    discovery: dict[str, Any],
) -> dict[str, Any]:
    """Link a scenario to the discovery capabilities that selected it."""
    relevant_caps = [
        cap for cap, scenarios in CAPABILITY_FOLLOWUPS.items() if scenario_id in scenarios
    ]
    hosts: list[str] = []
    endpoints: list[dict[str, Any]] = []
    service_hosts = discovery.get("service_hosts") or {}
    service_endpoints = discovery.get("service_endpoints") or {}
    for cap in relevant_caps:
        for host in service_hosts.get(cap) or []:
            if host not in hosts:
                hosts.append(host)
        endpoints.extend(list(service_endpoints.get(cap) or []))
    return {
        "capabilities": relevant_caps,
        "hosts": hosts,
        "endpoints": endpoints,
    }
