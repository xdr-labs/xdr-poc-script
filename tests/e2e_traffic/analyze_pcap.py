#!/usr/bin/env python3
"""Analyze capture.pcap and write pcap_summary.json for DSP Traffic Regression E2E."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any


HTTP_PORTS = {80, 8000, 8080, 8081}
RARE_PORTS = {
    23: "TELNET",
    554: "RTSP",
    5060: "SIP",
    5004: "RTP",
    5005: "RTP",
}


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def _empty_summary(*, mode: str, error: str | None = None) -> dict[str, Any]:
    return {
        "mode": mode,
        "error": error,
        "total_packets": 0,
        "tcp_packets": 0,
        "udp_packets": 0,
        "icmp_packets": 0,
        "http_requests": 0,
        "dns_queries": 0,
        "udp_53_packets": 0,
        "tcp_22_packets": 0,
        "tcp_80_packets": 0,
        "tcp_8080_packets": 0,
        "tcp_389_packets": 0,
        "tcp_445_packets": 0,
        "tcp_88_packets": 0,
        "udp_88_packets": 0,
        "unique_sources": [],
        "unique_destinations": [],
        "dst_port_counts": {},
        "src_dst_port_counts": {},
        "http_methods": {},
        "http_hosts": [],
        "http_uris": [],
        "http_user_agents": [],
        "dns_query_names": [],
        "rare_protocol_hits": {},
        "tcp_syn_packets": 0,
        "scenario_packet_hints": {},
    }


def analyze_with_tshark(pcap: Path) -> dict[str, Any]:
    summary = _empty_summary(mode="tshark")
    base = ["tshark", "-r", str(pcap), "-T", "fields"]

    # Packet counts by protocol
    for key, display_filter in (
        ("total_packets", None),
        ("tcp_packets", "tcp"),
        ("udp_packets", "udp"),
        ("icmp_packets", "icmp || icmpv6"),
        ("http_requests", "http.request"),
        ("dns_queries", "dns.flags.response == 0"),
        ("udp_53_packets", "udp.port == 53"),
        ("tcp_22_packets", "tcp.port == 22"),
        ("tcp_80_packets", "tcp.port == 80"),
        ("tcp_8080_packets", "tcp.port == 8080"),
        ("tcp_389_packets", "tcp.port == 389 || tcp.port == 636"),
        ("tcp_445_packets", "tcp.port == 445"),
        ("tcp_88_packets", "tcp.port == 88"),
        ("udp_88_packets", "udp.port == 88"),
        ("tcp_syn_packets", "tcp.flags.syn == 1 && tcp.flags.ack == 0"),
    ):
        cmd = ["tshark", "-r", str(pcap), "-T", "fields", "-e", "frame.number"]
        if display_filter:
            cmd.extend(["-Y", display_filter])
        proc = _run(cmd)
        if proc.returncode != 0 and key == "total_packets":
            summary["error"] = (proc.stderr or proc.stdout or "tshark failed").strip()
            return summary
        lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
        summary[key] = len(lines)

    # Endpoints / ports
    proc = _run(
        base
        + [
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "tcp.dstport",
            "-e",
            "udp.dstport",
            "-e",
            "tcp.srcport",
            "-e",
            "udp.srcport",
        ]
    )
    sources: set[str] = set()
    destinations: set[str] = set()
    dst_ports: Counter[str] = Counter()
    src_dst_ports: Counter[str] = Counter()
    rare_hits: Counter[str] = Counter()

    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        while len(parts) < 6:
            parts.append("")
        src, dst, tcp_dport, udp_dport, tcp_sport, udp_sport = parts[:6]
        if src:
            sources.add(src.split(",")[0])
        if dst:
            destinations.add(dst.split(",")[0])
        dport = tcp_dport or udp_dport
        sport = tcp_sport or udp_sport
        if dport:
            port = dport.split(",")[0]
            dst_ports[port] += 1
            try:
                port_i = int(port)
            except ValueError:
                port_i = -1
            if port_i in RARE_PORTS:
                rare_hits[RARE_PORTS[port_i]] += 1
            if sport:
                src_dst_ports[f"{sport.split(',')[0]}->{port}"] += 1

    summary["unique_sources"] = sorted(sources)
    summary["unique_destinations"] = sorted(destinations)
    summary["dst_port_counts"] = dict(dst_ports.most_common(100))
    summary["src_dst_port_counts"] = dict(src_dst_ports.most_common(100))
    summary["rare_protocol_hits"] = dict(rare_hits)

    # HTTP details
    proc = _run(
        [
            "tshark",
            "-r",
            str(pcap),
            "-Y",
            "http.request",
            "-T",
            "fields",
            "-e",
            "http.request.method",
            "-e",
            "http.host",
            "-e",
            "http.request.uri",
            "-e",
            "http.user_agent",
        ]
    )
    methods: Counter[str] = Counter()
    hosts: list[str] = []
    uris: list[str] = []
    uas: list[str] = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        while len(parts) < 4:
            parts.append("")
        method, host, uri, ua = parts[:4]
        if method:
            methods[method] += 1
        if host and host not in hosts:
            hosts.append(host)
        if uri and uri not in uris:
            uris.append(uri)
        if ua and ua not in uas:
            uas.append(ua)
    summary["http_methods"] = dict(methods)
    summary["http_hosts"] = hosts[:200]
    summary["http_uris"] = uris[:500]
    summary["http_user_agents"] = uas[:100]

    # DNS query names
    proc = _run(
        [
            "tshark",
            "-r",
            str(pcap),
            "-Y",
            "dns.flags.response == 0",
            "-T",
            "fields",
            "-e",
            "dns.qry.name",
        ]
    )
    names: list[str] = []
    for line in proc.stdout.splitlines():
        name = line.strip()
        if name and name not in names:
            names.append(name)
    summary["dns_query_names"] = names[:1000]

    summary["scenario_packet_hints"] = _build_hints(summary)
    return summary


_TCPDUMP_LINE_RE = re.compile(
    r"^(?P<source>\S+)\.(?P<sport>\d+)\s+>\s+(?P<dest>\S+)\.(?P<dport>\d+):\s+(?P<rest>.*)$"
)
_IP_LINE_RE = re.compile(
    r"IP(?:v6)?\s+(?P<source>\S+)\.(?P<sport>\d+)\s+>\s+(?P<dest>\S+)\.(?P<dport>\d+):\s+(?P<rest>.*)$"
)


def analyze_with_tcpdump(pcap: Path) -> dict[str, Any]:
    summary = _empty_summary(mode="tcpdump_degraded")
    proc = _run(["tcpdump", "-nn", "-r", str(pcap)])
    if proc.returncode != 0 and not proc.stdout:
        summary["error"] = (proc.stderr or "tcpdump -r failed").strip()
        return summary

    sources: set[str] = set()
    destinations: set[str] = set()
    dst_ports: Counter[str] = Counter()
    src_dst_ports: Counter[str] = Counter()
    methods: Counter[str] = Counter()
    hosts: list[str] = []
    uris: list[str] = []
    uas: list[str] = []
    dns_names: list[str] = []
    rare_hits: Counter[str] = Counter()

    for raw in proc.stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        summary["total_packets"] += 1
        lower = line.lower()
        if " icmp" in f" {lower}" or lower.startswith("icmp"):
            summary["icmp_packets"] += 1
        is_udp = " udp" in f" {lower}" or ": udp" in lower or "udp," in lower
        is_tcp = " tcp" in f" {lower}" or "flags [" in lower or "flags[" in lower
        if is_udp:
            summary["udp_packets"] += 1
        if is_tcp:
            summary["tcp_packets"] += 1
        if "flags [s]" in lower or "flags[s]" in lower:
            summary["tcp_syn_packets"] += 1

        m = _IP_LINE_RE.search(line) or _TCPDUMP_LINE_RE.search(line)
        if not m:
            # Fallback: try to find A.B.C.D.port > A.B.C.D.port
            m2 = re.search(
                r"(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+):\s+(.*)$",
                line,
            )
            if not m2:
                continue
            src, sport, dst, dport, rest = m2.groups()
        else:
            src, sport, dst, dport, rest = (
                m.group("source"),
                m.group("sport"),
                m.group("dest"),
                m.group("dport"),
                m.group("rest"),
            )

        sources.add(src)
        destinations.add(dst)
        dst_ports[dport] += 1
        src_dst_ports[f"{sport}->{dport}"] += 1
        try:
            dport_i = int(dport)
        except ValueError:
            dport_i = -1

        if dport_i == 53 or sport == "53":
            # tcpdump often omits an explicit "UDP" token for DNS lines.
            if is_udp or "udp" in rest.lower() or "domain" in rest.lower() or not is_tcp:
                summary["udp_53_packets"] += 1
                is_udp = True
        if dport_i == 22:
            summary["tcp_22_packets"] += 1
        if dport_i == 80:
            summary["tcp_80_packets"] += 1
        if dport_i == 8080:
            summary["tcp_8080_packets"] += 1
        if dport_i in (389, 636):
            summary["tcp_389_packets"] += 1
        if dport_i == 445:
            summary["tcp_445_packets"] += 1
        if dport_i == 88:
            if is_udp:
                summary["udp_88_packets"] += 1
            else:
                summary["tcp_88_packets"] += 1
        if dport_i in RARE_PORTS:
            rare_hits[RARE_PORTS[dport_i]] += 1

        # HTTP request line heuristics
        http_m = re.search(r"\b(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH)\s+(\S+)", rest)
        if http_m and dport_i in HTTP_PORTS | {443, 8443}:
            summary["http_requests"] += 1
            methods[http_m.group(1)] += 1
            uri = http_m.group(2)
            if uri not in uris:
                uris.append(uri)
        host_m = re.search(r"Host:\s*([^\s]+)", rest, re.I)
        if host_m and host_m.group(1) not in hosts:
            hosts.append(host_m.group(1))
        ua_m = re.search(r"User-Agent:\s*([^\r\n]+)", rest, re.I)
        if ua_m and ua_m.group(1) not in uas:
            uas.append(ua_m.group(1).strip())

        # DNS name heuristics (A? name. or name)
        if dport_i == 53 or sport == "53":
            summary["dns_queries"] += 1
            for dn in re.findall(r"([a-zA-Z0-9][a-zA-Z0-9\-\.]{2,}\.[a-zA-Z]{2,})", rest):
                if dn not in dns_names:
                    dns_names.append(dn)

    summary["unique_sources"] = sorted(sources)
    summary["unique_destinations"] = sorted(destinations)
    summary["dst_port_counts"] = dict(dst_ports.most_common(100))
    summary["src_dst_port_counts"] = dict(src_dst_ports.most_common(100))
    summary["http_methods"] = dict(methods)
    summary["http_hosts"] = hosts[:200]
    summary["http_uris"] = uris[:500]
    summary["http_user_agents"] = uas[:100]
    summary["dns_query_names"] = dns_names[:1000]
    summary["rare_protocol_hits"] = dict(rare_hits)
    summary["scenario_packet_hints"] = _build_hints(summary)
    return summary


def _build_hints(summary: dict[str, Any]) -> dict[str, Any]:
    dst_ports = {str(k): int(v) for k, v in (summary.get("dst_port_counts") or {}).items()}
    rare = summary.get("rare_protocol_hits") or {}
    http_ports = sum(int(dst_ports.get(str(p), 0)) for p in (80, 8080, 8000, 8081))
    return {
        "http_followup": {
            "http_requests": int(summary.get("http_requests") or 0),
            "http_port_packets": http_ports,
            "matched": bool(summary.get("http_requests") or http_ports),
        },
        "sql_injection": {
            "http_requests": int(summary.get("http_requests") or 0),
            "http_port_packets": http_ports,
            "matched": bool(summary.get("http_requests") or http_ports),
        },
        "ssh_failure": {
            "tcp_22_packets": int(summary.get("tcp_22_packets") or 0),
            "matched": int(summary.get("tcp_22_packets") or 0) > 0,
        },
        "dns_tunnel": {
            "udp_53_packets": int(summary.get("udp_53_packets") or 0),
            "matched": int(summary.get("udp_53_packets") or 0) > 0,
        },
        "dga": {
            "dns_queries": int(summary.get("dns_queries") or 0),
            "udp_53_packets": int(summary.get("udp_53_packets") or 0),
            "matched": int(summary.get("dns_queries") or 0) > 0
            or int(summary.get("udp_53_packets") or 0) > 0,
        },
        "port_sweep": {
            "tcp_syn_packets": int(summary.get("tcp_syn_packets") or 0),
            "unique_destinations": len(summary.get("unique_destinations") or []),
            "dst_port_variety": len(dst_ports),
            "matched": int(summary.get("tcp_syn_packets") or 0) > 0
            or (len(dst_ports) >= 2 and len(summary.get("unique_destinations") or []) >= 1),
        },
        "rare_protocol_activity": {
            "rare_protocol_hits": dict(rare),
            "matched": bool(rare),
        },
        "ldap_enumeration": {
            "tcp_389_packets": int(summary.get("tcp_389_packets") or 0),
            "matched": int(summary.get("tcp_389_packets") or 0) > 0,
        },
        "smb_login_failure": {
            "tcp_445_packets": int(summary.get("tcp_445_packets") or 0),
            "matched": int(summary.get("tcp_445_packets") or 0) > 0,
        },
        "kerberos_failure": {
            "tcp_88_packets": int(summary.get("tcp_88_packets") or 0),
            "udp_88_packets": int(summary.get("udp_88_packets") or 0),
            "matched": int(summary.get("tcp_88_packets") or 0)
            + int(summary.get("udp_88_packets") or 0)
            > 0,
        },
    }


def analyze_pcap(pcap: Path) -> dict[str, Any]:
    if not pcap.is_file():
        return _empty_summary(mode="missing", error=f"pcap not found: {pcap}")
    if pcap.stat().st_size == 0:
        return _empty_summary(mode="empty", error="pcap file is empty")
    if shutil.which("tshark"):
        summary = analyze_with_tshark(pcap)
        if not summary.get("error"):
            return summary
        # Fall through to degraded mode if tshark failed.
    if shutil.which("tcpdump"):
        return analyze_with_tcpdump(pcap)
    return _empty_summary(mode="unavailable", error="neither tshark nor tcpdump available")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Analyze DSP E2E capture.pcap")
    parser.add_argument("--pcap", required=True, help="Path to capture.pcap")
    parser.add_argument("--output", required=True, help="Path to pcap_summary.json")
    args = parser.parse_args(argv)

    pcap = Path(args.pcap)
    output = Path(args.output)
    summary = analyze_pcap(pcap)
    summary["pcap_path"] = str(pcap)
    summary["pcap_bytes"] = pcap.stat().st_size if pcap.is_file() else 0
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {output} (mode={summary.get('mode')}, total_packets={summary.get('total_packets')})")
    return 0 if not summary.get("error") or summary.get("total_packets", 0) > 0 else 1


if __name__ == "__main__":
    sys.exit(main())
