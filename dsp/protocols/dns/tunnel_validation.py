"""DNS Tunnel validation profile templates and evidence invariants."""

from __future__ import annotations

from typing import Any

from dsp.event_store import EventStore

DNS_TUNNEL_METRIC_NAMES = [
    "dns_tunnel_chunk_created_count",
    "dns_tunnel_query_sent_count",
    "dns_tunnel_idx_pattern_count",
    "planned_queries",
    "dispatched_queries",
    "observed_queries",
]

DNS_TUNNEL_FAIL_FAST_CODES = frozenset(
    {
        "DNS_TUNNEL_EVIDENCE_INCOMPLETE",
        "DNS_TUNNEL_INVALID_FQDN_PATTERN",
        "DNS_TUNNEL_INVALID_PROTOCOL",
        "DNS_TUNNEL_INVALID_PORT",
        "DNS_TUNNEL_DISPATCH_SHORTFALL",
    }
)

# Dispatched must cover nearly all planned queries (legacy 50-of-17k must fail).
_DISPATCH_MIN_RATIO = 0.95


def dns_tunnel_validation_profile(**overrides: Any) -> dict[str, Any]:
    """Standard DNS Tunnel validation profile for manifest.yaml."""
    profile: dict[str, Any] = {
        "profile_version": "1.0.0",
        "metrics": [
            {
                "name": "dns_tunnel_chunk_created_count",
                "event_filter": {
                    "event": "dns_tunnel_chunk_created",
                    "status": "info",
                },
                "aggregate": "count",
            },
            {
                "name": "dns_tunnel_query_sent_count",
                "event_filter": {
                    "event": "dns_tunnel_query_sent",
                    "status": "sent",
                },
                "aggregate": "count",
            },
            {
                "name": "dns_tunnel_idx_pattern_count",
                "event_filter": {
                    "event": "dns_tunnel_query_sent",
                    "status": "sent",
                },
                "aggregate": "count",
            },
        ],
        "success": {
            "dns_tunnel_query_sent_count": {
                "min": 1,
                "min_ratio_of": "planned_queries",
                "min_ratio": _DISPATCH_MIN_RATIO,
            },
            "dns_tunnel_chunk_created_count": {"min": 1},
            "dispatched_queries": {
                "min": 1,
                "min_ratio_of": "planned_queries",
                "min_ratio": _DISPATCH_MIN_RATIO,
            },
        },
        "fail_fast": [
            "SOT_EMPTY_AFTER_EXECUTE",
            "DNS_TUNNEL_EVIDENCE_INCOMPLETE",
            "DNS_TUNNEL_INVALID_FQDN_PATTERN",
            "DNS_TUNNEL_INVALID_PROTOCOL",
            "DNS_TUNNEL_INVALID_PORT",
            "DNS_TUNNEL_DISPATCH_SHORTFALL",
        ],
    }
    profile.update(overrides)
    return profile


def evaluate_dns_tunnel_invariants(
    store: EventStore,
    run_id: str,
    scenario_id: str,
) -> list[str]:
    """Validate DNS tunnel Event Store evidence against traffic contract."""
    events = [
        event
        for event in store.list_events(run_id, scenario_id)
        if event.event == "dns_tunnel_query_sent" and event.status == "sent"
    ]

    codes: list[str] = []
    for event in events:
        evidence = dict(event.evidence or {})
        query_role = str(evidence.get("query_role") or "idx_chunk")
        if query_role in {"session_start", "session_end"}:
            continue
        fqdn = str(evidence.get("fqdn") or event.artifact or "")
        query = str(evidence.get("query") or "")
        if not fqdn or not query:
            codes.append("DNS_TUNNEL_EVIDENCE_INCOMPLETE")
            break
        if "chunk.dns-tunnel" in fqdn or "chunk.dns-tunnel" in query:
            codes.append("DNS_TUNNEL_INVALID_FQDN_PATTERN")
            break
        if not fqdn.startswith("idx-"):
            codes.append("DNS_TUNNEL_INVALID_FQDN_PATTERN")
            break
        protocol = evidence.get("protocol")
        if protocol is not None and protocol != "dns_udp":
            codes.append("DNS_TUNNEL_INVALID_PROTOCOL")
            break
        port = evidence.get("port")
        if port is not None and int(port) != 53:
            codes.append("DNS_TUNNEL_INVALID_PORT")
            break

    shortfall = _dispatch_shortfall_code(store, run_id, scenario_id, sent_count=len(events))
    if shortfall:
        codes.append(shortfall)
    return list(dict.fromkeys(codes))


def _dispatch_shortfall_code(
    store: EventStore,
    run_id: str,
    scenario_id: str,
    *,
    sent_count: int,
) -> str | None:
    completed = _last_evidence(store, run_id, scenario_id, "dns_tunnel_completed")
    started = _last_evidence(store, run_id, scenario_id, "dns_tunnel_started")
    planned = int(
        completed.get("total_planned_queries")
        or completed.get("planned_queries")
        or started.get("total_planned_queries")
        or started.get("planned_queries")
        or 0
    )
    if planned <= 0:
        return None
    dispatched = int(
        completed.get("dispatched_queries")
        if completed.get("dispatched_queries") is not None
        else sent_count
    )
    if dispatched < int(planned * _DISPATCH_MIN_RATIO):
        return "DNS_TUNNEL_DISPATCH_SHORTFALL"
    return None


def _last_evidence(
    store: EventStore,
    run_id: str,
    scenario_id: str,
    event_name: str,
) -> dict[str, Any]:
    for event in reversed(store.list_events(run_id, scenario_id)):
        if event.event == event_name:
            return dict(event.evidence or {})
    return {}


def count_dns_tunnel_idx_pattern_queries(
    store: EventStore,
    run_id: str,
    scenario_id: str,
) -> int:
    """Count dns_tunnel_query_sent rows whose fqdn uses the idx- prefix."""
    events = [
        event
        for event in store.list_events(run_id, scenario_id)
        if event.event == "dns_tunnel_query_sent" and event.status == "sent"
    ]
    count = 0
    for event in events:
        evidence = dict(event.evidence or {})
        fqdn = str(evidence.get("fqdn") or event.artifact or "")
        if fqdn.startswith("idx-"):
            count += 1
    return count
