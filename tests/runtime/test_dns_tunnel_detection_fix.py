"""DNS Tunnel detection fix — planner parity, alive_hosts policy, evidence invariants."""

from __future__ import annotations

from datetime import datetime, timezone

from dsp.engine.scenario_engine import TargetSet
from dsp.event_store import Event, EventStore, ValidationDecision
from dsp.execution.remote.command.discovery_plans import build_plan_from_discovery
from dsp.execution.remote.command.scenario_plans import _plan_dns_tunnel as bundle_plan_dns_tunnel
from dsp.execution.remote.command.planner import _plan_dns_tunnel as command_plan_dns_tunnel
from dsp.plugins import PluginLoader
from dsp.protocols.dns.tunnel import plan_dns_tunnel, select_tunnel_targets
from dsp.protocols.dns.tunnel_events import (
    build_tunnel_chunk_created_event,
    build_tunnel_query_sent_event,
)
from dsp.validation import ValidationEngine


def _alive_targets_dict(
    alive: list[str],
    *,
    dns_hosts: list[str] | None = None,
) -> dict:
    return {
        "target_net": "221.139.249.0/24",
        "hosts": alive,
        "service_hosts": {
            "dns_hosts": dns_hosts or [],
            "http_targets": alive[:1],
        },
        "service_endpoints": {
            "dns_hosts": [(h, 53) for h in (dns_hosts or [])],
        },
        "discovery_enabled": True,
        "discovery_meta": {"alive_hosts": alive},
    }


def _target_set(alive: list[str], dns_hosts: list[str] | None = None) -> TargetSet:
    return TargetSet(
        target_net="221.139.249.0/24",
        hosts=alive,
        service_hosts={"dns_hosts": dns_hosts or [], "http_targets": alive[:1]},
        service_endpoints={
            "dns_hosts": [(h, 53) for h in (dns_hosts or [])],
        },
        discovery_enabled=True,
        discovery_meta={"alive_hosts": alive},
    )


def _plan_params(**overrides) -> dict:
    base = {
        "payload_mb": 0.0001,
        "max_chunks": 3,
        "domain": "dns-tunnel.com",
        "max_hosts": 2,
        "plan_seed": 42,
    }
    base.update(overrides)
    return base


def _assert_idx_queries(plan: dict) -> None:
    assert plan.get("mode") != "skip"
    assert plan["queries"]
    for item in plan["queries"]:
        fqdn = item["fqdn"]
        assert "chunk.dns-tunnel" not in fqdn
        if item.get("query_role", "idx_chunk") == "idx_chunk":
            assert fqdn.startswith("idx-")
        assert item["query"] == fqdn
        assert item["protocol"] == "dns_udp"
        assert item["port"] == 53
        assert item["target"] == item["resolver"]


def test_dns_tunnel_uses_alive_hosts_when_dns_hosts_present() -> None:
    alive = ["221.139.249.101", "221.139.249.102"]
    targets = _target_set(alive, dns_hosts=["221.139.249.200"])
    selected = select_tunnel_targets(targets, {}, max_hosts=2)
    assert selected == alive
    assert "221.139.249.200" not in selected


def test_dns_tunnel_runs_without_dns_hosts() -> None:
    alive = ["221.139.249.101"]
    plan = build_plan_from_discovery(
        "dns_tunnel",
        _alive_targets_dict(alive, dns_hosts=[]),
        _plan_params(max_hosts=1, max_chunks=2),
        dry_run=True,
    )
    assert plan["mode"] == "mock"
    assert {q["target"] for q in plan["queries"]} == {"221.139.249.101"}


def test_dga_skips_without_dns_hosts() -> None:
    """DGA discovery planning is out of scope; this path must not invent DGA traffic."""
    plan = build_plan_from_discovery(
        "dga",
        _alive_targets_dict(["221.139.249.101"], dns_hosts=[]),
        {"phase1_count": 1, "phase2_count": 0},
        dry_run=True,
    )
    assert plan["mode"] == "skip"


def test_remote_discovery_planner_emits_idx_fqdn_not_chunk_pattern() -> None:
    plan = build_plan_from_discovery(
        "dns_tunnel",
        _alive_targets_dict(["221.139.249.101"]),
        _plan_params(max_hosts=1, max_chunks=2),
        dry_run=True,
    )
    _assert_idx_queries(plan)


def test_local_webshell_remote_planner_parity() -> None:
    params = _plan_params(max_hosts=1, max_chunks=3)
    targets_dict = _alive_targets_dict(["221.139.249.101"])
    target_set = _target_set(["221.139.249.101"])

    local = plan_dns_tunnel(target_set, params, dry_run=True)
    bundle = bundle_plan_dns_tunnel(target_set, params, dry_run=True)
    command = command_plan_dns_tunnel(targets_dict, params, dry_run=True)
    remote = build_plan_from_discovery("dns_tunnel", targets_dict, params, dry_run=True)

    for plan in (local, bundle, command, remote):
        _assert_idx_queries(plan)

    local_fqdns = [q["fqdn"] for q in local["queries"]]
    assert local_fqdns == [q["fqdn"] for q in bundle["queries"]]
    assert local_fqdns == [q["fqdn"] for q in command["queries"]]
    assert local_fqdns == [q["fqdn"] for q in remote["queries"]]


def test_chunk_dns_tunnel_pattern_regression() -> None:
    plan = build_plan_from_discovery(
        "dns_tunnel",
        _alive_targets_dict(["221.139.249.101"]),
        _plan_params(max_hosts=1, max_chunks=5),
        dry_run=True,
    )
    serialized = str(plan["queries"])
    assert "chunk.dns-tunnel" not in serialized


def test_dns_tunnel_query_sent_evidence_fields_validate() -> None:
    store = EventStore(":memory:")
    run_id = "dns_tunnel_evidence_run"
    store.open_run(run_id)
    fqdn = "idx-0000-mfrggzdfmy.dns-tunnel.com"
    target = "221.139.249.101"
    store.append(
        build_tunnel_query_sent_event(
            run_id=run_id,
            scenario_id="dns_tunnel",
            target=target,
            fqdn=fqdn,
            source="remote",
            evidence={
                "target": target,
                "resolver": target,
                "fqdn": fqdn,
                "query": fqdn,
                "protocol": "dns_udp",
                "port": 53,
                "idx_pattern": True,
            },
        )
    )
    store.append(
        build_tunnel_chunk_created_event(
            run_id=run_id,
            scenario_id="dns_tunnel",
            target=target,
            fqdn=fqdn,
            source="remote",
            evidence={
                "target": target,
                "resolver": target,
                "fqdn": fqdn,
                "query": fqdn,
                "protocol": "dns_udp",
                "port": 53,
                "idx_pattern": True,
            },
        )
    )
    for event_name in ("scenario_started", "scenario_completed"):
        store.append(
            Event(
                run_id=run_id,
                scenario_id="dns_tunnel",
                timestamp=datetime.now(timezone.utc),
                stage="executor",
                event=event_name,
                status="info",
                source="runner",
            )
        )

    loader = PluginLoader()
    registry = loader.discover_and_load()
    result = ValidationEngine(store, registry).validate(run_id, "dns_tunnel")
    assert result.decision == ValidationDecision.SUCCESS
    assert result.fail_fast_codes == []


def test_invalid_chunk_pattern_fails_validation() -> None:
    store = EventStore(":memory:")
    run_id = "dns_tunnel_bad_fqdn"
    store.open_run(run_id)
    bad_fqdn = "0001.chunk.dns-tunnel.dns-tunnel.com"
    store.append(
        build_tunnel_query_sent_event(
            run_id=run_id,
            scenario_id="dns_tunnel",
            target="221.139.249.101",
            fqdn=bad_fqdn,
            source="remote",
            evidence={
                "target": "221.139.249.101",
                "resolver": "221.139.249.101",
                "fqdn": bad_fqdn,
                "query": bad_fqdn,
                "protocol": "dns_udp",
                "port": 53,
            },
        )
    )
    store.append(
        Event(
            run_id=run_id,
            scenario_id="dns_tunnel",
            timestamp=datetime.now(timezone.utc),
            stage="executor",
            event="scenario_started",
            status="info",
            source="runner",
        )
    )
    store.append(
        Event(
            run_id=run_id,
            scenario_id="dns_tunnel",
            timestamp=datetime.now(timezone.utc),
            stage="executor",
            event="scenario_completed",
            status="info",
            source="runner",
        )
    )
    loader = PluginLoader()
    registry = loader.discover_and_load()
    result = ValidationEngine(store, registry).validate(run_id, "dns_tunnel")
    assert result.decision == ValidationDecision.CODE_FAILURE
    assert "DNS_TUNNEL_INVALID_FQDN_PATTERN" in result.fail_fast_codes
