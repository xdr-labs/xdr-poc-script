"""Verify --target-net propagates to live scenario traffic target selection."""

from __future__ import annotations

import ipaddress
import json

import pytest

from dsp.engine.target_engine import (
    DEFAULT_LAB_FALLBACK_HOST,
    expand_target_net_hosts,
    host_in_target_net,
    resolve_targets,
)
from dsp.runner import RunManager

CUSTOM_TARGET_NET = "221.139.249.0/24"
LAB_TARGET_NET = "10.10.10.0/24"
LAB_FALLBACK = DEFAULT_LAB_FALLBACK_HOST

TRAFFIC_SCENARIOS = ["dns_tunnel", "http_followup", "port_sweep"]


def _load_events(run_dir) -> list[dict]:
    return [
        json.loads(line)
        for line in (run_dir / "events.jsonl").read_text().strip().splitlines()
        if line.strip()
    ]


def _collect_target_ips(events: list[dict], scenario_id: str) -> set[str]:
    ips: set[str] = set()
    for event in events:
        if event.get("scenario_id") != scenario_id:
            continue
        target = event.get("target")
        if isinstance(target, str) and target:
            ips.add(target)
        evidence = event.get("evidence") or {}
        for key in ("resolver", "host"):
            value = evidence.get(key)
            if isinstance(value, str) and value:
                ips.add(value)
    return ips


@pytest.mark.parametrize("target_net", [CUSTOM_TARGET_NET, "192.168.55.0/24"])
def test_resolve_targets_expands_cidr_not_lab_default(target_net: str):
    targets = resolve_targets(target_net)
    assert targets.target_net == target_net
    assert targets.hosts
    assert all(host_in_target_net(host, target_net) for host in targets.hosts)
    assert LAB_FALLBACK not in targets.hosts


def test_resolve_targets_empty_fail_closed():
    with pytest.raises(ValueError, match="target_net is required"):
        resolve_targets("")


def test_expand_target_net_custom_first_host():
    hosts = expand_target_net_hosts(CUSTOM_TARGET_NET, max_hosts=3)
    assert hosts[0] == "221.139.249.1"
    assert all(host_in_target_net(h, CUSTOM_TARGET_NET) for h in hosts)


@pytest.mark.parametrize("scenario_id", TRAFFIC_SCENARIOS)
def test_run_manager_event_targets_match_target_net(tmp_runs_dir, scenario_id: str, mock_curl_http):
    manager = RunManager(runs_dir=tmp_runs_dir)
    scenario_params = {
        "dns_tunnel": {
            "targets": ["221.139.249.1"],
            "max_chunks": 2,
            "max_hosts": 1,
            "timeout": 0.05,
        },
        "http_followup": {
            "endpoints": [["221.139.249.110", 8080]],
            "max_hosts": 1,
            "max_per_host": 1,
            "max_total": 1,
            "timeout": 1.0,
        },
        "port_sweep": {"max_hosts": 1, "max_ports": 2, "timeout": 1.0},
    }
    _, run_dir, exit_code = manager.run(
        scenario_ids=[scenario_id],
        target_net=CUSTOM_TARGET_NET,
        dry_run=False,
        scenario_params=scenario_params,
    )

    assert exit_code in (0, 1, 2)

    run_meta = json.loads((run_dir / "run.json").read_text())
    assert run_meta["target_net"] == CUSTOM_TARGET_NET

    events = _load_events(run_dir)
    target_ips = _collect_target_ips(events, scenario_id)
    assert target_ips, f"no targets recorded for {scenario_id}"

    assert LAB_FALLBACK not in target_ips, (
        f"{scenario_id} still uses lab fallback {LAB_FALLBACK}: {target_ips}"
    )
    for ip in target_ips:
        assert host_in_target_net(ip, CUSTOM_TARGET_NET), (
            f"{scenario_id} target {ip} outside {CUSTOM_TARGET_NET}"
        )


def test_run_manager_metadata_and_events_consistent(tmp_runs_dir):
    manager = RunManager(runs_dir=tmp_runs_dir)
    _, run_dir, _ = manager.run(
        scenario_ids=TRAFFIC_SCENARIOS,
        target_net=CUSTOM_TARGET_NET,
        dry_run=False,
        scenario_params={
            "dns_tunnel": {
            "targets": ["221.139.249.1"],
            "max_chunks": 2,
            "max_hosts": 1,
            "timeout": 0.05,
        },
            "http_followup": {"max_hosts": 1, "max_per_host": 1, "max_total": 1, "timeout": 1.0},
            "port_sweep": {"max_hosts": 1, "max_ports": 2, "timeout": 1.0},
        },
    )

    run_meta = json.loads((run_dir / "run.json").read_text())
    network = ipaddress.ip_network(CUSTOM_TARGET_NET, strict=False)
    events = _load_events(run_dir)

    for scenario_id in TRAFFIC_SCENARIOS:
        for event in events:
            if event.get("scenario_id") != scenario_id:
                continue
            target = event.get("target")
            if not target:
                continue
            assert ipaddress.ip_address(target) in network
            assert run_meta["target_net"] == CUSTOM_TARGET_NET
            assert target != LAB_FALLBACK

    dns_resolvers = {
        (e.get("evidence") or {}).get("resolver")
        for e in events
        if e.get("scenario_id") == "dns_tunnel" and e.get("event") == "dns_query_sent"
    }
    dns_resolvers.discard(None)
    assert dns_resolvers
    assert all(host_in_target_net(r, CUSTOM_TARGET_NET) for r in dns_resolvers)
    assert LAB_FALLBACK not in dns_resolvers
