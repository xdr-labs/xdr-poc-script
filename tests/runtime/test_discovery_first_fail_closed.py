"""Discovery-first fail-closed / skip regressions for Critical Gaps."""

from __future__ import annotations

import pytest

from dsp.engine.scenario_engine import TargetSet
from dsp.engine.target_engine import resolve_targets
from dsp.execution.remote.command.scenario_plans import (
    plan_port_sweep,
    plan_rare_protocol_activity,
)
from dsp.protocols.rare.attempts import plan_rare_protocol_activity as build_rare_plans
from dsp.runtime.scenario_plan import build_port_sweep_plan_view, select_port_sweep_hosts


def test_empty_target_net_fail_closed() -> None:
    with pytest.raises(ValueError, match="target_net is required"):
        resolve_targets("")
    with pytest.raises(ValueError, match="target_net is required"):
        resolve_targets("   ")


def test_port_sweep_skips_without_alive_hosts() -> None:
    targets = TargetSet(
        target_net="10.10.10.0/24",
        hosts=[],
        discovery_enabled=True,
        discovery_meta={"alive_hosts": []},
    )
    hosts, reason = select_port_sweep_hosts(targets, {}, max_hosts=2)
    assert hosts == []
    assert reason == "no_alive_hosts"

    plan_view = build_port_sweep_plan_view(targets, {"max_hosts": 2, "max_ports": 10})
    assert plan_view.selected_hosts == []
    assert plan_view.selection_reason == "no_alive_hosts"
    assert plan_view.planned_probes == 0

    plan = plan_port_sweep(targets, {"max_hosts": 2, "max_ports": 10}, dry_run=True)
    assert plan["mode"] == "skip"
    assert plan["reason"] == "no_alive_hosts"


def test_port_sweep_never_uses_target_net_expansion() -> None:
    targets = TargetSet(
        target_net="10.10.10.0/24",
        hosts=[],
        discovery_enabled=False,
        discovery_meta={},
    )
    hosts, reason = select_port_sweep_hosts(targets, {}, max_hosts=5)
    assert hosts == []
    assert reason == "no_alive_hosts"
    assert reason != "target_net_expansion"


def test_rare_protocol_skips_without_valid_target() -> None:
    targets = TargetSet(
        target_net="10.10.10.0/24",
        hosts=[],
        discovery_enabled=True,
        discovery_meta={"alive_hosts": []},
    )
    assert build_rare_plans(targets, {}) == []
    plan = plan_rare_protocol_activity(targets, {}, dry_run=True)
    assert plan["mode"] == "skip"
    assert plan["reason"] == "no_valid_target"


def test_rare_protocol_never_uses_localhost_fallback() -> None:
    targets = TargetSet(target_net="10.10.10.0/24", hosts=[])
    plans = build_rare_plans(targets, {})
    assert plans == []
    assert "127.0.0.1" not in {p.host for p in plans}
