"""DNS Tunnel scenario plan builders for webshell command-only execution."""

from __future__ import annotations

from typing import Any

from dsp.engine.scenario_engine import TargetSet
from dsp.execution.remote.models import ScenarioExecutionRequest
from dsp.protocols.dns.tunnel import plan_dns_tunnel as build_dns_tunnel_plan


def uses_remote_discovery(request: ScenarioExecutionRequest) -> bool:
    """DNS Tunnel on this branch uses DSP-provided TargetSet (alive hosts).

    Remote webshell discovery is intentionally not required for the DNS-only
    command path so other scenario discovery runtimes stay unchanged.
    """
    del request
    return False


def build_scenario_execution_plan(
    scenario_id: str,
    targets: TargetSet,
    params: dict[str, Any],
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Build executable plan from discovery TargetSet (DNS Tunnel only)."""
    if scenario_id != "dns_tunnel":
        return {
            "type": "skip",
            "mode": "skip",
            "reason": f"scenario {scenario_id!r} not supported on DNS command path",
        }
    return plan_dns_tunnel(targets, params, dry_run=dry_run)


def plan_dns_tunnel(targets: TargetSet, params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    return build_dns_tunnel_plan(targets, params, dry_run=dry_run)


_uses_remote_discovery = uses_remote_discovery
_plan_dns_tunnel = plan_dns_tunnel
