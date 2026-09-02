"""Executable plan builders for DNS Tunnel webshell command-only path."""

from __future__ import annotations

from typing import Any

from dsp.engine.scenario_engine import TargetSet
from dsp.execution.remote.models import ScenarioExecutionRequest
from dsp.plugins.models import PluginRecord
from dsp.protocols.dns.tunnel import plan_dns_tunnel


def targets_dict_to_target_set(data: dict[str, Any]) -> TargetSet:
    return TargetSet(
        target_net=str(data.get("target_net") or ""),
        hosts=list(data.get("hosts") or []),
        service_hosts=dict(data.get("service_hosts") or {}),
        service_endpoints={
            key: [tuple(item) for item in value]
            for key, value in (data.get("service_endpoints") or {}).items()
        },
        discovery_enabled=bool(data.get("discovery_enabled", True)),
        discovery_meta=dict(data.get("discovery_meta") or {}),
    )


def build_command_plan(
    request: ScenarioExecutionRequest,
    targets: TargetSet | dict[str, Any],
    record: PluginRecord,
) -> dict[str, Any]:
    """Build an executable DNS Tunnel plan for command dispatch."""
    from dsp.execution.remote.command.scenario_plans import build_scenario_execution_plan

    del record
    if isinstance(targets, dict):
        target_set = targets_dict_to_target_set(targets)
    else:
        target_set = targets

    return build_scenario_execution_plan(
        request.scenario_id,
        target_set,
        dict(request.scenario_params),
        dry_run=request.dry_run,
    )


def _plan_dns_tunnel(targets: dict[str, Any], params: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    return plan_dns_tunnel(targets_dict_to_target_set(targets), params, dry_run=dry_run)
