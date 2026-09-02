"""Discovery plan helpers — DNS Tunnel uses shared plan_dns_tunnel."""

from __future__ import annotations

from typing import Any

from dsp.execution.remote.command.planner import targets_dict_to_target_set
from dsp.protocols.dns.tunnel import plan_dns_tunnel


def build_plan_from_discovery(
    scenario_id: str,
    targets: dict[str, Any],
    params: dict[str, Any],
    *,
    dry_run: bool,
) -> dict[str, Any]:
    """Build a scenario plan from a discovery targets dict.

    DNS Tunnel only on this branch. Other scenarios return skip so their
    runtime behavior is not altered via this path.
    """
    if scenario_id == "dns_tunnel":
        return plan_dns_tunnel(
            targets_dict_to_target_set(targets),
            params,
            dry_run=dry_run,
        )
    return {
        "type": scenario_id,
        "mode": "skip",
        "reason": f"{scenario_id}_not_enabled_on_dns_command_path",
    }
