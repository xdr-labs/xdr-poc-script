"""CommandScenarioRunner — DNS Tunnel webshell command-only execution."""

from __future__ import annotations

from typing import TYPE_CHECKING

from dsp.engine.scenario_engine import RunContext, TargetSet
from dsp.execution.providers.runtime.command import CommandResult, CommandStatus
from dsp.execution.remote.command.events import (
    append_scenario_lifecycle,
    append_scenario_skipped,
)
from dsp.execution.remote.command.execute import execute_command_plan
from dsp.execution.remote.command.models import COMMAND_SCENARIOS, REMOTE_EXECUTION_MODE_COMMAND
from dsp.execution.remote.command.planner import build_command_plan
from dsp.execution.remote.exceptions import UnsupportedRemoteProviderError
from dsp.execution.remote.models import (
    TRANSPORT_METADATA_KEYS,
    RemoteScenarioExecutionResult,
    ScenarioExecutionRequest,
)
from dsp.plugins.models import PluginRecord

if TYPE_CHECKING:
    from dsp.execution.webshell_provider import WebshellExecutionProvider


def build_execution_result(
    request: ScenarioExecutionRequest,
    provider: WebshellExecutionProvider,
    command_result: CommandResult,
) -> RemoteScenarioExecutionResult:
    execution_metadata = dict(command_result.execution_metadata)
    transport_metadata = {
        key: execution_metadata[key]
        for key in TRANSPORT_METADATA_KEYS
        if key in execution_metadata
    }
    command_metadata = {
        "command_id": command_result.command_id,
        "command_status": command_result.status.value,
    }
    for key, value in execution_metadata.items():
        if key not in TRANSPORT_METADATA_KEYS:
            command_metadata[key] = value

    if command_result.started_at is not None:
        command_metadata["started_at"] = (
            command_result.started_at.isoformat().replace("+00:00", "Z")
        )
    if command_result.completed_at is not None:
        command_metadata["completed_at"] = (
            command_result.completed_at.isoformat().replace("+00:00", "Z")
        )

    return RemoteScenarioExecutionResult.new(
        scenario_id=request.scenario_id,
        transport_metadata=transport_metadata,
        provider_metadata=provider.get_webshell_metadata(),
        command_metadata=command_metadata,
    )


class CommandScenarioRunner:
    """Dispatch DNS Tunnel through webshell commands — no DSP runtime upload."""

    def run(
        self,
        request: ScenarioExecutionRequest,
        provider: WebshellExecutionProvider,
        *,
        targets: TargetSet,
        record: PluginRecord,
        ctx: RunContext,
        timeout_seconds: int = 300,
    ) -> RemoteScenarioExecutionResult:
        del timeout_seconds
        self._validate_provider(provider)
        store = ctx.event_store
        run_id = str(request.run_id)
        scenario_id = request.scenario_id

        if scenario_id not in COMMAND_SCENARIOS:
            raise UnsupportedRemoteProviderError(
                f"scenario {scenario_id!r} is not supported in DNS command-only webshell mode"
            )

        append_scenario_lifecycle(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="scenario_started",
            evidence={"remote_execution_mode": REMOTE_EXECUTION_MODE_COMMAND},
        )

        plan = build_command_plan(request, targets, record)
        if plan.get("mode") == "skip" or plan.get("type") == "skip":
            append_scenario_skipped(
                store,
                run_id=run_id,
                scenario_id=scenario_id,
                reason=str(plan.get("reason") or "no_targets"),
            )
            result = build_execution_result(
                request,
                provider,
                _skipped_command_result(request),
            )
            request.execution_metadata["scenario_skipped"] = True
            request.execution_metadata["remote_execution_mode"] = REMOTE_EXECUTION_MODE_COMMAND
            return result

        commands_dispatched = execute_command_plan(plan, provider, ctx, request)
        append_scenario_lifecycle(
            store,
            run_id=run_id,
            scenario_id=scenario_id,
            event="scenario_completed",
            evidence={
                "commands_dispatched": commands_dispatched,
                "remote_execution_mode": REMOTE_EXECUTION_MODE_COMMAND,
            },
        )

        command_result = CommandResult(
            command_id=f"cmd-{run_id}-{scenario_id}",
            status=CommandStatus.COMPLETED,
            execution_metadata={
                "delivery_only": True,
                "commands_dispatched": commands_dispatched,
                "remote_execution_mode": REMOTE_EXECUTION_MODE_COMMAND,
            },
        )
        result = build_execution_result(request, provider, command_result)
        request.execution_metadata["remote_execution_mode"] = REMOTE_EXECUTION_MODE_COMMAND
        request.execution_metadata["commands_dispatched"] = commands_dispatched
        request.execution_metadata["scenario_skipped"] = False
        return result

    @staticmethod
    def _validate_provider(provider: object) -> None:
        from dsp.execution.webshell_provider import WebshellExecutionProvider

        if not isinstance(provider, WebshellExecutionProvider):
            provider_type = getattr(provider, "provider_type", type(provider).__name__)
            raise UnsupportedRemoteProviderError(str(provider_type))


def _skipped_command_result(request: ScenarioExecutionRequest) -> CommandResult:
    return CommandResult(
        command_id=f"skip-{request.run_id}-{request.scenario_id}",
        status=CommandStatus.COMPLETED,
        execution_metadata={
            "delivery_only": True,
            "scenario_skipped": True,
            "remote_execution_mode": REMOTE_EXECUTION_MODE_COMMAND,
        },
    )
