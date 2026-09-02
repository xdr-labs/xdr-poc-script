"""Webshell command-only execution — no DSP runtime upload on live path."""

from dsp.execution.remote.command.models import (
    COMMAND_SCENARIOS,
    DISCOVERY_ORIGIN_WEBSHELL,
    EVENT_SOURCE_WEBSHELL,
    FORBIDDEN_REMOTE_ARTIFACTS,
    REMOTE_EXECUTION_MODE_COMMAND,
)

__all__ = [
    "COMMAND_SCENARIOS",
    "CommandScenarioRunner",
    "DISCOVERY_ORIGIN_WEBSHELL",
    "EVENT_SOURCE_WEBSHELL",
    "FORBIDDEN_REMOTE_ARTIFACTS",
    "REMOTE_EXECUTION_MODE_COMMAND",
]


def __getattr__(name: str):
    if name == "CommandScenarioRunner":
        from dsp.execution.remote.command.runner import CommandScenarioRunner

        return CommandScenarioRunner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
