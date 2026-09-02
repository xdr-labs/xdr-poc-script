"""Webshell execution provider — Mode B bridge over JSP/PHP/ASPX family adapters."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from dsp.engine.orchestrator import run_scenario
from dsp.engine.scenario_engine import RunContext, ScenarioSummary, TargetSet
from dsp.execution.base import ExecutionProvider
from dsp.execution.exceptions import WebshellExecutionConfigError
from dsp.execution.models import ExecutionContext, ProviderCapabilities
from dsp.execution.providers.runtime.command import (
    CommandExecutionPolicy,
    CommandRequest,
    CommandResult,
)
from dsp.execution.providers.runtime.command.command_exceptions import CommandTransportError
from dsp.execution.providers.runtime.runtime_models import RuntimeArtifact
from dsp.execution.providers.runtime.transport import TransportRuntimeConfiguration
from dsp.execution.providers.webshell.common.generic_provider import (
    GenericWebshellProvider,
)
from dsp.execution.providers.webshell.provider_factory import create_webshell_provider
from dsp.execution.webshell_config import WebshellExecutionConfig
from dsp.execution.webshell.transport.base import WebshellTransport
from dsp.execution.webshell.transport.real_http_transport import RealHttpTransport
from dsp.execution.remote.bundle.models import REMOTE_EXECUTION_MODE_BUNDLE
from dsp.execution.remote.bundle.runner import BundleScenarioRunner
from dsp.execution.remote.command.models import (
    COMMAND_SCENARIOS,
    REMOTE_EXECUTION_MODE_COMMAND,
)
from dsp.execution.remote.command.runner import CommandScenarioRunner
from dsp.execution.remote.exceptions import RemoteArtifactUploadError
from dsp.execution.remote.models import ScenarioExecutionRequest
from dsp.plugins.models import PluginRecord


class WebshellExecutionProvider(ExecutionProvider):
    """ExecutionProvider bridge that wraps a JSP/PHP/ASPX webshell family adapter."""

    def __init__(
        self,
        config: WebshellExecutionConfig,
        *,
        transport: WebshellTransport | None = None,
        family_provider: GenericWebshellProvider | None = None,
    ) -> None:
        self._config = config
        self._transport = transport
        self._family_provider = family_provider
        self._connected = False

    @classmethod
    def from_config(
        cls,
        *,
        transport: WebshellTransport | None = None,
        family_provider: GenericWebshellProvider | None = None,
        **provider_config: Any,
    ) -> WebshellExecutionProvider:
        """Build provider from factory keyword arguments."""
        config_data = dict(provider_config)
        if "provider_type" not in config_data and "webshell_family" in config_data:
            config_data["provider_type"] = config_data.pop("webshell_family")
        if "provider_type" not in config_data:
            raise WebshellExecutionConfigError(
                "provider_type is required (jsp, php, or aspx)",
                field="provider_type",
            )
        if "webshell_url" not in config_data:
            raise WebshellExecutionConfigError(
                "webshell_url is required",
                field="webshell_url",
            )
        config = WebshellExecutionConfig.from_dict(config_data)
        return cls(
            config,
            transport=transport,
            family_provider=family_provider,
        )

    @property
    def provider_type(self) -> str:
        return "webshell"

    @property
    def webshell_family(self) -> str:
        """Selected JSP/PHP/ASPX family identifier."""
        return self._config.provider_type

    @property
    def family_provider(self) -> GenericWebshellProvider | None:
        return self._family_provider

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider_type="webshell",
            execution_mode="remote",
            traffic_origin="remote_host",
            supports_udp=False,
            supports_tcp=True,
            supports_http_client=True,
        )

    def get_webshell_metadata(self) -> dict[str, Any]:
        """Expose wrapped family provider metadata when available."""
        if self._family_provider is None:
            return {
                "execution_provider": self.provider_type,
                "webshell_family": self.webshell_family,
                "webshell_url": self._config.webshell_url,
                "transport_type": self._config.transport_type,
            }
        metadata = self._family_provider.get_metadata()
        metadata["execution_provider"] = self.provider_type
        metadata["webshell_url"] = self._config.webshell_url
        return metadata

    def prepare(self, context: ExecutionContext) -> None:
        """Initialize transport, family provider, runtime, and remote session."""
        if self._family_provider is None:
            transport = self._transport or RealHttpTransport(
                retry_policy=self._config.retry_policy,
                verify_tls=self._config.verify_tls,
            )
            self._family_provider = create_webshell_provider(
                self._config.provider_type,
                transport=transport,
                webshell_url=self._config.webshell_url,
                transport_type=self._config.transport_type,
            )
            self._family_provider.create_runtime(
                config=TransportRuntimeConfiguration(
                    enable_healthcheck_on_connect=self._config.enable_healthcheck_on_connect,
                    command_policy=CommandExecutionPolicy(
                        allow_command_execution=True,
                    ),
                ),
            )

        if not self._connected:
            try:
                self._family_provider.connect()
            except Exception as exc:
                if context.dry_run:
                    context.execution_metadata["delivery_fallback_local"] = True
                    context.execution_metadata["delivery_fallback_reason"] = str(exc)
                    self._connected = True
                    return
                raise
            self._connected = True

        context.execution_metadata.update(
            {
                "traffic_origin_host": "remote",
                "execution_provider": self.provider_type,
                "webshell_family": self.webshell_family,
                "webshell_url": self._config.webshell_url,
                "transport_type": self._config.transport_type,
                "remote_execution_mode": REMOTE_EXECUTION_MODE_BUNDLE,
            }
        )

    def execute(
        self,
        context: ExecutionContext,
        record: PluginRecord,
        ctx: RunContext,
        targets: TargetSet,
        *,
        snapshot_dir: Path | None = None,
    ) -> ScenarioSummary | None:
        """Deliver scenario execution remotely via webshell command transport."""
        if context.execution_metadata.get("delivery_fallback_local"):
            summary = run_scenario(record, ctx, targets, snapshot_dir=snapshot_dir)
            context.execution_metadata["remote_execution_mode"] = "local_dry_run_fallback"
            return summary

        params = ctx.config.scenario_params.get(record.id, {})
        request = ScenarioExecutionRequest(
            scenario_id=record.id,
            scenario_params=dict(params),
            execution_metadata=dict(context.execution_metadata),
            run_id=context.run_id,
            target_net=context.target_net,
            dry_run=context.dry_run,
        )

        # DNS Tunnel only: command-only (no DSP package upload on webshell host).
        # All other scenarios keep baseline BundleScenarioRunner runtime behavior.
        if record.id in COMMAND_SCENARIOS:
            runner = CommandScenarioRunner()
            result = runner.run(
                request,
                self,
                targets=targets,
                record=record,
                ctx=ctx,
            )
            context.execution_metadata["remote_scenario_result"] = result.to_dict()
            context.execution_metadata["remote_execution_id"] = result.remote_execution_id
            context.execution_metadata["remote_execution_mode"] = REMOTE_EXECUTION_MODE_COMMAND
            context.execution_metadata["scenario_skipped"] = bool(
                request.execution_metadata.get("scenario_skipped")
            )
            context.execution_metadata["commands_dispatched"] = (
                request.execution_metadata.get("commands_dispatched", 0)
            )
            return None

        runner = BundleScenarioRunner()
        try:
            result = runner.run(
                request,
                self,
                targets=targets,
                record=record,
                diagnostics_dir=snapshot_dir,
            )
        except (CommandTransportError, RemoteArtifactUploadError) as exc:
            if not context.dry_run:
                raise
            context.execution_metadata["delivery_fallback_local"] = True
            context.execution_metadata["delivery_fallback_reason"] = str(exc)
            summary = run_scenario(record, ctx, targets, snapshot_dir=snapshot_dir)
            context.execution_metadata["remote_execution_mode"] = "local_dry_run_fallback"
            return summary
        context.execution_metadata["remote_scenario_result"] = result.to_dict()
        context.execution_metadata["remote_execution_id"] = result.remote_execution_id
        context.execution_metadata["remote_execution_mode"] = REMOTE_EXECUTION_MODE_BUNDLE
        return None

    def execute_command(
        self,
        command: CommandRequest | str,
        *,
        arguments: list[str] | None = None,
        timeout_seconds: int = 300,
    ) -> CommandResult:
        """Execute a command through the selected webshell family provider."""
        provider = self._require_family_provider()
        return provider.execute_command(
            command,
            arguments=arguments,
            timeout_seconds=timeout_seconds,
        )

    def upload_file(self, local_file: Path | str, remote_path: str) -> RuntimeArtifact:
        """Upload a local artifact through the selected webshell family provider."""
        provider = self._require_family_provider()
        return provider.upload_file(local_file, remote_path)

    def download_file(self, remote_path: str) -> RuntimeArtifact:
        """Download a remote artifact through the selected webshell family provider."""
        provider = self._require_family_provider()
        return provider.download_file(remote_path)

    def fetch_remote_file_via_cat(self, remote_path: str) -> bytes:
        """Read a remote file through the selected webshell family ``cat`` transport."""
        provider = self._require_family_provider()
        return provider.fetch_remote_file_via_cat(remote_path)

    def run_remote_command(
        self,
        command: str,
        *,
        timeout_seconds: float = 300.0,
    ) -> bytes:
        """Run a remote shell command and return captured command output bytes."""
        provider = self._require_family_provider()
        return provider.run_remote_command(command, timeout_seconds=timeout_seconds)

    def cleanup(self, context: ExecutionContext) -> None:
        """Release webshell runtime session state."""
        if self._family_provider is not None:
            self._family_provider.cleanup()
        self._connected = False

    def _require_family_provider(self) -> GenericWebshellProvider:
        if self._family_provider is None:
            raise RuntimeError(
                "webshell family provider is not initialized; call prepare() first"
            )
        return self._family_provider
