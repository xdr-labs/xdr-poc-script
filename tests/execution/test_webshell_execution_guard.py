"""Webshell command-only guard and policy tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from dsp.execution import WebshellExecutionProvider
from dsp.execution.providers.runtime.command import CommandExecutionPolicy
from dsp.execution.providers.runtime.transport import TransportRuntimeConfiguration
from dsp.execution.providers.webshell.jsp import JspWebshellProvider
from dsp.execution.remote.exceptions import RemoteArtifactUploadError, RemoteBundleExecutionError
from dsp.execution.webshell.transport import RealHttpTransport, RetryPolicy
from dsp.execution.webshell_config import WebshellExecutionConfig
from dsp.execution.webshell_execution_guard import (
    assert_webshell_command_allowed,
    assert_webshell_upload_allowed,
)
from dsp.runner import RunManager
from tests.e2e.fixtures.webshell_test_server import WebshellTestServer


def _connected_provider(server: WebshellTestServer) -> WebshellExecutionProvider:
    transport = RealHttpTransport(retry_policy=RetryPolicy(max_retries=0))
    family_provider = JspWebshellProvider(
        transport=transport,
        webshell_url=server.webshell_url,
    )
    family_provider.create_runtime(
        config=TransportRuntimeConfiguration(
            enable_healthcheck_on_connect=False,
            command_policy=CommandExecutionPolicy(allow_command_execution=True),
        ),
    )
    family_provider.connect()
    config = WebshellExecutionConfig(provider_type="jsp", webshell_url=server.webshell_url)
    return WebshellExecutionProvider(config, transport=transport, family_provider=family_provider)


@pytest.mark.parametrize(
    "remote_path",
    ["manifest.json", "/tmp/dsp/run01/manifest.json", "/tmp/dsp/run01/run_scenario.py"],
)
def test_forbidden_upload_paths_raise(remote_path: str) -> None:
    with pytest.raises(RemoteArtifactUploadError, match="forbidden webshell upload blocked"):
        assert_webshell_upload_allowed(remote_path)


@pytest.mark.parametrize(
    "command",
    [
        "python3 /tmp/dsp/run01/run_scenario.py",
        "dsp-remote-scenario port_sweep",
        "cat /tmp/dsp/run01/manifest.json",
    ],
)
def test_forbidden_commands_raise(command: str) -> None:
    with pytest.raises(RemoteBundleExecutionError):
        assert_webshell_command_allowed(command)


def test_webshell_normal_run_must_not_upload_manifest_or_runner(tmp_path: Path) -> None:
    server = WebshellTestServer(storage_dir=tmp_path / "server")
    server.start()
    try:
        manager = RunManager(runs_dir=tmp_path / "runs")
        manager.run(
            operational_profile="normal",
            scenario_ids=["port_sweep"],
            target_net="127.0.0.0/30",
            dry_run=False,
            execution_provider="webshell",
            webshell_family="jsp",
            webshell_url=server.webshell_url,
            remote_work_dir=str(tmp_path / "remote-work"),
        )
        joined_uploads = "\n".join(server.upload_calls)
        joined_commands = "\n".join(server.command_calls)
        assert "manifest.json" not in joined_uploads
        assert "run_scenario.py" not in joined_uploads
        assert "manifest.json" not in joined_commands
        assert "run_scenario.py" not in joined_commands
        assert "dsp-remote-scenario" not in joined_commands
    finally:
        server.stop()


def test_webshell_http_followup_uses_discovered_http_service_reason(tmp_path: Path) -> None:
    import json

    server = WebshellTestServer(storage_dir=tmp_path / "server")
    server.start()
    try:
        manager = RunManager(runs_dir=tmp_path / "runs")
        _, run_dir, exit_code = manager.run(
            operational_profile="normal",
            scenario_ids=["http_followup"],
            target_net="127.0.0.0/30",
            dry_run=False,
            execution_provider="webshell",
            webshell_family="jsp",
            webshell_url=server.webshell_url,
            remote_work_dir=str(tmp_path / "remote-work"),
        )
        assert exit_code == 0
        traffic = json.loads((run_dir / "traffic_summary.json").read_text(encoding="utf-8"))
        http_followup = (traffic.get("scenarios") or {}).get("http_followup") or {}
        assert (
            http_followup.get("selected_http_target_reason")
            == "discovered_http_service_from_webshell_discovery"
        )
        discovery = traffic.get("discovery") or {}
        assert discovery.get("discovery_origin") == "webshell_host"
        assert discovery.get("runner_upload") is False
    finally:
        server.stop()


def test_webshell_dns_tunnel_uses_alive_hosts(tmp_path: Path) -> None:
    import json

    server = WebshellTestServer(storage_dir=tmp_path / "server")
    server.start()
    try:
        manager = RunManager(runs_dir=tmp_path / "runs")
        _, run_dir, exit_code = manager.run(
            operational_profile="normal",
            scenario_ids=["dns_tunnel"],
            target_net="127.0.0.0/30",
            dry_run=False,
            execution_provider="webshell",
            webshell_family="jsp",
            webshell_url=server.webshell_url,
            remote_work_dir=str(tmp_path / "remote-work"),
        )
        assert exit_code == 0
        traffic = json.loads((run_dir / "traffic_summary.json").read_text(encoding="utf-8"))
        dns_tunnel = (traffic.get("scenarios") or {}).get("dns_tunnel") or {}
        assert dns_tunnel.get("target_selection") == "alive_hosts"
        alive_hosts = set((traffic.get("discovery") or {}).get("alive_hosts") or [])
        selected = dns_tunnel.get("selected_target") or dns_tunnel.get("target")
        if selected and alive_hosts:
            assert selected in alive_hosts
    finally:
        server.stop()
