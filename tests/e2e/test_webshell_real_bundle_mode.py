"""Real webshell command-only E2E — local fake JSP server, real CLI/RunManager path."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from dsp.event_store import EventQuery, EventStore
from dsp.execution.remote.exceptions import RemoteArtifactUploadError
from dsp.runner import RunManager
from tests.e2e.fixtures.webshell_test_server import WebshellTestServer


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _run_dsp_cli(
    *,
    webshell_url: str,
    remote_work_dir: str,
    runs_dir: Path,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = dict(**{k: v for k, v in __import__("os").environ.items()})
    env["DSP_RUNS_DIR"] = str(runs_dir)
    if extra_env:
        env.update(extra_env)
    cmd = [
        sys.executable,
        "-m",
        "dsp.runner.cli",
        "run",
        "--profile",
        "normal",
        "--execution-provider",
        "webshell",
        "--webshell-family",
        "jsp",
        "--webshell-url",
        webshell_url,
        "--remote-work-dir",
        remote_work_dir,
        "--target-net",
        "127.0.0.0/30",
        "--quiet",
    ]
    return subprocess.run(
        cmd,
        cwd=str(_repo_root()),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def _latest_run_dir(runs_dir: Path) -> Path:
    candidates = sorted(
        (path for path in runs_dir.iterdir() if path.is_dir()),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    assert candidates, f"no run directories under {runs_dir}"
    return candidates[0]


def _first_jsonl_line(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            return line
    raise AssertionError(f"no non-empty lines in {path}")


def _assert_no_forbidden_webshell_artifacts(server: WebshellTestServer) -> None:
    joined_uploads = "\n".join(server.upload_calls)
    joined_commands = "\n".join(server.command_calls)
    for token in (
        "manifest.json",
        "run_scenario.py",
        "remote_discovery.py",
        "dsp-remote-scenario",
        "python3 /tmp/dsp/",
    ):
        assert token not in joined_uploads, f"forbidden upload token: {token}"
        assert token not in joined_commands, f"forbidden command token: {token}"


@pytest.fixture
def webshell_fixture(tmp_path: Path):
    server = WebshellTestServer(storage_dir=tmp_path / "remote-storage")
    remote_work_dir = str(tmp_path / "remote-work")
    url = server.start()
    try:
        yield server, remote_work_dir, tmp_path / "runs"
    finally:
        server.stop()


def _run_port_sweep_manager(
    *,
    server: WebshellTestServer,
    remote_work_dir: str,
    runs_dir: Path,
) -> tuple[object, Path, int]:
    manager = RunManager(runs_dir=runs_dir)
    return manager.run(
        scenario_ids=["port_sweep"],
        target_net="127.0.0.0/30",
        dry_run=False,
        scenario_params={"port_sweep": {"max_hosts": 1, "max_ports": 2}},
        execution_provider="webshell",
        webshell_family="jsp",
        webshell_url=server.webshell_url,
        remote_work_dir=remote_work_dir,
    )


def test_real_webshell_command_only_cli_success(webshell_fixture) -> None:
    server, remote_work_dir, runs_dir = webshell_fixture
    runs_dir.mkdir(parents=True, exist_ok=True)

    completed = _run_dsp_cli(
        webshell_url=server.webshell_url,
        remote_work_dir=remote_work_dir,
        runs_dir=runs_dir,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout

    run_dir = _latest_run_dir(runs_dir)
    run_id = run_dir.name

    _assert_no_forbidden_webshell_artifacts(server)
    assert server.command_calls, "expected webshell command dispatch"

    for name in ("events.db", "report.json", "validation.json", "traffic_summary.json"):
        assert (run_dir / name).is_file(), f"missing {name}"

    store = EventStore.open_existing(run_dir / "events.db")
    try:
        imported = store.count(EventQuery(run_id=run_id))
        assert imported >= 1
        assert store.count(
            EventQuery(run_id=run_id, scenario_id="port_sweep", event="port_probe_sent")
        ) >= 1
    finally:
        store.close()

    assert (run_dir / "events.jsonl").is_file()
    assert _first_jsonl_line(run_dir / "events.jsonl").startswith("{")


def test_real_webshell_command_only_run_manager_success(
    tmp_path: Path,
    webshell_fixture,
) -> None:
    server, remote_work_dir, runs_dir = webshell_fixture
    manager = RunManager(runs_dir=runs_dir)
    run, run_dir, exit_code = manager.run(
        operational_profile="normal",
        scenario_ids=["port_sweep", "dns_tunnel", "http_followup"],
        target_net="127.0.0.0/30",
        dry_run=False,
        execution_provider="webshell",
        webshell_family="jsp",
        webshell_url=server.webshell_url,
        remote_work_dir=remote_work_dir,
    )

    assert exit_code == 0
    assert run.status.value == "completed"
    assert (run_dir / "events.jsonl").is_file()
    assert (run_dir / "report.json").is_file()
    _assert_no_forbidden_webshell_artifacts(server)

    traffic = json.loads((run_dir / "traffic_summary.json").read_text(encoding="utf-8"))
    discovery = traffic.get("discovery") or {}
    assert discovery.get("discovery_origin") == "webshell_host"
    assert discovery.get("runner_upload") is False
    http_followup = (traffic.get("scenarios") or {}).get("http_followup") or {}
    assert (
        http_followup.get("selected_http_target_reason")
        == "discovered_http_service_from_webshell_discovery"
    )


def test_html_wrapped_command_output_still_records_events(tmp_path: Path) -> None:
    server = WebshellTestServer(
        storage_dir=tmp_path / "storage",
        wrap_command_output_in_html=True,
        wrap_download_in_html=True,
    )
    server.start()
    manager = RunManager(runs_dir=tmp_path / "runs")
    try:
        _, run_dir, exit_code = manager.run(
            scenario_ids=["port_sweep"],
            target_net="127.0.0.0/30",
            dry_run=False,
            scenario_params={"port_sweep": {"max_hosts": 1, "max_ports": 2}},
            execution_provider="webshell",
            webshell_family="jsp",
            webshell_url=server.webshell_url,
            remote_work_dir=str(tmp_path / "remote-work"),
        )
        assert exit_code == 0
        assert (run_dir / "events.jsonl").is_file()
        _assert_no_forbidden_webshell_artifacts(server)
    finally:
        server.stop()


def test_forbidden_manifest_upload_fail_fast(tmp_path: Path) -> None:
    from dsp.execution.providers.runtime.command import CommandExecutionPolicy
    from dsp.execution.providers.runtime.transport import TransportRuntimeConfiguration
    from dsp.execution.providers.webshell.jsp import JspWebshellProvider
    from dsp.execution import WebshellExecutionProvider
    from dsp.execution.webshell.transport import RealHttpTransport, RetryPolicy
    from dsp.execution.webshell_config import WebshellExecutionConfig

    server = WebshellTestServer(storage_dir=tmp_path / "storage")
    server.start()
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
    provider = WebshellExecutionProvider(
        WebshellExecutionConfig(provider_type="jsp", webshell_url=server.webshell_url),
        transport=transport,
        family_provider=family_provider,
    )
    local = tmp_path / "manifest.json"
    local.write_text("{}", encoding="utf-8")
    try:
        with pytest.raises(RemoteArtifactUploadError, match="forbidden webshell upload blocked"):
            provider.upload_file(local, "/tmp/dsp/run01/manifest.json")
        assert not server.upload_calls
    finally:
        server.stop()
