"""Tests for scripts/run_dsp_release_1_0_lab_test.py."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from tests.e2e.fixtures.webshell_test_server import WebshellTestServer

DSP_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = DSP_ROOT / "scripts" / "run_dsp_release_1_0_lab_test.py"
RUN_ID = "release_1_0_lab_script_test"


def _run_script(*args: str, check: bool = False) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, str(SCRIPT_PATH), *args]
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def _parse_run_id(stdout: str) -> str:
    match = re.search(r"^run_id=(\S+)", stdout, re.MULTILINE)
    assert match is not None, f"run_id not found in output:\n{stdout}"
    return match.group(1)


def test_help_works() -> None:
    result = _run_script("--help")
    assert result.returncode == 0
    assert "--mode" in result.stdout
    assert "--traffic-profile" in result.stdout
    assert "local" in result.stdout
    assert "webshell" in result.stdout


def test_invalid_mode_fails_clearly() -> None:
    result = _run_script(
        "--mode",
        "invalid",
        "--output-dir",
        "/tmp/dsp-invalid-mode",
    )
    assert result.returncode != 0
    combined = f"{result.stdout}\n{result.stderr}"
    assert "invalid choice" in combined.lower() or "error" in combined.lower()


def test_invalid_traffic_profile_rejected(tmp_path: Path) -> None:
    result = _run_script(
        "--mode",
        "local",
        "--scenario",
        "dummy",
        "--traffic-profile",
        "turbo",
        "--dry-run",
        "--output-dir",
        str(tmp_path / "out"),
    )
    assert result.returncode == 2
    assert "unknown traffic profile" in result.stderr


def test_local_mode_creates_expected_files(tmp_path: Path) -> None:
    output_dir = tmp_path / "dsp-local-test"
    result = _run_script(
        "--mode",
        "local",
        "--scenario",
        "dummy",
        "--traffic-profile",
        "normal",
        "--dry-run",
        "--output-dir",
        str(output_dir),
        check=True,
    )

    assert result.returncode == 0
    assert "traffic_profile=normal" in result.stdout
    assert "event_count=" in result.stdout
    assert "manual_next_steps:" in result.stdout
    assert "generated_files:" in result.stdout

    run_id = _parse_run_id(result.stdout)
    run_dir = output_dir / run_id
    assert run_dir.is_dir(), f"missing run directory: {run_dir}"

    expected = [
        run_dir / "events.db",
        run_dir / f"run_{run_id}.json",
        run_dir / f"run_{run_id}.md",
        run_dir / "verification_checklist.md",
        run_dir / "investigation_notes.md",
        run_dir / "evidence_summary_template.md",
    ]
    for path in expected:
        assert path.is_file(), f"missing expected artifact: {path}"
        assert path.stat().st_size > 0


def test_local_mode_passes_traffic_profile(tmp_path: Path) -> None:
    output_dir = tmp_path / "dsp-local-balanced"
    result = _run_script(
        "--mode",
        "local",
        "--scenario",
        "dummy",
        "--traffic-profile",
        "balanced",
        "--dry-run",
        "--output-dir",
        str(output_dir),
        check=True,
    )
    # v1.3.0+ maps legacy alias "balanced" → "normal".
    assert "traffic_profile=normal" in result.stdout
    assert "scenario=dummy" in result.stdout


def test_webshell_mode_creates_expected_files(tmp_path: Path) -> None:
    output_dir = tmp_path / "dsp-webshell-test"
    storage_dir = tmp_path / "remote-storage"
    remote_work_dir = "/tmp/dsp"

    server = WebshellTestServer(storage_dir=storage_dir)
    server.start()
    try:
        result = _run_script(
            "--mode",
            "webshell",
            "--scenario",
            "port_sweep",
            "--traffic-profile",
            "normal",
            "--webshell-family",
            "jsp",
            "--webshell-url",
            server.webshell_url,
            "--remote-work-dir",
            remote_work_dir,
            "--output-dir",
            str(output_dir),
            "--run-id",
            RUN_ID,
            "--dry-run",
            check=True,
        )
    finally:
        server.stop()

    assert result.returncode == 0
    assert "traffic_profile=normal" in result.stdout
    assert "event_count=" in result.stdout
    assert "manual_next_steps:" in result.stdout

    run_id = _parse_run_id(result.stdout)
    run_dir = output_dir / run_id
    assert run_dir.is_dir(), f"missing run directory: {run_dir}"
    assert (run_dir / "events.db").is_file()
    assert (run_dir / "validation.json").is_file()
    assert (run_dir / "traffic_summary.json").is_file()

    assert server.command_calls[:3] == ["whoami", "hostname", "pwd"]
    assert not any("run_scenario.py" in call for call in server.upload_calls)
    assert not any("manifest.json" in call for call in server.upload_calls)
    assert not any(call.startswith("dsp-remote-scenario ") for call in server.command_calls)
    assert not any("python3 /tmp/dsp/" in call for call in server.command_calls)


def test_webshell_mode_rejects_disallowed_command(tmp_path: Path) -> None:
    result = _run_script(
        "--mode",
        "webshell",
        "--scenario",
        "dummy",
        "--webshell-family",
        "jsp",
        "--webshell-url",
        "http://127.0.0.1/shell.jsp",
        "--remote-work-dir",
        "/tmp/dsp",
        "--output-dir",
        str(tmp_path / "out"),
        "--webshell-commands",
        "rm,-rf,/",
    )
    assert result.returncode == 2
    assert "disallowed webshell command" in result.stderr
