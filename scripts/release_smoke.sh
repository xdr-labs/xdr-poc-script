#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -x .venv/bin/dsp ]]; then
  python3 -m venv .venv
  .venv/bin/pip install -e ".[dev]" -q
fi

export PATH="$ROOT/.venv/bin:$PATH"

echo "== dsp --version =="
dsp --version

echo "== dsp run local dry-run =="
dsp run --profile normal --dry-run --quiet

echo "== dsp run webshell dry-run =="
dsp run \
  --profile normal \
  --execution-provider webshell \
  --webshell-family jsp \
  --webshell-url http://dummy/shell.jsp \
  --dry-run \
  --quiet

echo "== dsp run webshell real local gate =="
python - <<'PY'
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from dsp.event_store import EventQuery, EventStore
from tests.e2e.fixtures.webshell_test_server import WebshellTestServer

root = Path.cwd()
runs_parent = Path(tempfile.mkdtemp(prefix="dsp-smoke-"))
remote_work_dir = runs_parent / "remote-work"
server = WebshellTestServer(storage_dir=runs_parent / "remote-storage")
url = server.start()
try:
    import subprocess

    env = dict(**{k: v for k, v in __import__("os").environ.items()})
    env["DSP_RUNS_DIR"] = str(runs_parent / "runs")
    completed = subprocess.run(
        [
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
            url,
            "--remote-work-dir",
            str(remote_work_dir),
            "--target-net",
            "127.0.0.0/30",
            "--quiet",
        ],
        cwd=str(root),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        raise SystemExit(completed.returncode)

    run_dirs = sorted(
        (runs_parent / "runs").iterdir(),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not run_dirs:
        raise SystemExit("webshell smoke: no run directory created")
    run_dir = run_dirs[0]
    run_id = run_dir.name
    required = (
        "events.jsonl",
        "events.db",
        "report.json",
        "validation.json",
        "execution_stdout_stderr.txt",
    )
    missing = [name for name in required if not (run_dir / name).is_file()]
    if missing:
        raise SystemExit(f"webshell smoke: missing artifacts: {', '.join(missing)}")

    store = EventStore.open_existing(run_dir / "events.db")
    try:
        imported = store.count(EventQuery(run_id=run_id))
    finally:
        store.close()
    if imported < 1:
        raise SystemExit("webshell smoke: no events imported")

    remote_run_dir = f"{remote_work_dir.as_posix().rstrip('/')}/{run_id}"
    remote_paths = server.remote_tree(str(remote_work_dir))
    print(f"webshell smoke run_dir={run_dir}")
    print(f"webshell smoke remote_run_dir={remote_run_dir}")
    print(f"webshell smoke imported_events={imported}")
    print(f"webshell smoke remote_paths={len(remote_paths)}")
finally:
    server.stop()
PY

echo "== pytest --collect-only =="
python -m pytest --collect-only -q

echo "release smoke: OK"
