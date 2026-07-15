"""SQL injection strengthening — unified suspected-query volume."""

from __future__ import annotations

import json

from dsp.protocols.http.sqli_payloads import (
    SQLI_PATHS,
    SQLI_REQUESTS_PER_HOST,
    plan_sqli_requests,
)
from dsp.runtime.traffic_profiles import scenario_params_for_profile
from dsp.runner import RunManager


def test_normal_profile_sql_injection_1000_requests_for_two_hosts():
    params = scenario_params_for_profile("sql_injection", "normal")
    assert params["max_total"] == 1000
    assert params["max_hosts"] == 2
    assert params["max_per_host"] == 500


def test_plan_sqli_requests_normal_profile_volume():
    params = scenario_params_for_profile("sql_injection", "normal")
    plans = plan_sqli_requests(
        endpoints=[("10.10.10.20", 8080), ("10.10.10.21", 9000)],
        max_hosts=params["max_hosts"],
    )
    assert len(plans) == 1000
    counts: dict[str, int] = {}
    for plan in plans:
        key = f"{plan.host}:{plan.port}"
        counts[key] = counts.get(key, 0) + 1
    assert len(counts) == 2
    assert all(count == SQLI_REQUESTS_PER_HOST for count in counts.values())


def test_plan_sqli_uses_all_csv_paths():
    plans = plan_sqli_requests(
        endpoints=[("10.10.10.20", 8080)],
        max_hosts=1,
        repeats_per_path=1,
    )
    paths = {p.path if not p.query else f"{p.path}?{p.query}" for p in plans}
    assert len(paths) == len(SQLI_PATHS)


def test_sql_injection_writes_jsonl_evidence(tmp_runs_dir):
    manager = RunManager(runs_dir=tmp_runs_dir)
    _, run_dir, exit_code = manager.run(
        scenario_ids=["sql_injection"],
        target_net="10.10.10.0/24",
        dry_run=True,
        scenario_params={
            "sql_injection": {
                "endpoints": [["10.10.10.20", 8080]],
                "max_hosts": 1,
            }
        },
    )
    assert exit_code == 0
    jsonl_path = run_dir / "sql_injection_requests.jsonl"
    assert jsonl_path.exists()
    records = [json.loads(line) for line in jsonl_path.read_text().splitlines() if line.strip()]
    assert len(records) == SQLI_REQUESTS_PER_HOST
    required_fields = {
        "target",
        "method",
        "url",
        "path",
        "parameter",
        "payload_category",
        "payload",
        "response_code",
        "transport",
    }
    assert required_fields.issubset(records[0])
    categories = {record["payload_category"] for record in records}
    assert "core_time_based" in categories
    assert "core_union_select" in categories
    assert "suspected_query" in categories
    assert records[0]["transport"] == "query"


def test_sql_injection_no_detection_success_inference(tmp_runs_dir):
    manager = RunManager(runs_dir=tmp_runs_dir)
    _, run_dir, _ = manager.run(
        scenario_ids=["sql_injection"],
        target_net="10.10.10.0/24",
        dry_run=True,
        scenario_params={
            "sql_injection": {
                "endpoints": [["10.10.10.20", 8080]],
                "max_hosts": 1,
            }
        },
    )
    validation = json.loads((run_dir / "validation.json").read_text())
    result = validation["results"][0]
    assert "detection_success" not in result
    assert "detection_inferred" not in result.get("metrics", {})
