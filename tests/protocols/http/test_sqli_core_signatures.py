"""Core SQLi signature payloads — time-based SLEEP() and UNION/MD5 detection patterns."""

from __future__ import annotations

from collections import Counter
from urllib.parse import unquote

from dsp.engine.host_selection import (
    HTTP_ENDPOINT_SELECTION_CACHE_KEY,
    HttpFollowupSelection,
    selection_to_cache,
)
from dsp.engine.scenario_engine import TargetSet
from dsp.execution.remote.command.discovery_plans import build_plan_from_discovery
from dsp.execution.remote.command.scenario_plans import plan_sql_injection
from dsp.protocols.http.sqli_payloads import (
    SQLI_CORE_REPEATS_PER_PATTERN,
    SQLI_CORE_TIME_BASED_CATEGORY,
    SQLI_CORE_UNION_SELECT_CATEGORY,
    build_core_time_based_payload,
    build_core_union_select_payload,
    plan_sqli_requests,
)
from dsp.protocols.http.target_probe import HTTPEndpointProbeResult
from dsp.runtime.traffic_profiles import scenario_params_for_profile
from dsp.runner import RunManager


REQUIRED_URI_MARKERS = ("SELECT", "SLEEP(", "UNION", "MD5(", "--")


def _cache_params(params: dict, *, host: str = "10.10.10.97", port: int = 8080) -> None:
    selected = HTTPEndpointProbeResult(
        host=host,
        port=port,
        scheme="http",
        status_counts={500: 1},
        selected=True,
        selection_reason="error_responses_available",
    )
    params[HTTP_ENDPOINT_SELECTION_CACHE_KEY] = selection_to_cache(
        HttpFollowupSelection(probed=[selected], selected=[selected])
    )


def _host_core_counts(plans) -> dict[str, Counter[str]]:
    counts: dict[str, Counter[str]] = {}
    for plan in plans:
        key = f"{plan.host}:{plan.port}"
        counts.setdefault(key, Counter())[plan.payload_category] += 1
    return counts


def test_normal_profile_includes_core_sqli_patterns() -> None:
    params = scenario_params_for_profile("sql_injection", "normal")
    assert params["core_repeats_per_pattern"] == 100
    plans = plan_sqli_requests(
        endpoints=[("10.10.10.20", 8080), ("10.10.10.21", 9000)],
        max_hosts=params["max_hosts"],
        max_per_host=params["max_per_host"],
        max_total=params["max_total"],
        core_repeats_per_pattern=params["core_repeats_per_pattern"],
    )
    assert params["max_per_host"] == 500
    assert any(p.payload_category == SQLI_CORE_TIME_BASED_CATEGORY for p in plans)
    assert any(p.payload_category == SQLI_CORE_UNION_SELECT_CATEGORY for p in plans)
    assert build_core_time_based_payload(6) in {p.payload for p in plans}
    assert build_core_union_select_payload(999999999) in {p.payload for p in plans}


def test_normal_profile_scales_core_sqli_per_host() -> None:
    params = scenario_params_for_profile("sql_injection", "normal")
    cases = [
        ([("10.10.10.1", 80)], 1, 200),
        ([("10.10.10.1", 80), ("10.10.10.2", 8080)], 2, 400),
        ([("10.10.10.1", 80), ("10.10.10.2", 8080), ("10.10.10.3", 8000)], 3, 600),
    ]
    for endpoints, max_hosts, min_core_total in cases:
        plans = plan_sqli_requests(
            endpoints=endpoints,
            max_hosts=max_hosts,
            max_per_host=params["max_per_host"],
            max_total=params["max_per_host"] * max_hosts,
            core_repeats_per_pattern=params["core_repeats_per_pattern"],
        )
        core = [
            p
            for p in plans
            if p.payload_category
            in {SQLI_CORE_TIME_BASED_CATEGORY, SQLI_CORE_UNION_SELECT_CATEGORY}
        ]
        assert len(core) >= min_core_total
        per_host = _host_core_counts(plans)
        assert len(per_host) == max_hosts
        for counts in per_host.values():
            assert counts[SQLI_CORE_TIME_BASED_CATEGORY] >= 100
            assert counts[SQLI_CORE_UNION_SELECT_CATEGORY] >= 100
            assert (
                counts[SQLI_CORE_TIME_BASED_CATEGORY]
                + counts[SQLI_CORE_UNION_SELECT_CATEGORY]
                >= 200
            )


def test_each_host_gets_at_least_100_core_patterns() -> None:
    params = scenario_params_for_profile("sql_injection", "normal")
    plans = plan_sqli_requests(
        endpoints=[("10.10.10.20", 8080), ("10.10.10.21", 9000)],
        max_hosts=2,
        max_per_host=params["max_per_host"],
        max_total=params["max_total"],
        core_repeats_per_pattern=params["core_repeats_per_pattern"],
    )
    for host in ("10.10.10.20", "10.10.10.21"):
        host_plans = [p for p in plans if p.host == host]
        time_based = [
            p for p in host_plans if p.payload_category == SQLI_CORE_TIME_BASED_CATEGORY
        ]
        union_select = [
            p for p in host_plans if p.payload_category == SQLI_CORE_UNION_SELECT_CATEGORY
        ]
        assert len(time_based) >= SQLI_CORE_REPEATS_PER_PATTERN
        assert len(union_select) >= SQLI_CORE_REPEATS_PER_PATTERN
        assert len({p.payload for p in time_based}) >= 3
        assert len({p.payload for p in union_select}) >= 3


def test_core_signature_uris_contain_detection_markers() -> None:
    plans = plan_sqli_requests(
        endpoints=[("10.10.10.20", 8080)],
        max_hosts=1,
        max_per_host=250,
        core_repeats_per_pattern=100,
    )
    time_based = [
        p for p in plans if p.payload_category == SQLI_CORE_TIME_BASED_CATEGORY
    ]
    union_select = [
        p for p in plans if p.payload_category == SQLI_CORE_UNION_SELECT_CATEGORY
    ]
    assert len(time_based) >= 100
    assert len(union_select) >= 100
    for plan in time_based[:5]:
        decoded = unquote(plan.url)
        assert "SELECT" in decoded
        assert "SLEEP(" in decoded
        assert "--" in decoded
    for plan in union_select[:5]:
        decoded = unquote(plan.url)
        assert "SELECT" in decoded
        assert "UNION" in decoded
        assert "MD5(" in decoded
        assert "--" in decoded
    combined = " ".join(unquote(p.url) for p in time_based[:20] + union_select[:20])
    for marker in REQUIRED_URI_MARKERS:
        assert marker in combined


def test_core_signature_uris_are_not_double_encoded() -> None:
    plans = plan_sqli_requests(
        endpoints=[("10.10.10.20", 8080)],
        max_hosts=1,
        max_per_host=250,
        core_repeats_per_pattern=100,
    )
    core_urls = [
        p.url
        for p in plans
        if p.payload_category
        in {SQLI_CORE_TIME_BASED_CATEGORY, SQLI_CORE_UNION_SELECT_CATEGORY}
    ]
    assert len(core_urls) >= 200
    for url in core_urls:
        assert "%25" not in url


def test_core_payloads_are_not_deduped_to_unique_set() -> None:
    plans = plan_sqli_requests(
        endpoints=[("10.10.10.20", 8080)],
        max_hosts=1,
        max_per_host=250,
        core_repeats_per_pattern=100,
    )
    time_based = [
        p.payload for p in plans if p.payload_category == SQLI_CORE_TIME_BASED_CATEGORY
    ]
    # Same SLEEP template may repeat, but request count must remain 100.
    assert len(time_based) == 100
    assert len(set(time_based)) < len(time_based)


def test_local_and_webshell_core_sqli_plans_match() -> None:
    params = scenario_params_for_profile("sql_injection", "normal")
    _cache_params(params)
    targets = TargetSet(
        target_net="10.10.10.0/24",
        hosts=["10.10.10.97"],
        service_hosts={"http_targets": ["10.10.10.97"]},
        service_endpoints={"http_targets": [("10.10.10.97", 8080)]},
        discovery_enabled=True,
    )
    discovery = {
        "target_net": "10.10.10.0/24",
        "hosts": ["10.10.10.97"],
        "service_hosts": {"http_targets": ["10.10.10.97"]},
        "service_endpoints": {"http_targets": [("10.10.10.97", 8080)]},
        "discovery_enabled": True,
        "discovery_meta": {"discovery_origin": "webshell_host"},
    }

    local_plan = plan_sql_injection(targets, params, dry_run=False)
    remote_plan = build_plan_from_discovery(
        "sql_injection",
        discovery,
        params,
        dry_run=False,
    )
    assert local_plan["mode"] != "skip"
    assert remote_plan["mode"] != "skip"
    assert len(local_plan["requests"]) == len(remote_plan["requests"]) == 500
    local_core = [
        item
        for item in local_plan["requests"]
        if item["payload_category"]
        in {SQLI_CORE_TIME_BASED_CATEGORY, SQLI_CORE_UNION_SELECT_CATEGORY}
    ]
    remote_core = [
        item
        for item in remote_plan["requests"]
        if item["payload_category"]
        in {SQLI_CORE_TIME_BASED_CATEGORY, SQLI_CORE_UNION_SELECT_CATEGORY}
    ]
    assert len(local_core) >= 200
    assert len(remote_core) >= 200
    assert {item["url"] for item in local_plan["requests"]} == {
        item["url"] for item in remote_plan["requests"]
    }


def test_sqli_skips_without_http_targets(tmp_runs_dir) -> None:
    manager = RunManager(runs_dir=tmp_runs_dir)
    _, run_dir, exit_code = manager.run(
        scenario_ids=["sql_injection"],
        target_net="10.10.10.0/24",
        dry_run=True,
        scenario_params={
            "sql_injection": {
                "max_hosts": 1,
                HTTP_ENDPOINT_SELECTION_CACHE_KEY: selection_to_cache(
                    HttpFollowupSelection(
                        probed=[],
                        selected=[],
                        skip_reason="HTTP_TARGETS_NOT_FOUND",
                    )
                ),
            }
        },
    )
    assert exit_code == 0
    validation = (run_dir / "validation.json").read_text()
    assert "skipped" in validation or "HTTP_TARGETS_NOT_FOUND" in (
        run_dir / "events.jsonl"
    ).read_text()


def test_core_payloads_use_query_parameters_not_hardcoded_search_only() -> None:
    plans = plan_sqli_requests(
        endpoints=[("10.10.10.20", 8080)],
        max_hosts=1,
        max_per_host=250,
        core_repeats_per_pattern=100,
    )
    core = [
        p
        for p in plans
        if p.payload_category
        in {SQLI_CORE_TIME_BASED_CATEGORY, SQLI_CORE_UNION_SELECT_CATEGORY}
    ]
    assert all(p.parameter for p in core)
    assert all("=" in p.query for p in core)
    paths = {p.path for p in core}
    assert paths
    assert not all(p.path == "/search" for p in core)


def test_normal_dry_run_attempts_match_planned_core_volume(tmp_runs_dir) -> None:
    import json

    params = scenario_params_for_profile("sql_injection", "normal")
    selected = [
        HTTPEndpointProbeResult(
            host="10.10.10.20",
            port=8080,
            scheme="http",
            status_counts={500: 1},
            selected=True,
            selection_reason="error_responses_available",
        ),
        HTTPEndpointProbeResult(
            host="10.10.10.21",
            port=80,
            scheme="http",
            status_counts={404: 1},
            selected=True,
            selection_reason="error_responses_available",
        ),
    ]
    params[HTTP_ENDPOINT_SELECTION_CACHE_KEY] = selection_to_cache(
        HttpFollowupSelection(probed=selected, selected=selected)
    )
    manager = RunManager(runs_dir=tmp_runs_dir)
    _, run_dir, exit_code = manager.run(
        scenario_ids=["sql_injection"],
        target_net="10.10.10.0/24",
        dry_run=True,
        operational_profile="normal",
        scenario_params={"sql_injection": params},
    )
    assert exit_code == 0
    records = [
        json.loads(line)
        for line in (run_dir / "sql_injection_requests.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert len(records) == 1000
    per_target: dict[str, Counter[str]] = {}
    for record in records:
        target = record["target"]
        per_target.setdefault(target, Counter())[record["payload_category"]] += 1
    assert len(per_target) == 2
    for target, counts in per_target.items():
        assert counts["core_time_based"] >= 100, target
        assert counts["core_union_select"] >= 100, target
        assert counts["core_time_based"] + counts["core_union_select"] >= 200, target
