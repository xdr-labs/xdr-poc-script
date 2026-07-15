"""Core SQLi signature payloads — time-based SLEEP() and UNION/MD5 detection patterns."""

from __future__ import annotations

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


def test_normal_profile_includes_core_sqli_patterns() -> None:
    params = scenario_params_for_profile("sql_injection", "normal")
    plans = plan_sqli_requests(
        endpoints=[("10.10.10.20", 8080), ("10.10.10.21", 9000)],
        max_hosts=params["max_hosts"],
        max_per_host=params["max_per_host"],
        max_total=params["max_total"],
    )
    assert params["max_per_host"] == 500
    assert any(p.payload_category == SQLI_CORE_TIME_BASED_CATEGORY for p in plans)
    assert any(p.payload_category == SQLI_CORE_UNION_SELECT_CATEGORY for p in plans)
    assert build_core_time_based_payload(6) in {p.payload for p in plans}
    assert build_core_union_select_payload(999999999) in {p.payload for p in plans}


def test_each_host_gets_at_least_10_core_patterns() -> None:
    plans = plan_sqli_requests(
        endpoints=[("10.10.10.20", 8080), ("10.10.10.21", 9000)],
        max_hosts=2,
        max_per_host=500,
        max_total=1000,
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
        max_per_host=40,
    )
    time_based = [
        p for p in plans if p.payload_category == SQLI_CORE_TIME_BASED_CATEGORY
    ]
    union_select = [
        p for p in plans if p.payload_category == SQLI_CORE_UNION_SELECT_CATEGORY
    ]
    assert len(time_based) >= 10
    assert len(union_select) >= 10
    for plan in time_based:
        decoded = unquote(plan.url)
        assert "SELECT" in decoded
        assert "SLEEP(" in decoded
        assert "--" in decoded
    for plan in union_select:
        decoded = unquote(plan.url)
        assert "SELECT" in decoded
        assert "UNION" in decoded
        assert "MD5(" in decoded
        assert "--" in decoded
    # Combined marker set must appear across the planned core URIs.
    combined = " ".join(unquote(p.url) for p in time_based + union_select)
    for marker in REQUIRED_URI_MARKERS:
        assert marker in combined


def test_core_signature_uris_are_not_double_encoded() -> None:
    plans = plan_sqli_requests(
        endpoints=[("10.10.10.20", 8080)],
        max_hosts=1,
        max_per_host=40,
    )
    core_urls = [
        p.url
        for p in plans
        if p.payload_category
        in {SQLI_CORE_TIME_BASED_CATEGORY, SQLI_CORE_UNION_SELECT_CATEGORY}
    ]
    assert core_urls
    for url in core_urls:
        assert "%25" not in url
        assert "%27" in url or "SLEEP" in unquote(url) or "UNION" in unquote(url)
        # Single-encoded forms expected in wire URI.
        if "SLEEP" in unquote(url):
            assert "SLEEP(" in unquote(url)
            assert "%28" in url or "(" in url


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
    assert len(local_plan["requests"]) == len(remote_plan["requests"])
    assert {item["url"] for item in local_plan["requests"]} == {
        item["url"] for item in remote_plan["requests"]
    }
    local_categories = {item["payload_category"] for item in local_plan["requests"]}
    assert SQLI_CORE_TIME_BASED_CATEGORY in local_categories
    assert SQLI_CORE_UNION_SELECT_CATEGORY in local_categories


def test_sqli_skips_without_http_targets(tmp_runs_dir) -> None:
    manager = RunManager(runs_dir=tmp_runs_dir)
    _, run_dir, exit_code = manager.run(
        scenario_ids=["sql_injection"],
        target_net="10.10.10.0/24",
        dry_run=True,
        scenario_params={
            "sql_injection": {
                "max_hosts": 1,
                # Force empty selection via cache with no selected endpoints.
                HTTP_ENDPOINT_SELECTION_CACHE_KEY: selection_to_cache(
                    HttpFollowupSelection(probed=[], selected=[], skip_reason="HTTP_TARGETS_NOT_FOUND")
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
        max_per_host=40,
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
    assert paths  # derived from existing path pool
    assert not all(p.path == "/search" for p in core)
