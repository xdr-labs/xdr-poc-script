"""Unified SQL injection module — path volume, encoding, and cross-provider parity."""

from __future__ import annotations

from dsp.engine.host_selection import (
    HTTP_ENDPOINT_SELECTION_CACHE_KEY,
    HttpFollowupSelection,
    selection_to_cache,
)
from dsp.engine.scenario_engine import TargetSet
from dsp.execution.remote.command.discovery_plans import build_plan_from_discovery
from dsp.execution.remote.command.scenario_plans import plan_sql_injection
from dsp.protocols.http.sqli_payloads import (
    SQLI_PATHS,
    SQLI_REPEATS_PER_PATH,
    SQLI_REQUESTS_PER_HOST,
    plan_sqli_requests,
)
from dsp.protocols.http.target_probe import HTTPEndpointProbeResult
from dsp.runtime.traffic_profiles import scenario_params_for_profile


def _targets() -> TargetSet:
    return TargetSet(
        target_net="10.10.10.0/24",
        hosts=["10.10.10.97"],
        service_hosts={"http_targets": ["10.10.10.97"]},
        service_endpoints={"http_targets": [("10.10.10.97", 8080)]},
        discovery_enabled=True,
    )


def _discovery_dict() -> dict:
    return {
        "target_net": "10.10.10.0/24",
        "hosts": ["10.10.10.97"],
        "service_hosts": {"http_targets": ["10.10.10.97"]},
        "service_endpoints": {"http_targets": [("10.10.10.97", 8080)]},
        "discovery_enabled": True,
        "discovery_meta": {"discovery_origin": "webshell_host"},
    }


def _cache_params(params: dict) -> None:
    selected = HTTPEndpointProbeResult(
        host="10.10.10.97",
        port=8080,
        scheme="http",
        status_counts={500: 1},
        selected=True,
        selection_reason="error_responses_available",
    )
    params[HTTP_ENDPOINT_SELECTION_CACHE_KEY] = selection_to_cache(
        HttpFollowupSelection(probed=[selected], selected=[selected])
    )


def test_sqli_paths_count_is_53() -> None:
    assert len(SQLI_PATHS) == 53
    assert SQLI_REPEATS_PER_PATH == 3
    assert SQLI_REQUESTS_PER_HOST == 500


def test_sqli_requests_per_single_target() -> None:
    plans = plan_sqli_requests(endpoints=[("10.10.10.20", 8080)], max_hosts=1)
    assert len(plans) == 500
    assert all(p.transport == "query" for p in plans)
    categories = {p.payload_category for p in plans}
    assert "core_time_based" in categories
    assert "core_union_select" in categories
    assert "suspected_query" in categories
    assert sum(1 for p in plans if p.payload_category == "core_time_based") >= 100
    assert sum(1 for p in plans if p.payload_category == "core_union_select") >= 100


def test_sqli_requests_per_two_targets() -> None:
    plans = plan_sqli_requests(
        endpoints=[("10.10.10.20", 8080), ("10.10.10.21", 9000)],
        max_hosts=2,
    )
    assert len(plans) == 1000


def test_sqli_urls_are_not_double_encoded() -> None:
    plans = plan_sqli_requests(
        endpoints=[("10.1.151.235", 80)],
        max_hosts=1,
        paths=(
            "/wp-content/plugins/raygun4wp/readme.txt",
            "/api/v1/components?name=1&1%5B0%5D&1%5B1%5D=a&1%5B2%5D&1%5B3%5D=or+'a'='a')%20and%20(select%20sleep(6))--",
            "/dvwa/",
        ),
        repeats_per_path=1,
    )
    urls = {plan.url for plan in plans}
    assert "http://10.1.151.235/wp-content/plugins/raygun4wp/readme.txt" in urls
    assert (
        "http://10.1.151.235/api/v1/components?name=1&1%5B0%5D&1%5B1%5D=a&1%5B2%5D&1%5B3%5D=or+'a'='a')%20and%20(select%20sleep(6))--"
        in urls
    )
    assert "http://10.1.151.235/dvwa/" in urls
    assert "%25" not in urls


def test_local_remote_and_webshell_use_common_sqli_module() -> None:
    params = scenario_params_for_profile("sql_injection", "normal")
    _cache_params(params)
    targets = _targets()

    direct = plan_sqli_requests(
        endpoints=[("10.10.10.97", 8080)],
        max_hosts=1,
    )
    local_plan = plan_sql_injection(targets, params, dry_run=False)
    remote_plan = build_plan_from_discovery(
        "sql_injection",
        _discovery_dict(),
        params,
        dry_run=False,
    )

    assert len(direct) == 500
    assert len(local_plan["requests"]) == 500
    assert len(remote_plan["requests"]) == 500
    assert {item["url"] for item in local_plan["requests"]} == {
        item["url"] for item in remote_plan["requests"]
    }
