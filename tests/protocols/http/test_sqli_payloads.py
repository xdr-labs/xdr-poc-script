"""SQL injection payload generation and URL construction unit tests."""

from __future__ import annotations

import pytest

from dsp.protocols.base import HttpProtocolError
from dsp.protocols.http.sqli_payloads import (
    SQLI_PATHS,
    SQLI_PAYLOAD_CATEGORIES,
    SQLI_PAYLOADS,
    SQLI_REQUESTS_PER_HOST,
    build_sqli_url,
    plan_sqli_requests,
)


def test_sqli_paths_count_from_stellar_csv():
    assert len(SQLI_PATHS) == 53
    assert "/wp-content/plugins/raygun4wp/readme.txt" in SQLI_PATHS
    assert "/dvwa/" in SQLI_PATHS


def test_sqli_payload_categories_defined():
    assert "boolean_based" in SQLI_PAYLOAD_CATEGORIES
    assert len(SQLI_PAYLOADS) > 30


def test_build_sqli_url_https_with_payload():
    url = build_sqli_url("10.10.10.20", 443, "/login", "id=1' OR '1'='1")
    assert url.startswith("https://10.10.10.20/login?")
    assert "OR" in url


def test_build_sqli_url_http_nonstandard_port():
    url = build_sqli_url("10.10.10.20", 8080, "/api", "id=1 AND 1=1")
    assert url.startswith("http://10.10.10.20:8080/api?")
    assert "AND" in url
    assert "1=1" in url


def test_plan_sqli_requests_single_host_fixed_volume():
    plans = plan_sqli_requests(endpoints=[("10.10.10.20", 8080)])
    assert len(plans) == SQLI_REQUESTS_PER_HOST
    assert all(p.host == "10.10.10.20" for p in plans)


def test_plan_sqli_requests_two_hosts_fixed_volume():
    plans = plan_sqli_requests(
        endpoints=[("10.10.10.20", 8080), ("10.10.10.21", 9000)],
        max_hosts=2,
    )
    assert len(plans) == SQLI_REQUESTS_PER_HOST * 2


def test_plan_sqli_requests_use_suspected_query_category():
    plans = plan_sqli_requests(endpoints=[("10.10.10.20", 8080)], max_hosts=1)
    assert plans[0].payload_category == "core_time_based"
    assert plans[0].method == "GET"
    categories = {p.payload_category for p in plans}
    assert "suspected_query" in categories
    assert "core_union_select" in categories


def test_planned_sqli_request_url_property():
    plans = plan_sqli_requests(endpoints=[("lab.local", 8080)], max_hosts=1)
    assert plans[0].url.startswith("http://lab.local:8080")


def test_plan_sqli_requests_requires_endpoint():
    with pytest.raises(HttpProtocolError, match="at least one endpoint"):
        plan_sqli_requests(endpoints=[])
