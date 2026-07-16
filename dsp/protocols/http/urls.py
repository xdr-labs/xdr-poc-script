"""HTTP Follow-up URL planning — fixed paths, attack paths, port priority."""

from __future__ import annotations

import random
from dataclasses import dataclass

from dsp.protocols.base import HttpProtocolError

# HTTP-only detection mode — sensor-visible path/query/body/header (no TLS)
HTTP_PORT_PRIORITY = (80, 8080, 8000, 8008, 8888, 9000)
HTTPS_PORT_PRIORITY = (443, 8443)
PORT_PRIORITY = HTTP_PORT_PRIORITY
HTTP_DETECTION_PORTS = frozenset(HTTP_PORT_PRIORITY)
FIXED_PATHS = (
    "/",
    "/login",
    "/admin",
    "/api",
    "/status",
    "/health",
    "/robots.txt",
    "/favicon.ico",
    "/index.html",
    "/dashboard",
)
# stellar_poc_followup.sh mandatory_payload_urls + payload_recon_urls (subset)
MANDATORY_ATTACK_PATHS = (
    "/WEB-INF/web.xml",
    "/../../etc/passwd",
    "/cmd.jsp",
    "/backdoor.jsp",
    "/admin",
    "/swagger",
    "/graphql",
)
PAYLOAD_RECON_PATHS = (
    "/WEB-INF/web.xml",
    "/WEB-INF/classes/",
    "/.env",
    "/backup.zip",
    "/admin/login",
    "/actuator/env",
    "/cmd.jsp",
    "/backdoor.jsp",
    "/swagger",
    "/swagger-ui.html",
    "/graphql",
    "/graphql/console",
    "/shell.jsp",
    "/../../etc/passwd",
    "/conf/server.xml",
)
ATTACK_SCAN_PATHS = MANDATORY_ATTACK_PATHS + PAYLOAD_RECON_PATHS
# stellar_poc_followup.sh pick_bad_query_attack
ATTACK_QUERY_PAYLOADS = (
    "?file=../../../../WEB-INF/web.xml",
    "?path=..%2f..%2f..%2fetc%2fpasswd",
    "?id=%00%00%00",
    "?action=../../../../secret/config",
    "?cmd=|whoami&file=../../../../WEB-INF/classes/",
    "?%00=1&page=admin",
    "?file=%2e%2e%2f%2e%2e%2fweb.xml",
    "?id=%25%25%25invalid%25%25%25",
)
MAX_HOSTS_DEFAULT = 2
MAX_REQUESTS_PER_HOST_DEFAULT = 500
MAX_REQUESTS_TOTAL_DEFAULT = 1000
HTTPS_PORTS = frozenset(HTTPS_PORT_PRIORITY)


@dataclass(frozen=True)
class PlannedHttpRequest:
    host: str
    port: int
    path: str
    query: str = ""
    method: str = "GET"
    headers: dict[str, str] | None = None

    @property
    def full_path(self) -> str:
        return f"{self.path}{self.query}" if self.query else self.path

    @property
    def url(self) -> str:
        return build_url(self.host, self.port, self.full_path)

    @property
    def scheme(self) -> str:
        return "https" if self.port in HTTPS_PORTS else "http"


def pick_attack_query() -> str:
    return random.choice(ATTACK_QUERY_PAYLOADS)


def build_attack_path(path: str, *, query: str | None = None) -> tuple[str, str]:
    """Return (path, query) for URL scan — attack payload in query, not UA."""
    base = path.split("?", 1)[0]
    if query is not None:
        return base, query if query.startswith("?") else f"?{query}"
    chosen = pick_attack_query()
    return base, chosen


def build_url(host: str, port: int, path: str) -> str:
    """Build HTTP/HTTPS URL for a host, port, and fixed path."""
    host = host.strip()
    if not host:
        raise HttpProtocolError("host is required")
    if port <= 0:
        raise HttpProtocolError("port must be positive")
    if not path.startswith("/"):
        raise HttpProtocolError(f"path must start with '/': {path!r}")

    scheme = "https" if port in HTTPS_PORTS else "http"
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        return f"{scheme}://{host}{path}"
    return f"{scheme}://{host}:{port}{path}"


def select_port_for_host(host_index: int, port_priority: tuple[int, ...] = PORT_PRIORITY) -> int:
    """Pick port from priority list based on host index."""
    if not port_priority:
        raise HttpProtocolError("port_priority is empty")
    return port_priority[host_index % len(port_priority)]


def _dedupe_paths(*groups: tuple[str, ...]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for group in groups:
        for path in group:
            if path not in seen:
                seen.add(path)
                ordered.append(path)
    return ordered


def compute_requests_per_target(
    num_targets: int,
    max_total: int,
    *,
    min_per_target: int = 100,
) -> int:
    """Even request budget per target — at least min_per_target when total allows."""
    if num_targets < 1 or max_total < 1:
        raise HttpProtocolError("target count and max_total must be positive")
    per_target = max_total // num_targets
    if per_target < min_per_target and num_targets * min_per_target <= max_total:
        per_target = min_per_target
    return per_target


def plan_followup_requests(
    *,
    endpoints: list[tuple[str, int]],
    max_hosts: int = MAX_HOSTS_DEFAULT,
    max_per_host: int = MAX_REQUESTS_PER_HOST_DEFAULT,
    max_total: int = MAX_REQUESTS_TOTAL_DEFAULT,
    include_attack_paths: bool = True,
) -> list[PlannedHttpRequest]:
    """
    Plan HTTP follow-up / URL scan requests across explicit host:port endpoints.

    When include_attack_paths is True, bash mandatory attack paths are prepended.
    Paths cycle when max_per_host exceeds unique path count (bash HTTP_SCAN_REPEAT parity).
    """
    if max_hosts < 1 or max_per_host < 1 or max_total < 1:
        raise HttpProtocolError("request caps must be positive")

    selected: list[tuple[str, int]] = [
        (h.strip(), int(p)) for h, p in endpoints if h.strip() and int(p) > 0
    ][:max_hosts]
    if not selected:
        raise HttpProtocolError("at least one endpoint is required")

    if include_attack_paths:
        mandatory_paths = list(MANDATORY_ATTACK_PATHS)
        recon_paths = list(PAYLOAD_RECON_PATHS)
        fixed_paths = list(FIXED_PATHS)
    else:
        mandatory_paths = []
        recon_paths = []
        fixed_paths = list(FIXED_PATHS)
    if not mandatory_paths and not recon_paths and not fixed_paths:
        raise HttpProtocolError("no paths available for follow-up requests")

    plans: list[PlannedHttpRequest] = []
    mandatory_idx = 0
    recon_idx = 0
    fixed_idx = 0

    def _next_attack_spec() -> tuple[str, str]:
        nonlocal mandatory_idx, recon_idx, fixed_idx
        if mandatory_idx < len(mandatory_paths):
            path = mandatory_paths[mandatory_idx]
            mandatory_idx += 1
        elif recon_paths:
            path = recon_paths[recon_idx % len(recon_paths)]
            recon_idx += 1
        elif fixed_paths:
            path = fixed_paths[fixed_idx % len(fixed_paths)]
            fixed_idx += 1
        else:
            path = "/"
        base, query = build_attack_path(path)
        return base, query

    for host, port in selected:
        host_sent = 0
        while host_sent < max_per_host and len(plans) < max_total:
            path, query = _next_attack_spec()
            plans.append(PlannedHttpRequest(host=host, port=port, path=path, query=query))
            host_sent += 1

    return plans
