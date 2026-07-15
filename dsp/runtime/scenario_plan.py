"""Provider-independent scenario planning — shared by local and remote execution."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from dsp.engine.scenario_engine import TargetSet
from dsp.protocols.http.urls import HTTP_DETECTION_PORTS
from dsp.protocols.recon import DEFAULT_PORTS, MAX_PORTS_DEFAULT, plan_port_sweep

INITIAL_COMPROMISE_ENDPOINT_KEY = "initial_compromise_endpoint"
INITIAL_COMPROMISE_SELECTION_REASON = "initial_compromise_host"
WEBSHELL_EXECUTION_KEY = "_webshell_execution"
WEBSHELL_SERVER_ATTACK_SCENARIOS = frozenset({"host_behavior_check"})
DISCOVERED_HTTP_SERVICE_REASON = "discovered_http_service"
DISCOVERED_HTTPS_SERVICE_REASON = "discovered_https_service"
DISCOVERED_HTTP_SERVICE_FROM_WEBSHELL_DISCOVERY = (
    "discovered_http_service_from_webshell_discovery"
)
DISCOVERED_HTTP_SERVICE_UNVERIFIED_FROM_DSP_HOST = (
    "discovered_http_service_unverified_from_dsp_host"
)


@dataclass(frozen=True)
class InitialCompromiseEndpoint:
    """Webshell host endpoint derived from ``webshell_url`` (Phase A target)."""

    host: str
    port: int
    scheme: str

    def to_dict(self) -> dict[str, str | int]:
        return {"host": self.host, "port": self.port, "scheme": self.scheme}


@dataclass(frozen=True)
class PortSweepPlanView:
    """Canonical port_sweep plan snapshot before provider execution."""

    selected_hosts: list[str]
    selected_ports: tuple[int, ...]
    planned_probes: int
    selection_reason: str
    full_sweep_requested: bool
    max_hosts: int
    max_ports: int

def webshell_server_endpoint(params: dict[str, Any]) -> InitialCompromiseEndpoint | None:
    """Return the user-provided webshell server endpoint — no discovery or fallback."""
    ctx = params.get(WEBSHELL_EXECUTION_KEY)
    if not isinstance(ctx, dict):
        return None
    url = ctx.get("webshell_url")
    if not url:
        return None
    return parse_initial_compromise_endpoint(str(url))


def parse_initial_compromise_endpoint(webshell_url: str) -> InitialCompromiseEndpoint:
    """Derive Phase A compromise target host:port from a webshell URL."""
    parsed = urlparse(webshell_url.strip())
    if not parsed.hostname:
        raise ValueError(f"invalid webshell_url: {webshell_url!r}")
    host = parsed.hostname
    if parsed.port is not None:
        port = parsed.port
    elif parsed.scheme == "https":
        port = 443
    else:
        port = 80
    scheme = parsed.scheme or "http"
    if port in HTTP_DETECTION_PORTS:
        scheme = "http"
    return InitialCompromiseEndpoint(host=host, port=port, scheme=scheme)


def apply_webshell_initial_compromise_plan(
    scenario_params: dict[str, dict[str, Any]],
    scenario_ids: list[str],
    webshell_url: str,
) -> InitialCompromiseEndpoint:
    """Record the user-provided webshell server as the execution and attack target."""
    endpoint = parse_initial_compromise_endpoint(webshell_url)
    payload = endpoint.to_dict()
    parsed = urlparse(webshell_url)
    execution_context = {
        "webshell_url": webshell_url,
        "execution_host": endpoint.host,
        "execution_port": endpoint.port,
        "execution_path": parsed.path or "/",
        "endpoint": payload,
    }
    scenario_params[WEBSHELL_EXECUTION_KEY] = execution_context
    for sid in scenario_ids:
        scenario_params.setdefault(sid, {})[WEBSHELL_EXECUTION_KEY] = execution_context
    return endpoint


def select_port_sweep_hosts(
    targets: TargetSet,
    config: dict[str, Any],
    *,
    max_hosts: int,
) -> tuple[list[str], str]:
    """Select port sweep hosts using discovery-first, provider-independent rules.

    Never expands ``target_net`` CIDR as a silent fallback. Empty discovery /
    host buckets skip the scenario (``no_alive_hosts``).
    """
    if config.get("hosts"):
        hosts = [str(h) for h in config["hosts"]][:max_hosts]
        return hosts, "explicit_hosts"
    if targets.discovery_enabled:
        meta = targets.discovery_meta or {}
        alive = [str(h) for h in (meta.get("alive_hosts") or targets.hosts or [])]
        if alive:
            return alive[:max_hosts], "alive_hosts"
        return [], "no_alive_hosts"
    if targets.hosts:
        return [str(h) for h in targets.hosts][:max_hosts], "discovered_hosts"
    return [], "no_alive_hosts"


def resolve_port_sweep_ports(config: dict[str, Any], max_ports: int) -> tuple[int, ...]:
    raw = config.get("ports")
    if raw is None:
        return DEFAULT_PORTS[:max_ports]
    return tuple(int(p) for p in raw)[:max_ports]


def build_port_sweep_plan_view(
    targets: TargetSet,
    params: dict[str, Any],
) -> PortSweepPlanView:
    """Build the canonical port_sweep execution plan for any provider."""
    max_hosts = int(params.get("max_hosts", 2))
    max_ports = int(params.get("max_ports", MAX_PORTS_DEFAULT))
    hosts, reason = select_port_sweep_hosts(targets, params, max_hosts=max_hosts)
    ports = resolve_port_sweep_ports(params, max_ports)
    if not hosts or reason == "no_alive_hosts":
        return PortSweepPlanView(
            selected_hosts=[],
            selected_ports=ports,
            planned_probes=0,
            selection_reason="no_alive_hosts",
            full_sweep_requested=bool(params.get("full_sweep")),
            max_hosts=max_hosts,
            max_ports=max_ports,
        )
    probes = plan_port_sweep(
        hosts,
        max_hosts=max_hosts,
        ports=ports,
        max_ports=max_ports,
        safe_mode=bool(params.get("safe_mode", True)),
    )
    return PortSweepPlanView(
        selected_hosts=hosts,
        selected_ports=ports,
        planned_probes=len(probes),
        selection_reason=reason,
        full_sweep_requested=bool(params.get("full_sweep")),
        max_hosts=max_hosts,
        max_ports=max_ports,
    )


def build_scenario_execution_plan(
    scenario_id: str,
    targets: TargetSet,
    params: dict[str, Any],
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Provider-independent scenario plan from discovery ``TargetSet`` only."""
    from dsp.execution.remote.command.scenario_plans import build_scenario_execution_plan as _build

    return _build(scenario_id, targets, params, dry_run=dry_run)


def scenario_plan_parity_view(plan: dict[str, Any]) -> dict[str, Any]:
    """Extract comparable target fields for local/webshell plan parity checks."""
    plan_type = str(plan.get("type") or "")
    mode = plan.get("mode")
    if mode == "skip" or plan_type == "skip":
        return {"type": plan_type, "mode": "skip", "reason": plan.get("reason")}

    view: dict[str, Any] = {"type": plan_type, "mode": mode}
    if plan_type == "port_sweep":
        probes = plan.get("probes") or []
        hosts = sorted({str(p["host"]) for p in probes})
        ports = sorted({int(p["port"]) for p in probes})
        view.update(
            {
                "hosts": hosts,
                "ports": ports,
                "probe_count": len(probes),
            }
        )
    elif plan_type in ("http_followup", "sql_injection"):
        requests = plan.get("requests") or []
        endpoints = sorted(
            {
                item["url"].split("://", 1)[1].split("/", 1)[0]
                for item in requests
                if item.get("url")
            }
        )
        view["endpoints"] = endpoints
        view["request_count"] = len(requests)
    elif plan_type == "ssh_failure":
        attempts = plan.get("attempts") or []
        view["hosts"] = sorted({str(a["host"]) for a in attempts})
        view["attempt_count"] = len(attempts)
    elif plan_type == "dns_tunnel":
        queries = plan.get("queries") or []
        view["targets"] = sorted({str(q.get("target") or q.get("host") or "") for q in queries})
        view["query_count"] = len(queries)
    elif plan_type == "dga":
        domains = plan.get("domains") or []
        view["resolver"] = plan.get("resolver")
        view["domain_count"] = len(domains)
    elif plan_type == "rare_protocol_activity":
        probes = plan.get("probes") or []
        view["probes"] = sorted(
            (p["protocol"], p["host"], p["port"], p["transport"]) for p in probes
        )
        view["probe_count"] = len(probes)
    elif plan_type in ("ldap_enumeration", "smb_login_failure", "kerberos_failure"):
        key = "actions" if plan_type == "ldap_enumeration" else "attempts"
        items = plan.get(key) or []
        view["hosts"] = sorted({str(item["host"]) for item in items})
        view["item_count"] = len(items)
    return view
