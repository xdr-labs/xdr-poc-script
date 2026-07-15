"""Scenario host selection — discovery capability hosts only (no CIDR .1/.2 fallback)."""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from dsp.engine.scenario_engine import TargetSet
from dsp.protocols.http.target_probe import (
    HTTPEndpointProbeResult,
    annotate_probe_selection,
    is_selectable_http_endpoint,
    pick_best_endpoint_per_host,
    probe_all_http_candidates,
    probe_http_endpoint,
    probe_quality_sort_key,
    selection_reason_for,
)
from dsp.protocols.http.urls import HTTP_DETECTION_PORTS, HTTP_PORT_PRIORITY
from dsp.runtime.http_endpoint_selection import select_discovered_http_endpoint_tuples
from dsp.runtime.scenario_plan import (
    DISCOVERED_HTTP_SERVICE_FROM_WEBSHELL_DISCOVERY,
    DISCOVERED_HTTP_SERVICE_REASON,
    DISCOVERED_HTTPS_SERVICE_REASON,
    DISCOVERED_HTTP_SERVICE_UNVERIFIED_FROM_DSP_HOST,
    INITIAL_COMPROMISE_ENDPOINT_KEY,
    INITIAL_COMPROMISE_SELECTION_REASON,
    WEBSHELL_EXECUTION_KEY,
)

# HTTP-only detection mode — no HTTPS fallback for URL scan / SQLi
HTTP_PLAIN_PORTS = HTTP_PORT_PRIORITY
SKIP_REASON_HTTP_TARGETS_NOT_FOUND = "HTTP_TARGETS_NOT_FOUND"


@dataclass
class HttpFollowupSelection:
    """Shared HTTP endpoint selection consumed by discovery, executors, and reporting."""

    probed: list[HTTPEndpointProbeResult] = field(default_factory=list)
    selected: list[HTTPEndpointProbeResult] = field(default_factory=list)
    skip_reason: str | None = None
    selected_http_target_reason: str = ""
    https_targets_skipped: list[str] = field(default_factory=list)

    @property
    def endpoints(self) -> list[HTTPEndpointProbeResult]:
        return self.selected

    @property
    def probe_summaries(self) -> list[dict[str, int | str | bool]]:
        return [item.to_dict() for item in self.probed]

    @property
    def rejected_targets(self) -> list[str]:
        return build_rejected_target_labels(self.probe_summaries)

    @property
    def redirect_only_candidates(self) -> list[str]:
        return [
            f"{item.scheme}://{item.host}:{item.port}"
            for item in self.probed
            if item.is_redirect_only
        ]


def select_hosts_for_capability(
    targets: TargetSet,
    config: dict,
    *,
    capability: str,
    max_hosts: int,
) -> list[str]:
    """
    Select hosts from discovery capability bucket only.

    Does not fall back to CIDR expansion (.1, .2, …) — mirrors bash usable_* files.
    """
    if config.get("hosts"):
        return [str(h) for h in config["hosts"]][:max_hosts]

    discovered = targets.hosts_for_capability(capability)
    if discovered:
        return discovered[:max_hosts]

    return []


def select_merged_http_hosts(
    targets: TargetSet,
    config: dict,
    *,
    max_hosts: int,
) -> list[str]:
    """HTTP URL scan: http_targets + https_targets from discovery only."""
    if config.get("hosts"):
        return [str(h) for h in config["hosts"]][:max_hosts]

    merged = targets.merged_http_hosts()
    if merged:
        return merged[:max_hosts]

    return []


def _dedupe_endpoints(endpoints: list[tuple[str, int]]) -> list[tuple[str, int]]:
    seen: set[tuple[str, int]] = set()
    ordered: list[tuple[str, int]] = []
    for host, port in endpoints:
        key = (host, port)
        if key not in seen:
            seen.add(key)
            ordered.append(key)
    return ordered


def _filter_http_detection_endpoints(endpoints: list[tuple[str, int]]) -> list[tuple[str, int]]:
    return [(host, port) for host, port in endpoints if port in HTTP_DETECTION_PORTS]


def _https_targets_skipped_list(targets: TargetSet) -> list[str]:
    labels: list[str] = []
    for host, port in _dedupe_endpoints(targets.endpoints_for_capability("https_targets")):
        labels.append(f"{host}:{port}")
    return sorted(labels)


def _http_only_skip_selection_with_probe(
    probed: list[HTTPEndpointProbeResult],
) -> HttpFollowupSelection:
    annotated = annotate_probe_selection(probed, [])
    return HttpFollowupSelection(
        probed=annotated,
        selected=[],
        skip_reason=SKIP_REASON_HTTP_TARGETS_NOT_FOUND,
    )


def _http_only_skip_selection(targets: TargetSet) -> HttpFollowupSelection:
    """Skip when discovery has HTTPS targets but no HTTP detection endpoints."""
    return HttpFollowupSelection(
        selected=[],
        skip_reason=SKIP_REASON_HTTP_TARGETS_NOT_FOUND,
        https_targets_skipped=_https_targets_skipped_list(targets),
    )


def _explicit_config_endpoints(config: dict) -> list[tuple[str, int]]:
    raw = config.get("endpoints")
    if not raw:
        return []
    endpoints: list[tuple[str, int]] = []
    for item in raw:
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            endpoints.append((str(item[0]), int(item[1])))
        elif isinstance(item, dict):
            endpoints.append((str(item["host"]), int(item["port"])))
    return _dedupe_endpoints(endpoints)


def _collect_candidate_triples(targets: TargetSet, config: dict) -> list[tuple[str, int, str]]:
    """HTTP probe candidates — explicit endpoints or all allowed ports per host."""
    explicit = _explicit_config_endpoints(config)
    if explicit:
        return [(host, port, "http") for host, port in explicit]

    if config.get("hosts"):
        http_hosts = [str(h) for h in config["hosts"]]
    else:
        http_hosts = targets.hosts_for_capability("http_targets")
    if not http_hosts:
        return []

    discovered = _filter_http_detection_endpoints(
        _dedupe_endpoints(targets.endpoints_for_capability("http_targets"))
    )
    discovered_ports_by_host: dict[str, set[int]] = {}
    for host, port in discovered:
        discovered_ports_by_host.setdefault(host, set()).add(port)

    rank = {port: idx for idx, port in enumerate(HTTP_PLAIN_PORTS)}
    candidates: list[tuple[str, int, str]] = []
    for host in sorted(http_hosts, key=lambda h: tuple(int(p) for p in h.split("."))):
        ports_to_probe = set(HTTP_DETECTION_PORTS)
        ports_to_probe.update(discovered_ports_by_host.get(host, set()))
        for port in sorted(ports_to_probe, key=lambda p: (rank.get(p, len(HTTP_PLAIN_PORTS)), p)):
            candidates.append((host, port, "http"))
    return candidates


HTTP_ENDPOINT_SELECTION_CACHE_KEY = "_http_endpoint_selection"


def build_rejected_target_labels(probe_summaries: list[dict[str, int | str | bool]]) -> list[str]:
    rejected: list[str] = []
    for row in probe_summaries:
        if row.get("selected"):
            continue
        reason = str(row.get("rejection_reason") or "not_selected")
        rejected.append(f"{row['host']}:{row['port']} ({reason})")
    return rejected


def selection_to_cache(selection: HttpFollowupSelection) -> dict[str, object]:
    return {
        "probed": [item.to_dict() for item in selection.probed],
        "selected": [item.to_dict() for item in selection.selected],
        "skip_reason": selection.skip_reason,
        "selected_http_target_reason": selection.selected_http_target_reason,
        "https_targets_skipped": selection.https_targets_skipped,
        # Legacy keys for older cache readers
        "endpoints": [
            {
                "host": item.host,
                "port": item.port,
                "scheme": item.scheme,
                "selection_reason": item.selection_reason,
            }
            for item in selection.selected
        ],
        "probe_summaries": selection.probe_summaries,
        "rejected_targets": selection.rejected_targets,
        "redirect_only_candidates": selection.redirect_only_candidates,
    }


def selection_from_cache(data: dict[str, object]) -> HttpFollowupSelection:
    if data.get("probed") or data.get("selected"):
        probed = [HTTPEndpointProbeResult.from_dict(item) for item in data.get("probed", [])]
        selected = [HTTPEndpointProbeResult.from_dict(item) for item in data.get("selected", [])]
        if probed and not any(item.selected for item in probed):
            probed = annotate_probe_selection(probed, selected)
        return HttpFollowupSelection(
            probed=probed,
            selected=selected,
            skip_reason=data.get("skip_reason"),  # type: ignore[arg-type]
            selected_http_target_reason=str(data.get("selected_http_target_reason") or ""),
            https_targets_skipped=list(data.get("https_targets_skipped") or []),
        )

    selected = [
        HTTPEndpointProbeResult(
            host=str(item["host"]),
            port=int(item["port"]),
            scheme=str(item.get("scheme") or "http"),
            selection_reason=str(item.get("selection_reason") or ""),
            selected=True,
        )
        for item in data.get("endpoints", [])
    ]
    probed = [HTTPEndpointProbeResult.from_dict(item) for item in data.get("probe_summaries") or []]
    if probed and selected:
        probed = annotate_probe_selection(probed, selected)
    elif probed and not selected:
        probed = annotate_probe_selection(probed, [])
    return HttpFollowupSelection(
        probed=probed,
        selected=selected,
        skip_reason=data.get("skip_reason"),  # type: ignore[arg-type]
        selected_http_target_reason=str(data.get("selected_http_target_reason") or ""),
        https_targets_skipped=list(data.get("https_targets_skipped") or []),
    )


def _initial_compromise_endpoint(config: dict) -> dict[str, object] | None:
    raw = config.get(INITIAL_COMPROMISE_ENDPOINT_KEY)
    if not isinstance(raw, dict):
        return None
    if "host" not in raw or "port" not in raw:
        return None
    return raw


def _webshell_execution_endpoint(config: dict) -> dict[str, object] | None:
    ctx = config.get(WEBSHELL_EXECUTION_KEY)
    if isinstance(ctx, dict):
        endpoint = ctx.get("endpoint")
        if isinstance(endpoint, dict) and "host" in endpoint and "port" in endpoint:
            return endpoint
    return _initial_compromise_endpoint(config)


def _webshell_execution_context(config: dict) -> dict[str, object] | None:
    ctx = config.get(WEBSHELL_EXECUTION_KEY)
    return ctx if isinstance(ctx, dict) else None


def _attack_target_reason_for_discovery(selection: HttpFollowupSelection) -> str:
    if not selection.selected:
        return ""
    endpoint = selection.selected[0]
    if endpoint.scheme == "https":
        return DISCOVERED_HTTPS_SERVICE_REASON
    return DISCOVERED_HTTP_SERVICE_REASON


def _discovered_http_hosts_selection_reason(targets: TargetSet) -> str:
    """Pick HTTP target reason for webshell-mode discovery without DSP-side probe."""
    meta = targets.discovery_meta or {}
    if meta.get("discovery_origin") == "webshell_host":
        return DISCOVERED_HTTP_SERVICE_FROM_WEBSHELL_DISCOVERY
    return DISCOVERED_HTTP_SERVICE_UNVERIFIED_FROM_DSP_HOST


def _reconcile_webshell_selection_reason(
    selection: HttpFollowupSelection,
    targets: TargetSet,
) -> HttpFollowupSelection:
    """Refresh cached selection reason labels without changing endpoints."""
    if not selection.selected:
        return selection
    reason = _discovered_http_hosts_selection_reason(targets)
    if selection.selected_http_target_reason == reason and all(
        ep.selection_reason == reason for ep in selection.selected
    ):
        return selection
    selected = [
        replace(
            ep,
            selection_reason=reason,
            rejection_reason="",
        )
        for ep in selection.selected
    ]
    annotated = (
        annotate_probe_selection(selection.probed, selected)
        if selection.probed
        else selected
    )
    return HttpFollowupSelection(
        probed=annotated,
        selected=selected,
        skip_reason=selection.skip_reason,
        selected_http_target_reason=reason,
        https_targets_skipped=selection.https_targets_skipped,
    )


def _discovered_http_endpoint_tuples(
    targets: TargetSet,
    config: dict,
    *,
    max_hosts: int,
) -> list[tuple[str, int]]:
    """Pick one HTTP endpoint per discovered host from discovery metadata."""
    if config.get("hosts"):
        http_hosts = [str(h) for h in config["hosts"]]
    else:
        http_hosts = list(targets.hosts_for_capability("http_targets"))
    if not http_hosts and not config.get("hosts"):
        return []

    discovered = _filter_http_detection_endpoints(
        _dedupe_endpoints(targets.endpoints_for_capability("http_targets"))
    )
    return select_discovered_http_endpoint_tuples(
        http_hosts=http_hosts,
        http_endpoints=discovered,
        max_hosts=max_hosts,
        explicit_hosts=[str(h) for h in config["hosts"]] if config.get("hosts") else None,
    )


def _dsp_probe_failure_summary(probe_summaries: list[dict[str, int | str | bool]]) -> str:
    if not probe_summaries:
        return "no endpoints probed"
    qualities = {response_quality_label(row) for row in probe_summaries}
    if qualities <= {"connection_error"}:
        return "connection_error"
    if qualities <= {"timeout_only"}:
        return "timeout"
    if "connection_error" in qualities or "timeout_only" in qualities:
        return "failed / timeout / connection_error"
    return "no selectable endpoint from DSP host"


def selection_from_discovered_http_hosts_unverified(
    targets: TargetSet,
    config: dict,
    *,
    probed: list[HTTPEndpointProbeResult],
    max_hosts: int,
) -> HttpFollowupSelection:
    """Webshell mode: keep discovered attack hosts when DSP-side probe cannot verify them."""
    endpoint_tuples = _discovered_http_endpoint_tuples(
        targets,
        config,
        max_hosts=max_hosts,
    )
    if not endpoint_tuples:
        annotated = annotate_probe_selection(probed, []) if probed else []
        return HttpFollowupSelection(
            probed=annotated,
            selected=[],
            skip_reason=SKIP_REASON_HTTP_TARGETS_NOT_FOUND,
            https_targets_skipped=_https_targets_skipped_list(targets),
        )

    selection_reason = _discovered_http_hosts_selection_reason(targets)
    selected = [
        HTTPEndpointProbeResult(
            host=host,
            port=port,
            scheme="http",
            selected=True,
            selection_reason=selection_reason,
            rejection_reason="",
        )
        for host, port in endpoint_tuples
    ]
    annotated = annotate_probe_selection(probed, selected) if probed else selected
    return HttpFollowupSelection(
        probed=annotated,
        selected=selected,
        selected_http_target_reason=selection_reason,
        https_targets_skipped=_https_targets_skipped_list(targets),
    )


def selection_from_initial_compromise(
    endpoint: dict[str, object],
    *,
    dry_run: bool = False,
    timeout: float = 10.0,
    selection_reason: str = INITIAL_COMPROMISE_SELECTION_REASON,
) -> HttpFollowupSelection:
    """Fixed Phase A target — webshell host from ``webshell_url``."""
    host = str(endpoint["host"])
    port = int(endpoint["port"])
    scheme = str(endpoint.get("scheme") or "http")
    probed = probe_http_endpoint(
        host,
        port,
        scheme,
        dry_run=dry_run,
        timeout=timeout,
    )
    selected = replace(
        probed,
        selected=True,
        selection_reason=selection_reason,
        rejection_reason="",
    )
    annotated = annotate_probe_selection([probed], [selected])
    return HttpFollowupSelection(
        probed=annotated,
        selected=[selected],
        selected_http_target_reason=selection_reason,
    )


def resolve_http_attack_endpoint_selection(
    targets: TargetSet,
    config: dict,
    *,
    max_hosts: int,
    dry_run: bool = False,
    timeout: float = 10.0,
) -> HttpFollowupSelection:
    """Select HTTP attack targets using discovery-first rules."""
    selection = probe_and_select_http_followup_endpoints(
        targets,
        config,
        max_hosts=max_hosts,
        dry_run=dry_run,
        timeout=timeout,
    )
    if selection.selected:
        return HttpFollowupSelection(
            probed=selection.probed,
            selected=selection.selected,
            skip_reason=selection.skip_reason,
            selected_http_target_reason=_attack_target_reason_for_discovery(selection),
            https_targets_skipped=selection.https_targets_skipped,
        )
    return selection


def resolve_http_endpoint_selection(
    targets: TargetSet,
    config: dict,
    *,
    max_hosts: int,
    dry_run: bool = False,
    timeout: float = 10.0,
) -> HttpFollowupSelection:
    """Return cached or freshly probed HTTP endpoint selection for URL scan / SQLi."""
    cached = config.get(HTTP_ENDPOINT_SELECTION_CACHE_KEY)
    if cached:
        return selection_from_cache(cached)  # type: ignore[arg-type]
    return resolve_http_attack_endpoint_selection(
        targets,
        config,
        max_hosts=max_hosts,
        dry_run=dry_run,
        timeout=timeout,
    )


def resolve_discovery_http_selection(
    targets: TargetSet,
    config: dict,
    *,
    max_hosts: int | None = None,
    dry_run: bool = False,
    webshell_mode: bool = False,
    timeout: float = 10.0,
) -> HttpFollowupSelection:
    """Resolve HTTP follow-up selection from shared cache or discovery buckets."""
    cached = config.get(HTTP_ENDPOINT_SELECTION_CACHE_KEY)
    if cached:
        selection = selection_from_cache(cached)  # type: ignore[arg-type]
        if selection.selected:
            if webshell_mode:
                reconciled = _reconcile_webshell_selection_reason(selection, targets)
                if reconciled.selected_http_target_reason != selection.selected_http_target_reason:
                    config[HTTP_ENDPOINT_SELECTION_CACHE_KEY] = selection_to_cache(reconciled)
                return reconciled
            return selection

    hosts_limit = max_hosts if max_hosts is not None else int(config.get("max_hosts", 2))
    if targets.discovery_enabled:
        # Discovery already populated HTTP buckets — no live probe needed.
        return selection_from_discovered_http_hosts_unverified(
            targets,
            config,
            probed=[],
            max_hosts=hosts_limit,
        )
    return resolve_http_attack_endpoint_selection(
        targets,
        config,
        max_hosts=hosts_limit,
        dry_run=dry_run,
        timeout=timeout,
    )


def http_selection_summary_fields(
    selection: HttpFollowupSelection,
    targets: TargetSet,
) -> dict[str, object]:
    """Serialize HTTP endpoint selection for events and traffic_summary."""
    selected_targets = format_selected_target_labels(selection.selected)
    return {
        "selected_targets": selected_targets,
        "target_count": len(selection.selected),
        "http_targets": targets.hosts_for_capability("http_targets"),
        "https_targets": targets.hosts_for_capability("https_targets"),
        "selected_http_target_reason": selection.selected_http_target_reason,
        "probe_summaries": selection.probe_summaries,
        "target_probe": selection.probe_summaries,
        "rejected_targets": selection.rejected_targets,
        "redirect_only_candidates": selection.redirect_only_candidates,
        "https_targets_skipped": selection.https_targets_skipped,
        "hosts": [ep.host for ep in selection.selected],
        "endpoints": [
            {"host": ep.host, "port": ep.port, "scheme": ep.scheme, "selection_reason": ep.selection_reason}
            for ep in selection.selected
        ],
    }


def cache_http_endpoint_selection(
    scenario_params: dict[str, dict[str, object]],
    *,
    scenario_ids: list[str],
    targets: TargetSet,
    dry_run: bool,
    webshell_mode: bool = False,
) -> None:
    """Probe once and share endpoint selection across HTTP detection scenarios."""
    http_scenarios = [sid for sid in scenario_ids if sid in ("http_followup", "sql_injection")]
    if not http_scenarios:
        return

    ref_params = scenario_params.get(http_scenarios[0], {})
    max_hosts = max(
        int(scenario_params.get(sid, {}).get("max_hosts", 2))
        for sid in http_scenarios
    )
    selection = resolve_discovery_http_selection(
        targets,
        ref_params,
        max_hosts=max_hosts,
        dry_run=dry_run,
        webshell_mode=webshell_mode,
        timeout=float(ref_params.get("timeout", 10.0)),
    )
    cache = selection_to_cache(selection)
    for sid in http_scenarios:
        scenario_params.setdefault(sid, {})[HTTP_ENDPOINT_SELECTION_CACHE_KEY] = cache


def format_selected_target_labels(endpoints: list[HTTPEndpointProbeResult]) -> list[str]:
    """Format selected targets with probe-based selection reason."""
    return [f"{ep.host}:{ep.port} ({ep.selection_reason})" for ep in endpoints]


def response_quality_label(row: dict[str, int | str | bool]) -> str:
    """Summarize probe response quality for operator diagnostics."""
    if int(row.get("probe_400", 0)) or int(row.get("probe_403", 0)) or int(row.get("probe_404", 0)):
        return "error_responses"
    if int(row.get("probe_success", 0)) > 0:
        return "success_responses"
    if int(row.get("redirect_only", 0)):
        return "redirect_only"
    if int(row.get("probe_timeout", 0)) and not int(row.get("probe_error", 0)):
        return "timeout_only"
    if int(row.get("probe_error", 0)):
        return "connection_error"
    return "no_response"


def cached_http_endpoint_selection(
    scenario_params: dict[str, dict[str, object]],
    scenario_ids: list[str],
) -> HttpFollowupSelection | None:
    """Return shared cached HTTP endpoint selection when present."""
    for sid in scenario_ids:
        if sid not in ("http_followup", "sql_injection"):
            continue
        cached = scenario_params.get(sid, {}).get(HTTP_ENDPOINT_SELECTION_CACHE_KEY)
        if cached:
            return selection_from_cache(cached)  # type: ignore[arg-type]
    return None


def format_http_probe_diagnostic_lines(
    selection: HttpFollowupSelection,
    *,
    discovered_http_hosts: list[str] | None = None,
    webshell_endpoint_diagnostics: list[dict[str, int | str | bool]] | None = None,
    webshell_mode: bool = False,
) -> list[str]:
    """Format operator-readable probe diagnostics for each HTTP endpoint."""
    lines: list[str] = []
    unverified_webshell = (
        webshell_mode
        and selection.selected_http_target_reason
        == DISCOVERED_HTTP_SERVICE_UNVERIFIED_FROM_DSP_HOST
    )

    if discovered_http_hosts is not None:
        if webshell_mode:
            lines.append("Discovered HTTP attack hosts:")
            if discovered_http_hosts:
                for host in discovered_http_hosts:
                    lines.append(f"  {host}")
            else:
                lines.append("  (none)")
        else:
            lines.append(f"discovered_attack_http_endpoints={discovered_http_hosts}")

    if webshell_endpoint_diagnostics is not None:
        lines.append("webshell_endpoint_diagnostics:")
        if not webshell_endpoint_diagnostics:
            lines.append("  (no webshell endpoint probed)")
        else:
            for row in webshell_endpoint_diagnostics:
                host = str(row["host"])
                port = int(row["port"])
                quality = response_quality_label(row)
                lines.append(f"  {host}:{port} scheme=http response_quality={quality}")

    if webshell_mode:
        lines.append("DSP-side endpoint probe:")
        if unverified_webshell:
            lines.append(f"  {_dsp_probe_failure_summary(selection.probe_summaries)}")
        elif not selection.probed:
            lines.append("  (no endpoints probed)")
        else:
            for row in selection.probe_summaries:
                host = str(row["host"])
                port = int(row["port"])
                quality = response_quality_label(row)
                if row.get("selected"):
                    status = "selected"
                    reason = str(row.get("selection_reason") or "")
                else:
                    status = "rejected"
                    reason = str(row.get("rejection_reason") or "")
                line = f"  {host}:{port} response_quality={quality} {status}"
                if reason:
                    line += f" reason={reason}"
                lines.append(line)
        if unverified_webshell:
            lines.append("Webshell mode decision:")
            lines.append(
                "  keeping discovered attack hosts because traffic will "
                "originate from webshell host"
            )
    else:
        lines.append("HTTP endpoint probe diagnostics:")
        if not selection.probed:
            lines.append("  (no endpoints probed)")
        else:
            for row in selection.probe_summaries:
                host = str(row["host"])
                port = int(row["port"])
                label = f"{host}:{port}"
                quality = response_quality_label(row)
                if row.get("selected"):
                    status = "selected"
                    reason = str(row.get("selection_reason") or "")
                else:
                    status = "rejected"
                    reason = str(row.get("rejection_reason") or "")
                line = f"  {label} scheme=http response_quality={quality} {status}"
                if reason:
                    line += f" reason={reason}"
                lines.append(line)

    if selection.selected:
        if webshell_mode:
            lines.append("Selected attack targets:")
            for ep in selection.selected:
                lines.append(f"  {ep.host}:{ep.port} reason={ep.selection_reason}")
        lines.append(f"selected_endpoints={format_selected_target_labels(selection.selected)}")
    else:
        lines.append(
            "selected_endpoints=[] "
            f"skip_reason={selection.skip_reason or SKIP_REASON_HTTP_TARGETS_NOT_FOUND}"
        )
    return lines


def print_http_endpoint_probe_diagnostics(
    scenario_params: dict[str, dict[str, object]],
    scenario_ids: list[str],
    *,
    discovered_http_hosts: list[str] | None = None,
    webshell_execution: dict[str, object] | None = None,
    attack_target_net: str | None = None,
) -> HttpFollowupSelection | None:
    """Print probe diagnostics and return cached selection when available."""
    selection = cached_http_endpoint_selection(scenario_params, scenario_ids)
    if selection is None:
        return None
    webshell_probe_rows: list[dict[str, int | str | bool]] | None = None
    for line in format_http_probe_diagnostic_lines(
        selection,
        discovered_http_hosts=discovered_http_hosts,
        webshell_endpoint_diagnostics=webshell_probe_rows,
        webshell_mode=webshell_execution is not None,
    ):
        print(line)
    if attack_target_net:
        print(f"attack_target_net={attack_target_net}")
    return selection


def http_target_probe_payload(
    selection: HttpFollowupSelection,
    *,
    discovered_http_hosts: list[str] | None = None,
    webshell_execution: dict[str, object] | None = None,
    attack_target_net: str | None = None,
) -> dict[str, object]:
    """Serialize probe diagnostics for traffic_summary / run artifacts."""
    payload: dict[str, object] = {
        "discovery_http_hosts": discovered_http_hosts or [],
        "discovered_attack_http_endpoints": discovered_http_hosts or [],
        "target_probe": selection.probe_summaries,
        "selected_targets": format_selected_target_labels(selection.selected)
        if selection.selected
        else [],
        "selected_attack_targets": format_selected_target_labels(selection.selected)
        if selection.selected
        else [],
        "rejected_targets": selection.rejected_targets,
        "skip_reason": selection.skip_reason,
        "selected_target_reason": selection.selected_http_target_reason,
        "selected_endpoint_probe": [item.to_dict() for item in selection.selected],
    }
    if attack_target_net:
        payload["attack_target_net"] = attack_target_net
    if webshell_execution:
        payload["execution_host"] = webshell_execution.get("execution_host")
        payload["webshell_url"] = webshell_execution.get("webshell_url")
    return payload


def select_http_followup_endpoints(
    targets: TargetSet,
    config: dict,
    *,
    max_hosts: int,
    dry_run: bool = False,
    timeout: float = 10.0,
) -> tuple[list[HTTPEndpointProbeResult], str | None]:
    """Backward-compatible wrapper — returns (endpoints, skip_reason)."""
    selection = probe_and_select_http_followup_endpoints(
        targets,
        config,
        max_hosts=max_hosts,
        dry_run=dry_run,
        timeout=timeout,
    )
    return selection.selected, selection.skip_reason


def probe_and_select_http_followup_endpoints(
    targets: TargetSet,
    config: dict,
    *,
    max_hosts: int,
    dry_run: bool = False,
    timeout: float = 10.0,
    command_runner=None,
) -> HttpFollowupSelection:
    """
    Select HTTP follow-up endpoints with curl probe scoring.

    Plain HTTP first; deprioritize redirect-only (301-only) targets.
    """
    candidates = _collect_candidate_triples(targets, config)
    if not candidates:
        if _https_targets_skipped_list(targets):
            return _http_only_skip_selection(targets)
        return HttpFollowupSelection(selected=[], skip_reason="skipped_no_http_service")

    probed = probe_all_http_candidates(
        candidates,
        dry_run=dry_run,
        timeout=timeout,
        command_runner=command_runner,
    )
    if not probed:
        if _https_targets_skipped_list(targets):
            return _http_only_skip_selection(targets)
        return HttpFollowupSelection(selected=[], skip_reason="skipped_no_http_service")

    best_per_host = pick_best_endpoint_per_host(probed)
    if not best_per_host:
        skip_reason = (
            SKIP_REASON_HTTP_TARGETS_NOT_FOUND
            if targets.hosts_for_capability("http_targets") or config.get("hosts")
            else "skipped_no_http_service"
        )
        annotated = annotate_probe_selection(probed, [])
        if skip_reason == SKIP_REASON_HTTP_TARGETS_NOT_FOUND:
            return HttpFollowupSelection(
                probed=annotated,
                selected=[],
                skip_reason=skip_reason,
                https_targets_skipped=_https_targets_skipped_list(targets),
            )
        return HttpFollowupSelection(
            probed=annotated,
            selected=[],
            skip_reason=skip_reason,
        )

    hosts_ranked = sorted(best_per_host.values(), key=probe_quality_sort_key)
    chosen = hosts_ranked[:1] if max_hosts == 1 else hosts_ranked[:max_hosts]
    selected = [
        replace(
            stats,
            selected=True,
            selection_reason=selection_reason_for(stats),
            rejection_reason="",
        )
        for stats in chosen
    ]
    annotated = annotate_probe_selection(probed, selected)
    primary_reason = selected[0].selection_reason if selected else ""

    if not selected:
        skip_reason = (
            SKIP_REASON_HTTP_TARGETS_NOT_FOUND
            if targets.hosts_for_capability("http_targets") or config.get("hosts")
            else "skipped_no_http_service"
        )
        return HttpFollowupSelection(
            probed=annotated,
            selected=[],
            skip_reason=skip_reason,
            https_targets_skipped=_https_targets_skipped_list(targets),
        )

    return HttpFollowupSelection(
        probed=annotated,
        selected=selected,
        selected_http_target_reason=primary_reason,
    )
