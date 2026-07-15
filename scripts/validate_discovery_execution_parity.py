#!/usr/bin/env python3
"""Report discovery-first ordering and local/webshell plan parity for all profiles."""

from __future__ import annotations

import json
import sys

from dsp.engine.host_selection import cache_http_endpoint_selection
from dsp.engine.scenario_engine import TargetSet
from dsp.execution.remote.command.scenario_plans import _plan_http_followup, _plan_port_sweep, _plan_sql_injection
from dsp.runtime.operational_profiles import build_operational_scenario_params, scenarios_for_profile
from dsp.runtime.scenario_plan import apply_webshell_initial_compromise_plan, build_port_sweep_plan_view
from dsp.runner.target_selection import resolve_scenario_targets


WEBSHELL_URL = "http://10.10.10.50:8080/shell.jsp"


def _targets() -> TargetSet:
    return TargetSet(
        target_net="10.10.10.0/24",
        hosts=["10.10.10.97", "10.10.10.98"],
        service_hosts={
            "http_targets": ["10.10.10.97"],
            "ssh_hosts": ["10.10.10.98"],
            "ldap_hosts": ["10.10.10.98"],
            "smb_hosts": ["10.10.10.98"],
        },
        service_endpoints={
            "http_targets": [("10.10.10.97", 8080)],
            "ssh_hosts": [("10.10.10.98", 22)],
        },
        discovery_enabled=True,
    )


def _http_targets(params: dict, scenario_ids: list[str], *, webshell: bool) -> dict[str, list[str]]:
    merged = {k: dict(v) for k, v in params.items()}
    if webshell:
        apply_webshell_initial_compromise_plan(merged, scenario_ids, WEBSHELL_URL)
    cache_http_endpoint_selection(
        merged,
        scenario_ids=scenario_ids,
        targets=_targets(),
        dry_run=True,
    )
    out: dict[str, list[str]] = {}
    for sid in ("http_followup", "sql_injection"):
        if sid not in scenario_ids:
            continue
        if sid == "http_followup":
            plan = _plan_http_followup(_targets(), merged[sid], dry_run=True)
        else:
            plan = _plan_sql_injection(_targets(), merged[sid], dry_run=True)
        urls = [r["url"] for r in plan.get("requests", [])[:1]]
        out[sid] = urls
    return out


def _report_profile(profile: str, provider: str) -> dict:
    webshell = provider == "webshell"
    order = scenarios_for_profile(profile)
    params = build_operational_scenario_params(profile, order, target_net="10.10.10.0/24")
    targets = _targets()
    selected: dict[str, list[str]] = {}
    merged = {k: dict(v) for k, v in params.items()}
    if webshell:
        apply_webshell_initial_compromise_plan(merged, order, WEBSHELL_URL)
    cache_http_endpoint_selection(
        merged,
        scenario_ids=order,
        targets=targets,
        dry_run=True,
    )
    for sid in order:
        if sid in ("port_sweep", "ssh_failure"):
            selected[sid] = resolve_scenario_targets(sid, targets, merged.get(sid, {}))
    http = _http_targets(params, order, webshell=webshell)
    port_plan = build_port_sweep_plan_view(targets, merged.get("port_sweep", {}))
    return {
        "profile": profile,
        "provider": provider,
        "scenario_order": order,
        "selected_targets": selected,
        "http_plan_urls": http,
        "port_sweep_hosts": port_plan.selected_hosts if "port_sweep" in order else [],
    }


def _http_plan_hosts(url_map: dict[str, list[str]]) -> dict[str, list[str]]:
    hosts: dict[str, list[str]] = {}
    for sid, urls in url_map.items():
        extracted: list[str] = []
        for url in urls:
            host = url.split("://", 1)[1].split(":", 1)[0].split("/", 1)[0]
            extracted.append(host)
        hosts[sid] = extracted
    return hosts


def main() -> int:
    reports = []
    for profile in ("normal", "high"):
        for provider in ("local", "webshell"):
            reports.append(_report_profile(profile, provider))
    print(json.dumps(reports, indent=2))
    local = [r for r in reports if r["provider"] == "local"]
    webshell = [r for r in reports if r["provider"] == "webshell"]
    for loc, ws in zip(local, webshell):
        assert loc["scenario_order"] == ws["scenario_order"]
        if "port_sweep" in loc["scenario_order"]:
            assert loc["port_sweep_hosts"] == ws["port_sweep_hosts"]
        if loc["http_plan_urls"]:
            assert _http_plan_hosts(loc["http_plan_urls"]) == _http_plan_hosts(ws["http_plan_urls"])
            assert "10.10.10.97" in str(loc["http_plan_urls"])
            assert "10.10.10.97" in str(ws["http_plan_urls"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
