#!/usr/bin/env python3
"""Collect DSP run evidence into evidence_summary.json for Traffic Regression E2E."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any


CORE_FILES = (
    "events.jsonl",
    "validation.json",
    "traffic_summary.json",
    "scenario_plan.json",
    "http_followup_requests.jsonl",
    "http_request_dump.json",
    "sql_injection_requests.jsonl",
    "run.json",
    "report.json",
)

FORBIDDEN_WEBSHELL_MARKERS = (
    "manifest.json",
    "run_scenario.py",
    "remote_discovery.py",
    "discover_runner.py",
    "dsp-remote-scenario",
    "python3 /tmp/dsp/",
)


def _load_json(path: Path) -> Any | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            rows.append(obj)
    return rows


def _file_status(run_dir: Path, name: str) -> dict[str, Any]:
    path = run_dir / name
    if not path.is_file():
        return {"status": "missing", "path": str(path), "bytes": 0}
    return {"status": "present", "path": str(path), "bytes": path.stat().st_size}


def _latest_run_dir(runs_root: Path) -> Path | None:
    if not runs_root.is_dir():
        return None
    candidates = [p for p in runs_root.iterdir() if p.is_dir()]
    if not candidates:
        return None
    candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0]


def _resolve_run_dir(explicit: str | None, runs_root: str | None, hint_file: str | None) -> Path:
    if explicit:
        path = Path(explicit)
        if not path.is_dir():
            raise FileNotFoundError(f"run directory not found: {path}")
        return path

    if hint_file:
        hint = Path(hint_file)
        if hint.is_file():
            text = hint.read_text(encoding="utf-8").strip()
            if text:
                path = Path(text)
                if path.is_dir():
                    return path

    if runs_root:
        latest = _latest_run_dir(Path(runs_root))
        if latest:
            return latest

    default_root = Path.home() / ".dsp" / "runs"
    latest = _latest_run_dir(default_root)
    if latest:
        return latest
    raise FileNotFoundError("unable to locate DSP run directory")


def _scenario_ids_from_summary(traffic: dict[str, Any] | None, events: list[dict[str, Any]]) -> list[str]:
    ids: list[str] = []
    if traffic and isinstance(traffic.get("scenarios"), dict):
        ids.extend(str(k) for k in traffic["scenarios"].keys())
    for ev in events:
        sid = ev.get("scenario_id")
        if sid and str(sid) not in ids:
            ids.append(str(sid))
    return ids


def _count_metric(block: dict[str, Any], keys: tuple[str, ...]) -> int | None:
    for key in keys:
        if key in block and block[key] is not None:
            try:
                return int(block[key])
            except (TypeError, ValueError):
                continue
    return None


def _extract_scenario(
    sid: str,
    traffic: dict[str, Any] | None,
    events: list[dict[str, Any]],
    validation: dict[str, Any] | None,
) -> dict[str, Any]:
    block = {}
    if traffic and isinstance(traffic.get("scenarios"), dict):
        block = dict(traffic["scenarios"].get(sid) or {})

    sid_events = [e for e in events if e.get("scenario_id") == sid]
    skipped = bool(block.get("skipped"))
    skip_reason = block.get("skip_reason")
    if not skipped:
        for e in sid_events:
            if str(e.get("event", "")).endswith("_skipped") or e.get("event") in {
                "smb_scenario_skipped",
                "http_followup_skipped",
                "sql_injection_skipped",
                "ssh_failure_skipped",
                "rare_protocol_activity_skipped",
                "ldap_enumeration_skipped",
                "kerberos_failure_skipped",
            }:
                skipped = True
                skip_reason = (e.get("evidence") or {}).get("reason") or e.get("status")
                break

    targets = (
        block.get("target_ips")
        or block.get("selected_targets")
        or block.get("hosts")
        or []
    )
    if isinstance(targets, str):
        targets = [targets]
    # Normalize "host:port (reason)" entries to host strings while keeping originals.
    normalized_targets: list[str] = []
    for t in targets:
        s = str(t)
        host = s.split()[0].split("(")[0].strip()
        normalized_targets.append(host if host else s)
    targets = normalized_targets

    expected = _count_metric(
        block,
        (
            "planned_count",
            "expected_count",
            "commands_planned",
            "probe_count_planned",
            "probes_planned",
            "requests_planned",
            "attempts_planned",
            "domains_planned",
            "dga_domain_generated_count",
        ),
    )
    actual = _count_metric(
        block,
        (
            "actual_count",
            "probe_count",
            "probes_sent",
            "requests_sent",
            "request_count",
            "http_request_count",
            "attempts",
            "attempt_count",
            "attempts_planned",
            "commands_dispatched",
            "domains_queried",
            "domains_generated",
            "dga_domain_generated_count",
            "query_count",
            "packets_sent",
            "auth_attempts",
            "auth_attempt_count",
            "smb_auth_attempt_count",
            "tcp_connect_attempts",
            "connection_attempt_count",
        ),
    )
    if actual is None and sid == "dga":
        # Count generated-domain events (status is often "info", not traffic-like).
        actual = sum(1 for e in sid_events if e.get("event") == "dga_domain_generated")
        if actual == 0:
            for e in reversed(sid_events):
                if e.get("event") == "dga_completed":
                    evidence = e.get("evidence") or {}
                    for key in ("domains_generated", "dga_domain_generated_count"):
                        if evidence.get(key) is not None:
                            try:
                                actual = int(evidence[key])
                            except (TypeError, ValueError):
                                actual = 0
                            break
                    break
    if actual is None:
        # Fall back to counting traffic-like events.
        traffic_like = [
            e
            for e in sid_events
            if e.get("status") in {"sent", "ok", "success", "failed", "error", "timeout", "nxdomain", "response"}
            or str(e.get("event", "")).endswith(("_sent", "_attempt", "_failed", "_opened", "_generated", "_observed"))
        ]
        actual = len(traffic_like) if traffic_like else 0

    # DGA targets come from dns_hosts / started event, not always traffic_summary.target_ips.
    if sid == "dga" and not targets:
        for e in sid_events:
            if e.get("event") in {"dga_started", "dga_completed"} and e.get("target"):
                targets = [str(e.get("target"))]
                break
        if not targets:
            dns_hosts = list(((traffic.get("discovery") or {}).get("dns_hosts")) or [])
            if not dns_hosts:
                dns_hosts = list(
                    (((traffic.get("discovery") or {}).get("service_hosts") or {}).get("dns_hosts")) or []
                )
            targets = [str(h) for h in dns_hosts[:5]]

    selection_reason = (
        block.get("host_selection_reason")
        or block.get("selection_reason")
        or block.get("selected_from")
        or block.get("target_selection_reason")
        or block.get("selected_http_target_reason")
    )
    if not selection_reason:
        for e in sid_events:
            evidence = e.get("evidence") or {}
            for key in (
                "host_selection_reason",
                "selection_reason",
                "selected_from",
                "selected_http_target_reason",
                "target_selection_reason",
            ):
                if evidence.get(key):
                    selection_reason = evidence.get(key)
                    break
            if selection_reason:
                break
            # Infer alive_hosts selection when discovery hosts are present in started evidence.
            if sid == "port_sweep" and evidence.get("discovery"):
                selection_reason = "alive_hosts"
                break
    if not selection_reason and sid == "port_sweep" and targets and traffic:
        alive = list(((traffic.get("discovery") or {}).get("alive_hosts")) or [])
        if alive and any(str(t).split(":")[0] in set(map(str, alive)) for t in targets):
            selection_reason = "alive_hosts"

    origins: list[str] = []
    for e in sid_events:
        src = e.get("source")
        if src and str(src) not in origins:
            origins.append(str(src))
        evidence = e.get("evidence") or {}
        for key in ("origin", "traffic_origin", "execution_origin"):
            val = evidence.get(key)
            if val and str(val) not in origins:
                origins.append(str(val))

    validation_result = None
    if validation:
        # validation.json shapes vary; try common layouts.
        results = validation.get("results") or validation.get("scenarios") or validation
        if isinstance(results, dict) and sid in results:
            validation_result = results[sid]
        elif isinstance(results, list):
            for item in results:
                if isinstance(item, dict) and item.get("scenario_id") == sid:
                    validation_result = item
                    break

    event_names = sorted({str(e.get("event")) for e in sid_events if e.get("event")})
    phase1_markers = []
    for e in sid_events:
        evidence = e.get("evidence") or {}
        phase = evidence.get("phase")
        if phase:
            phase1_markers.append(str(phase))
        if evidence.get("initial_compromise_endpoint"):
            phase1_markers.append("initial_compromise_endpoint")

    executed = (not skipped) and (
        (actual or 0) > 0 or bool(sid_events)
    )
    return {
        "scenario_id": sid,
        "executed": executed,
        "skipped": skipped,
        "skip_reason": skip_reason,
        "expected_count": expected,
        "actual_count": actual,
        "targets": list(targets) if isinstance(targets, list) else [],
        "selection_reason": selection_reason,
        "origins": origins,
        "event_names": event_names,
        "event_count": len(sid_events),
        "validation": validation_result,
        "phase_markers": sorted(set(phase1_markers)),
        "traffic_block": {
            k: block.get(k)
            for k in (
                "target_ips",
                "selected_targets",
                "skipped",
                "skip_reason",
                "probe_count",
                "requests_sent",
                "attempts",
                "commands_dispatched",
                "commands_planned",
                "host_selection_reason",
                "selection_reason",
                "selected_from",
            )
            if k in block
        },
    }


def _scan_forbidden_artifacts(events: list[dict[str, Any]], run_dir: Path) -> list[str]:
    hits: list[str] = []
    blob_parts: list[str] = []
    for e in events:
        blob_parts.append(json.dumps(e, ensure_ascii=False))
    blob = "\n".join(blob_parts)
    for marker in FORBIDDEN_WEBSHELL_MARKERS:
        if marker in blob:
            hits.append(marker)

    for name in ("manifest.json", "run_scenario.py", "remote_discovery.py", "discover_runner.py"):
        # Presence under run_dir alone is not proof of remote deploy; still record if found.
        matches = list(run_dir.rglob(name))
        if matches:
            hits.append(f"local_path:{name}")
    return sorted(set(hits))


def collect_evidence(
    run_dir: Path,
    *,
    provider_hint: str | None = None,
    profile_hint: str | None = None,
) -> dict[str, Any]:
    files = {name: _file_status(run_dir, name) for name in CORE_FILES}
    events = _load_jsonl(run_dir / "events.jsonl")
    validation = _load_json(run_dir / "validation.json")
    traffic = _load_json(run_dir / "traffic_summary.json")
    run_meta = _load_json(run_dir / "run.json") or {}
    report = _load_json(run_dir / "report.json") or {}

    provider = (
        provider_hint
        or run_meta.get("execution_provider")
        or run_meta.get("provider")
        or report.get("execution_provider")
        or "unknown"
    )
    profile = (
        profile_hint
        or run_meta.get("profile")
        or run_meta.get("traffic_profile")
        or (traffic or {}).get("traffic_profile")
        or "unknown"
    )

    discovery = (traffic or {}).get("discovery") or {}
    scenario_ids = _scenario_ids_from_summary(traffic if isinstance(traffic, dict) else None, events)
    scenarios = {
        sid: _extract_scenario(
            sid,
            traffic if isinstance(traffic, dict) else None,
            events,
            validation if isinstance(validation, dict) else None,
        )
        for sid in scenario_ids
    }

    # HTTP follow-up request dump counts
    http_followup_rows = _load_jsonl(run_dir / "http_followup_requests.jsonl")
    sql_rows = _load_jsonl(run_dir / "sql_injection_requests.jsonl")
    http_dump = _load_json(run_dir / "http_request_dump.json")

    empty_target_fallback = False
    target_net = (traffic or {}).get("target_net") or run_meta.get("target_net")
    hosts = discovery.get("alive_hosts") or []
    if not target_net and "10.10.10.20" in json.dumps(traffic or {}):
        empty_target_fallback = True
    if hosts == ["10.10.10.20"] and (traffic or {}).get("target_net") == "10.10.10.0/24":
        # Heuristic only; compare step confirms with run args.
        pass

    # Detect port_sweep CIDR expansion
    port_sweep = scenarios.get("port_sweep") or {}
    port_sweep_cidr_expansion = False
    reason = str(port_sweep.get("selection_reason") or "")
    if reason == "target_net_expansion":
        port_sweep_cidr_expansion = True
    # Also scan events
    for e in events:
        if e.get("scenario_id") != "port_sweep":
            continue
        evidence = e.get("evidence") or {}
        for key in ("host_selection_reason", "selection_reason", "selected_from"):
            if evidence.get(key) == "target_net_expansion":
                port_sweep_cidr_expansion = True

    # rare localhost fallback
    rare_localhost = False
    rare = scenarios.get("rare_protocol_activity") or {}
    for t in rare.get("targets") or []:
        if str(t) in {"127.0.0.1", "::1", "localhost"}:
            rare_localhost = True
    for e in events:
        if e.get("scenario_id") != "rare_protocol_activity":
            continue
        tgt = str(e.get("target") or "")
        if tgt in {"127.0.0.1", "::1", "localhost"}:
            rare_localhost = True
        evidence = e.get("evidence") or {}
        for key in ("host", "target", "destination"):
            if str(evidence.get(key) or "") in {"127.0.0.1", "::1", "localhost"}:
                rare_localhost = True

    # SMB auth vs tcp-only
    smb_events = [e for e in events if e.get("scenario_id") == "smb_login_failure"]
    smb_block = {}
    if isinstance(traffic, dict):
        smb_block = dict((traffic.get("scenarios") or {}).get("smb_login_failure") or {})
    smb_auth = any(
        e.get("event") in {"smb_auth_attempt", "smb_auth_failed"} for e in smb_events
    ) or int(smb_block.get("auth_attempts") or smb_block.get("auth_failed") or 0) > 0
    smb_tcp = (
        any(
            e.get("event")
            in {"smb_connection_opened", "smb_connection_failed", "smb_scenario_started"}
            for e in smb_events
        )
        or int(smb_block.get("tcp_connect_attempts") or 0) > 0
        or bool((scenarios.get("smb_login_failure") or {}).get("executed"))
    )
    smb_skipped = bool((scenarios.get("smb_login_failure") or {}).get("skipped") or smb_block.get("skipped"))

    # Phase 1 markers
    phase1_present = False
    for sid, sc in scenarios.items():
        if sc.get("phase_markers"):
            phase1_present = True
    for e in events:
        evidence = e.get("evidence") or {}
        if evidence.get("phase") == "phase1_webshell_attack":
            phase1_present = True
        if evidence.get("initial_compromise_endpoint"):
            phase1_present = True

    forbidden = _scan_forbidden_artifacts(events, run_dir)

    # Planning parity signals (local vs webshell share discovery buckets)
    planning = {
        "discovery_enabled": bool(discovery.get("enabled")),
        "discovery_origin": discovery.get("discovery_origin"),
        "alive_hosts": list(discovery.get("alive_hosts") or []),
        "service_hosts": discovery.get("service_hosts") or discovery.get("service_hosts") or {},
        "dns_hosts": (discovery.get("service_hosts") or {}).get("dns_hosts")
        or (discovery.get("service_hosts") or {}).get("dns")
        or [],
        "http_targets": (discovery.get("service_hosts") or {}).get("http_targets") or [],
        "ssh_hosts": (discovery.get("service_hosts") or {}).get("ssh_hosts") or [],
        "ldap_hosts": (discovery.get("service_hosts") or {}).get("ldap_hosts") or [],
        "smb_hosts": (discovery.get("service_hosts") or {}).get("smb_hosts") or [],
        "kerberos_hosts": (discovery.get("service_hosts") or {}).get("kerberos_hosts") or [],
    }
    # Prefer nested service_hosts from discovery meta
    svc = discovery.get("service_hosts")
    if isinstance(svc, dict):
        for key in (
            "dns_hosts",
            "http_targets",
            "ssh_hosts",
            "ldap_hosts",
            "smb_hosts",
            "kerberos_hosts",
        ):
            if key in svc:
                planning[key] = list(svc.get(key) or [])

    return {
        "run_dir": str(run_dir),
        "provider": provider,
        "profile": profile,
        "target_net": target_net,
        "files": files,
        "scenario_ids": scenario_ids,
        "scenarios": scenarios,
        "discovery": planning,
        "http_followup_request_count": len(http_followup_rows),
        "sql_injection_request_count": len(sql_rows),
        "http_request_dump_present": files["http_request_dump.json"]["status"] == "present",
        "http_request_dump": http_dump if isinstance(http_dump, dict) else None,
        "gaps": {
            "empty_target_net_fallback_suspected": empty_target_fallback,
            "port_sweep_cidr_expansion": port_sweep_cidr_expansion,
            "rare_protocol_localhost_fallback": rare_localhost,
            "smb_auth_events_present": smb_auth,
            "smb_tcp_activity_present": smb_tcp and not smb_skipped,
            "smb_tcp_only": bool(smb_tcp and not smb_auth and not smb_skipped),
            "phase1_webshell_markers_present": phase1_present,
            "webshell_forbidden_artifacts": forbidden,
        },
        "run_meta": {
            "run_id": run_meta.get("run_id") or run_dir.name,
            "execution_provider": run_meta.get("execution_provider"),
            "profile": run_meta.get("profile") or run_meta.get("traffic_profile"),
            "target_net": run_meta.get("target_net"),
            "webshell_url": run_meta.get("webshell_url") or (traffic or {}).get("webshell_url"),
            "webshell_family": run_meta.get("webshell_family") or run_meta.get("webshell_type"),
        },
        "event_count": len(events),
        "validation_present": files["validation.json"]["status"] == "present",
        "traffic_summary_present": files["traffic_summary.json"]["status"] == "present",
        "scenario_plan_present": files["scenario_plan.json"]["status"] == "present",
        "notes": [
            "scenario_plan.json is not written by current DSP; missing is expected unless reintroduced.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Collect DSP evidence for E2E traffic regression")
    parser.add_argument("--run-dir", help="Explicit DSP run directory")
    parser.add_argument("--runs-root", help="DSP runs root (uses latest subdirectory)")
    parser.add_argument("--run-dir-file", help="File containing run directory path")
    parser.add_argument("--output", required=True, help="Path to evidence_summary.json")
    parser.add_argument("--provider", default=None)
    parser.add_argument("--profile", default=None)
    args = parser.parse_args(argv)

    try:
        run_dir = _resolve_run_dir(args.run_dir, args.runs_root, args.run_dir_file)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    summary = collect_evidence(run_dir, provider_hint=args.provider, profile_hint=args.profile)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {output} (run_dir={run_dir}, scenarios={len(summary.get('scenarios') or {})})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
