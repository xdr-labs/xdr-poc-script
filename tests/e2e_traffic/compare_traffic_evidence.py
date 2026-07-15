#!/usr/bin/env python3
"""Compare pcap + DSP evidence for Traffic Regression E2E and write reports."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


RESULT_PASS = "PASS"
RESULT_FAIL = "FAIL"
RESULT_REVIEW = "REVIEW"
RESULT_SKIP = "SKIP"
RESULT_HOST_ONLY_PASS = "HOST_ONLY_PASS"


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def _resolve_profile_expectations(expected_profiles: dict[str, Any], profile: str) -> dict[str, Any]:
    profiles = expected_profiles.get("profiles") or {}
    base = dict(profiles.get(profile) or {})
    inherits = base.get("inherits")
    if inherits and inherits in profiles:
        parent = dict(profiles[inherits])
        parent_scenarios = dict(parent.get("scenarios") or {})
        child_scenarios = dict(base.get("scenarios") or {})
        merged = dict(parent)
        merged.update({k: v for k, v in base.items() if k != "scenarios"})
        parent_scenarios.update(child_scenarios)
        merged["scenarios"] = parent_scenarios
        return merged
    return base


def _packet_matched(sid: str, pcap: dict[str, Any], rule: dict[str, Any]) -> tuple[bool, int, str]:
    hints = (pcap.get("scenario_packet_hints") or {}).get(sid) or {}
    if hints:
        matched = bool(hints.get("matched"))
        # Prefer a meaningful observed count
        for key in (
            "http_requests",
            "tcp_22_packets",
            "udp_53_packets",
            "dns_queries",
            "tcp_syn_packets",
            "tcp_445_packets",
            "tcp_389_packets",
            "tcp_88_packets",
            "http_port_packets",
        ):
            if key in hints and hints[key]:
                return matched, int(hints[key]), key
        if "rare_protocol_hits" in hints:
            total = sum(int(v) for v in (hints.get("rare_protocol_hits") or {}).values())
            return matched, total, "rare_protocol_hits"
        return matched, 1 if matched else 0, "hint"

    # Fallback without hints
    if sid in {"http_followup", "sql_injection"}:
        count = int(pcap.get("http_requests") or 0) + int(pcap.get("tcp_80_packets") or 0) + int(
            pcap.get("tcp_8080_packets") or 0
        )
        return count > 0, count, "http/tcp"
    if sid == "ssh_failure":
        count = int(pcap.get("tcp_22_packets") or 0)
        return count > 0, count, "tcp_22"
    if sid in {"dns_tunnel", "dga"}:
        count = int(pcap.get("udp_53_packets") or 0) + int(pcap.get("dns_queries") or 0)
        return count > 0, count, "dns/udp53"
    if sid == "port_sweep":
        count = int(pcap.get("tcp_syn_packets") or 0) or int(pcap.get("tcp_packets") or 0)
        return count > 0, count, "tcp"
    if sid == "smb_login_failure":
        count = int(pcap.get("tcp_445_packets") or 0)
        return count > 0, count, "tcp_445"
    if sid == "ldap_enumeration":
        count = int(pcap.get("tcp_389_packets") or 0)
        return count > 0, count, "tcp_389"
    if sid == "kerberos_failure":
        count = int(pcap.get("tcp_88_packets") or 0) + int(pcap.get("udp_88_packets") or 0)
        return count > 0, count, "port_88"
    if sid == "rare_protocol_activity":
        rare = pcap.get("rare_protocol_hits") or {}
        count = sum(int(v) for v in rare.values())
        return count > 0, count, "rare"
    return False, 0, "none"


def _evidence_present(sid: str, evidence: dict[str, Any], rule: dict[str, Any]) -> tuple[bool, str]:
    sc = (evidence.get("scenarios") or {}).get(sid)
    files = evidence.get("files") or {}
    required_files = rule.get("evidence_files") or []
    missing = []
    present = []
    for name in required_files:
        st = (files.get(name) or {}).get("status")
        if st == "present":
            present.append(name)
        else:
            # events.jsonl / traffic_summary.json / validation.json are core;
            # scenario-specific dumps may be absent when skipped.
            missing.append(name)

    if not sc:
        if missing and all(m in {"http_followup_requests.jsonl", "http_request_dump.json", "sql_injection_requests.jsonl"} for m in missing):
            return False, "scenario missing from evidence"
        return False, "scenario missing from evidence"

    if sc.get("skipped"):
        return True, f"skipped:{sc.get('skip_reason') or 'unspecified'}"

    if sc.get("event_count", 0) > 0 or sc.get("actual_count"):
        # Core evidence exists even if optional dump files missing.
        core_ok = any(
            (files.get(n) or {}).get("status") == "present"
            for n in ("events.jsonl", "traffic_summary.json", "validation.json")
        )
        if core_ok:
            note = "evidence present"
            if missing:
                note += f"; optional/missing={','.join(missing)}"
            return True, note
    if present:
        return True, f"files present: {','.join(present)}"
    return False, f"missing evidence files: {','.join(missing) if missing else 'unknown'}"


def _skip_allowed(sid: str, sc: dict[str, Any], profile_exp: dict[str, Any], discovery: dict[str, Any]) -> bool:
    if not sc or not sc.get("skipped"):
        return False
    exp = (profile_exp.get("scenarios") or {}).get(sid) or {}
    reason = str(sc.get("skip_reason") or "").lower()
    mapping = {
        "dga": ("skip_allowed_if_no_dns_hosts", "dns_hosts", "dns"),
        "ssh_failure": ("skip_allowed_if_no_ssh_hosts", "ssh_hosts", "ssh"),
        "ldap_enumeration": ("skip_allowed_if_no_ldap_hosts", "ldap_hosts", "ldap"),
        "smb_login_failure": ("skip_allowed_if_no_smb_hosts", "smb_hosts", "smb"),
        "kerberos_failure": ("skip_allowed_if_no_kerberos_hosts", "kerberos_hosts", "kerberos"),
    }
    if sid in mapping:
        flag, bucket, token = mapping[sid]
        if exp.get(flag):
            hosts = discovery.get(bucket) or []
            if not hosts:
                return True
            if token in reason or "no_" in reason:
                return True
    if "no_" in reason or reason in {"no_targets", "no_alive_hosts", "webshell_connect_failed"}:
        return True
    return False


def _count_within_tolerance(expected: int | None, observed: int | None, *, floor_ratio: float = 0.5) -> bool:
    if expected is None or observed is None:
        return True  # cannot hard-fail on unknown expected
    if expected <= 0:
        return observed >= 0
    # Allow lower bound for lab environments where targets may refuse/connect-fail.
    return observed >= max(1, int(expected * floor_ratio)) or observed >= expected


def _provider_origin_ok(provider: str, origins: list[str]) -> tuple[str, str]:
    if provider == "local":
        expected = "local|dsp_host"
        if not origins:
            return RESULT_REVIEW, "no origin recorded"
        bad = [o for o in origins if o in {"remote", "remote_host"}]
        if bad and not any(o in {"local", "dsp_host"} for o in origins):
            return RESULT_FAIL, f"expected local origin, observed {origins}"
        return RESULT_PASS, f"observed {origins}"
    if provider == "webshell":
        expected = "remote|remote_host"
        if not origins:
            return RESULT_REVIEW, "no origin recorded"
        if any(o in {"remote", "remote_host"} for o in origins):
            return RESULT_PASS, f"observed {origins}"
        if any(o in {"local", "dsp_host"} for o in origins):
            return RESULT_FAIL, f"expected remote origin, observed {origins}"
        return RESULT_REVIEW, f"observed {origins}"
    return RESULT_REVIEW, f"unknown provider {provider}"


def _discovery_selection_ok(
    sid: str,
    sc: dict[str, Any],
    rule: dict[str, Any],
    discovery: dict[str, Any],
    profile_exp: dict[str, Any],
) -> tuple[str, str]:
    source = rule.get("discovery_source") or ((profile_exp.get("scenarios") or {}).get(sid) or {}).get(
        "selected_from"
    )
    if not source or source in {"none", "webshell_host", "rare_ports_or_alive_hosts"}:
        return RESULT_PASS, f"source={source or 'n/a'}"

    if sc.get("skipped"):
        return RESULT_SKIP, f"skipped ({sc.get('skip_reason')})"

    targets = [str(t) for t in (sc.get("targets") or [])]
    bucket = {
        "alive_hosts": discovery.get("alive_hosts") or [],
        "dns_hosts": discovery.get("dns_hosts") or [],
        "http_targets": discovery.get("http_targets") or [],
        "ssh_hosts": discovery.get("ssh_hosts") or [],
        "ldap_hosts": discovery.get("ldap_hosts") or [],
        "smb_hosts": discovery.get("smb_hosts") or [],
        "kerberos_hosts": discovery.get("kerberos_hosts") or [],
    }.get(str(source), [])

    reason = str(sc.get("selection_reason") or "")
    if source == "alive_hosts" and reason == "target_net_expansion":
        return RESULT_FAIL, "selected via target_net_expansion (CIDR fallback)"

    if not bucket:
        # No discovery bucket — skip allowed cases handled elsewhere.
        if sid in {"dga", "ssh_failure", "ldap_enumeration", "smb_login_failure", "kerberos_failure"}:
            return RESULT_REVIEW, f"no {source} in discovery; scenario not skipped"
        return RESULT_REVIEW, f"discovery bucket empty: {source}"

    if not targets:
        return RESULT_REVIEW, "no selected targets recorded"

    # Soft check: at least one selected target in bucket (or bucket non-empty with execution)
    overlap = [t for t in targets if t in set(map(str, bucket))]
    if overlap:
        return RESULT_PASS, f"selected {overlap[:3]} from {source}"
    # Targets may be endpoints host:port
    host_only = [t.split(":")[0] for t in targets]
    overlap2 = [t for t in host_only if t in set(map(str, bucket))]
    if overlap2:
        return RESULT_PASS, f"selected {overlap2[:3]} from {source}"
    return RESULT_REVIEW, f"targets {targets[:3]} not in {source}={list(bucket)[:5]}"


def evaluate_regression_gaps(
    evidence: dict[str, Any],
    gap_rules: dict[str, Any],
    *,
    provider: str,
    target_net_arg: str | None,
) -> list[dict[str, Any]]:
    rules = gap_rules.get("rules") or {}
    gaps = evidence.get("gaps") or {}
    rows: list[dict[str, Any]] = []

    # empty target_net fallback
    rule = rules.get("no_empty_target_net_fallback") or {}
    detected = False
    observed = "not detected"
    if target_net_arg is not None and str(target_net_arg).strip() == "":
        # Explicit empty was requested — check if fallback host appears.
        blob = json.dumps(evidence)
        if "10.10.10.20" in blob:
            detected = True
            observed = "empty target_net resolved with 10.10.10.20"
    if gaps.get("empty_target_net_fallback_suspected"):
        detected = True
        observed = "fallback host suspected in evidence"
    rows.append(
        {
            "gap_rule": "no_empty_target_net_fallback",
            "expected": rule.get("expected"),
            "observed": observed,
            "result": rule.get("result_if_detected", RESULT_FAIL) if detected else RESULT_PASS,
        }
    )

    # port_sweep CIDR expansion
    rule = rules.get("no_port_sweep_cidr_expansion_without_discovery") or {}
    detected = bool(gaps.get("port_sweep_cidr_expansion"))
    rows.append(
        {
            "gap_rule": "no_port_sweep_cidr_expansion_without_discovery",
            "expected": rule.get("expected"),
            "observed": "target_net_expansion" if detected else "not detected",
            "result": rule.get("result_if_detected", RESULT_FAIL) if detected else RESULT_PASS,
        }
    )

    # rare localhost
    rule = rules.get("no_rare_protocol_localhost_fallback") or {}
    detected = bool(gaps.get("rare_protocol_localhost_fallback"))
    rows.append(
        {
            "gap_rule": "no_rare_protocol_localhost_fallback",
            "expected": rule.get("expected"),
            "observed": "127.0.0.1/localhost target" if detected else "not detected",
            "result": rule.get("result_if_detected", RESULT_FAIL) if detected else RESULT_PASS,
        }
    )

    # SMB semantics
    rule = rules.get("smb_login_failure_semantics") or {}
    smb_sc = (evidence.get("scenarios") or {}).get("smb_login_failure") or {}
    if smb_sc.get("skipped"):
        smb_result = RESULT_SKIP
        smb_obs = f"skipped:{smb_sc.get('skip_reason')}"
    elif gaps.get("smb_auth_events_present"):
        smb_result = RESULT_PASS
        smb_obs = "SMB auth failure events present"
    elif gaps.get("smb_tcp_only") or gaps.get("smb_tcp_activity_present"):
        smb_result = rule.get("result_if_tcp_only", RESULT_REVIEW)
        smb_obs = "TCP/445 connect only (no SMB auth failure evidence)"
    else:
        smb_result = RESULT_REVIEW
        smb_obs = "smb_login_failure not observed"
    rows.append(
        {
            "gap_rule": "smb_login_failure_semantics",
            "expected": rule.get("expected"),
            "observed": smb_obs,
            "result": smb_result,
        }
    )

    # Phase 1 webshell host targeting
    rule = rules.get("phase1_webshell_host_targeting") or {}
    if provider != "webshell":
        rows.append(
            {
                "gap_rule": "phase1_webshell_host_targeting",
                "expected": rule.get("expected"),
                "observed": "n/a (local provider)",
                "result": RESULT_SKIP,
            }
        )
    else:
        if gaps.get("phase1_webshell_markers_present"):
            phase_result = RESULT_PASS
            phase_obs = "phase1 markers present"
        else:
            phase_result = rule.get("result_if_missing", RESULT_REVIEW)
            phase_obs = "phase1 webshell-host targeting markers not found"
        rows.append(
            {
                "gap_rule": "phase1_webshell_host_targeting",
                "expected": rule.get("expected"),
                "observed": phase_obs,
                "result": phase_result,
            }
        )

    # webshell command-only
    rule = rules.get("webshell_command_only") or {}
    forbidden = gaps.get("webshell_forbidden_artifacts") or []
    if provider != "webshell":
        rows.append(
            {
                "gap_rule": "webshell_command_only",
                "expected": "n/a for local",
                "observed": "n/a (local provider)",
                "result": RESULT_SKIP,
            }
        )
    else:
        detected = bool(forbidden)
        rows.append(
            {
                "gap_rule": "webshell_command_only",
                "expected": "command-only; no runtime deploy",
                "observed": f"forbidden={forbidden}" if detected else "no forbidden artifacts",
                "result": rule.get("result_if_detected", RESULT_FAIL) if detected else RESULT_PASS,
            }
        )

    return rows


def compare(
    *,
    pcap: dict[str, Any],
    evidence: dict[str, Any],
    packet_rules: dict[str, Any],
    expected_profiles: dict[str, Any],
    gap_rules: dict[str, Any],
    run_info: dict[str, Any],
) -> dict[str, Any]:
    provider = str(run_info.get("provider") or evidence.get("provider") or "local")
    profile = str(run_info.get("profile") or evidence.get("profile") or "normal")
    profile_exp = _resolve_profile_expectations(expected_profiles, profile)
    scenario_rules = packet_rules.get("scenarios") or {}
    discovery = evidence.get("discovery") or {}

    # Determine scenario set: profile expectations ∩ evidence (plus evidence-only extras)
    expected_scenario_ids = list((profile_exp.get("scenarios") or {}).keys())
    evidence_ids = list(evidence.get("scenario_ids") or [])
    scenario_ids: list[str] = []
    for sid in expected_scenario_ids + evidence_ids:
        if sid not in scenario_ids:
            scenario_ids.append(sid)
    # Always include host_behavior / eicar rules if present in packet rules and evidence
    for sid in scenario_rules:
        if sid not in scenario_ids and sid in (evidence.get("scenarios") or {}):
            scenario_ids.append(sid)

    scenario_rows: list[dict[str, Any]] = []
    profile_rows: list[dict[str, Any]] = []
    discovery_rows: list[dict[str, Any]] = []
    origin_rows: list[dict[str, Any]] = []
    problems: list[dict[str, Any]] = []

    counts = {
        RESULT_PASS: 0,
        RESULT_FAIL: 0,
        RESULT_REVIEW: 0,
        RESULT_SKIP: 0,
        RESULT_HOST_ONLY_PASS: 0,
    }

    for sid in scenario_ids:
        rule = scenario_rules.get(sid) or {}
        exp = (profile_exp.get("scenarios") or {}).get(sid) or {}
        sc = (evidence.get("scenarios") or {}).get(sid) or {}
        pcap_required = bool(rule.get("pcap_required", exp.get("pcap_required", False)))
        evidence_only = bool(rule.get("evidence_only", False))
        evidence_required = bool(exp.get("evidence_required", True)) if exp else True

        ev_ok, ev_note = _evidence_present(sid, evidence, rule)
        pkt_ok, pkt_count, pkt_metric = _packet_matched(sid, pcap, rule)

        expected_count = sc.get("expected_count")
        for key in (
            "expected_requests",
            "expected_attempts",
            "expected_domains",
            "expected_total",
            "max_requests",
            "max_connects",
            "max_queries",
            "max_attempts",
            "min_commands",
        ):
            if expected_count is None and key in exp:
                expected_count = exp[key]
        observed_count = sc.get("actual_count")
        if sid == "http_followup" and evidence.get("http_followup_request_count"):
            observed_count = evidence.get("http_followup_request_count")
        if sid == "sql_injection" and evidence.get("sql_injection_request_count"):
            observed_count = evidence.get("sql_injection_request_count")

        result = RESULT_PASS
        notes: list[str] = []

        if _skip_allowed(sid, sc, profile_exp, discovery):
            result = RESULT_SKIP
            notes.append(ev_note)
        elif evidence_only or not pcap_required:
            if ev_ok and (sc.get("executed") or sc.get("event_count", 0) > 0 or sc.get("skipped")):
                if sc.get("skipped"):
                    result = RESULT_SKIP
                else:
                    result = RESULT_HOST_ONLY_PASS
                notes.append("evidence-only scenario")
            elif evidence_required:
                result = RESULT_FAIL
                notes.append("required evidence missing for host-only scenario")
            else:
                result = RESULT_REVIEW
                notes.append(ev_note)
        else:
            # Traffic scenario
            if sc.get("skipped") and not _skip_allowed(sid, sc, profile_exp, discovery):
                result = RESULT_REVIEW
                notes.append(f"skipped unexpectedly: {sc.get('skip_reason')}")
            elif not ev_ok and pkt_ok:
                result = RESULT_REVIEW
                notes.append("packet present but evidence missing/incomplete")
            elif ev_ok and not pkt_ok and not sc.get("skipped"):
                result = RESULT_FAIL
                notes.append("evidence present but required packets missing")
            elif not ev_ok and not pkt_ok:
                result = RESULT_FAIL
                notes.append("required evidence and packets missing")
            else:
                # both present (or skip handled)
                if not _count_within_tolerance(
                    int(expected_count) if expected_count is not None else None,
                    int(observed_count) if observed_count is not None else None,
                ):
                    result = RESULT_FAIL
                    notes.append(
                        f"count below tolerance expected={expected_count} observed={observed_count}"
                    )
                else:
                    result = RESULT_PASS
                    notes.append(ev_note)

        # Discovery / follow-up validation row
        disc_result, disc_note = _discovery_selection_ok(sid, sc, rule, discovery, profile_exp)
        if disc_result == RESULT_FAIL and result == RESULT_PASS:
            result = RESULT_FAIL
            notes.append(disc_note)
        elif disc_result == RESULT_REVIEW and result == RESULT_PASS:
            # keep PASS for scenario traffic but surface review in discovery table
            pass

        observed_dest = ",".join(str(t) for t in (sc.get("targets") or [])[:5]) or "-"
        discovery_rows.append(
            {
                "scenario": sid,
                "discovery_source": rule.get("discovery_source")
                or exp.get("selected_from")
                or "-",
                "selected_target": observed_dest,
                "observed_destination": observed_dest,
                "result": disc_result,
                "notes": disc_note,
            }
        )

        # Provider origin
        origin_result, origin_note = _provider_origin_ok(provider, list(sc.get("origins") or []))
        if sc.get("skipped") or result == RESULT_SKIP:
            origin_result = RESULT_SKIP
        origin_rows.append(
            {
                "provider": provider,
                "scenario": sid,
                "expected_origin": "remote_host" if provider == "webshell" else "dsp_host/local",
                "observed_source": ",".join(sc.get("origins") or []) or "-",
                "result": origin_result,
                "notes": origin_note,
            }
        )
        if origin_result == RESULT_FAIL and result not in {RESULT_FAIL, RESULT_SKIP}:
            result = RESULT_FAIL
            notes.append(origin_note)

        # Surface known SMB TCP-only gap on the scenario row itself.
        if sid == "smb_login_failure" and result not in {RESULT_FAIL, RESULT_SKIP}:
            gaps = evidence.get("gaps") or {}
            if gaps.get("smb_tcp_only") and not gaps.get("smb_auth_events_present"):
                result = RESULT_REVIEW
                notes.append("SMB TCP/445 connect only (no auth failure evidence)")

        scenario_rows.append(
            {
                "scenario": sid,
                "required": "pcap+evidence"
                if pcap_required
                else ("evidence_only" if evidence_only or not pcap_required else "optional"),
                "evidence": "yes" if ev_ok else "no",
                "packet": "yes" if pkt_ok else ("n/a" if not pcap_required else "no"),
                "expected": expected_count if expected_count is not None else "-",
                "observed": observed_count if observed_count is not None else pkt_count,
                "result": result,
                "notes": "; ".join(notes) if notes else "",
                "packet_metric": pkt_metric,
                "packet_count": pkt_count,
            }
        )

        profile_rows.append(
            {
                "profile": profile,
                "scenario": sid,
                "expected": expected_count if expected_count is not None else exp,
                "actual": observed_count if observed_count is not None else "-",
                "result": result,
            }
        )

        counts[result] = counts.get(result, 0) + 1
        if result == RESULT_FAIL:
            problem_detail = notes[0] if notes else "failed"
            problems.append(
                {
                    "problem": "%s: %s" % (sid, problem_detail),
                    "impact": "traffic/evidence regression",
                    "required_fix": "inspect DSP evidence and pcap for this scenario",
                }
            )

    gap_rows = evaluate_regression_gaps(
        evidence,
        gap_rules,
        provider=provider,
        target_net_arg=run_info.get("target_net"),
    )
    for row in gap_rows:
        gres = row["result"]
        counts[gres] = counts.get(gres, 0) + 1
        if gres == RESULT_FAIL:
            problems.append(
                {
                    "problem": f"gap:{row['gap_rule']}: {row['observed']}",
                    "impact": "critical regression gap",
                    "required_fix": str(row.get("expected") or "align with charter/WBS"),
                }
            )

    # Overall: FAIL if any FAIL; else PASS (REVIEW/SKIP/HOST_ONLY_PASS do not fail exit)
    overall = RESULT_FAIL if counts.get(RESULT_FAIL, 0) > 0 else RESULT_PASS

    # Evidence file table
    evidence_files = []
    for name, meta in (evidence.get("files") or {}).items():
        evidence_files.append(
            {
                "evidence_file": name,
                "status": meta.get("status"),
                "notes": f"bytes={meta.get('bytes', 0)}",
            }
        )
    for note in evidence.get("notes") or []:
        if "scenario_plan.json" in note:
            for row in evidence_files:
                if row["evidence_file"] == "scenario_plan.json":
                    row["notes"] = note

    # Pcap summary table rows
    pcap_table = [
        ("total_packets", pcap.get("total_packets")),
        ("tcp_packets", pcap.get("tcp_packets")),
        ("udp_packets", pcap.get("udp_packets")),
        ("icmp_packets", pcap.get("icmp_packets")),
        ("http_requests", pcap.get("http_requests")),
        ("dns_queries", pcap.get("dns_queries")),
        ("udp_53", pcap.get("udp_53_packets")),
        ("tcp_22", pcap.get("tcp_22_packets")),
        ("tcp_80", pcap.get("tcp_80_packets")),
        ("tcp_8080", pcap.get("tcp_8080_packets")),
        ("tcp_389/636", pcap.get("tcp_389_packets")),
        ("tcp_445", pcap.get("tcp_445_packets")),
        ("tcp_88", pcap.get("tcp_88_packets")),
        ("udp_88", pcap.get("udp_88_packets")),
    ]

    return {
        "run_info": run_info,
        "overall_result": overall,
        "counts": counts,
        "scenario_results": scenario_rows,
        "profile_validation": profile_rows,
        "discovery_validation": discovery_rows,
        "provider_origin_validation": origin_rows,
        "regression_gap_validation": gap_rows,
        "pcap_summary_table": pcap_table,
        "evidence_summary_table": evidence_files,
        "problems": problems,
        "pcap_mode": pcap.get("mode"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def render_markdown(report: dict[str, Any]) -> str:
    info = report.get("run_info") or {}
    counts = report.get("counts") or {}
    lines: list[str] = []
    lines.append("# DSP Traffic Regression E2E Report")
    lines.append("")
    lines.append("## Run Info")
    lines.append("")
    for key, label in (
        ("provider", "provider"),
        ("profile", "profile"),
        ("target_net", "target network"),
        ("interface", "interface"),
        ("webshell_type", "webshell type"),
        ("webshell_url", "webshell url"),
        ("dsp_command", "dsp command"),
        ("started_at", "started_at"),
        ("ended_at", "ended_at"),
        ("output_dir", "output dir"),
    ):
        lines.append(f"* {label}: {info.get(key, '-')}")
    lines.append("")
    lines.append("## Overall Result")
    lines.append("")
    for key in (RESULT_PASS, RESULT_FAIL, RESULT_REVIEW, RESULT_SKIP, RESULT_HOST_ONLY_PASS):
        lines.append(f"* {key}: {counts.get(key, 0)}")
    lines.append("")
    lines.append("## Scenario Results")
    lines.append("")
    lines.append("| Scenario | Required | Evidence | Packet | Expected | Observed | Result | Notes |")
    lines.append("| -------- | -------- | -------- | ------ | -------: | -------: | ------ | ----- |")
    for row in report.get("scenario_results") or []:
        lines.append(
            f"| {row.get('scenario')} | {row.get('required')} | {row.get('evidence')} | "
            f"{row.get('packet')} | {row.get('expected')} | {row.get('observed')} | "
            f"{row.get('result')} | {row.get('notes')} |"
        )
    lines.append("")
    lines.append("## Profile Validation")
    lines.append("")
    lines.append("| Profile | Scenario | Expected | Actual | Result |")
    lines.append("| ------- | -------- | -------: | -----: | ------ |")
    for row in report.get("profile_validation") or []:
        exp = row.get("expected")
        if isinstance(exp, dict):
            exp = json.dumps(exp, ensure_ascii=False)
        lines.append(
            f"| {row.get('profile')} | {row.get('scenario')} | {exp} | {row.get('actual')} | {row.get('result')} |"
        )
    lines.append("")
    lines.append("## Discovery / Follow-up Validation")
    lines.append("")
    lines.append("| Scenario | Discovery Source | Selected Target | Observed Destination | Result |")
    lines.append("| -------- | ---------------- | --------------- | -------------------- | ------ |")
    for row in report.get("discovery_validation") or []:
        lines.append(
            f"| {row.get('scenario')} | {row.get('discovery_source')} | {row.get('selected_target')} | "
            f"{row.get('observed_destination')} | {row.get('result')} |"
        )
    lines.append("")
    lines.append("## Provider Origin Validation")
    lines.append("")
    lines.append("| Provider | Expected Origin | Observed Source | Result |")
    lines.append("| -------- | --------------- | --------------- | ------ |")
    # Collapse per-scenario into unique provider rows + keep detail via first FAIL/REVIEW
    seen = set()
    for row in report.get("provider_origin_validation") or []:
        key = (row.get("provider"), row.get("scenario"))
        if key in seen:
            continue
        seen.add(key)
        lines.append(
            f"| {row.get('provider')} ({row.get('scenario')}) | {row.get('expected_origin')} | "
            f"{row.get('observed_source')} | {row.get('result')} |"
        )
    lines.append("")
    lines.append("## Regression Gap Validation")
    lines.append("")
    lines.append("| Gap Rule | Expected | Observed | Result |")
    lines.append("| -------- | -------- | -------- | ------ |")
    for row in report.get("regression_gap_validation") or []:
        lines.append(
            f"| {row.get('gap_rule')} | {row.get('expected')} | {row.get('observed')} | {row.get('result')} |"
        )
    lines.append("")
    lines.append("## Pcap Summary")
    lines.append("")
    lines.append("| Protocol / Port | Count |")
    lines.append("| --------------- | ----: |")
    for name, count in report.get("pcap_summary_table") or []:
        lines.append(f"| {name} | {count} |")
    lines.append("")
    lines.append(f"_pcap analysis mode: {report.get('pcap_mode')}_")
    lines.append("")
    lines.append("## Evidence Summary")
    lines.append("")
    lines.append("| Evidence File | Status | Notes |")
    lines.append("| ------------- | ------ | ----- |")
    for row in report.get("evidence_summary_table") or []:
        lines.append(
            f"| {row.get('evidence_file')} | {row.get('status')} | {row.get('notes')} |"
        )
    lines.append("")
    lines.append("## Problems")
    lines.append("")
    lines.append("| Problem | Impact | Required Fix |")
    lines.append("| ------- | ------ | ------------ |")
    problems = report.get("problems") or []
    if not problems:
        lines.append("| (none) | - | - |")
    else:
        for row in problems:
            lines.append(
                f"| {row.get('problem')} | {row.get('impact')} | {row.get('required_fix')} |"
            )
    lines.append("")
    lines.append("## Final Result")
    lines.append("")
    lines.append(str(report.get("overall_result")))
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("이 E2E 테스트는 Stellar 테스트 전에 실행하는 DSP traffic regression 검증이다.")
    lines.append("")
    lines.append("이 테스트는 Stellar alert/case를 확인하지 않는다.")
    lines.append("")
    lines.append("이 테스트는 탐지 성공 여부를 판단하지 않는다.")
    lines.append("")
    lines.append("이 테스트는 DSP evidence와 실제 packet이 일치하는지만 확인한다.")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare DSP evidence vs pcap for E2E traffic regression")
    parser.add_argument("--pcap-summary", required=True)
    parser.add_argument("--evidence-summary", required=True)
    parser.add_argument("--scenario-rules", required=True)
    parser.add_argument("--expected-profiles", required=True)
    parser.add_argument("--gap-rules", required=True)
    parser.add_argument("--run-info", required=True, help="JSON file with run metadata")
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--output-md", required=True)
    args = parser.parse_args(argv)

    pcap = _load_json(Path(args.pcap_summary))
    evidence = _load_json(Path(args.evidence_summary))
    packet_rules = _load_yaml(Path(args.scenario_rules))
    expected_profiles = _load_yaml(Path(args.expected_profiles))
    gap_rules = _load_yaml(Path(args.gap_rules))
    run_info = _load_json(Path(args.run_info))

    report = compare(
        pcap=pcap,
        evidence=evidence,
        packet_rules=packet_rules,
        expected_profiles=expected_profiles,
        gap_rules=gap_rules,
        run_info=run_info,
    )

    out_json = Path(args.output_json)
    out_md = Path(args.output_md)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    out_md.write_text(render_markdown(report), encoding="utf-8")

    overall = report.get("overall_result")
    print(f"Wrote {out_md}")
    print(f"Wrote {out_json}")
    print(f"OVERALL={overall}")
    return 0 if overall == RESULT_PASS else 1


if __name__ == "__main__":
    sys.exit(main())
