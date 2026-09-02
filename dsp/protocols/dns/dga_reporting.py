"""DGA reporting profile templates and report section builders."""

from __future__ import annotations

from typing import Any

from dsp.event_store import ValidationResult
from dsp.protocols.dns.dga_validation import DGA_METRIC_NAMES


def dga_report_profile(**overrides: Any) -> dict[str, Any]:
    """Standard DGA report_profile block for manifest.yaml."""
    profile: dict[str, Any] = {
        "profile_version": "1.0.0",
        "protocol": "dga",
        "highlight_metrics": list(DGA_METRIC_NAMES),
        "sample_events": 5,
        "sample_filter": {"event": "dga_domain_generated"},
    }
    profile.update(overrides)
    return profile


def build_dga_report_section(
    result: ValidationResult,
    event_samples: list[dict[str, Any]] | None = None,
    summary: dict[str, Any] | None = None,
) -> list[str]:
    """Build supplementary DGA section for report.md."""
    summary = summary or {}
    lines = [
        f"### DGA — {result.scenario_id}",
        "",
        "| Metric | Value | Store Source |",
        "|--------|-------|--------------|",
    ]
    trace_map = {
        "dga_domain_generated_count": "event=dga_domain_generated, status=info",
        "dga_query_dispatched_count": "event=dns_query_sent, status=sent",
        "dga_nxdomain_observed_count": "event=dga_nxdomain_observed, status=nxdomain",
        "dga_resolved_observed_count": "event=dga_resolved_observed, status=response",
    }
    for name in DGA_METRIC_NAMES:
        value = result.metrics.get(name, 0)
        source = trace_map.get(name, "—")
        lines.append(f"| {name} | {value} | {source} |")

    effective_tld = summary.get("effective_tld", "xdr.ooo")
    sample_domains = summary.get("sample_domains", [])
    domains_generated = summary.get("domains_generated") or summary.get("generated_domains")
    dispatched = summary.get("dispatched_queries")

    lines.extend(["", "**DGA Summary**", ""])
    lines.append(f"- **Effective TLD:** {effective_tld}")
    if domains_generated is not None:
        lines.append(f"- **Generated domains:** {domains_generated}")
    if dispatched is not None:
        lines.append(f"- **Dispatched queries:** {dispatched}")
    lines.append(
        f"- **NXDOMAIN observed:** {result.metrics.get('dga_nxdomain_observed_count', summary.get('observed_nxdomain', 0))}"
    )
    lines.append(
        f"- **Resolved observed:** {result.metrics.get('dga_resolved_observed_count', summary.get('observed_resolved', 0))}"
    )
    if sample_domains:
        lines.append(f"- **Sample domains:** {', '.join(sample_domains[:5])}")

    lines.extend(
        [
            "",
            f"**Decision:** {result.decision.value} ({result.reason})",
            "",
        ]
    )

    if event_samples:
        lines.append(f"**Sample events:** {len(event_samples)} excerpt(s) from Event Store")
        lines.append("")

    return lines
