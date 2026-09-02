"""Reporting Engine — ValidationResult primary, Event Store samples."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dsp import REPORT_FORMAT_VERSION
from dsp.event_store import EventStore, Run, ValidationResult
from dsp.plugins.registry import PluginRegistry


@dataclass
class Report:
    run_id: str
    report_format_version: str = REPORT_FORMAT_VERSION
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    path: str = "report.md"
    traffic_validation: list[ValidationResult] = field(default_factory=list)
    detection_confirmation: list[Any] | None = None
    event_samples: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    run_metadata: dict[str, Any] = field(default_factory=dict)
    summaries: dict[str, dict[str, Any]] = field(default_factory=dict)
    discovery: dict[str, Any] = field(default_factory=dict)
    traffic_summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "report_format_version": self.report_format_version,
            "generated_at": self.generated_at.isoformat().replace("+00:00", "Z"),
            "path": self.path,
            "traffic_validation": [r.to_dict() for r in self.traffic_validation],
            "detection_confirmation": self.detection_confirmation,
            "event_samples": self.event_samples,
            "run_metadata": self.run_metadata,
            "summaries": self.summaries,
            "discovery": self.discovery,
            "traffic_summary": self.traffic_summary,
        }


class ReportingEngine:
    """Build reports from ValidationResult[] + Event Store samples only."""

    def __init__(self, store: EventStore, registry: PluginRegistry | None = None) -> None:
        self.store = store
        self.registry = registry

    def generate(
        self,
        run_id: str,
        results: list[ValidationResult],
        run: Run | None = None,
        summaries: dict[str, dict[str, Any]] | None = None,
        discovery: dict[str, Any] | None = None,
        traffic_summary: dict[str, Any] | None = None,
    ) -> Report:
        event_samples: dict[str, list[dict[str, Any]]] = {}
        for result in results:
            record = self.registry.get(result.scenario_id) if self.registry else None
            sample_limit = 5
            sample_filter = None
            if record:
                rp = record.manifest.report_profile
                sample_limit = int(rp.get("sample_events", 5))
                sample_filter = rp.get("sample_filter")

            samples = self.store.sample(
                run_id,
                result.scenario_id,
                limit=min(sample_limit, 20),
                event_filter=sample_filter,
            )
            event_samples[result.scenario_id] = [
                {
                    "event": s.event,
                    "status": s.status,
                    "artifact": s.artifact,
                    "timestamp": s.timestamp.isoformat().replace("+00:00", "Z"),
                }
                for s in samples
            ]

        run_metadata = run.to_dict() if run else {"run_id": run_id}
        traffic = dict(traffic_summary or {})
        discovery_payload = dict(discovery or traffic.get("discovery") or {})

        return Report(
            run_id=run_id,
            traffic_validation=results,
            event_samples=event_samples,
            run_metadata=run_metadata,
            summaries=summaries or {},
            discovery=discovery_payload,
            traffic_summary=traffic,
        )

    def write_report_md(
        self,
        path: Path,
        report: Report,
        summaries: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        lines: list[str] = [
            "# DSP Run Report",
            "",
            f"**Run ID:** {report.run_id}",
            f"**Report Format:** {report.report_format_version}",
            f"**Generated:** {report.generated_at.isoformat().replace('+00:00', 'Z')}",
            "",
            "## Run Metadata",
            "",
            "```json",
            json.dumps(report.run_metadata, indent=2),
            "```",
            "",
        ]

        from dsp.runtime.discovery_report import format_discovery_report_lines

        discovery_lines = format_discovery_report_lines(report.discovery or {})
        if discovery_lines:
            lines.extend(discovery_lines)

        lines.extend(
            [
            "## Traffic Validation (Primary Table)",
            "",
            "| Scenario | Decision | Reason | Metrics |",
            "|----------|----------|--------|---------|",
        ]
        )

        for result in report.traffic_validation:
            metrics_str = json.dumps(result.metrics)
            lines.append(
                f"| {result.scenario_id} | {result.decision.value} | "
                f"{result.reason} | {metrics_str} |"
            )

        lines.extend(["", "## Event Samples", ""])
        for scenario_id, samples in report.event_samples.items():
            lines.append(f"### {scenario_id}")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(samples, indent=2))
            lines.append("```")
            lines.append("")

        if report.summaries:
            lines.extend(["## Scenario Summaries (Supplementary)", ""])
            lines.append("```json")
            lines.append(json.dumps(report.summaries, indent=2))
            lines.append("```")
            lines.append("")

        dns_sections = self._build_dns_protocol_sections(report)
        if dns_sections:
            lines.extend(["## DNS Protocol Details", ""])
            lines.extend(dns_sections)

        tunnel_sections = self._build_dns_tunnel_sections(report, summaries or report.summaries)
        if tunnel_sections:
            lines.extend(["## DNS Tunnel Details", ""])
            lines.extend(tunnel_sections)

        dga_sections = self._build_dga_sections(report)
        if dga_sections:
            lines.extend(["## DGA Details", ""])
            lines.extend(dga_sections)

        http_sections = self._build_http_followup_sections(report)
        if http_sections:
            lines.extend(["## HTTP Follow-up Details", ""])
            lines.extend(http_sections)

        ssh_sections = self._build_ssh_failure_sections(report)
        if ssh_sections:
            lines.extend(["## SSH Login Failure Details", ""])
            lines.extend(ssh_sections)

        smb_sections = self._build_smb_login_failure_sections(report)
        if smb_sections:
            lines.extend(["## SMB Login Failure Details", ""])
            lines.extend(smb_sections)

        port_sweep_sections = self._build_port_sweep_sections(report)
        if port_sweep_sections:
            lines.extend(["## Port Sweep Details", ""])
            lines.extend(port_sweep_sections)

        ldap_sections = self._build_ldap_enumeration_sections(report)
        if ldap_sections:
            lines.extend(["## LDAP Enumeration Details", ""])
            lines.extend(ldap_sections)

        kerberos_sections = self._build_kerberos_failure_sections(report)
        if kerberos_sections:
            lines.extend(["## Kerberos Failure Details", ""])
            lines.extend(kerberos_sections)

        sqli_sections = self._build_sql_injection_sections(report)
        if sqli_sections:
            lines.extend(["## SQL Injection Details", ""])
            lines.extend(sqli_sections)

        detection_sections = self._build_detection_confirmation_sections(report)
        if detection_sections:
            lines.extend(detection_sections)

        lines.extend(
            [
                "## Embedded Validation JSON",
                "",
                "```json",
                json.dumps(
                    [r.to_dict() for r in report.traffic_validation],
                    indent=2,
                ),
                "```",
                "",
            ]
        )

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines), encoding="utf-8")
        report.path = str(path)

    def write_report_json(self, path: Path, report: Report) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")

    def _build_detection_confirmation_sections(self, report: Report) -> list[str]:
        """Optional S3 appendix — does not alter the S2 primary table."""
        if not report.detection_confirmation:
            return []

        lines = [
            "## Detection Confirmation",
            "",
            "_Optional S3 evidence — does not affect S2 pass/fail._",
            "",
            "| Scenario | Provider | S3 Status | Evidence Count | Evidence Path |",
            "|----------|----------|-----------|----------------|---------------|",
        ]
        for entry in report.detection_confirmation:
            lines.append(
                f"| {entry.get('scenario_id', '')} | {entry.get('provider', '')} | "
                f"{entry.get('status', '')} | {entry.get('evidence_count', 0)} | "
                f"{entry.get('evidence_path', '')} |"
            )

        lines.extend(["", "```json", json.dumps(report.detection_confirmation, indent=2), "```", ""])
        return lines

    def build_primary_table_rows(self, results: list[ValidationResult]) -> list[dict[str, Any]]:
        """Primary table sourced exclusively from ValidationResult."""
        return [
            {
                "scenario_id": r.scenario_id,
                "decision": r.decision.value,
                "reason": r.reason,
                "metrics": dict(r.metrics),
            }
            for r in results
        ]

    def _build_dns_protocol_sections(self, report: Report) -> list[str]:
        """Append DNS protocol section when manifest report_profile.protocol == dns."""
        if not self.registry:
            return []
        from dsp.protocols.dns.reporting import build_dns_report_section

        lines: list[str] = []
        for result in report.traffic_validation:
            record = self.registry.get(result.scenario_id)
            if not record:
                continue
            rp = record.manifest.report_profile
            if rp.get("protocol") != "dns":
                continue
            samples = report.event_samples.get(result.scenario_id)
            lines.extend(build_dns_report_section(result, samples))
        return lines

    def _build_dns_tunnel_sections(
        self,
        report: Report,
        summaries: dict[str, dict[str, Any]] | None,
    ) -> list[str]:
        """Append DNS Tunnel section when manifest report_profile.protocol == dns_tunnel."""
        if not self.registry:
            return []
        from dsp.protocols.dns.tunnel_reporting import build_dns_tunnel_report_section

        lines: list[str] = []
        for result in report.traffic_validation:
            record = self.registry.get(result.scenario_id)
            if not record:
                continue
            rp = record.manifest.report_profile
            if rp.get("protocol") != "dns_tunnel":
                continue
            samples = report.event_samples.get(result.scenario_id)
            tunnel_summary = self._tunnel_summary_from_store(result.run_id, result.scenario_id)
            if summaries and result.scenario_id in summaries:
                notes = summaries[result.scenario_id].get("notes", [])
                for note in notes:
                    if note.startswith("duration_sec="):
                        tunnel_summary.setdefault(
                            "duration_sec",
                            note.split("=", 1)[1],
                        )
                    elif note.startswith("targets="):
                        raw = note.split("=", 1)[1]
                        if raw:
                            tunnel_summary.setdefault("targets", raw.split(","))
                    elif note.startswith("sample_fqdns="):
                        raw = note.split("=", 1)[1]
                        if raw:
                            tunnel_summary.setdefault("sample_fqdns", raw.split(","))
            lines.extend(
                build_dns_tunnel_report_section(result, samples, tunnel_summary)
            )
        return lines

    def _tunnel_summary_from_store(self, run_id: str, scenario_id: str) -> dict[str, Any]:
        for ev in self.store.list_events(run_id, scenario_id):
            if ev.event == "dns_tunnel_completed":
                return dict(ev.evidence)
        return {}

    def _build_dga_sections(self, report: Report) -> list[str]:
        """Append DGA section when manifest report_profile.protocol == dga."""
        if not self.registry:
            return []
        from dsp.protocols.dns.dga_reporting import build_dga_report_section

        lines: list[str] = []
        for result in report.traffic_validation:
            record = self.registry.get(result.scenario_id)
            if not record:
                continue
            rp = record.manifest.report_profile
            if rp.get("protocol") != "dga":
                continue
            samples = report.event_samples.get(result.scenario_id)
            dga_summary = self._dga_summary_from_store(result.run_id, result.scenario_id)
            lines.extend(build_dga_report_section(result, samples, dga_summary))
        return lines

    def _dga_summary_from_store(self, run_id: str, scenario_id: str) -> dict[str, Any]:
        for ev in self.store.list_events(run_id, scenario_id):
            if ev.event == "dga_completed":
                return dict(ev.evidence)
        return {}

    def _build_http_followup_sections(self, report: Report) -> list[str]:
        """Append HTTP Follow-up section when report_profile.protocol == http_followup."""
        if not self.registry:
            return []
        from dsp.protocols.http.reporting import build_http_followup_report_section

        lines: list[str] = []
        for result in report.traffic_validation:
            record = self.registry.get(result.scenario_id)
            if not record:
                continue
            rp = record.manifest.report_profile
            if rp.get("protocol") != "http_followup":
                continue
            samples = report.event_samples.get(result.scenario_id)
            summary = self._http_followup_summary_from_store(result.run_id, result.scenario_id)
            lines.extend(build_http_followup_report_section(result, samples, summary))
        return lines

    def _http_followup_summary_from_store(self, run_id: str, scenario_id: str) -> dict[str, Any]:
        for ev in self.store.list_events(run_id, scenario_id):
            if ev.event == "http_followup_completed":
                return dict(ev.evidence)
        return {}

    def _build_ssh_failure_sections(self, report: Report) -> list[str]:
        """Append SSH Login Failure section when report_profile.protocol == ssh_failure."""
        if not self.registry:
            return []
        from dsp.protocols.ssh.reporting import build_ssh_failure_report_section

        lines: list[str] = []
        for result in report.traffic_validation:
            record = self.registry.get(result.scenario_id)
            if not record:
                continue
            rp = record.manifest.report_profile
            if rp.get("protocol") != "ssh_failure":
                continue
            samples = report.event_samples.get(result.scenario_id)
            summary = self._ssh_failure_summary_from_store(result.run_id, result.scenario_id)
            lines.extend(build_ssh_failure_report_section(result, samples, summary))
        return lines

    def _ssh_failure_summary_from_store(self, run_id: str, scenario_id: str) -> dict[str, Any]:
        for ev in self.store.list_events(run_id, scenario_id):
            if ev.event == "ssh_failure_completed":
                return dict(ev.evidence)
        return {}

    def _build_smb_login_failure_sections(self, report: Report) -> list[str]:
        """Append SMB Login Failure section when report_profile.protocol == smb_login_failure."""
        if not self.registry:
            return []
        from dsp.protocols.smb.smb_reporting import build_smb_login_failure_report_section

        lines: list[str] = []
        for result in report.traffic_validation:
            record = self.registry.get(result.scenario_id)
            if not record:
                continue
            rp = record.manifest.report_profile
            if rp.get("protocol") != "smb_login_failure":
                continue
            samples = report.event_samples.get(result.scenario_id)
            summary = self._smb_login_failure_summary_from_store(result.run_id, result.scenario_id)
            lines.extend(build_smb_login_failure_report_section(result, samples, summary))
        return lines

    def _smb_login_failure_summary_from_store(self, run_id: str, scenario_id: str) -> dict[str, Any]:
        for ev in self.store.list_events(run_id, scenario_id):
            if ev.event == "smb_scenario_completed":
                return dict(ev.evidence)
        return {}

    def _build_port_sweep_sections(self, report: Report) -> list[str]:
        """Append Port Sweep section when report_profile.protocol == port_sweep."""
        if not self.registry:
            return []
        from dsp.protocols.recon.port_sweep_reporting import build_port_sweep_report_section

        lines: list[str] = []
        for result in report.traffic_validation:
            record = self.registry.get(result.scenario_id)
            if not record:
                continue
            rp = record.manifest.report_profile
            if rp.get("protocol") != "port_sweep":
                continue
            samples = report.event_samples.get(result.scenario_id)
            summary = self._port_sweep_summary_from_store(result.run_id, result.scenario_id)
            lines.extend(build_port_sweep_report_section(result, samples, summary))
        return lines

    def _port_sweep_summary_from_store(self, run_id: str, scenario_id: str) -> dict[str, Any]:
        for ev in self.store.list_events(run_id, scenario_id):
            if ev.event == "port_sweep_completed":
                return dict(ev.evidence)
        return {}

    def _build_ldap_enumeration_sections(self, report: Report) -> list[str]:
        """Append LDAP Enumeration section when report_profile.protocol == ldap_enumeration."""
        if not self.registry:
            return []
        from dsp.protocols.ldap.ldap_reporting import build_ldap_enumeration_report_section

        lines: list[str] = []
        for result in report.traffic_validation:
            record = self.registry.get(result.scenario_id)
            if not record:
                continue
            rp = record.manifest.report_profile
            if rp.get("protocol") != "ldap_enumeration":
                continue
            samples = report.event_samples.get(result.scenario_id)
            summary = self._ldap_enumeration_summary_from_store(result.run_id, result.scenario_id)
            lines.extend(build_ldap_enumeration_report_section(result, samples, summary))
        return lines

    def _ldap_enumeration_summary_from_store(self, run_id: str, scenario_id: str) -> dict[str, Any]:
        for ev in self.store.list_events(run_id, scenario_id):
            if ev.event == "ldap_enum_completed":
                return dict(ev.evidence)
        return {}

    def _build_kerberos_failure_sections(self, report: Report) -> list[str]:
        """Append Kerberos Failure section when report_profile.protocol == kerberos_failure."""
        if not self.registry:
            return []
        from dsp.protocols.kerberos.kerberos_reporting import build_kerberos_failure_report_section

        lines: list[str] = []
        for result in report.traffic_validation:
            record = self.registry.get(result.scenario_id)
            if not record:
                continue
            rp = record.manifest.report_profile
            if rp.get("protocol") != "kerberos_failure":
                continue
            samples = report.event_samples.get(result.scenario_id)
            summary = self._kerberos_failure_summary_from_store(result.run_id, result.scenario_id)
            lines.extend(build_kerberos_failure_report_section(result, samples, summary))
        return lines

    def _kerberos_failure_summary_from_store(self, run_id: str, scenario_id: str) -> dict[str, Any]:
        for ev in self.store.list_events(run_id, scenario_id):
            if ev.event == "kerberos_scenario_completed":
                return dict(ev.evidence)
        return {}

    def _build_sql_injection_sections(self, report: Report) -> list[str]:
        """Append SQL Injection section when report_profile.protocol == sql_injection."""
        if not self.registry:
            return []
        from dsp.protocols.http.sqli_reporting import build_sql_injection_report_section

        lines: list[str] = []
        for result in report.traffic_validation:
            record = self.registry.get(result.scenario_id)
            if not record:
                continue
            rp = record.manifest.report_profile
            if rp.get("protocol") != "sql_injection":
                continue
            samples = report.event_samples.get(result.scenario_id)
            summary = self._sql_injection_summary_from_store(result.run_id, result.scenario_id)
            lines.extend(build_sql_injection_report_section(result, samples, summary))
        return lines

    def _sql_injection_summary_from_store(self, run_id: str, scenario_id: str) -> dict[str, Any]:
        for ev in self.store.list_events(run_id, scenario_id):
            if ev.event == "sql_injection_completed":
                return dict(ev.evidence)
        return {}
