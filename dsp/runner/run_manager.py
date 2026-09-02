"""Run lifecycle and artifact management."""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dsp import __version__ as DSP_VERSION
from dsp.detection.factory import (
    UnsupportedDetectionProviderError,
    UnsupportedStellarClientModeError,
    create_detection_adapter,
)
from dsp.detection.manager import DetectionManager
from dsp.detection.reporting import build_detection_confirmation_entries
from dsp.engine import RunConfig, RunContext, resolve_targets
from dsp.engine.host_selection import (
    cache_http_endpoint_selection,
    http_target_probe_payload,
    print_http_endpoint_probe_diagnostics,
)
from dsp.runtime.scenario_plan import apply_webshell_initial_compromise_plan
from dsp.evidence import EvidenceExportRequest, EvidenceExporter
from dsp.execution import ExecutionContext, create_execution_provider
from dsp.execution.remote import RemoteEventCollectionRequest, RemoteEventCollector
from dsp.execution.remote.command.models import REMOTE_EXECUTION_MODE_COMMAND
from dsp.execution.remote.paths import resolve_remote_bundle_path
from dsp.execution.webshell_provider import WebshellExecutionProvider
from dsp.event_store import EventQuery, EventStore, Run, RunStatus, ValidationDecision
from dsp.manual_verification import (
    ManualVerificationPackageGenerator,
    ManualVerificationRequest,
)
from dsp.plugins import PluginLoader, PluginStatus
from dsp.reporting import ReportingEngine
from dsp.runner.progress_emitter import ProgressEmitter
from dsp.validation.skip_reasons import extract_skip_reason
from dsp.runner.target_selection import (
    resolve_selected_targets_by_protocol,
    scenario_start_metadata,
)
from dsp.validation import ValidationEngine

SUPPORTED_EXECUTION_PROVIDERS = frozenset({"local", "webshell"})
SUPPORTED_WEBSHELL_FAMILIES = frozenset({"jsp", "php", "aspx"})
DEFAULT_REMOTE_WORK_DIR = "/tmp/dsp"


def _latest_skip_evidence(
    store: EventStore,
    run_id: str,
    scenario_id: str,
) -> dict[str, Any]:
    skip_names = (
        f"{scenario_id}_skipped",
        "http_followup_skipped",
        "sql_injection_skipped",
        "smb_scenario_skipped",
        "ssh_failure_skipped",
        "kerberos_failure_skipped",
        "ldap_enumeration_skipped",
        "dns_tunnel_skipped",
        "dga_skipped",
        "scenario_skipped",
    )
    for event in reversed(store.list_events(run_id)):
        if event.scenario_id != scenario_id:
            continue
        if event.event in skip_names:
            return dict(event.evidence or {})
    return {}


def _scenario_executor_skipped(store: EventStore, run_id: str, scenario_id: str) -> bool:
    skip_names = (
        f"{scenario_id}_skipped",
        "http_followup_skipped",
        "sql_injection_skipped",
        "smb_scenario_skipped",
        "ssh_failure_skipped",
        "kerberos_failure_skipped",
        "ldap_enumeration_skipped",
        "dns_tunnel_skipped",
        "dga_skipped",
        "scenario_skipped",
    )
    for event_name in skip_names:
        if store.count(
            EventQuery(run_id=run_id, scenario_id=scenario_id, event=event_name)
        ) > 0:
            return True
    return False


def _latest_completed_evidence(
    store: EventStore,
    run_id: str,
    scenario_id: str,
) -> dict[str, Any]:
    for event in reversed(store.list_events(run_id)):
        if event.scenario_id == scenario_id and str(event.event).endswith("_completed"):
            return dict(event.evidence or {})
    return {}


def _scenario_completion_extras(scenario_id: str, evidence: dict[str, Any]) -> dict[str, Any]:
    extras: dict[str, Any] = {}
    if scenario_id == "http_followup":
        dump_summary = evidence.get("request_dump_summary") or {}
        extras["unique_paths"] = dump_summary.get("unique_paths")
        extras["unique_user_agents"] = dump_summary.get("unique_user_agents")
        extras["malicious_rare_ua_count"] = evidence.get("malicious_rare_ua_count")
        extras["abnormal_user_agents"] = evidence.get("abnormal_user_agents")
        extras["normal_user_agents"] = evidence.get("normal_user_agents")
        extras["abnormal_user_agent_ratio"] = evidence.get("abnormal_user_agent_ratio")
        extras["payload_only_ua"] = evidence.get("payload_only_ua")
        extras["target_count"] = evidence.get("target_count")
        extras["target_distribution"] = evidence.get("target_distribution")
        extras["requests_per_second"] = evidence.get("requests_per_second")
        extras["duration_sec"] = evidence.get("duration_sec")
        extras["concurrency"] = evidence.get("concurrency")
        extras["selected_http_target_reason"] = evidence.get("selected_http_target_reason")
        extras["response_code_distribution"] = evidence.get("response_code_distribution")
        extras["redirect_only_warning"] = evidence.get("redirect_only_warning")
    elif scenario_id == "port_sweep":
        extras["duration_sec"] = evidence.get("duration_sec")
        extras["probes_per_second"] = evidence.get("probes_per_second")
        extras["concurrency"] = evidence.get("concurrency")
    return {k: v for k, v in extras.items() if v is not None}


def _scenario_artifact_paths(scenario_id: str, run_dir: Path) -> dict[str, str]:
    artifacts: dict[str, str] = {}
    if scenario_id == "http_followup":
        artifacts["evidence_file"] = str(run_dir / "http_followup_requests.jsonl")
        artifacts["sample_dump"] = str(run_dir / "http_request_dump.json")
    elif scenario_id == "sql_injection":
        artifacts["evidence_file"] = str(run_dir / "sql_injection_requests.jsonl")
    return artifacts


def _write_sql_injection_artifacts(run_dir: Path, evidence: dict[str, Any]) -> None:
    request_evidence = evidence.get("sql_injection_request_evidence")
    if request_evidence:
        evidence_lines = "".join(
            json.dumps(record, ensure_ascii=False) + "\n"
            for record in request_evidence
        )
        (run_dir / "sql_injection_requests.jsonl").write_text(
            evidence_lines,
            encoding="utf-8",
        )


def _write_http_followup_artifacts(run_dir: Path, evidence: dict[str, Any]) -> None:
    request_evidence = evidence.get("request_evidence")
    if request_evidence:
        evidence_lines = "".join(
            json.dumps(record, ensure_ascii=False) + "\n"
            for record in request_evidence
        )
        (run_dir / "http_followup_requests.jsonl").write_text(
            evidence_lines,
            encoding="utf-8",
        )
    dump = evidence.get("request_dump")
    if dump:
        (run_dir / "http_request_dump.json").write_text(
            json.dumps(
                {
                    "sample_count": len(dump),
                    "summary": evidence.get("request_dump_summary", {}),
                    "samples": dump,
                },
                indent=2,
            ),
            encoding="utf-8",
        )


def default_runs_dir() -> Path:
    override = os.environ.get("DSP_RUNS_DIR")
    if override:
        return Path(override)
    return Path.home() / ".dsp" / "runs"


def generate_run_id() -> str:
    date = datetime.now(timezone.utc).strftime("%Y%m%d")
    slug = uuid.uuid4().hex[:6]
    return f"{date}_{slug}"


def compute_exit_code(results: list) -> int:
    """Exit code derived from ValidationResult only."""
    if not results:
        return 3
    decisions = [r.decision for r in results]
    if all(d == ValidationDecision.SUCCESS for d in decisions):
        return 0
    if all(
        d in (ValidationDecision.SUCCESS, ValidationDecision.SKIPPED) for d in decisions
    ) and any(d == ValidationDecision.SUCCESS for d in decisions):
        return 0
    if any(d == ValidationDecision.CODE_FAILURE for d in decisions):
        return 2
    if any(d == ValidationDecision.FAILED for d in decisions):
        return 1
    if all(d == ValidationDecision.SKIPPED for d in decisions):
        return 3
    if any(d == ValidationDecision.PARTIAL for d in decisions):
        return 1
    return 1


class RunManager:
    def __init__(
        self,
        runs_dir: Path | None = None,
        scenarios_dir: Path | None = None,
    ) -> None:
        self.runs_dir = runs_dir or default_runs_dir()
        loader = PluginLoader(scenarios_dir=scenarios_dir)
        self.registry = loader.discover_and_load()

    def run(
        self,
        scenario_ids: list[str],
        target_net: str = "10.10.10.0/24",
        dry_run: bool = False,
        scenario_params: dict[str, dict] | None = None,
        confirm_detection: bool = False,
        detection_provider: str = "stellar",
        stellar_client: str = "manual",
        execution_provider: str = "local",
        webshell_family: str | None = None,
        webshell_url: str | None = None,
        remote_work_dir: str = DEFAULT_REMOTE_WORK_DIR,
        verify_tls: bool = False,
        export_evidence: bool = True,
        operational_profile: str | None = None,
        on_progress: Callable[[str, dict[str, Any]], None] | None = None,
        max_hosts: int | None = None,
        traffic_profile: str | None = None,
    ) -> tuple[Run, Path, int]:
        if execution_provider not in SUPPORTED_EXECUTION_PROVIDERS:
            run = Run(
                run_id=generate_run_id(),
                status=RunStatus.CONFIG_ERROR,
                target_net=target_net,
                dry_run=dry_run,
                requested_scenarios=scenario_ids,
            )
            return run, self.runs_dir, 3

        if execution_provider == "webshell":
            missing = []
            if not webshell_family:
                missing.append("webshell_family")
            if not webshell_url:
                missing.append("webshell_url")
            if webshell_family and webshell_family not in SUPPORTED_WEBSHELL_FAMILIES:
                missing.append(f"unsupported webshell_family={webshell_family!r}")
            if missing:
                run = Run(
                    run_id=generate_run_id(),
                    status=RunStatus.CONFIG_ERROR,
                    target_net=target_net,
                    dry_run=dry_run,
                    requested_scenarios=scenario_ids,
                )
                return run, self.runs_dir, 3

        active = set(self.registry.active_ids())
        if not scenario_ids:
            scenario_ids = sorted(active)
        if not scenario_ids:
            run = Run(
                run_id=generate_run_id(),
                status=RunStatus.CONFIG_ERROR,
                target_net=target_net,
                dry_run=dry_run,
            )
            return run, self.runs_dir, 3

        for sid in scenario_ids:
            record = self.registry.get(sid)
            if record is None:
                run = Run(
                    run_id=generate_run_id(),
                    status=RunStatus.CONFIG_ERROR,
                    target_net=target_net,
                    dry_run=dry_run,
                    requested_scenarios=scenario_ids,
                )
                return run, self.runs_dir, 3
            if record.status == PluginStatus.DISABLED:
                run = Run(
                    run_id=generate_run_id(),
                    status=RunStatus.CONFIG_ERROR,
                    target_net=target_net,
                    dry_run=dry_run,
                    requested_scenarios=scenario_ids,
                )
                return run, self.runs_dir, 3
            if not record.is_runnable:
                run = Run(
                    run_id=generate_run_id(),
                    status=RunStatus.CONFIG_ERROR,
                    target_net=target_net,
                    dry_run=dry_run,
                    requested_scenarios=scenario_ids,
                )
                return run, self.runs_dir, 3

        if confirm_detection:
            try:
                create_detection_adapter(
                    detection_provider,
                    stellar_client=stellar_client,
                )
            except (UnsupportedDetectionProviderError, UnsupportedStellarClientModeError):
                run = Run(
                    run_id=generate_run_id(),
                    status=RunStatus.CONFIG_ERROR,
                    target_net=target_net,
                    dry_run=dry_run,
                    requested_scenarios=scenario_ids,
                )
                return run, self.runs_dir, 2

        run_id = generate_run_id()
        run_dir = self.runs_dir / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        run_started_at = datetime.now(timezone.utc)

        emitter = ProgressEmitter(on_progress) if on_progress is not None else None
        if emitter is not None:
            emitter.emit(
                "run_started",
                {
                    "provider": execution_provider,
                    "target_net": target_net,
                    "profile": operational_profile,
                },
            )

        config = RunConfig(
            target_net=target_net,
            dry_run=dry_run,
            scenario_params=scenario_params or {},
        )
        run = Run(
            run_id=run_id,
            target_net=target_net,
            started_at=datetime.now(timezone.utc),
            status=RunStatus.RUNNING,
            dry_run=dry_run,
            requested_scenarios=scenario_ids,
            config_snapshot={
                "target_net": target_net,
                "dry_run": dry_run,
                "execution_provider": execution_provider,
                "operational_profile": operational_profile,
            },
            dsp_version=DSP_VERSION,
        )

        db_path = run_dir / "events.db"
        store = EventStore(db_path)
        store.open_run(run_id, metadata=run.to_dict())

        ctx = RunContext(
            run_id=run_id,
            target_net=target_net,
            event_store=store,
            config=config,
            dry_run=dry_run,
            activity_emitter=emitter.emit_activity if emitter is not None else None,
            artifact_dir=run_dir,
        )
        targets = resolve_targets(
            target_net,
            max_hosts=max_hosts or 254,
            discovery=not dry_run,
            dry_run=dry_run,
        )

        if execution_provider == "webshell" and webshell_url:
            apply_webshell_initial_compromise_plan(
                config.scenario_params,
                scenario_ids,
                webshell_url,
            )
            if webshell_family and "host_behavior_check" in scenario_ids:
                config.scenario_params.setdefault("host_behavior_check", {})[
                    "webshell_family"
                ] = webshell_family

        cache_http_endpoint_selection(
            config.scenario_params,
            scenario_ids=scenario_ids,
            targets=targets,
            dry_run=dry_run,
        )
        http_probe_selection = print_http_endpoint_probe_diagnostics(
            config.scenario_params,
            scenario_ids,
            discovered_http_hosts=targets.hosts_for_capability("http_targets"),
        )
        if http_probe_selection is not None:
            probe_payload = http_target_probe_payload(
                http_probe_selection,
                discovered_http_hosts=targets.hosts_for_capability("http_targets"),
            )
            (run_dir / "http_target_probe.json").write_text(
                json.dumps(probe_payload, indent=2),
                encoding="utf-8",
            )
            if emitter is not None:
                emitter.emit("http_probe_diagnostics", probe_payload)

        if emitter is not None:
            emitter.emit("discovery_started", {})
            emitter.emit(
                "discovery_completed",
                {
                    "hosts_found": len(targets.hosts),
                    "probed_hosts": targets.discovery_meta.get("probed_hosts", 0),
                    "alive_hosts": targets.discovery_meta.get("alive_hosts", []),
                    "service_hosts": targets.discovery_meta.get("service_hosts", {}),
                    "service_endpoints": targets.discovery_meta.get("service_endpoints", {}),
                    "open_endpoints": targets.discovery_meta.get("open_endpoints", 0),
                },
            )
            selected = resolve_selected_targets_by_protocol(
                scenario_ids,
                targets,
                config.scenario_params,
            )
            emitter.emit("targets_selected", {"groups": selected})

        provider = self._create_execution_provider(
            execution_provider,
            webshell_family=webshell_family,
            webshell_url=webshell_url,
            verify_tls=verify_tls,
            dry_run=dry_run,
        )
        exec_ctx = ExecutionContext(
            run_id=run_id,
            target_net=target_net,
            dry_run=dry_run,
            provider_type=provider.provider_type,
        )
        if execution_provider == "webshell":
            exec_ctx.execution_metadata["remote_work_dir"] = remote_work_dir
            exec_ctx.execution_metadata["remote_bundle_path"] = resolve_remote_bundle_path(
                remote_work_dir,
                run_id,
            )

        provider.prepare(exec_ctx)
        collector = RemoteEventCollector() if execution_provider == "webshell" else None

        summaries: dict[str, dict] = {}
        total_scenarios = len(scenario_ids)
        try:
            for index, sid in enumerate(scenario_ids, start=1):
                record = self.registry.get(sid)
                assert record is not None
                exec_ctx.scenario_id = sid
                if emitter is not None:
                    params = config.scenario_params.get(sid, {})
                    emitter.emit(
                        "scenario_started",
                        {
                            "scenario_id": sid,
                            "index": index,
                            "total": total_scenarios,
                            "metadata": scenario_start_metadata(
                                sid,
                                targets,
                                params,
                                profile=operational_profile,
                            ),
                            "run_dir": str(run_dir),
                        },
                    )
                    emitter.on_scenario_started(sid)
                summary = provider.execute(
                    exec_ctx,
                    record,
                    ctx,
                    targets,
                    snapshot_dir=run_dir,
                )
                if summary:
                    summaries[sid] = {
                        "scenario_id": summary.scenario_id,
                        "metrics": summary.metrics,
                        "event_count": summary.event_count,
                        "notes": summary.notes,
                    }
                if emitter is not None:
                    if _scenario_executor_skipped(store, run_id, sid):
                        skip_evidence = _latest_skip_evidence(store, run_id, sid)
                        skip_reason = extract_skip_reason(skip_evidence, scenario_id=sid)
                        emitter.on_scenario_completed()
                        emitter.emit(
                            "scenario_skipped",
                            {
                                "scenario_id": sid,
                                "reason": skip_reason,
                                "evidence": skip_evidence,
                            },
                        )
                    else:
                        emitter.on_scenario_completed()
                        completed_metrics = summaries.get(sid, {}).get("metrics", {})
                        completed_evidence = _latest_completed_evidence(store, run_id, sid)
                        if sid == "http_followup" and completed_evidence:
                            _write_http_followup_artifacts(run_dir, completed_evidence)
                        if sid == "sql_injection" and completed_evidence:
                            _write_sql_injection_artifacts(run_dir, completed_evidence)
                        emitter.emit(
                            "scenario_completed",
                            {
                                "scenario_id": sid,
                                "metrics": completed_metrics,
                                "extras": _scenario_completion_extras(sid, completed_evidence),
                                "artifacts": _scenario_artifact_paths(sid, run_dir),
                            },
                        )

                if execution_provider == "webshell" and collector is not None:
                    if exec_ctx.execution_metadata.get("delivery_fallback_local"):
                        continue
                    # Command-only scenarios (e.g. dns_tunnel) already append to the
                    # local Event Store; there is no remote bundle events.jsonl.
                    if (
                        exec_ctx.execution_metadata.get("remote_execution_mode")
                        == REMOTE_EXECUTION_MODE_COMMAND
                    ):
                        continue
                    assert isinstance(provider, WebshellExecutionProvider)
                    remote_execution_id = exec_ctx.execution_metadata.get(
                        "remote_execution_id",
                        run_id,
                    )
                    remote_bundle_path = exec_ctx.execution_metadata["remote_bundle_path"]
                    collection_result = collector.collect(
                        RemoteEventCollectionRequest(
                            remote_execution_id=str(remote_execution_id),
                            remote_bundle_path=str(remote_bundle_path),
                            diagnostics_dir=run_dir,
                        ),
                        provider,
                        store,
                    )
                    exec_ctx.execution_metadata["events_imported"] = (
                        collection_result.events_imported
                    )
        finally:
            provider.cleanup(exec_ctx)

        validator = ValidationEngine(store, self.registry)
        results = validator.validate_run(run_id, scenario_ids)
        validator.write_validation_json(run_dir / "validation.json", results)

        detection_confirmation = None
        if confirm_detection:
            s3_results, adapter_vendor_id = self._run_detection_confirmation(
                store=store,
                run=run,
                results=results,
                run_dir=run_dir,
                detection_provider=detection_provider,
                stellar_client=stellar_client,
            )
            evidence_path = str(run_dir / "evidence" / run_id / adapter_vendor_id)
            detection_confirmation = build_detection_confirmation_entries(
                s3_results,
                evidence_path,
            )

        run.status = RunStatus.COMPLETED
        run.ended_at = datetime.now(timezone.utc)

        from dsp.runtime.traffic_summary import build_traffic_summary

        summary_profile = traffic_profile or operational_profile or "normal"
        traffic_summary = build_traffic_summary(
            store,
            run_id=run_id,
            scenario_ids=scenario_ids,
            targets=targets,
            traffic_profile=summary_profile,
        )
        (run_dir / "traffic_summary.json").write_text(
            json.dumps(traffic_summary, indent=2),
            encoding="utf-8",
        )

        reporter = ReportingEngine(store, self.registry)
        report = reporter.generate(
            run_id,
            results,
            run=run,
            summaries=summaries,
            discovery=traffic_summary.get("discovery"),
            traffic_summary=traffic_summary,
        )
        if detection_confirmation is not None:
            report.detection_confirmation = detection_confirmation
        reporter.write_report_md(run_dir / "report.md", report)
        reporter.write_report_json(run_dir / "report.json", report)

        store.export_jsonl(run_dir / "events.jsonl")
        event_count = store.count(EventQuery(run_id=run_id))

        http_completed = next(
            (
                e
                for e in reversed(store.list_events(run_id))
                if getattr(e, "event", None) == "http_followup_completed"
            ),
            None,
        )
        if http_completed is not None:
            _write_http_followup_artifacts(run_dir, http_completed.evidence or {})

        sql_completed = next(
            (
                e
                for e in reversed(store.list_events(run_id))
                if getattr(e, "event", None) == "sql_injection_completed"
            ),
            None,
        )
        if sql_completed is not None:
            _write_sql_injection_artifacts(run_dir, sql_completed.evidence or {})

        store.close_run()
        self._write_run_json(run_dir / "run.json", run)

        if export_evidence:
            self._export_evidence(store, run_id=run_id, run_dir=run_dir)
            if emitter is not None:
                emitter.emit("evidence_generated", {})

        exit_code = compute_exit_code(results)
        duration_sec = (datetime.now(timezone.utc) - run_started_at).total_seconds()
        if emitter is not None:
            emitter.emit(
                "run_completed",
                {
                    "duration_sec": duration_sec,
                    "event_count": event_count,
                    "summaries": summaries,
                    "run_dir": str(run_dir),
                },
            )
        store.close()
        return run, run_dir, exit_code

    @staticmethod
    def _create_execution_provider(
        execution_provider: str,
        *,
        webshell_family: str | None = None,
        webshell_url: str | None = None,
        verify_tls: bool = False,
        dry_run: bool = False,
    ):
        if execution_provider == "local":
            return create_execution_provider("local")
        return create_execution_provider(
            "webshell",
            webshell_family=webshell_family,
            webshell_url=webshell_url,
            verify_tls=verify_tls,
            enable_healthcheck_on_connect=not dry_run,
        )

    @staticmethod
    def _export_evidence(
        store: EventStore,
        *,
        run_id: str,
        run_dir: Path,
    ) -> dict[str, Any]:
        evidence_result = EvidenceExporter(store).export(
            EvidenceExportRequest(run_id=run_id, output_directory=run_dir)
        )
        manual_result = ManualVerificationPackageGenerator(store).generate(
            ManualVerificationRequest(run_id=run_id, output_directory=run_dir)
        )
        return {
            "evidence_export_metadata": dict(evidence_result.export_metadata),
            "manual_verification_metadata": dict(manual_result.package_metadata),
        }

    def _run_detection_confirmation(
        self,
        *,
        store: EventStore,
        run: Run,
        results: list,
        run_dir: Path,
        detection_provider: str,
        stellar_client: str = "manual",
    ) -> tuple[list, str]:
        adapter = create_detection_adapter(
            detection_provider,
            stellar_client=stellar_client,
        )
        manager = DetectionManager(store, [adapter])
        s3_results = manager.confirm_detection(
            run,
            results,
            vendor_id=adapter.vendor_id,
            output_dir=run_dir,
        )
        manager.write_s3_results(run_dir, s3_results, vendor_id=adapter.vendor_id)
        return s3_results, adapter.vendor_id

    def regenerate_report(self, run_id: str) -> Path:
        run_dir = self.runs_dir / run_id
        run_json = run_dir / "run.json"
        validation_json = run_dir / "validation.json"
        db_path = run_dir / "events.db"

        run = Run.from_dict(json.loads(run_json.read_text(encoding="utf-8")))
        results = ValidationEngine.load_validation_json(validation_json)
        store = EventStore.open_existing(db_path)

        reporter = ReportingEngine(store, self.registry)
        report = reporter.generate(run_id, results, run=run)
        reporter.write_report_md(run_dir / "report.md", report)
        reporter.write_report_json(run_dir / "report.json", report)
        store.close()
        return run_dir / "report.md"

    @staticmethod
    def _write_run_json(path: Path, run: Run) -> None:
        path.write_text(json.dumps(run.to_dict(), indent=2), encoding="utf-8")
