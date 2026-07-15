"""Validation Engine — manifest-driven, Event Store only."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dsp.event_store import EventStore, EventQuery, MetricDef, ValidationDecision, ValidationResult
from dsp.plugins.models import Manifest, PluginRecord
from dsp.plugins.registry import PluginRegistry

_SCENARIO_SKIP_EVENTS = frozenset({
    "scenario_skipped",
    "smb_scenario_skipped",
    "http_followup_skipped",
    "sql_injection_skipped",
    "ssh_failure_skipped",
    "rare_protocol_activity_skipped",
    "port_sweep_skipped",
})


class ValidationEngine:
    """Generic validation_profile applicator — no per-scenario branches."""

    def __init__(self, store: EventStore, registry: PluginRegistry) -> None:
        self.store = store
        self.registry = registry

    def validate_run(self, run_id: str, scenario_ids: list[str]) -> list[ValidationResult]:
        results: list[ValidationResult] = []
        for scenario_id in scenario_ids:
            record = self.registry.get(scenario_id)
            if record is None:
                results.append(
                    ValidationResult(
                        run_id=run_id,
                        scenario_id=scenario_id,
                        decision=ValidationDecision.CODE_FAILURE,
                        reason="unknown_scenario",
                        metrics={},
                        validated_at=datetime.now(timezone.utc),
                    )
                )
                continue
            results.append(self.validate(run_id, scenario_id, record))
        return results

    def validate(
        self,
        run_id: str,
        scenario_id: str,
        record: PluginRecord | None = None,
    ) -> ValidationResult:
        if record is None:
            record = self.registry.get(scenario_id)
        if record is None:
            return ValidationResult(
                run_id=run_id,
                scenario_id=scenario_id,
                decision=ValidationDecision.CODE_FAILURE,
                reason="unknown_scenario",
                metrics={},
                validated_at=datetime.now(timezone.utc),
            )

        manifest = record.manifest
        vp = manifest.validation_profile
        profile_version = str(vp.get("profile_version", "1.0.0"))
        metric_defs = _parse_metrics(vp.get("metrics", []))

        skipped = self._is_scenario_skipped(run_id, scenario_id)
        if skipped:
            return ValidationResult(
                run_id=run_id,
                scenario_id=scenario_id,
                decision=ValidationDecision.SKIPPED,
                reason="scenario_skipped",
                metrics={},
                validated_at=datetime.now(timezone.utc),
                validation_profile_version=profile_version,
            )

        fail_fast_codes = self._evaluate_fail_fast(run_id, scenario_id, vp, metric_defs)
        if fail_fast_codes:
            from dsp.runtime.scenario_store_metrics import aggregate_scenario_metrics

            return ValidationResult(
                run_id=run_id,
                scenario_id=scenario_id,
                decision=ValidationDecision.CODE_FAILURE,
                reason=fail_fast_codes[0],
                metrics=aggregate_scenario_metrics(self.store, self.registry, run_id, scenario_id),
                fail_fast_codes=fail_fast_codes,
                validated_at=datetime.now(timezone.utc),
                validation_profile_version=profile_version,
            )

        from dsp.runtime.scenario_store_metrics import aggregate_scenario_metrics

        metrics = aggregate_scenario_metrics(self.store, self.registry, run_id, scenario_id)
        decision, reason = self._apply_thresholds(metrics, vp)
        missing_items: list[str] = []
        if (
            scenario_id == "host_behavior_check"
            and decision == ValidationDecision.FAILED
            and reason == "thresholds_not_met"
        ):
            from dsp.protocols.host.behavior_observability import (
                build_host_behavior_checklist,
                missing_items_for_validation,
            )

            checklist = build_host_behavior_checklist(self.store, run_id, scenario_id)
            missing_items = missing_items_for_validation(checklist, metrics=metrics)

        return ValidationResult(
            run_id=run_id,
            scenario_id=scenario_id,
            decision=decision,
            reason=reason,
            metrics=metrics,
            fail_fast_codes=[],
            missing_items=missing_items,
            validated_at=datetime.now(timezone.utc),
            validation_profile_version=profile_version,
        )

    def _has_event(self, run_id: str, scenario_id: str, event_name: str) -> bool:
        return (
            self.store.count(
                EventQuery(run_id=run_id, scenario_id=scenario_id, event=event_name)
            )
            > 0
        )

    def _is_scenario_skipped(self, run_id: str, scenario_id: str) -> bool:
        for event_name in _SCENARIO_SKIP_EVENTS:
            if self._has_event(run_id, scenario_id, event_name):
                return True
        for event_name in (f"{scenario_id}_skipped",):
            if self._has_event(run_id, scenario_id, event_name):
                return True
        return False

    def _evaluate_fail_fast(
        self,
        run_id: str,
        scenario_id: str,
        vp: dict[str, Any],
        metric_defs: list[MetricDef],
    ) -> list[str]:
        codes: list[str] = []
        fail_fast = vp.get("fail_fast", [])

        completed = self._has_event(run_id, scenario_id, "scenario_completed")
        aborted = self._has_event(run_id, scenario_id, "scenario_aborted")
        started = self._has_event(run_id, scenario_id, "scenario_started")

        if "SOT_EMPTY_AFTER_EXECUTE" in fail_fast:
            if started and not completed and not aborted:
                pass
            elif started and completed:
                traffic_count = self._traffic_event_count(run_id, scenario_id)
                if traffic_count == 0:
                    codes.append("SOT_EMPTY_AFTER_EXECUTE")

        if "COUNTER_IMPOSSIBLE" in fail_fast:
            for name, value in self.store.aggregate(run_id, scenario_id, metric_defs).items():
                if isinstance(value, (int, float)) and value < 0:
                    codes.append("COUNTER_IMPOSSIBLE")

        if scenario_id == "dns_tunnel":
            from dsp.protocols.dns.tunnel_validation import (
                DNS_TUNNEL_FAIL_FAST_CODES,
                evaluate_dns_tunnel_invariants,
            )

            invariant_codes = evaluate_dns_tunnel_invariants(
                self.store,
                run_id,
                scenario_id,
            )
            for code in invariant_codes:
                if code in fail_fast and code not in codes:
                    codes.append(code)

        return codes

    def _traffic_event_count(self, run_id: str, scenario_id: str) -> int:
        lifecycle = {
            "scenario_started",
            "scenario_completed",
            "scenario_skipped",
            "scenario_aborted",
            "scenario_prepared",
        }
        total = self.store.count(EventQuery(run_id=run_id, scenario_id=scenario_id))
        for ev in lifecycle:
            total -= self.store.count(
                EventQuery(run_id=run_id, scenario_id=scenario_id, event=ev)
            )
        return max(total, 0)

    def _apply_thresholds(
        self, metrics: dict[str, int | float], vp: dict[str, Any]
    ) -> tuple[ValidationDecision, str]:
        success_rules = vp.get("success", {})
        partial_rules = vp.get("partial", {})

        if _thresholds_met(metrics, success_rules):
            return ValidationDecision.SUCCESS, "thresholds_met"

        if partial_rules and _thresholds_met(metrics, partial_rules):
            return ValidationDecision.PARTIAL, "partial_thresholds_met"

        return ValidationDecision.FAILED, "thresholds_not_met"

    def write_validation_json(self, path: Path, results: list[ValidationResult]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "validation_result_schema": "1.0.0",
            "results": [r.to_dict() for r in results],
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @staticmethod
    def load_validation_json(path: Path) -> list[ValidationResult]:
        data = json.loads(path.read_text(encoding="utf-8"))
        return [ValidationResult.from_dict(r) for r in data.get("results", [])]


def _parse_metrics(raw_metrics: list[dict[str, Any]]) -> list[MetricDef]:
    defs: list[MetricDef] = []
    for m in raw_metrics:
        defs.append(
            MetricDef(
                name=m["name"],
                event_filter=dict(m.get("event_filter", {})),
                aggregate=m["aggregate"],
                json_path=m.get("json_path"),
            )
        )
    return defs


def _thresholds_met(
    metrics: dict[str, int | float | str | bool],
    rules: dict[str, dict[str, Any]],
) -> bool:
    for metric_name, rule in rules.items():
        if metric_name not in metrics:
            return False
        value = metrics[metric_name]
        if "min" in rule and value < rule["min"]:
            return False
        if "max" in rule and value > rule["max"]:
            return False
        if "eq" in rule and value != rule["eq"]:
            return False
    return True
