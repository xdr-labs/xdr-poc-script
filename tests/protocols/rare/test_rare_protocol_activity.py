"""Rare protocol activity unit tests."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from dsp.engine.scenario_engine import TargetSet
from dsp.event_store import EventStore, ValidationDecision
from dsp.protocols.rare import (
    RareProtocolClient,
    build_rare_protocol_probe_attempt_event,
    build_rare_protocol_report_section,
    plan_rare_protocol_activity,
    rare_protocol_validation_profile,
)
from dsp.protocols.rare.attempts import PlannedRareProbe, RARE_PROTOCOL_PORTS
from dsp.plugins import PluginLoader
from dsp.validation.engine import ValidationEngine


def test_plan_skips_when_no_valid_target() -> None:
    targets = TargetSet(
        target_net="10.10.10.0/24",
        hosts=[],
        discovery_enabled=True,
        discovery_meta={"alive_hosts": []},
    )
    plans = plan_rare_protocol_activity(targets, {})
    assert plans == []


def test_plan_does_not_fallback_to_localhost() -> None:
    targets = TargetSet(
        target_net="10.10.10.0/24",
        hosts=[],
        discovery_enabled=True,
        discovery_meta={"alive_hosts": []},
    )
    plans = plan_rare_protocol_activity(targets, {})
    assert plans == []
    assert all(plan.host not in {"127.0.0.1", "::1", "localhost"} for plan in plans)


def test_plan_includes_all_protocols_on_alive_host_fallback() -> None:
    targets = TargetSet(
        target_net="10.10.10.0/24",
        hosts=["10.10.10.20"],
        discovery_enabled=True,
        discovery_meta={"alive_hosts": ["10.10.10.20"]},
    )
    plans = plan_rare_protocol_activity(targets, {})
    protocols = {plan.protocol for plan in plans}
    assert protocols == set(RARE_PROTOCOL_PORTS.keys())
    assert len(plans) == 4
    assert all(plan.host == "10.10.10.20" for plan in plans)


def test_plan_skips_local_interface_ip_prefers_other_alive_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """Local provider must not probe self-IP (no br0 packets); prefer other alive host."""
    monkeypatch.setattr(
        "dsp.protocols.rare.attempts._local_interface_ips",
        lambda: {"127.0.0.1", "::1", "localhost", "10.10.10.1"},
    )
    targets = TargetSet(
        target_net="10.10.10.0/24",
        hosts=["10.10.10.1", "10.10.10.10"],
        discovery_enabled=True,
        discovery_meta={"alive_hosts": ["10.10.10.1", "10.10.10.10"]},
    )
    plans = plan_rare_protocol_activity(targets, {})
    assert len(plans) == 4
    assert all(plan.host == "10.10.10.10" for plan in plans)
    assert "10.10.10.1" not in {plan.host for plan in plans}


def test_plan_uses_probe_hosts_for_fallback() -> None:
    targets = TargetSet(
        target_net="10.10.10.0/24",
        hosts=[],
        discovery_enabled=True,
        discovery_meta={"alive_hosts": []},
    )
    plans = plan_rare_protocol_activity(targets, {"probe_hosts": ["10.10.10.20"]})
    protocols = {plan.protocol for plan in plans}
    assert protocols == set(RARE_PROTOCOL_PORTS.keys())
    assert all(plan.host == "10.10.10.20" for plan in plans)


def test_plan_uses_alive_hosts_for_fallback_not_webshell_host() -> None:
    targets = TargetSet(
        target_net="10.10.10.0/24",
        hosts=["10.10.10.97", "10.10.10.50"],
        discovery_enabled=True,
        discovery_meta={"alive_hosts": ["10.10.10.97", "10.10.10.50"]},
    )
    plans = plan_rare_protocol_activity(
        targets,
        {
            "_webshell_execution": {
                "execution_host": "10.10.10.50",
                "webshell_url": "http://10.10.10.50:8080/shell.jsp",
            }
        },
    )
    assert len(plans) == 4
    assert all(plan.host == "10.10.10.97" for plan in plans)


def test_plan_uses_discovered_rare_port_endpoints() -> None:
    targets = TargetSet(
        target_net="10.10.10.0/24",
        hosts=["10.10.10.20"],
        service_endpoints={"custom": [("10.10.10.20", 554)]},
        discovery_enabled=True,
    )
    plans = plan_rare_protocol_activity(targets, {})
    rtsp = [p for p in plans if p.protocol == "RTSP"]
    assert len(rtsp) == 1
    assert rtsp[0].host == "10.10.10.20"
    assert rtsp[0].port == 554


def test_client_mock_telnet() -> None:
    client = RareProtocolClient(mode="mock")
    plan = PlannedRareProbe(
        protocol="TELNET",
        host="10.10.10.20",
        port=23,
        transport="tcp",
        artifact="telnet:10.10.10.20:23",
    )
    result = client.probe(plan)
    assert result.success is True
    assert result.protocol == "TELNET"


@patch("socket.create_connection")
def test_client_live_telnet_banner(mock_connect: MagicMock) -> None:
    sock = MagicMock()
    sock.recv.return_value = b"Welcome telnet"
    mock_connect.return_value.__enter__.return_value = sock
    client = RareProtocolClient(mode="live", timeout=1.0)
    plan = PlannedRareProbe(
        protocol="TELNET",
        host="10.10.10.20",
        port=23,
        transport="tcp",
        artifact="telnet:10.10.10.20:23",
    )
    result = client.probe(plan)
    assert result.success is True
    assert result.outcome == "banner_read"


def test_validation_profile_matches_events() -> None:
    store = EventStore(":memory:")
    run_id = "rare-unit-1"
    store.open_run(run_id)
    store.append(
        build_rare_protocol_probe_attempt_event(
            run_id=run_id,
            scenario_id="rare_protocol_activity",
            target="10.10.10.20",
            artifact="telnet:10.10.10.20:23",
            source="local",
            evidence={"protocol": "TELNET"},
        )
    )
    loader = PluginLoader()
    registry = loader.discover_and_load()
    engine = ValidationEngine(store, registry)
    result = engine.validate(run_id, "rare_protocol_activity")
    assert result.decision == ValidationDecision.SUCCESS
    assert result.metrics["rare_protocol_probe_attempt_count"] == 1


def test_validation_skipped_when_no_probe_plans() -> None:
    from dsp.event_store import Event
    from dsp.protocols.rare.events import RARE_PROTOCOL_ACTIVITY_SKIPPED

    store = EventStore(":memory:")
    run_id = "rare-skip-1"
    store.open_run(run_id)
    store.append(
        Event(
            run_id=run_id,
            scenario_id="rare_protocol_activity",
            timestamp=datetime.now(timezone.utc),
            stage="executor",
            event=RARE_PROTOCOL_ACTIVITY_SKIPPED,
            status="info",
            source="local",
            evidence={"reason": "no_probe_plans"},
        )
    )
    loader = PluginLoader()
    registry = loader.discover_and_load()
    engine = ValidationEngine(store, registry)
    result = engine.validate(run_id, "rare_protocol_activity")
    assert result.decision == ValidationDecision.SKIPPED
    assert result.reason == "scenario_skipped"


def test_report_section_contains_protocol_summary() -> None:
    from dsp.event_store import ValidationResult

    result = ValidationResult(
        run_id="r1",
        scenario_id="rare_protocol_activity",
        decision=ValidationDecision.SUCCESS,
        reason="thresholds_met",
        metrics={
            "rare_protocol_probe_attempt_count": 4,
            "rare_protocol_probe_success_count": 2,
            "rare_protocol_probe_failure_count": 2,
        },
    )
    lines = build_rare_protocol_report_section(
        result,
        summary={
            "protocols": ["TELNET", "RTSP", "SIP", "RTP"],
            "attempt_count": 4,
            "success_count": 2,
            "failure_count": 2,
        },
    )
    text = "\n".join(lines)
    assert "Rare Protocol Activity" in text
    assert "TELNET" in text
    assert "**Attempts:** 4" in text
