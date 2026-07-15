"""Normal-profile planned volume regression — target quantities vs profile params."""

from __future__ import annotations

from dsp.engine.scenario_engine import TargetSet
from dsp.protocols.dns.tunnel import CHUNK_SIZE_DEFAULT, plan_chunk_count, plan_dns_tunnel
from dsp.protocols.http.sqli_payloads import plan_sqli_requests
from dsp.protocols.http.urls import plan_followup_requests
from dsp.protocols.http.user_agents import attach_followup_user_agents
from dsp.runtime.scenario_plan import build_port_sweep_plan_view
from dsp.runtime.operational_profiles import build_operational_scenario_params
from dsp.runtime.traffic_profiles import scenario_params_for_profile
from dsp.runner.target_selection import scenario_start_metadata


def _lab_targets() -> TargetSet:
  """Lab-like discovery: 2 HTTP, 1 DNS, 4 alive, no LDAP/SMB/Kerberos."""
  alive = ["10.10.10.1", "10.10.10.10", "10.10.10.20", "10.10.10.30"]
  return TargetSet(
      target_net="10.10.10.0/24",
      hosts=alive,
      service_hosts={
          "dns_hosts": ["10.10.10.10"],
          "http_targets": ["10.10.10.1", "10.10.10.20"],
          "ssh_hosts": alive,
          "ldap_hosts": [],
          "smb_hosts": [],
          "kerberos_hosts": [],
      },
      service_endpoints={
          "http_targets": [("10.10.10.1", 8888), ("10.10.10.20", 80)],
          "dns_hosts": [("10.10.10.10", 53)],
      },
      discovery_enabled=True,
      discovery_meta={"alive_hosts": alive, "discovery_origin": "webshell_host"},
  )


def test_normal_profile_http_followup_1000_suspicious_ua() -> None:
    params = scenario_params_for_profile("http_followup", "normal")
    plans = plan_followup_requests(
        endpoints=[("10.10.10.1", 8888), ("10.10.10.20", 80)],
        max_hosts=params["max_hosts"],
        max_per_host=params["max_per_host"],
        max_total=params["max_total"],
        include_attack_paths=True,
    )
    enriched, stats = attach_followup_user_agents(plans)
    assert len(enriched) == 1000
    assert stats["abnormal_user_agents_planned"] == 1000
    assert stats["normal_user_agents_planned"] == 0


def test_normal_profile_sql_injection_1000_two_targets() -> None:
    params = scenario_params_for_profile("sql_injection", "normal")
    plans = plan_sqli_requests(
        endpoints=[("10.10.10.1", 8888), ("10.10.10.20", 80)],
        max_hosts=params["max_hosts"],
        max_per_host=params["max_per_host"],
        max_total=params["max_total"],
    )
    assert len(plans) == 1000
    assert params["max_per_host"] == 500


def test_normal_profile_ssh_failure_150_attempts() -> None:
    params = scenario_params_for_profile("ssh_failure", "normal")
    assert params["max_total"] == 150
    assert params["max_hosts"] == 2


def test_normal_profile_port_sweep_20_probes() -> None:
    targets = _lab_targets()
    params = build_operational_scenario_params(
        "normal",
        ["port_sweep"],
        target_net="10.10.10.0/24",
    )["port_sweep"]
    plan = build_port_sweep_plan_view(targets, params)
    assert plan.planned_probes == 20


def test_normal_profile_dga_45_domains_one_dns_host() -> None:
    params = scenario_params_for_profile("dga", "normal")
    total = int(params["phase1_count"]) + int(params["phase2_count"])
    assert total == 45


def test_normal_profile_dns_tunnel_2mb_no_chunk_cap() -> None:
    params = build_operational_scenario_params(
        "normal",
        ["dns_tunnel"],
        target_net="10.10.10.0/24",
    )["dns_tunnel"]
    assert params["payload_mb"] == 2.0
    assert "max_chunks" not in params
    plan = plan_dns_tunnel(_lab_targets(), params, dry_run=False)
    expected_idx = plan_chunk_count(2.0, CHUNK_SIZE_DEFAULT)
    idx_count = sum(1 for q in plan["queries"] if q.get("query_role") == "idx_chunk")
    assert idx_count == expected_idx * 2  # max_hosts=2 alive targets
    assert plan.get("max_chunks") is None


def test_dns_tunnel_start_metadata_not_fixed_50() -> None:
    targets = _lab_targets()
    params = scenario_params_for_profile("dns_tunnel", "normal")
    meta = scenario_start_metadata("dns_tunnel", targets, params, webshell_mode=True)
    idx_per_host = plan_chunk_count(2.0, CHUNK_SIZE_DEFAULT)
    assert meta["payload_mb"] == 2.0
    assert meta["planned_queries"] == (idx_per_host + 2) * 2
    assert meta["planned_queries"] != 50


def test_dns_tunnel_targets_alive_hosts_not_dns_service() -> None:
    plan = plan_dns_tunnel(_lab_targets(), scenario_params_for_profile("dns_tunnel", "normal"), dry_run=False)
    assert plan["target_selection"] == "alive_hosts"
    targets_in_plan = {q["target"] for q in plan["queries"]}
    assert "10.10.10.10" in targets_in_plan  # alive host, also dns service
    assert targets_in_plan <= {"10.10.10.1", "10.10.10.10"}  # max_hosts=2 from alive list order
