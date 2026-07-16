"""DNS Tunnel volume profile tests."""

from __future__ import annotations

import json

import pytest

from dsp.protocols.dns.volume_profiles import (
    VOLUME_PROFILES,
    apply_volume_profile,
    resolve_volume_profile,
)
from dsp.runner import RunManager


def test_resolve_volume_profile_demo():
    profile = resolve_volume_profile("demo")
    assert profile["payload_mb"] == 0.5
    assert profile["max_hosts"] == 1


def test_apply_volume_profile_explicit_overrides_profile():
    params = apply_volume_profile(
        {"volume_profile": "demo", "max_chunks": 20},
        dry_run=True,
    )
    assert params["max_chunks"] == 20


def test_apply_volume_profile_default_standard_for_dry_run():
    from dsp.protocols.dns.volume_profiles import DRY_RUN_MAX_CHUNKS_DEFAULT

    params = apply_volume_profile({}, dry_run=True)
    assert params["max_chunks"] == DRY_RUN_MAX_CHUNKS_DEFAULT
    assert params["payload_mb"] == VOLUME_PROFILES["standard"]["payload_mb"]


def test_unknown_volume_profile_raises():
    with pytest.raises(ValueError, match="unknown volume profile"):
        resolve_volume_profile("invalid")


def test_dns_tunnel_dry_run_default_uses_standard_profile(tmp_runs_dir):
    manager = RunManager(runs_dir=tmp_runs_dir)
    _, run_dir, exit_code = manager.run(
        scenario_ids=["dns_tunnel"],
        dry_run=True,
    )

    assert exit_code == 0
    validation = json.loads((run_dir / "validation.json").read_text())
    metrics = validation["results"][0]["metrics"]
    assert metrics["dns_tunnel_query_sent_count"] == 102
    assert metrics["dns_tunnel_chunk_created_count"] == 102
    assert (run_dir / "events.db").stat().st_size < 2 * 1024 * 1024
