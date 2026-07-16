"""Guard: operator release branch + normal volume contract stay aligned."""

from __future__ import annotations

import re
from pathlib import Path

from dsp.runtime.normal_profile_contract import (
    OPERATOR_RELEASE_BRANCH,
    assert_normal_profile_contract,
    expected_dns_tunnel_idx_chunks,
    validate_normal_profile_templates,
)
from dsp.runtime.operational_profiles import DISCOVERY_FIRST_SCENARIO_ORDER, scenarios_for_profile

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_normal_profile_volume_contract() -> None:
    assert validate_normal_profile_templates() == []
    assert_normal_profile_contract()
    assert expected_dns_tunnel_idx_chunks() == 34953


def test_normal_scenario_order_port_early_dns_last() -> None:
    scenarios = scenarios_for_profile("normal")
    assert scenarios == list(DISCOVERY_FIRST_SCENARIO_ORDER)
    assert scenarios[1] == "port_sweep"
    assert scenarios[-1] == "dns_tunnel"
    assert "http_followup" in scenarios
    assert scenarios.index("http_followup") < scenarios.index("dns_tunnel")


def test_operator_scripts_default_to_rc_branch() -> None:
    menu = (_REPO_ROOT / "dsp-menu.sh").read_text(encoding="utf-8")
    install = (_REPO_ROOT / "install-dsp.sh").read_text(encoding="utf-8")
    assert OPERATOR_RELEASE_BRANCH == "release/v1.4.0-rc"
    assert re.search(
        rf'RELEASE_BRANCH=.*{re.escape(OPERATOR_RELEASE_BRANCH)}',
        menu,
    ), "dsp-menu.sh must default to OPERATOR_RELEASE_BRANCH"
    assert re.search(
        rf'release/v1\.4\.0-rc',
        install,
    ), "install-dsp.sh must default to release/v1.4.0-rc"
    # Retired line must not be the hardcoded default anymore.
    assert not re.search(r'RELEASE_BRANCH="release/v1\.4\.0"', menu)
    assert 'release/v1.4.0"' not in install or "v1.4.0-rc" in install
