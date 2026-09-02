"""Map Event Store skip evidence to operator-facing SKIPPED reasons."""

from __future__ import annotations

from typing import Any

# Exact evidence.reason values → report text.
_EXACT: dict[str, str] = {
    "HTTP_TARGETS_NOT_FOUND": "No HTTP service discovered",
    "skipped_no_http_service": "No HTTP service discovered",
    "no_http_endpoints": "No HTTP service discovered",
    "no_open_445_service": "No SMB service discovered",
    "no_alive_hosts": "No eligible target",
    "no_targets": "No eligible target",
    "no_kerberos_hosts": "No Kerberos service discovered",
    "no_ldap_hosts": "No LDAP service discovered",
    "scenario_skipped": "scenario_skipped",
}

# Substring / prefix heuristics for legacy reason strings.
_CONTAINS: tuple[tuple[str, str], ...] = (
    ("smb_hosts", "No SMB service discovered"),
    ("no smb", "No SMB service discovered"),
    ("ssh_hosts", "No SSH service discovered"),
    ("no ssh", "No SSH service discovered"),
    ("http", "No HTTP service discovered"),
    ("kerberos", "No Kerberos service discovered"),
    ("ldap", "No LDAP service discovered"),
    ("no_alive", "No eligible target"),
    ("no eligible", "No eligible target"),
    ("no_targets", "No eligible target"),
)


def humanize_skip_reason(raw: str | None, *, scenario_id: str = "") -> str:
    """Return a concrete SKIPPED reason; never invent success from missing data."""
    text = (raw or "").strip()
    if not text:
        return _default_for_scenario(scenario_id)
    if text in _EXACT:
        return _EXACT[text]
    lower = text.lower()
    for needle, display in _CONTAINS:
        if needle in lower:
            return display
    return text


def _default_for_scenario(scenario_id: str) -> str:
    defaults = {
        "http_followup": "No HTTP service discovered",
        "sql_injection": "No HTTP service discovered",
        "smb_login_failure": "No SMB service discovered",
        "ssh_failure": "No SSH service discovered",
        "kerberos_failure": "No Kerberos service discovered",
        "ldap_enumeration": "No LDAP service discovered",
        "dns_tunnel": "No eligible target",
        "dga": "No eligible target",
    }
    return defaults.get(scenario_id, "scenario_skipped")


def extract_skip_reason(evidence: dict[str, Any] | None, *, scenario_id: str = "") -> str:
    """Prefer evidence.reason, then common alternate keys."""
    payload = dict(evidence or {})
    raw = payload.get("reason") or payload.get("skip_reason") or payload.get("message")
    return humanize_skip_reason(str(raw) if raw is not None else None, scenario_id=scenario_id)
