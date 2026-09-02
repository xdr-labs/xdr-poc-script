"""DGA validation profile templates."""

from __future__ import annotations

from typing import Any

DGA_METRIC_NAMES = [
    "dga_domain_generated_count",
    "dga_query_dispatched_count",
    "dga_nxdomain_observed_count",
    "dga_resolved_observed_count",
]


def dga_validation_profile(**overrides: Any) -> dict[str, Any]:
    """Standard DGA validation profile for manifest.yaml.

    Success is execution/evidence based (generated + dispatched).
    NXDOMAIN/resolved observations are recorded but do not gate success —
    DSP does not infer detection outcome from resolver responses.
    """
    profile: dict[str, Any] = {
        "profile_version": "1.0.0",
        "metrics": [
            {
                "name": "dga_domain_generated_count",
                "event_filter": {
                    "event": "dga_domain_generated",
                    "status": "info",
                },
                "aggregate": "count",
            },
            {
                "name": "dga_query_dispatched_count",
                "event_filter": {
                    "event": "dns_query_sent",
                    "status": "sent",
                },
                "aggregate": "count",
            },
            {
                "name": "dga_nxdomain_observed_count",
                "event_filter": {
                    "event": "dga_nxdomain_observed",
                    "status": "nxdomain",
                },
                "aggregate": "count",
            },
            {
                "name": "dga_resolved_observed_count",
                "event_filter": {
                    "event": "dga_resolved_observed",
                    "status": "response",
                },
                "aggregate": "count",
            },
        ],
        "success": {
            "dga_domain_generated_count": {"min": 1},
            "dga_query_dispatched_count": {"min": 1},
        },
        "fail_fast": ["SOT_EMPTY_AFTER_EXECUTE"],
    }
    profile.update(overrides)
    return profile
