"""DNS Tunnel volume profiles — operational controls without architecture change."""

from __future__ import annotations

from typing import Any

# Named profiles for operator-controlled execution volume.
# Explicit scenario_params keys always override profile values.
# Align with operational traffic profiles: normal·high 1.0 MB per target.
VOLUME_PROFILES: dict[str, dict[str, Any]] = {
    "demo": {
        "payload_mb": 1.0,
        "max_hosts": 1,
    },
    "standard": {
        "payload_mb": 1.0,
        "chunk_size": 30,
        "max_hosts": 1,
    },
    "stress": {
        # Same per-target payload as standard; host fan-out comes from operational high.
        "payload_mb": 1.0,
        "chunk_size": 30,
        "max_hosts": 1,
    },
}

DEFAULT_DRY_RUN_PROFILE = "standard"
DEFAULT_LIVE_PROFILE = "standard"

DRY_RUN_MAX_CHUNKS_DEFAULT = 100


def resolve_volume_profile(name: str) -> dict[str, Any]:
    """Return a copy of the named volume profile."""
    if name not in VOLUME_PROFILES:
        raise ValueError(
            f"unknown volume profile: {name!r}; "
            f"choose from {sorted(VOLUME_PROFILES)}"
        )
    return dict(VOLUME_PROFILES[name])


def apply_volume_profile(
    params: dict[str, Any],
    *,
    dry_run: bool,
) -> dict[str, Any]:
    """Merge volume profile defaults; explicit params win."""
    merged = dict(params)
    explicit_volume_keys = {"payload_mb", "max_chunks", "chunk_size", "max_hosts", "volume_profile"}
    has_explicit_volume = bool(explicit_volume_keys.intersection(params))

    if not has_explicit_volume:
        default_profile = DEFAULT_DRY_RUN_PROFILE if dry_run else DEFAULT_LIVE_PROFILE
        merged = {**resolve_volume_profile(default_profile), **merged}

    profile_name = merged.pop("volume_profile", None)
    if profile_name:
        merged = {**resolve_volume_profile(str(profile_name)), **merged}

    if dry_run and "max_chunks" not in merged:
        merged["max_chunks"] = DRY_RUN_MAX_CHUNKS_DEFAULT

    return merged
