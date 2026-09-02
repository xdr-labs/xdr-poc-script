"""Remote discovery stubs — not used on DNS-only command path."""

from __future__ import annotations

from typing import Any


def get_cached_remote_discovery(*_args: Any, **_kwargs: Any) -> None:
    return None


def prefetch_webshell_target_net_discovery(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
    raise RuntimeError("remote discovery is not enabled on the DNS Tunnel command path")
