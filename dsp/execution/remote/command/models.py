"""Webshell command-only models — DNS Tunnel scoped for this branch."""

from __future__ import annotations

# Live webshell path uses command dispatch only (no DSP runtime upload).
REMOTE_EXECUTION_MODE_COMMAND = "command"

# Deprecated bundle mode — retained for non-DNS scenarios on baseline webshell.
REMOTE_EXECUTION_MODE_BUNDLE = "bundle"

# This branch enables command-only execution for DNS Tunnel only.
# Other scenarios continue on baseline BundleScenarioRunner.
COMMAND_SCENARIOS = frozenset({"dns_tunnel"})

FORBIDDEN_REMOTE_ARTIFACTS = frozenset(
    {
        "manifest.json",
        "run_scenario.py",
        "remote_discovery.py",
        "discover_runner.py",
    }
)

DISCOVERY_ORIGIN_WEBSHELL = "webshell_host"
EVENT_SOURCE_WEBSHELL = "remote"

DISCOVERY_METHOD_COMMAND_INLINE_BASE64_EXEC = "command_inline_base64_exec"
COMMAND_DELIVERY_INLINE_BASE64_EXEC = "inline_base64_exec"
DNS_QUERY_METHOD_PYTHON_SOCKET_UDP53 = "python3_socket_udp53"
