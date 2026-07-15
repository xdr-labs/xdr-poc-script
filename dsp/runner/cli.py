"""DSP CLI entry point."""

from __future__ import annotations

import argparse
import sys

from dsp import __version__
from dsp.plugins import PluginLoader
from dsp.runner.console_output import OperationalConsole
from dsp.runner.run_manager import RunManager
from dsp.runtime.operational_profiles import (
    HOST_BEHAVIOR_CHECK_SCENARIO_ID,
    build_explicit_scenario_params_with_profile,
    build_operational_scenario_params,
    ensure_webshell_phase1_scenarios,
    parse_operational_profile,
    resolve_runnable_scenarios,
)
from dsp.runtime.target_net_guard import validate_target_net_scope

_DETECTION_EPILOG = """
Detection confirmation (S3) examples:

  # Manual S3 evidence pack (default — no Stellar API required):
  dsp run --profile normal --confirm-detection

  # Offline mock Stellar client (CI / demo only):
  dsp run --profile normal --confirm-detection --stellar-client mock

  # Experimental live Stellar HTTP client (optional, requires env vars):
  # See docs/experimental/STELLAR_HTTP_API_MODE.md
  export DSP_STELLAR_BASE_URL=https://stellar.lab.example
  export DSP_STELLAR_API_TOKEN=<token>
  dsp run --profile normal --confirm-detection \\
    --detection-provider stellar --stellar-client http

S3 is optional and never changes S2 exit codes or ValidationResult.
Normal DSP operation does not require Stellar API tokens.
"""


def _resolve_run_plan(
    manager: RunManager,
    *,
    scenarios_arg: str | None,
    profile_arg: str | None,
    target_net: str,
    max_hosts: int | None = None,
    execution_provider: str = "local",
) -> tuple[list[str], dict[str, dict] | None, str | None]:
    """Return scenario_ids, scenario_params, and operational_profile for a run."""
    if scenarios_arg:
        scenario_ids = [s.strip() for s in scenarios_arg.split(",") if s.strip()]
        operational_profile = None
        scenario_params = None
        if profile_arg:
            operational_profile = parse_operational_profile(profile_arg)
            scenario_params = build_explicit_scenario_params_with_profile(
                scenario_ids,
                operational_profile,
                target_net=target_net,
                max_hosts=max_hosts,
            )
    else:
        operational_profile = parse_operational_profile(profile_arg or "normal")
        scenario_ids = resolve_runnable_scenarios(
            operational_profile,
            manager.registry.active_ids(),
        )
        if not scenario_ids:
            raise ValueError(
                f"no runnable scenarios for profile {operational_profile!r}"
            )
        scenario_params = build_operational_scenario_params(
            operational_profile,
            scenario_ids,
            target_net=target_net,
            max_hosts=max_hosts,
        )

    if execution_provider == "webshell":
        scenario_ids = ensure_webshell_phase1_scenarios(
            scenario_ids,
            active_ids=manager.registry.active_ids(),
        )
        if scenario_params is None:
            scenario_params = {}
        if HOST_BEHAVIOR_CHECK_SCENARIO_ID in scenario_ids:
            scenario_params.setdefault(
                HOST_BEHAVIOR_CHECK_SCENARIO_ID,
                build_operational_scenario_params(
                    operational_profile or "normal",
                    [HOST_BEHAVIOR_CHECK_SCENARIO_ID],
                    target_net=target_net,
                    max_hosts=max_hosts,
                ).get(HOST_BEHAVIOR_CHECK_SCENARIO_ID, {}),
            )

    return scenario_ids, scenario_params, operational_profile


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dsp", description="Detection Scenario Platform")
    parser.add_argument("--version", action="version", version=f"dsp {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="Execute scenarios")
    run_parser.add_argument(
        "--scenarios",
        help="Advanced: comma-separated scenario IDs (overrides profile coverage)",
    )
    run_parser.add_argument(
        "--profile",
        type=parse_operational_profile,
        metavar="{normal,high}",
        default=None,
        help=(
            "Operational profile: normal (default — limited representative targets), "
            "high (same per-target volume, all discovered targets). "
            "Default when --scenarios is omitted: normal. "
            "Legacy aliases: low/balanced→normal, burst→high."
        ),
    )
    run_parser.add_argument("--dry-run", action="store_true", help="Dry-run mode (no network)")
    run_parser.add_argument("--target-net", default="10.10.10.0/24", help="Target CIDR")
    run_parser.add_argument(
        "--confirm-detection",
        action="store_true",
        help=(
            "Optional S3 detection confirmation after S2 validation. "
            "Default: manual evidence templates (no API). "
            "Does not affect exit code or ValidationResult."
        ),
    )
    run_parser.add_argument(
        "--detection-provider",
        default="stellar",
        help="Detection provider for --confirm-detection (default: stellar)",
    )
    run_parser.add_argument(
        "--stellar-client",
        default="manual",
        choices=["manual", "mock", "http"],
        help=(
            "S3 confirmation mode (default: manual). "
            "'manual' writes operator evidence templates (no API); "
            "'mock' uses deterministic local Stellar responses (CI/demo); "
            "'http' queries a live Stellar API (experimental — see docs/experimental/)."
        ),
    )
    run_parser.add_argument(
        "--execution-provider",
        default="local",
        choices=["local", "webshell"],
        help="Execution provider: local (in-process) or webshell (remote host).",
    )
    run_parser.add_argument(
        "--webshell-family",
        choices=["jsp", "php", "aspx"],
        help="Webshell family (required when --execution-provider=webshell).",
    )
    run_parser.add_argument(
        "--webshell-url",
        help="Webshell endpoint URL (required when --execution-provider=webshell).",
    )
    run_parser.add_argument(
        "--remote-work-dir",
        default="/tmp/dsp",
        help="Remote working directory for webshell bundle output (default: /tmp/dsp).",
    )
    run_parser.add_argument(
        "--verify-tls",
        action="store_true",
        help="Verify TLS certificates for webshell HTTP transport.",
    )
    run_parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress operational progress output (advanced/debug).",
    )
    run_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Emit detailed per-action progress (every probe, request, and query).",
    )
    run_parser.add_argument(
        "--allow-large-target",
        action="store_true",
        help="Allow --target-net larger than /24 (requires --max-hosts).",
    )
    run_parser.add_argument(
        "--enable-host-behavior-check",
        action="store_true",
        help=(
            "Deprecated — host_behavior_check is always included in webshell "
            "attack-chain runs (Phase 1 required)."
        ),
    )
    run_parser.add_argument(
        "--max-hosts",
        type=int,
        default=None,
        help="Cap discovered hosts for target-net expansion and scenario selection.",
    )
    run_parser.epilog = _DETECTION_EPILOG
    run_parser.formatter_class = argparse.RawDescriptionHelpFormatter

    plugins_parser = sub.add_parser("plugins", help="Plugin management")
    plugins_sub = plugins_parser.add_subparsers(dest="plugins_command", required=True)
    plugins_sub.add_parser("list", help="List discovered plugins")

    report_parser = sub.add_parser("report", help="Regenerate report from run artifacts")
    report_parser.add_argument("--run-id", required=True, help="Run ID to regenerate")

    args = parser.parse_args(argv)

    if args.command == "run":
        manager = RunManager()
        try:
            validate_target_net_scope(
                args.target_net,
                allow_large_target=args.allow_large_target,
                max_hosts=args.max_hosts,
            )
            scenario_ids, scenario_params, operational_profile = _resolve_run_plan(
                manager,
                scenarios_arg=args.scenarios,
                profile_arg=args.profile,
                target_net=args.target_net,
                max_hosts=args.max_hosts,
                execution_provider=args.execution_provider,
            )
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

        console = OperationalConsole(
            provider=args.execution_provider,
            target_net=args.target_net,
            profile=operational_profile,
        )
        on_progress = None if args.quiet else console.handle_progress

        run, run_dir, exit_code = manager.run(
            scenario_ids=scenario_ids,
            target_net=args.target_net,
            dry_run=args.dry_run,
            scenario_params=scenario_params,
            confirm_detection=args.confirm_detection,
            detection_provider=args.detection_provider,
            stellar_client=args.stellar_client,
            execution_provider=args.execution_provider,
            webshell_family=args.webshell_family,
            webshell_url=args.webshell_url,
            remote_work_dir=args.remote_work_dir,
            verify_tls=args.verify_tls,
            operational_profile=operational_profile,
            on_progress=on_progress,
            max_hosts=args.max_hosts,
            verbose=args.verbose,
        )

        if not args.quiet:
            console.print_evidence_summary(run_dir)

        if args.quiet:
            print(f"Run {run.run_id} status={run.status.value} dir={run_dir}")
        return exit_code

    if args.command == "plugins":
        if args.plugins_command == "list":
            loader = PluginLoader()
            registry = loader.discover_and_load()
            for record in registry.all():
                print(f"{record.id}\t{record.status.value}\t{record.status_reason or ''}")
            return 0

    if args.command == "report":
        manager = RunManager()
        path = manager.regenerate_report(args.run_id)
        print(f"Report regenerated: {path}")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
