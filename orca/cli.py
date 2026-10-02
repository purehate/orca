"""ORCA CLI entry point."""

import argparse
import os
import re
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from orca import __version__
from orca.ai.analyzer import redact_untrusted_text
from orca.baseline import (
    BaselineError,
    ScanDelta,
    compare_to_baseline,
    findings_for_review,
)
from orca.checks import ALL_CHECKS
from orca.core import Scanner
from orca.discover import discover_hosts, expand_network
from orca.findings import ScanResult, Severity
from orca.reporters import ConsoleReporter, HTMLReporter, JSONReporter
from orca.shadow_hunt import hunt_shadow_instances
from orca.target import Target
from orca.utils.banner import print_banner


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ORCA — Odoo Recon & Configuration Analyzer (unauthenticated frontend scanner)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
        "  orca -u https://target.odoo.com\n"
        "  orca --discover -t 10.0.0.0/24 --shadow-hunt\n"
        "  orca -u https://target.odoo.com --format html -o report.html",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    # Discovery mode
    parser.add_argument(
        "--discover",
        action="store_true",
        help="Discovery mode: scan networks/hosts for Odoo instances",
    )
    parser.add_argument(
        "-t", "--target", help="Target IP, CIDR range, or hostname (e.g., 10.0.0.0/16)"
    )
    parser.add_argument(
        "--target-file", help="File containing list of hosts/IPs (one per line)"
    )
    parser.add_argument(
        "--ports",
        default="80,443,8069,8080,8443",
        help="Comma-separated ports to probe (default: 80,443,8069,8080,8443)",
    )
    parser.add_argument(
        "--probe-xmlrpc",
        action="store_true",
        default=True,
        help="Confirm ambiguous hosts with XML-RPC version probe",
    )
    parser.add_argument(
        "--shadow-hunt",
        action="store_true",
        help="Flag shadow/dev instances (requires --discover)",
    )

    # Standard scan mode
    parser.add_argument("-u", "--url", help="Target Odoo URL")
    parser.add_argument(
        "-D", "--database", help="Database name (for authenticated checks)"
    )
    parser.add_argument("-U", "--username", help="Username (for authenticated checks)")
    parser.add_argument(
        "-P",
        "--password",
        nargs="?",
        const="",
        help="Password (for authenticated checks)",
    )

    parser.add_argument(
        "--checks", help="Comma-separated list of checks to run (default: all)"
    )
    parser.add_argument("--skip-checks", help="Comma-separated list of checks to skip")
    parser.add_argument(
        "--min-severity",
        choices=[s.value for s in Severity],
        help="Minimum severity to report",
    )
    parser.add_argument(
        "--include-path",
        action="append",
        default=[],
        help="Authorized same-origin path to assess; repeat for multiple paths",
    )
    parser.add_argument(
        "--crawl",
        action="store_true",
        help="Crawl same-origin links and inventory forms/API references with GET requests only",
    )
    parser.add_argument(
        "--crawl-max-pages",
        type=int,
        default=50,
        help="Maximum pages fetched by the crawler (default: 50, maximum: 200)",
    )
    parser.add_argument(
        "--crawl-depth",
        type=int,
        default=2,
        help="Maximum link depth from each included path (default: 2, maximum: 5)",
    )

    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument(
        "--format",
        choices=["console", "json", "html", "csv"],
        default="console",
        help="Output format",
    )

    parser.add_argument("--rate", type=float, help="Max requests per second")
    parser.add_argument("--jitter", type=float, help="Request jitter percentage")
    parser.add_argument(
        "--threads", type=int, default=10, help="Concurrent check threads"
    )
    parser.add_argument("--proxy", help="HTTP proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument(
        "--timeout", type=int, default=15, help="Request timeout in seconds"
    )
    parser.add_argument(
        "--verify-ssl", action="store_true", help="Verify SSL certificates"
    )

    # Advisory AI review
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Review deterministic findings with a local or private model and write an evidence packet",
    )
    parser.add_argument(
        "--ai-provider",
        choices=["ollama", "openai-compatible"],
        default=os.environ.get("ORCA_AI_PROVIDER", "ollama"),
        help="Model API type (default: ORCA_AI_PROVIDER or ollama)",
    )
    parser.add_argument(
        "--ai-model",
        default=os.environ.get("ORCA_AI_MODEL"),
        help="Model name (default: ORCA_AI_MODEL or qwen3:0.6b for Ollama)",
    )
    parser.add_argument(
        "--ai-endpoint",
        default=os.environ.get("ORCA_AI_ENDPOINT"),
        help="Model API base URL (required for openai-compatible providers)",
    )
    parser.add_argument(
        "--ai-api-key-env",
        default="ORCA_AI_API_KEY",
        help="Environment variable containing the model API key; its value is never persisted",
    )
    parser.add_argument(
        "--ai-timeout",
        type=float,
        default=180.0,
        help="Seconds allowed for each model review",
    )
    parser.add_argument(
        "--ai-max-findings",
        type=int,
        default=25,
        help="Maximum findings reviewed by the model, highest severity first",
    )
    parser.add_argument(
        "--evidence-dir",
        help="Directory for scan facts, review state, hashes, and replay guide (--ai default: scans/<host>/<UTC-timestamp>/orca); writes a pending packet when --ai is omitted",
    )
    parser.add_argument(
        "--baseline",
        help="Prior scan.json or evidence directory used to classify new, fixed, and changed findings",
    )
    parser.add_argument(
        "--fail-on-new",
        choices=[severity.value for severity in Severity if severity != Severity.INFO],
        help="Exit non-zero only for new or severity-increased findings at or above this level",
    )

    return parser.parse_args()


def resolve_checks(args: argparse.Namespace):
    check_map = {c.name: c for c in ALL_CHECKS}
    checks = list(ALL_CHECKS)
    if args.checks:
        names = [n.strip() for n in args.checks.split(",")]
        checks = [check_map[n] for n in names if n in check_map]
    if args.skip_checks:
        skip = {n.strip() for n in args.skip_checks.split(",")}
        checks = [c for c in checks if c.name not in skip]
    return checks


def _validate_scan_scope(args: argparse.Namespace) -> Optional[str]:
    """Validate bounded crawler inputs before any network traffic occurs."""
    if not 1 <= args.crawl_max_pages <= 200:
        return "--crawl-max-pages must be between 1 and 200"
    if not 0 <= args.crawl_depth <= 5:
        return "--crawl-depth must be between 0 and 5"
    for path in args.include_path:
        parsed = urlparse(path)
        if (
            not path.startswith("/")
            or parsed.scheme
            or parsed.netloc
            or ".." in parsed.path
            or any(character in path for character in ("\r", "\n", "\x00"))
        ):
            return f"--include-path must be a safe same-origin absolute path: {path!r}"
    if args.crawl:
        if args.rate is None:
            args.rate = 1.0
        elif args.rate <= 0 or args.rate > 5:
            return "crawler rate must be greater than 0 and no more than 5 requests/second"
    return None


def run_discovery(args: argparse.Namespace) -> int:
    from rich.console import Console

    console = Console()

    hosts = []
    if args.target:
        if "/" in args.target:
            console.print(f"[cyan][*][/cyan] Expanding network {args.target}...")
            hosts = expand_network(args.target)
            console.print(f"[cyan][*][/cyan] {len(hosts)} hosts to probe")
        else:
            hosts = [args.target]
    elif args.target_file:
        with open(args.target_file, "r") as f:
            hosts = [line.strip() for line in f if line.strip()]
    else:
        console.print(
            "[red][-][/red] Discovery mode requires --target or --target-file"
        )
        return 1

    ports = [int(p.strip()) for p in args.ports.split(",")]
    threads = args.threads
    timeout = args.timeout

    console.print(
        f"[cyan][*][/cyan] Starting discovery on {len(hosts)} host(s), ports {ports}"
    )
    console.print(f"[cyan][*][/cyan] Threads: {threads}, Timeout: {timeout}s")

    results = discover_hosts(
        hosts=hosts,
        ports=ports,
        threads=threads,
        timeout=timeout,
        verify_ssl=args.verify_ssl,
        probe_xmlrpc=args.probe_xmlrpc,
    )

    if not results:
        console.print("[yellow][!][/yellow] No Odoo instances detected")
        return 0

    console.print(f"\n[green][+][/green] Found {len(results)} Odoo instance(s):\n")

    # Categorize
    high = [r for r in results if r.confidence == "high"]
    med = [r for r in results if r.confidence == "medium"]
    low = [r for r in results if r.confidence == "low"]

    for r in high:
        console.print(
            f"[green][HIGH][/green] {r.url}  |  ver={r.version or '?'}  |  title='{r.title or '?'}'  |  db='{r.db_hint or '?'}'  |  werkzeug={r.werkzeug}  |  waf={r.waf or 'none'}"
        )
    for r in med:
        console.print(
            f"[yellow][MED][/yellow]  {r.url}  |  ver={r.version or '?'}  |  title='{r.title or '?'}'"
        )
    for r in low:
        console.print(f"[dim][LOW][/dim]   {r.url}")

    # Shadow hunt
    if args.shadow_hunt:
        console.print(
            f"\n[cyan][*][/cyan] Running shadow-hunt probes on {len(results)} discovered host(s)..."
        )
        shadow_results = hunt_shadow_instances(
            urls=[r.url for r in results],
            threads=args.threads,
            timeout=args.timeout,
        )
        if shadow_results:
            console.print(
                f"\n[red][!][/red] Found {len(shadow_results)} potential shadow/dev instance(s):\n"
            )
            for sr in shadow_results:
                color = (
                    "red"
                    if sr.confidence == "high"
                    else "yellow"
                    if sr.confidence == "medium"
                    else "white"
                )
                console.print(
                    f"[{color}][{sr.confidence.upper()}][/[{color}]] {sr.url}"
                )
                for note in sr.notes:
                    console.print(f"    - {note}")
                console.print()
        else:
            console.print("\n[green][+][/green] No shadow/dev indicators detected")

    if args.output:
        if args.format == "json":
            import json

            out = json.dumps([r.to_dict() for r in results], indent=2)
            with open(args.output, "w") as f:
                f.write(out)
        elif args.format == "csv":
            import csv

            with open(args.output, "w", newline="") as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=[
                        "url",
                        "version",
                        "title",
                        "db_hint",
                        "werkzeug",
                        "waf",
                        "confidence",
                        "response_time_ms",
                    ],
                )
                writer.writeheader()
                for r in results:
                    writer.writerow(r.to_dict())
        else:
            with open(args.output, "w") as f:
                for r in results:
                    f.write(
                        f"{r.confidence}\t{r.url}\t{r.version or ''}\t{r.title or ''}\n"
                    )
        console.print(f"\n[green][+][/green] Results saved to {args.output}")

    return 0


def _build_replay_command(args: argparse.Namespace) -> str:
    """Build a shell-safe replay command that never contains credentials."""
    command = ["orca", "--url", redact_untrusted_text(args.url, 1_000)]
    value_options = (
        ("--checks", args.checks),
        ("--skip-checks", args.skip_checks),
        ("--min-severity", args.min_severity),
        ("--rate", args.rate),
        ("--jitter", args.jitter),
        ("--threads", args.threads),
        ("--timeout", args.timeout),
        ("--crawl-max-pages", args.crawl_max_pages),
        ("--crawl-depth", args.crawl_depth),
    )
    for flag, value in value_options:
        if value is not None:
            command.extend([flag, str(value)])
    if args.verify_ssl:
        command.append("--verify-ssl")
    for path in args.include_path:
        command.extend(["--include-path", path])
    if args.crawl:
        command.append("--crawl")
    command.extend(["--format", "json", "--output", "replay-scan.json"])
    return shlex.join(command)


def _default_evidence_dir(url: str) -> Path:
    """Return the gitignored scans/<host>/<UTC-timestamp>/orca packet path."""
    # A path-like host such as ".." must not escape the scans/ tree.
    host = re.sub(r"[^a-z0-9.-]", "_", urlparse(url).hostname or "").strip(".")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path("scans", host or "target", timestamp, "orca")


def _run_ai_review(
    args: argparse.Namespace,
    result: ScanResult,
    delta: Optional[ScanDelta] = None,
) -> Optional[Path]:
    """Run advisory review and persist a complete evidence packet."""
    from rich.console import Console

    from orca.ai import AIAnalyzer, EvidencePacketWriter, build_client

    console = Console()
    model = args.ai_model or "qwen3:0.6b"
    try:
        client = build_client(
            provider=args.ai_provider,
            model=model,
            endpoint=args.ai_endpoint,
            api_key_env=args.ai_api_key_env,
            timeout=args.ai_timeout,
        )
        analyzer = AIAnalyzer(client, max_findings=args.ai_max_findings)
        review_input = findings_for_review(result, delta) if delta else result
        review, prompts, responses = analyzer.review(review_input)
        output_dir = Path(args.evidence_dir or _default_evidence_dir(result.target.url))
        manifest = EvidencePacketWriter().write(
            output_dir=output_dir,
            result=result,
            review=review,
            prompts=prompts,
            responses=responses,
            replay_command=_build_replay_command(args),
            delta=delta,
        )
    except (ValueError, OSError) as exc:
        error = redact_untrusted_text(str(exc), 2_000)
        console.print(f"[red][-][/red] AI review could not be completed: {error}")
        return None

    color = "green" if review.status == "complete" else "yellow"
    console.print(
        f"[{color}][+][/{color}] AI review {review.status}; evidence packet: {manifest.parent}"
    )
    return manifest


def _write_pending_agent_packet(
    args: argparse.Namespace,
    result: ScanResult,
    delta: Optional[ScanDelta] = None,
) -> Optional[Path]:
    """Write deterministic evidence for review by the connected agent."""
    from rich.console import Console

    from orca.ai import AIReviewReport, EvidencePacketWriter

    console = Console()
    review = AIReviewReport(
        provider="connected-agent",
        model="not-recorded",
        prompt_version="agent-review-v1",
        status="pending",
    )
    try:
        manifest = EvidencePacketWriter().write(
            output_dir=Path(args.evidence_dir),
            result=result,
            review=review,
            prompts={},
            responses={},
            replay_command=_build_replay_command(args),
            delta=delta,
        )
    except OSError as exc:
        error = redact_untrusted_text(str(exc), 2_000)
        console.print(f"[red][-][/red] Evidence packet could not be written: {error}")
        return None

    console.print(
        "[green][+][/green] Evidence packet ready for connected-agent review: "
        f"{manifest.parent}"
    )
    return manifest


def _exit_code(findings) -> int:
    severities = [finding.severity for finding in findings]
    if Severity.CRITICAL in severities:
        return 3
    if Severity.HIGH in severities:
        return 2
    if Severity.MEDIUM in severities:
        return 1
    return 0


def main() -> None:
    if "--help" in sys.argv or "-h" in sys.argv or "--version" in sys.argv:
        from rich.console import Console

        print_banner(Console(), __version__)

    args = parse_arguments()

    if args.fail_on_new and not args.baseline:
        print("Error: --fail-on-new requires --baseline")
        sys.exit(4)

    if args.discover:
        sys.exit(run_discovery(args))

    if not args.url:
        print("Error: --url is required (or use --discover for network scanning)")
        sys.exit(1)

    scope_error = _validate_scan_scope(args)
    if scope_error:
        print(f"Error: {scope_error}")
        sys.exit(4)

    reporter = ConsoleReporter()
    print_banner(reporter.console, __version__)

    target = Target(
        url=args.url,
        rate_limit=args.rate,
        jitter=args.jitter,
        proxy=args.proxy,
        verify_ssl=args.verify_ssl,
    )

    checks = resolve_checks(args)
    min_sev = Severity(args.min_severity) if args.min_severity else None

    scanner = Scanner(
        target=target,
        checks=checks,
        min_severity=min_sev,
        threads=args.threads,
    )
    scanner.result.scan_config.update(
        {
            "include_paths": list(args.include_path),
            "crawl": args.crawl,
            "crawl_max_pages": args.crawl_max_pages,
            "crawl_depth": args.crawl_depth,
            "rate": args.rate,
        }
    )

    result = scanner.run()

    delta = None
    if args.baseline:
        try:
            delta = compare_to_baseline(result, Path(args.baseline))
        except BaselineError as exc:
            reporter.console.print(f"[red][-][/red] Baseline comparison failed: {exc}")
            sys.exit(4)
        reporter.console.print(
            "[cyan][*][/cyan] Baseline delta: "
            f"{len(delta.new)} new, {len(delta.fixed)} fixed, "
            f"{len(delta.changed)} changed, {len(delta.unchanged)} unchanged"
        )

    if args.ai:
        _run_ai_review(args, result, delta)
    elif args.evidence_dir:
        _write_pending_agent_packet(args, result, delta)

    if args.format == "console":
        reporter.print_result(result)
    elif args.format == "json":
        out = JSONReporter().generate(result)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
            print(f"[+] JSON report saved to {args.output}")
        else:
            print(out)
    elif args.format == "html":
        out = HTMLReporter().generate(result)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(out)
            print(f"[+] HTML report saved to {args.output}")
        else:
            print(out)
    elif args.format == "csv":
        import csv

        with open(
            args.output or "orca_report.csv", "w", newline="", encoding="utf-8"
        ) as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "check",
                    "severity",
                    "title",
                    "description",
                    "request",
                    "response_status",
                    "remediation",
                ]
            )
            for finding in result.findings:
                ev = finding.evidence
                writer.writerow(
                    [
                        finding.check_name,
                        finding.severity.value,
                        finding.title,
                        finding.description,
                        ev.request,
                        ev.response_status,
                        finding.remediation,
                    ]
                )
        print(f"[+] CSV report saved to {args.output or 'orca_report.csv'}")

    if args.fail_on_new:
        assert delta is not None
        blocking = delta.blocking_fingerprints(Severity(args.fail_on_new))
        findings = [
            finding for finding in result.findings if finding.fingerprint in blocking
        ]
        code = _exit_code(findings)
        sys.exit(code or (1 if findings else 0))
    sys.exit(_exit_code(result.findings))


if __name__ == "__main__":
    main()
