"""ORCA CLI entry point."""

import argparse
import sys
from typing import Optional

from orca import __version__
from orca.checks import ALL_CHECKS
from orca.core import Scanner
from orca.discover import discover_hosts, expand_network
from orca.findings import Severity
from orca.reporters import ConsoleReporter, JSONReporter, HTMLReporter
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
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    # Discovery mode
    parser.add_argument("--discover", action="store_true", help="Discovery mode: scan networks/hosts for Odoo instances")
    parser.add_argument("-t", "--target", help="Target IP, CIDR range, or hostname (e.g., 10.0.0.0/16)")
    parser.add_argument("--target-file", help="File containing list of hosts/IPs (one per line)")
    parser.add_argument("--ports", default="80,443,8069,8080,8443", help="Comma-separated ports to probe (default: 80,443,8069,8080,8443)")
    parser.add_argument("--probe-xmlrpc", action="store_true", default=True, help="Confirm ambiguous hosts with XML-RPC version probe")
    parser.add_argument("--shadow-hunt", action="store_true", help="Flag shadow/dev instances (requires --discover)")

    # Standard scan mode
    parser.add_argument("-u", "--url", help="Target Odoo URL")
    parser.add_argument("-D", "--database", help="Database name (for authenticated checks)")
    parser.add_argument("-U", "--username", help="Username (for authenticated checks)")
    parser.add_argument("-P", "--password", nargs="?", const="", help="Password (for authenticated checks)")

    parser.add_argument("--checks", help="Comma-separated list of checks to run (default: all)")
    parser.add_argument("--skip-checks", help="Comma-separated list of checks to skip")
    parser.add_argument("--min-severity", choices=[s.value for s in Severity], help="Minimum severity to report")

    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument("--format", choices=["console", "json", "html", "csv"], default="console", help="Output format")

    parser.add_argument("--rate", type=float, help="Max requests per second")
    parser.add_argument("--jitter", type=float, help="Request jitter percentage")
    parser.add_argument("--threads", type=int, default=10, help="Concurrent check threads")
    parser.add_argument("--proxy", help="HTTP proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificates")

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
        console.print("[red][-][/red] Discovery mode requires --target or --target-file")
        return 1

    ports = [int(p.strip()) for p in args.ports.split(",")]
    threads = args.threads
    timeout = args.timeout

    console.print(f"[cyan][*][/cyan] Starting discovery on {len(hosts)} host(s), ports {ports}")
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
        console.print(f"[green][HIGH][/green] {r.url}  |  ver={r.version or '?'}  |  title='{r.title or '?'}'  |  db='{r.db_hint or '?'}'  |  werkzeug={r.werkzeug}  |  waf={r.waf or 'none'}")
    for r in med:
        console.print(f"[yellow][MED][/yellow]  {r.url}  |  ver={r.version or '?'}  |  title='{r.title or '?'}'")
    for r in low:
        console.print(f"[dim][LOW][/dim]   {r.url}")

    # Shadow hunt
    if args.shadow_hunt:
        console.print(f"\n[cyan][*][/cyan] Running shadow-hunt probes on {len(results)} discovered host(s)...")
        shadow_results = hunt_shadow_instances(
            urls=[r.url for r in results],
            threads=args.threads,
            timeout=args.timeout,
        )
        if shadow_results:
            console.print(f"\n[red][!][/red] Found {len(shadow_results)} potential shadow/dev instance(s):\n")
            for sr in shadow_results:
                color = "red" if sr.confidence == "high" else "yellow" if sr.confidence == "medium" else "white"
                console.print(f"[{color}][{sr.confidence.upper()}][/[{color}]] {sr.url}")
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
                writer = csv.DictWriter(f, fieldnames=["url", "version", "title", "db_hint", "werkzeug", "waf", "confidence", "response_time_ms"])
                writer.writeheader()
                for r in results:
                    writer.writerow(r.to_dict())
        else:
            with open(args.output, "w") as f:
                for r in results:
                    f.write(f"{r.confidence}\t{r.url}\t{r.version or ''}\t{r.title or ''}\n")
        console.print(f"\n[green][+][/green] Results saved to {args.output}")

    return 0


def main() -> None:
    if "--help" in sys.argv or "-h" in sys.argv or "--version" in sys.argv:
        from rich.console import Console
        print_banner(Console(), __version__)

    args = parse_arguments()

    if args.discover:
        sys.exit(run_discovery(args))

    if not args.url:
        print("Error: --url is required (or use --discover for network scanning)")
        sys.exit(1)

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

    result = scanner.run()

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
        with open(args.output or "orca_report.csv", "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["check", "severity", "title", "description", "request", "response_status", "remediation"])
            for finding in result.findings:
                ev = finding.evidence
                writer.writerow([
                    finding.check_name,
                    finding.severity.value,
                    finding.title,
                    finding.description,
                    ev.request,
                    ev.response_status,
                    finding.remediation,
                ])
        print(f"[+] CSV report saved to {args.output or 'orca_report.csv'}")

    # Exit code based on highest severity
    severities = [f.severity for f in result.findings]
    if Severity.CRITICAL in severities:
        sys.exit(3)
    elif Severity.HIGH in severities:
        sys.exit(2)
    elif Severity.MEDIUM in severities:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
