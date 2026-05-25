"""Rich-based console reporter."""

from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from orca.findings import Finding, ScanResult, Severity


class ConsoleReporter:
    def __init__(self):
        self.console = Console()

    def print_banner(self, version: str) -> None:
        banner = Text()
        banner.append("    ____  _____   ______   ____\n", style="bold cyan")
        banner.append("   / __ \\/ ___/  / ____/  / __ \\\n", style="bold cyan")
        banner.append("  / /_/ /\\__ \\  / /      / /_/ /\n", style="bold cyan")
        banner.append(" / _, _/___/ / / /___   / _, _/\n", style="bold cyan")
        banner.append("/_/ |_|/____/  \\____/  /_/ |_|\n", style="bold cyan")
        banner.append(f"  Odoo Recon & Configuration Analyzer v{version}\n", style="dim")
        self.console.print(banner)

    def print_result(self, result: ScanResult) -> None:
        target = result.target
        self.console.print(Panel.fit(
            f"[bold]Target:[/bold] {target.url}\n"
            f"[bold]Version:[/bold] {target.version or 'Unknown'}\n"
            f"[bold]Databases:[/bold] {', '.join(target.databases) if target.databases else 'None detected'}\n"
            f"[bold]Modules:[/bold] {len(target.detected_modules)} detected\n"
            f"[bold]WAF:[/bold] {target.waf_detected or 'None detected'}",
            title="Scan Summary",
            border_style="blue",
        ))

        if not result.findings:
            self.console.print("[green]No findings.[/green]")
            return

        # Group by severity
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            findings = result.findings_by_severity(sev)
            if not findings:
                continue
            self._print_findings_table(sev, findings)

        total = len(result.findings)
        self.console.print(f"\n[bold]{total} finding(s) reported.[/bold]")

    def _print_findings_table(self, severity: Severity, findings: List[Finding]) -> None:
        color = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "green",
            Severity.INFO: "blue",
        }.get(severity, "white")

        table = Table(title=f"{severity.value.upper()} ({len(findings)})", style=color)
        table.add_column("Check", style="dim", no_wrap=True)
        table.add_column("Title", no_wrap=False)
        table.add_column("Evidence", style="dim", no_wrap=False)

        for f in findings:
            ev = f.evidence
            evidence_text = f"HTTP {ev.response_status}"
            if ev.notes:
                evidence_text += f" | {ev.notes}"
            table.add_row(f.check_name, f.title, evidence_text)

        self.console.print(table)
