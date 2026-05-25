"""ORCA scanner engine."""

from __future__ import annotations

import signal
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Type

from rich.console import Console

from orca.checks.base import BaseCheck
from orca.checks import ALL_CHECKS
from orca.findings import ScanResult, Severity, TargetMeta
from orca.target import Target


console = Console()


def on_sigint(signum, frame):
    console.print("\n[yellow][!][/yellow] [white]Interrupted by user. Exiting...[/white]")
    sys.exit(0)


signal.signal(signal.SIGINT, on_sigint)


class Scanner:
    def __init__(
        self,
        target: Target,
        checks: Optional[List[Type[BaseCheck]]] = None,
        min_severity: Optional[Severity] = None,
        threads: int = 10,
    ):
        self.target = target
        self.checks = checks or ALL_CHECKS
        self.min_severity = min_severity
        self.threads = threads
        self.result = ScanResult(
            target=TargetMeta(url=target.url),
            scan_config={
                "threads": threads,
                "min_severity": min_severity.value if min_severity else None,
            },
        )

    def run(self) -> ScanResult:
        console.print(f"[cyan][*][/cyan] Starting scan of {self.target.url}")
        console.print(f"[cyan][*][/cyan] Running {len(self.checks)} check(s) with {self.threads} thread(s)")

        # Separate auth-required checks if we have no auth (skip them)
        auth_checks = [c for c in self.checks if c.requires_auth]
        no_auth_checks = [c for c in self.checks if not c.requires_auth]

        if auth_checks:
            console.print(f"[yellow][!][/yellow] Skipping {len(auth_checks)} auth-required check(s) (no credentials provided)")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for check_cls in no_auth_checks:
                instance = check_cls(self.target, self.result)
                future = executor.submit(instance.run)
                futures[future] = check_cls.name

            for future in as_completed(futures):
                name = futures[future]
                try:
                    future.result()
                    console.print(f"[green][+][/green] Check '{name}' completed")
                except Exception as exc:
                    console.print(f"[red][-][/red] Check '{name}' failed: {exc}")

        self.result.completed_at = __import__("datetime").datetime.utcnow().isoformat() + "Z"
        # Filter by min severity if set
        if self.min_severity:
            self.result.findings = [f for f in self.result.findings if f.severity >= self.min_severity]

        return self.result
