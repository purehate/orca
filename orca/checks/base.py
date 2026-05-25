"""Base check class for ORCA."""

from abc import ABC, abstractmethod
from typing import List, Optional

from orca.findings import Evidence, Finding, ScanResult, Severity
from orca.target import Target


class BaseCheck(ABC):
    """Abstract base class for all ORCA security checks."""

    name: str = ""
    description: str = ""
    requires_auth: bool = False

    def __init__(self, target: Target, result: ScanResult):
        self.target = target
        self.result = result

    @abstractmethod
    def run(self) -> None:
        """Execute the check and append findings to self.result."""
        pass

    def add_finding(
        self,
        title: str,
        description: str,
        severity: Severity,
        remediation: str = "",
        request: str = "",
        response_snippet: str = "",
        response_status: int = 0,
        notes: str = "",
        cwe: str = "",
        references: Optional[List[str]] = None,
    ) -> None:
        finding = Finding(
            check_name=self.name,
            title=title,
            description=description,
            severity=severity,
            remediation=remediation,
            evidence=Evidence(
                request=request,
                response_snippet=response_snippet,
                response_status=response_status,
                notes=notes,
            ),
            cwe=cwe,
            references=references or [],
            target=self.target.url,
        )
        self.result.add_finding(finding)
