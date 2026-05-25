"""Structured finding model for ORCA scan results."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other: Severity) -> bool:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other: Severity) -> bool:
        return self == other or self < other

    def __gt__(self, other: Severity) -> bool:
        return not self <= other

    def __ge__(self, other: Severity) -> bool:
        return not self < other


@dataclass
class Evidence:
    """HTTP-level evidence for a finding."""
    request: str = ""
    response_snippet: str = ""
    response_status: int = 0
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """Single security finding."""
    check_name: str
    title: str
    description: str
    severity: Severity
    remediation: str = ""
    evidence: Evidence = field(default_factory=Evidence)
    cwe: str = ""
    references: List[str] = field(default_factory=list)
    target: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "check_name": self.check_name,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "remediation": self.remediation,
            "evidence": self.evidence.to_dict(),
            "cwe": self.cwe,
            "references": self.references,
            "target": self.target,
        }


@dataclass
class TargetMeta:
    """Metadata discovered about the target."""
    url: str = ""
    version: Optional[str] = None
    version_raw: Optional[Any] = None
    databases: List[str] = field(default_factory=list)
    detected_modules: List[str] = field(default_factory=list)
    waf_detected: Optional[str] = None
    tech_stack: List[str] = field(default_factory=list)
    session_cookie_name: str = "session_id"
    csrf_token_present: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "version": self.version,
            "version_raw": self.version_raw,
            "databases": self.databases,
            "detected_modules": self.detected_modules,
            "waf_detected": self.waf_detected,
            "tech_stack": self.tech_stack,
            "session_cookie_name": self.session_cookie_name,
            "csrf_token_present": self.csrf_token_present,
        }


@dataclass
class ScanResult:
    """Aggregated result of a complete scan."""
    target: TargetMeta = field(default_factory=TargetMeta)
    findings: List[Finding] = field(default_factory=list)
    scan_config: Dict[str, Any] = field(default_factory=dict)
    started_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    completed_at: Optional[str] = None

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def findings_by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "scan_config": self.scan_config,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)
