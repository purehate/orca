"""Structured models for AI-assisted finding review."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List

VALID_VERDICTS = {"confirmed", "likely", "false_positive", "needs_manual"}
VALID_GATE_STATUSES = {"pass", "fail", "unknown"}
REQUIRED_GATES = (
    "observed_behavior",
    "reachability",
    "authorization_context",
    "exploitability",
    "impact",
    "false_positive_checks",
)


@dataclass(frozen=True)
class ValidationGate:
    """One evidence gate used to constrain an AI verdict."""

    name: str
    status: str
    evidence: str


@dataclass(frozen=True)
class FindingReview:
    """An advisory review linked to one deterministic scanner finding."""

    finding_id: str
    fingerprint: str
    verdict: str
    confidence: float
    summary: str
    root_cause_hypothesis: str
    attack_path: str
    prerequisites: List[str]
    impact: str
    reproduction_steps: List[str]
    remediation_steps: List[str]
    legitimate_behavior_checks: List[str]
    uncertainty: List[str]
    gates: List[ValidationGate]
    prompt_sha256: str
    response_sha256: str
    response_file: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AIReviewReport:
    """Aggregate status for one advisory model pass."""

    provider: str
    model: str
    prompt_version: str
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    completed_at: str = ""
    status: str = "running"
    reviews: List[FindingReview] = field(default_factory=list)
    errors: List[Dict[str, str]] = field(default_factory=list)
    skipped_findings: int = 0

    def finish(self) -> None:
        self.completed_at = datetime.now(timezone.utc).isoformat()
        if self.errors and self.reviews:
            self.status = "partial"
        elif self.errors:
            self.status = "failed"
        else:
            self.status = "complete"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "prompt_version": self.prompt_version,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "status": self.status,
            "reviews": [review.to_dict() for review in self.reviews],
            "errors": list(self.errors),
            "skipped_findings": self.skipped_findings,
        }
