"""Cross-run finding comparison for recurring ORCA assessments."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Set

from orca.findings import ScanResult, Severity


class BaselineError(ValueError):
    """Raised when a baseline cannot be interpreted as an ORCA scan."""


@dataclass(frozen=True)
class ScanDelta:
    """Stable-fingerprint comparison between a previous and current scan."""

    baseline_path: str
    new: List[Dict[str, Any]]
    fixed: List[Dict[str, Any]]
    changed: List[Dict[str, Any]]
    unchanged: List[Dict[str, Any]]

    @property
    def review_fingerprints(self) -> Set[str]:
        fingerprints = {item["fingerprint"] for item in self.new}
        fingerprints.update(item["fingerprint"] for item in self.changed)
        return fingerprints

    def blocking_fingerprints(self, minimum: Severity) -> Set[str]:
        """Return new or severity-increased findings at or above a threshold."""
        blocking = {
            item["fingerprint"]
            for item in self.new
            if Severity(item["severity"]) >= minimum
        }
        for item in self.changed:
            before = Severity(item["before"]["severity"])
            after = Severity(item["after"]["severity"])
            if after > before and after >= minimum:
                blocking.add(item["fingerprint"])
        return blocking

    def to_dict(self) -> Dict[str, Any]:
        return {
            "baseline_path": self.baseline_path,
            "summary": {
                "new": len(self.new),
                "fixed": len(self.fixed),
                "changed": len(self.changed),
                "unchanged": len(self.unchanged),
            },
            "new": self.new,
            "fixed": self.fixed,
            "changed": self.changed,
            "unchanged": self.unchanged,
        }


def _fingerprint(record: Dict[str, Any]) -> str:
    existing = record.get("fingerprint")
    if isinstance(existing, str) and existing:
        return existing
    evidence = record.get("evidence")
    evidence = evidence if isinstance(evidence, dict) else {}
    identity = {
        "check_name": record.get("check_name", ""),
        "title": record.get("title", ""),
        "target": record.get("target", ""),
        "request": evidence.get("request", ""),
    }
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _normalize(record: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(record)
    normalized["fingerprint"] = _fingerprint(record)
    normalized.setdefault("id", f"ORCA-{normalized['fingerprint'][:12].upper()}")
    return normalized


def _material_view(record: Dict[str, Any]) -> Dict[str, Any]:
    evidence = record.get("evidence")
    evidence = evidence if isinstance(evidence, dict) else {}
    return {
        "severity": record.get("severity"),
        "description": record.get("description"),
        "remediation": record.get("remediation"),
        "response_status": evidence.get("response_status"),
    }


def load_baseline(path: Path) -> Dict[str, Any]:
    """Load findings from an evidence directory or scan JSON file."""
    scan_path = path / "scan.json" if path.is_dir() else path
    try:
        with scan_path.open(encoding="utf-8") as handle:
            payload = json.load(handle)
    except json.JSONDecodeError as exc:
        raise BaselineError(f"Baseline is not valid JSON: {scan_path}") from exc
    except OSError as exc:
        raise BaselineError(f"Could not read baseline: {scan_path}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("findings"), list):
        raise BaselineError("Baseline must be an ORCA scan object with a findings list")
    findings = payload["findings"]
    if not all(isinstance(item, dict) for item in findings):
        raise BaselineError("Every baseline finding must be an object")
    normalized = [_normalize(item) for item in findings]
    valid_severities = {severity.value for severity in Severity}
    if any(item.get("severity") not in valid_severities for item in normalized):
        raise BaselineError("Every baseline finding must have a valid severity")
    fingerprints = [item["fingerprint"] for item in normalized]
    if len(fingerprints) != len(set(fingerprints)):
        raise BaselineError("Baseline contains duplicate finding fingerprints")
    return {**payload, "findings": normalized}


def compare_to_baseline(result: ScanResult, path: Path) -> ScanDelta:
    """Compare current deterministic findings with a prior scan."""
    payload = load_baseline(path)
    baseline_target = payload.get("target", {})
    baseline_target = (
        baseline_target.get("url") if isinstance(baseline_target, dict) else None
    )
    if (
        baseline_target
        and result.target.url
        and baseline_target.rstrip("/") != result.target.url.rstrip("/")
    ):
        raise BaselineError("Baseline target does not match the current scan target")
    baseline = {_fingerprint(item): item for item in payload["findings"]}
    current_records = [_normalize(finding.to_dict()) for finding in result.findings]
    current = {item["fingerprint"]: item for item in current_records}

    new = [current[key] for key in sorted(current.keys() - baseline.keys())]
    fixed = [baseline[key] for key in sorted(baseline.keys() - current.keys())]
    changed = []
    unchanged = []
    for key in sorted(current.keys() & baseline.keys()):
        before = baseline[key]
        after = current[key]
        if _material_view(before) != _material_view(after):
            changed.append({"fingerprint": key, "before": before, "after": after})
        else:
            unchanged.append(after)
    return ScanDelta(
        baseline_path=str(path),
        new=new,
        fixed=fixed,
        changed=changed,
        unchanged=unchanged,
    )


def findings_for_review(result: ScanResult, delta: ScanDelta) -> ScanResult:
    """Return a scan view limited to new and materially changed findings."""
    fingerprints = delta.review_fingerprints
    return ScanResult(
        target=result.target,
        findings=[
            finding
            for finding in result.findings
            if finding.fingerprint in fingerprints
        ],
        scan_config=dict(result.scan_config),
        started_at=result.started_at,
        completed_at=result.completed_at,
    )
