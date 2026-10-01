import json
from pathlib import Path

import pytest

from orca.baseline import BaselineError, compare_to_baseline, findings_for_review
from orca.findings import Evidence, Finding, ScanResult, Severity, TargetMeta


def _finding(title: str, severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        check_name="test",
        title=title,
        description=f"Description for {title}",
        severity=severity,
        remediation=f"Fix {title}",
        evidence=Evidence(request=f"GET /{title}", response_status=200),
        target="https://example.test",
    )


def _write_baseline(path: Path, findings) -> Path:
    path.mkdir()
    with (path / "scan.json").open("w", encoding="utf-8") as handle:
        json.dump({"findings": [finding.to_dict() for finding in findings]}, handle)
    return path


def test_compare_classifies_new_fixed_changed_and_unchanged(tmp_path: Path) -> None:
    unchanged = _finding("unchanged")
    fixed = _finding("fixed")
    changed_before = _finding("changed", Severity.LOW)
    changed_after = _finding("changed", Severity.HIGH)
    new = _finding("new")
    baseline = _write_baseline(
        tmp_path / "baseline", [unchanged, fixed, changed_before]
    )
    current = ScanResult(
        target=TargetMeta(url="https://example.test"),
        findings=[unchanged, changed_after, new],
    )

    delta = compare_to_baseline(current, baseline)

    assert [item["title"] for item in delta.new] == ["new"]
    assert [item["title"] for item in delta.fixed] == ["fixed"]
    assert [item["after"]["title"] for item in delta.changed] == ["changed"]
    assert [item["title"] for item in delta.unchanged] == ["unchanged"]


def test_legacy_baseline_without_fingerprints_is_supported(tmp_path: Path) -> None:
    finding = _finding("legacy")
    legacy = finding.to_dict()
    legacy.pop("id")
    legacy.pop("fingerprint")
    baseline_path = tmp_path / "scan.json"
    with baseline_path.open("w", encoding="utf-8") as handle:
        json.dump({"findings": [legacy]}, handle)

    delta = compare_to_baseline(ScanResult(findings=[finding]), baseline_path)

    assert len(delta.unchanged) == 1
    assert delta.new == []


def test_blocking_fingerprints_include_new_and_severity_increases(
    tmp_path: Path,
) -> None:
    changed_before = _finding("changed", Severity.LOW)
    changed_after = _finding("changed", Severity.HIGH)
    new_medium = _finding("new-medium", Severity.MEDIUM)
    baseline = _write_baseline(tmp_path / "baseline", [changed_before])
    result = ScanResult(findings=[changed_after, new_medium])

    delta = compare_to_baseline(result, baseline)

    assert delta.blocking_fingerprints(Severity.HIGH) == {changed_after.fingerprint}
    assert delta.blocking_fingerprints(Severity.MEDIUM) == {
        changed_after.fingerprint,
        new_medium.fingerprint,
    }


def test_review_scope_contains_only_new_and_changed_findings(tmp_path: Path) -> None:
    unchanged = _finding("unchanged")
    changed_before = _finding("changed", Severity.LOW)
    changed_after = _finding("changed", Severity.HIGH)
    new = _finding("new")
    baseline = _write_baseline(tmp_path / "baseline", [unchanged, changed_before])
    result = ScanResult(findings=[unchanged, changed_after, new])

    scoped = findings_for_review(result, compare_to_baseline(result, baseline))

    assert {finding.title for finding in scoped.findings} == {"changed", "new"}


def test_invalid_baseline_has_actionable_error(tmp_path: Path) -> None:
    baseline = tmp_path / "bad.json"
    with baseline.open("w", encoding="utf-8") as handle:
        handle.write("not json")

    with pytest.raises(BaselineError, match="not valid JSON"):
        compare_to_baseline(ScanResult(), baseline)


def test_baseline_target_must_match_current_target(tmp_path: Path) -> None:
    baseline = tmp_path / "scan.json"
    with baseline.open("w", encoding="utf-8") as handle:
        json.dump({"target": {"url": "https://other.test"}, "findings": []}, handle)

    with pytest.raises(BaselineError, match="target does not match"):
        compare_to_baseline(
            ScanResult(target=TargetMeta(url="https://example.test")), baseline
        )


def test_duplicate_fingerprints_are_rejected(tmp_path: Path) -> None:
    finding = _finding("duplicate")
    baseline = tmp_path / "scan.json"
    with baseline.open("w", encoding="utf-8") as handle:
        json.dump({"findings": [finding.to_dict(), finding.to_dict()]}, handle)

    with pytest.raises(BaselineError, match="duplicate"):
        compare_to_baseline(ScanResult(), baseline)
