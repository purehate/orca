import argparse
import json
from pathlib import Path

from orca import ai as ai_package
from orca.cli import (
    _build_replay_command,
    _exit_code,
    _run_ai_review,
    _validate_scan_scope,
)
from orca.findings import Evidence, Finding, ScanResult, Severity, TargetMeta


def _finding() -> Finding:
    return Finding(
        check_name="idor",
        title="Unauthenticated record access",
        description="A record was returned without authentication.",
        severity=Severity.HIGH,
        evidence=Evidence(request="GET /web/content?id=7", response_status=200),
        target="https://example.test",
    )


def _model_response() -> str:
    return json.dumps(
        {
            "verdict": "likely",
            "confidence": 0.8,
            "summary": "Evidence supports an authorization concern.",
            "root_cause_hypothesis": "The route may omit a record check.",
            "attack_path": "Anonymous request reaches a record response.",
            "prerequisites": ["Network access to the target."],
            "impact": "A record may be disclosed.",
            "reproduction_steps": ["Repeat the request without a session."],
            "remediation_steps": ["Enforce record authorization."],
            "legitimate_behavior_checks": ["Owners can still fetch their record."],
            "uncertainty": ["Record sensitivity is not captured."],
            "gates": [
                {
                    "name": name,
                    "status": "pass",
                    "evidence": "Supported by captured data.",
                }
                for name in (
                    "observed_behavior",
                    "reachability",
                    "authorization_context",
                    "exploitability",
                    "impact",
                    "false_positive_checks",
                )
            ],
        }
    )


class _FakeClient:
    provider_name = "test"
    model = "test-model"

    def generate(self, prompt: str) -> str:
        return _model_response()


def test_run_ai_review_writes_evidence_packet(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setattr(ai_package, "build_client", lambda **kwargs: _FakeClient())
    args = argparse.Namespace(
        url="https://example.test",
        checks=None,
        skip_checks=None,
        min_severity="medium",
        rate=1.0,
        jitter=None,
        threads=1,
        timeout=10,
        verify_ssl=True,
        include_path=[],
        crawl=False,
        crawl_max_pages=50,
        crawl_depth=2,
        ai_provider="ollama",
        ai_model="test-model",
        ai_endpoint=None,
        ai_api_key_env="ORCA_AI_API_KEY",
        ai_timeout=5.0,
        ai_max_findings=10,
        evidence_dir=str(tmp_path / "packet"),
    )
    result = ScanResult(
        target=TargetMeta(url="https://example.test"), findings=[_finding()]
    )

    manifest = _run_ai_review(args, result)

    assert manifest is not None
    assert manifest.exists()
    review = json.loads((manifest.parent / "ai-review.json").read_text(encoding="utf-8"))
    assert review["status"] == "complete"
    assert len(review["reviews"]) == 1
    assert review["skipped_findings"] == 0


def test_replay_command_excludes_credentials_and_ai_connection_details() -> None:
    args = argparse.Namespace(
        url="https://operator:password@example.test/odoo",
        checks="idor,misconfig",
        skip_checks=None,
        min_severity="medium",
        rate=2.0,
        jitter=None,
        threads=4,
        timeout=10,
        verify_ssl=True,
        include_path=["/quoteengine"],
        crawl=True,
        crawl_max_pages=25,
        crawl_depth=2,
        password="private-password",
        proxy="http://proxy-user:proxy-pass@proxy.test",
        ai_endpoint="http://private-model.test/v1",
    )

    command = _build_replay_command(args)

    assert "operator" not in command
    assert "password" not in command
    assert "private-password" not in command
    assert "proxy-pass" not in command
    assert "private-model" not in command
    assert "[REDACTED]@example.test/odoo" in command
    assert "--checks idor,misconfig" in command
    assert "--include-path /quoteengine" in command
    assert "--crawl" in command


def test_crawler_scope_defaults_to_policy_rate() -> None:
    args = argparse.Namespace(
        crawl=True,
        crawl_max_pages=50,
        crawl_depth=2,
        include_path=["/quoteengine"],
        rate=None,
    )

    assert _validate_scan_scope(args) is None
    assert args.rate == 1.0


def test_crawler_scope_rejects_external_or_unbounded_inputs() -> None:
    external = argparse.Namespace(
        crawl=True,
        crawl_max_pages=50,
        crawl_depth=2,
        include_path=["https://other.test/page"],
        rate=1.0,
    )
    too_fast = argparse.Namespace(
        crawl=True,
        crawl_max_pages=50,
        crawl_depth=2,
        include_path=["/quoteengine"],
        rate=5.1,
    )

    assert "same-origin" in _validate_scan_scope(external)
    assert "no more than 5" in _validate_scan_scope(too_fast)


def test_exit_code_preserves_scanner_severity_contract() -> None:
    high = Finding("test", "high", "", Severity.HIGH)
    medium = Finding("test", "medium", "", Severity.MEDIUM)
    low = Finding("test", "low", "", Severity.LOW)

    assert _exit_code([high]) == 2
    assert _exit_code([medium]) == 1
    assert _exit_code([low]) == 0
