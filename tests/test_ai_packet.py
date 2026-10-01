import hashlib
import json
from pathlib import Path

from test_ai_analyzer import FakeClient, _response

from orca.ai.analyzer import AIAnalyzer
from orca.ai.packet import EvidencePacketWriter
from orca.findings import Evidence, Finding, ScanResult, Severity, TargetMeta


def test_packet_contains_replay_review_and_verified_artifacts(tmp_path: Path) -> None:
    finding = Finding(
        check_name="misconfig",
        title="Missing security header",
        description="A security header was not observed.",
        severity=Severity.LOW,
        evidence=Evidence(request="GET /", response_status=200),
        target="https://example.test",
    )
    result = ScanResult(
        target=TargetMeta(url="https://example.test", version="19"),
        findings=[finding],
        completed_at="2026-10-01T12:01:00+00:00",
    )
    review, prompts, responses = AIAnalyzer(FakeClient(_response())).review(result)

    manifest_path = EvidencePacketWriter().write(
        output_dir=tmp_path / "packet",
        result=result,
        review=review,
        prompts=prompts,
        responses=responses,
        replay_command="orca --url https://example.test --format json --output replay-scan.json",
    )

    with manifest_path.open(encoding="utf-8") as handle:
        manifest = json.load(handle)
    paths = {artifact["path"] for artifact in manifest["artifacts"]}
    assert {"scan.json", "ai-review.json", "ai-review.md", "replay.md"} <= paths
    assert any(path.startswith("prompts/") for path in paths)
    assert any(path.startswith("responses/") for path in paths)

    for artifact in manifest["artifacts"]:
        artifact_path = manifest_path.parent / artifact["path"]
        with artifact_path.open("rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        assert digest == artifact["sha256"]


def test_packet_never_contains_api_key_environment_value(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("ORCA_AI_API_KEY", "super-secret-key")
    result = ScanResult(
        target=TargetMeta(url="https://example.test"), completed_at="done"
    )
    review, prompts, responses = AIAnalyzer(FakeClient(_response())).review(result)

    EvidencePacketWriter().write(
        output_dir=tmp_path / "packet",
        result=result,
        review=review,
        prompts=prompts,
        responses=responses,
        replay_command="orca --url https://example.test",
    )

    for path in (tmp_path / "packet").rglob("*"):
        if path.is_file():
            assert "super-secret-key" not in path.read_text(encoding="utf-8")


def test_packet_redacts_credentials_from_scan_and_markdown(tmp_path: Path) -> None:
    finding = Finding(
        check_name="auth",
        title="Credential-shaped evidence",
        description="Captured headers require review.",
        severity=Severity.MEDIUM,
        evidence=Evidence(
            request="Authorization: Bearer secret-token",
            response_snippet="Set-Cookie: session_id=private-session",
            response_status=200,
        ),
        target="https://example.test",
    )
    result = ScanResult(
        target=TargetMeta(url="https://example.test"),
        findings=[finding],
        completed_at="done",
    )
    review, prompts, responses = AIAnalyzer(FakeClient(_response())).review(result)

    EvidencePacketWriter().write(
        output_dir=tmp_path / "packet",
        result=result,
        review=review,
        prompts=prompts,
        responses=responses,
        replay_command="orca --url https://example.test",
    )

    for path in (tmp_path / "packet").rglob("*"):
        if path.is_file():
            content = path.read_text(encoding="utf-8")
            assert "secret-token" not in content
            assert "private-session" not in content
