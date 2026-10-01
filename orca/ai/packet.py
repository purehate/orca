"""Write self-contained, integrity-verifiable external review packets."""

from __future__ import annotations

import hashlib
import json
import platform
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List

from orca import __version__
from orca.ai.analyzer import redact_untrusted_text, sanitize_artifact
from orca.ai.models import AIReviewReport, FindingReview
from orca.findings import ScanResult


class EvidencePacketWriter:
    """Persist scan facts and advisory analysis without storing credentials."""

    def write(
        self,
        output_dir: Path,
        result: ScanResult,
        review: AIReviewReport,
        prompts: Dict[str, str],
        responses: Dict[str, str],
        replay_command: str,
    ) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        prompt_dir = output_dir / "prompts"
        response_dir = output_dir / "responses"
        prompt_dir.mkdir(exist_ok=True)
        response_dir.mkdir(exist_ok=True)

        self._write_json(output_dir / "scan.json", sanitize_artifact(result.to_dict()))
        self._write_json(output_dir / "ai-review.json", review.to_dict())
        self._write_text(
            output_dir / "ai-review.md", self._render_review(result, review)
        )
        self._write_text(
            output_dir / "replay.md", self._render_replay(replay_command, review)
        )
        for finding_id, prompt in prompts.items():
            self._write_text(prompt_dir / f"{finding_id}.txt", prompt)
        for finding_id, response in responses.items():
            self._write_text(response_dir / f"{finding_id}.txt", response)

        manifest_path = output_dir / "manifest.json"
        artifacts = self._artifact_hashes(output_dir, excluded={manifest_path})
        manifest = {
            "schema_version": 1,
            "orca_version": __version__,
            "python_version": platform.python_version(),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "target": redact_untrusted_text(result.target.url, 1_000),
            "scan_started_at": result.started_at,
            "scan_completed_at": result.completed_at,
            "ai_status": review.status,
            "provider": review.provider,
            "model": review.model,
            "artifacts": artifacts,
        }
        self._write_json(manifest_path, manifest)
        return manifest_path

    @staticmethod
    def _write_text(path: Path, content: str) -> None:
        with path.open("w", encoding="utf-8") as handle:
            handle.write(content)

    def _write_json(self, path: Path, content: object) -> None:
        self._write_text(
            path, json.dumps(content, indent=2, sort_keys=True, default=str) + "\n"
        )

    @staticmethod
    def _artifact_hashes(
        output_dir: Path, excluded: Iterable[Path]
    ) -> List[Dict[str, object]]:
        excluded_set = {path.resolve() for path in excluded}
        artifacts: List[Dict[str, object]] = []
        for path in sorted(item for item in output_dir.rglob("*") if item.is_file()):
            if path.resolve() in excluded_set:
                continue
            with path.open("rb") as handle:
                content = handle.read()
            artifacts.append(
                {
                    "path": str(path.relative_to(output_dir)),
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "bytes": len(content),
                }
            )
        return artifacts

    @staticmethod
    def _render_review(result: ScanResult, review: AIReviewReport) -> str:
        reviews = {item.fingerprint: item for item in review.reviews}
        lines = [
            "# ORCA External Security Review",
            "",
            f"- Target: `{redact_untrusted_text(result.target.url, 1_000)}`",
            f"- Scan window: `{result.started_at}` to `{result.completed_at}`",
            f"- Deterministic findings: **{len(result.findings)}**",
            f"- AI review status: **{review.status}**",
            f"- Advisory model: `{review.provider}/{review.model}`",
            "",
            "> AI conclusions are advisory. Scanner evidence and human validation remain authoritative.",
            "",
        ]
        for finding in result.findings:
            finding_id = f"ORCA-{finding.fingerprint[:12].upper()}"
            lines.extend(
                [
                    f"## {finding_id}: {finding.title}",
                    "",
                    f"**Scanner severity:** {finding.severity.value.upper()}  ",
                    f"**Check:** `{finding.check_name}`  ",
                    f"**CWE:** `{finding.cwe or 'not assigned'}`  ",
                    "",
                    redact_untrusted_text(finding.description, 4_000),
                    "",
                    "### Captured evidence",
                    "",
                    f"- Request: `{redact_untrusted_text(finding.evidence.request, 2_000) or 'not captured'}`",
                    f"- Response status: `{finding.evidence.response_status or 'not captured'}`",
                    f"- Response: `{redact_untrusted_text(finding.evidence.response_snippet) or 'not captured'}`",
                    "",
                ]
            )
            ai_review = reviews.get(finding.fingerprint)
            if ai_review:
                lines.extend(EvidencePacketWriter._render_finding_review(ai_review))
            else:
                lines.extend(
                    [
                        "### AI validation",
                        "",
                        "Not reviewed by the configured model.",
                        "",
                    ]
                )
        if review.errors:
            lines.extend(["## Model errors", ""])
            for error in review.errors:
                lines.append(f"- `{error['finding_id']}`: {error['error']}")
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _render_finding_review(review: FindingReview) -> List[str]:
        lines = [
            "### AI validation",
            "",
            f"**Verdict:** {review.verdict.upper()} ({review.confidence:.0%} confidence)",
            "",
            review.summary,
            "",
            f"**Root-cause hypothesis:** {review.root_cause_hypothesis}",
            "",
            f"**Attack path:** {review.attack_path}",
            "",
            f"**Impact:** {review.impact}",
            "",
            "| Validation gate | Status | Evidence |",
            "|---|---|---|",
        ]
        for gate in review.gates:
            lines.append(f"| {gate.name} | {gate.status.upper()} | {gate.evidence} |")
        sections = (
            ("Prerequisites", review.prerequisites),
            ("Safe reproduction", review.reproduction_steps),
            ("Remediation", review.remediation_steps),
            ("Legitimate behavior checks", review.legitimate_behavior_checks),
            ("Uncertainty", review.uncertainty),
        )
        for heading, items in sections:
            lines.extend(["", f"#### {heading}", ""])
            lines.extend(
                f"{index}. {item}" for index, item in enumerate(items, start=1)
            )
        lines.append("")
        return lines

    @staticmethod
    def _render_replay(command: str, review: AIReviewReport) -> str:
        return "\n".join(
            [
                "# Replay and Human Verification",
                "",
                "Run only against the same explicitly authorized target and scope.",
                "",
                "```bash",
                command,
                "```",
                "",
                "## Reviewer checklist",
                "",
                "- Confirm the target and written authorization before replay.",
                "- Compare `scan.json` to the request/response evidence.",
                "- Challenge every AI gate marked PASS against captured facts.",
                "- Replay the listed non-destructive reproduction steps.",
                "- Verify attacker prerequisites and rule out the stated benign explanation.",
                "- Apply remediation in a non-production environment.",
                "- Replay the same proof before and after the fix.",
                "- Run every legitimate-behavior check after remediation.",
                "- Record residual risk and any unexecuted checks.",
                "- Verify artifact hashes in `manifest.json` before relying on the packet.",
                "",
                f"Model status at packet creation: `{review.status}`.",
                "",
            ]
        )
