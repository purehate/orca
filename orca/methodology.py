"""Machine-readable external assessment methodology and coverage boundaries."""

from __future__ import annotations

from typing import Dict, Iterable, List


OWASP_TOP_10_2025 = (
    (
        "A01:2025",
        "Broken Access Control",
        "focused",
        ("idor", "rpc_surface", "reports", "exposure", "crawler"),
    ),
    (
        "A02:2025",
        "Security Misconfiguration",
        "focused",
        ("misconfig", "recon", "sensitive_files", "page"),
    ),
    (
        "A03:2025",
        "Software Supply Chain Failures",
        "partial",
        ("cve", "source_leak"),
    ),
    (
        "A04:2025",
        "Cryptographic Failures",
        "partial",
        ("auth_issues", "misconfig", "page"),
    ),
    (
        "A05:2025",
        "Injection",
        "focused",
        ("xss", "fuzzer", "lfi", "ssrf"),
    ),
    (
        "A06:2025",
        "Insecure Design",
        "partial",
        ("crawler", "endpoints", "exposure"),
    ),
    (
        "A07:2025",
        "Authentication Failures",
        "focused",
        ("auth_issues", "rpc_surface", "exposure"),
    ),
    (
        "A08:2025",
        "Software or Data Integrity Failures",
        "partial",
        ("source_leak", "sensitive_files", "reports"),
    ),
    (
        "A09:2025",
        "Security Logging and Alerting Failures",
        "not_externally_verifiable",
        (),
    ),
    (
        "A10:2025",
        "Mishandling of Exceptional Conditions",
        "focused",
        ("disclosure", "fuzzer", "endpoints"),
    ),
)


def build_methodology_artifact(check_names: Iterable[str]) -> Dict:
    """Describe what the selected external checks can and cannot establish."""
    executed = set(check_names)
    categories: List[Dict] = []
    for category_id, name, observability, available_checks in OWASP_TOP_10_2025:
        selected = sorted(executed.intersection(available_checks))
        if observability == "not_externally_verifiable":
            status = observability
        elif selected:
            status = observability
        else:
            status = "not_run"
        categories.append(
            {
                "id": category_id,
                "name": name,
                "status": status,
                "executed_checks": selected,
                "available_checks": list(available_checks),
            }
        )

    return {
        "framework": "OWASP Top 10:2025",
        "framework_url": "https://owasp.org/Top10/2025/",
        "testing_criteria": "Odoo Security vulnerability reporting guidelines",
        "testing_criteria_url": "https://www.odoo.com/security-report",
        "scope": "Unauthenticated outside-in assessment",
        "coverage_interpretation": {
            "focused": "Selected checks directly probe part of this category; this is not exhaustive coverage.",
            "partial": "External signals are tested, but source, configuration, dependency, or workflow evidence is also required.",
            "not_externally_verifiable": "This category requires internal evidence from the code-review workflow.",
            "not_run": "No selected ORCA check mapped to this category in this run.",
        },
        "policy_alignment": [
            {
                "control": "Same-origin custom-surface discovery",
                "implementation": "Crawler follows only same-origin links and does not submit forms.",
            },
            {
                "control": "Bounded automation",
                "implementation": "Crawler defaults to 1 request/second, rejects rates above 5, and enforces page/depth caps.",
            },
            {
                "control": "No denial-of-service testing",
                "implementation": "Crawler uses bounded GET requests and excludes destructive-looking routes.",
            },
            {
                "control": "Reproducible evidence",
                "implementation": "Findings include stable IDs, request facts, replay commands, and hashed evidence packets.",
            },
            {
                "control": "Human-reviewed AI",
                "implementation": "AI verdicts are advisory and cannot remove findings or change scanner exit codes.",
            },
        ],
        "categories": categories,
        "limitations": [
            "Unauthenticated testing cannot verify authenticated roles, tenant boundaries, or post-login business logic.",
            "External testing cannot prove source-code, dependency, logging, monitoring, or CI/CD control effectiveness; those require the internal code-review workflow.",
            "A category marked focused or partial is not a claim that every vulnerability in that category was tested.",
        ],
    }
