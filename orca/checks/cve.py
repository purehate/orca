"""CVE correlation check using NVD API."""

import re
from typing import Any, Dict, List, Optional, Set

import requests

from orca.checks.base import BaseCheck
from orca.findings import Severity

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _normalize_version(version_string: Optional[str]) -> Optional[str]:
    match = re.search(r"(\d+)", str(version_string)) if version_string else None
    return match.group(1) if match else None


def _query_nvd(keyword: str, timeout: int = 12) -> List[Dict[str, Any]]:
    try:
        resp = requests.get(
            NVD_API,
            params={"keywordSearch": keyword, "resultsPerPage": 10},
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("vulnerabilities", [])
    except (requests.RequestException, ValueError, TypeError):
        return []


def _version_tuple(value: str) -> Optional[tuple]:
    match = re.match(r"^(\d+)(?:\.(\d+))?", value)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2) or 0)


def _iter_cpe_matches(value: Any):
    if isinstance(value, dict):
        matches = value.get("cpeMatch", [])
        if isinstance(matches, list):
            yield from matches
        for key in ("configurations", "nodes", "children"):
            children = value.get(key, [])
            if isinstance(children, list):
                for child in children:
                    yield from _iter_cpe_matches(child)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_cpe_matches(item)


def _version_matches_cpe(version: str, match: Dict[str, Any]) -> bool:
    detected = _version_tuple(version)
    criteria = str(match.get("criteria", ""))
    parts = criteria.split(":")
    if detected is None or len(parts) < 6:
        return False

    exact = parts[5]
    if exact not in ("*", "-"):
        return detected == _version_tuple(exact)

    bounds = (
        ("versionStartIncluding", lambda current, bound: current >= bound),
        ("versionStartExcluding", lambda current, bound: current > bound),
        ("versionEndIncluding", lambda current, bound: current <= bound),
        ("versionEndExcluding", lambda current, bound: current < bound),
    )
    for key, comparator in bounds:
        raw_bound = match.get(key)
        if raw_bound:
            bound = _version_tuple(str(raw_bound))
            if bound is None or not comparator(detected, bound):
                return False
    return True


def _odoo_version_applicability(
    cve: Dict[str, Any], detected_version: Optional[str]
) -> Optional[bool]:
    """Return whether NVD CPE data confirms applicability to this Odoo major."""
    if not detected_version:
        return None
    matches = []
    for match in _iter_cpe_matches(cve.get("configurations", [])):
        criteria = str(match.get("criteria", "")).lower()
        if match.get("vulnerable") and ":a:odoo:odoo:" in criteria:
            matches.append(match)
    if not matches:
        return None
    return any(_version_matches_cpe(detected_version, match) for match in matches)


def _extract_score(cve: Dict[str, Any]) -> Optional[float]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            try:
                return float(metrics[key][0]["cvssData"]["baseScore"])
            except (KeyError, IndexError, ValueError):
                continue
    return None


def _score_to_severity(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    elif score >= 7.0:
        return Severity.HIGH
    elif score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _extract_description(cve: Dict[str, Any]) -> str:
    descriptions = cve.get("descriptions", [])
    for d in descriptions:
        if d.get("lang", "") == "en":
            return d.get("value", "No description")
    return descriptions[0].get("value", "No description") if descriptions else "No description"


def _extract_references(cve: Dict[str, Any], limit: int = 3) -> List[str]:
    refs = [r["url"] for r in cve.get("references", []) if "url" in r]
    return refs[:limit]


class CVECheck(BaseCheck):
    name = "cve"
    description = "Correlate detected Odoo version and modules with known CVEs via NVD"
    requires_auth = False

    def run(self) -> None:
        version = self.target.version
        if not version:
            try:
                from orca.utils.http import detect_odoo_version
                resp = self.target.get("/web/login", timeout=8)
                if resp.status_code == 200:
                    version = detect_odoo_version(resp.text)
            except requests.RequestException:
                version = None

        normalized = _normalize_version(version)
        modules = list(self.result.target.detected_modules)[:5]
        seen_cves: Set[str] = set()
        all_vulns: List[Dict[str, Any]] = []

        # Search by version
        if normalized:
            for term in (f"odoo {normalized}", f"odoo {normalized}.0"):
                for vuln in _query_nvd(term):
                    cve_id = vuln["cve"]["id"]
                    if cve_id not in seen_cves:
                        seen_cves.add(cve_id)
                        all_vulns.append(vuln)

        # Search by top modules
        for mod in modules:
            for vuln in _query_nvd(f"odoo {mod}", timeout=10):
                cve_id = vuln["cve"]["id"]
                if cve_id not in seen_cves:
                    seen_cves.add(cve_id)
                    all_vulns.append(vuln)

        if not all_vulns:
            self.add_finding(
                title="No CVEs found for detected version/modules",
                description=f"No known CVEs in NVD for Odoo version {version or 'unknown'} or modules: {', '.join(modules) if modules else 'none'}.",
                severity=Severity.INFO,
                remediation="Continue monitoring NVD for new disclosures.",
            )
            return

        candidates = []
        for vuln in all_vulns:
            cve = vuln["cve"]
            cve_id = cve["id"]
            score = _extract_score(cve)
            severity = _score_to_severity(score) if score else Severity.INFO
            desc = _extract_description(cve)
            refs = _extract_references(cve)

            applicability = _odoo_version_applicability(cve, normalized)
            if applicability is False:
                continue
            if applicability is None:
                candidates.append(
                    {
                        "id": cve_id,
                        "reason": "NVD does not provide matching Odoo CPE version data for the detected release.",
                        "cvss": score,
                        "references": refs,
                    }
                )
                continue

            self.add_finding(
                title=f"Known CVE: {cve_id}",
                description=f"{desc} (CVSS: {score if score else 'N/A'})",
                severity=severity,
                remediation="Apply the vendor patch or upgrade to a fixed version. Review the CVE references for specific workaround instructions.",
                cwe="CWE-1035",
                references=refs,
            )

        if candidates:
            self.result.artifacts["cve_candidates"] = candidates
            candidate_ids = ", ".join(item["id"] for item in candidates)
            self.add_finding(
                title="CVE candidates require environment applicability confirmation",
                description=f"NVD keyword search returned {len(candidates)} candidate(s) without CPE evidence matching Odoo {normalized or 'unknown'}: {candidate_ids}.",
                severity=Severity.INFO,
                remediation="Confirm packaging, edition, module, and fixed-build applicability before treating any candidate as a vulnerability.",
                references=sorted(
                    {reference for item in candidates for reference in item["references"]}
                )[:5],
            )
