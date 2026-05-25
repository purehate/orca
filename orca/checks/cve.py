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
    except Exception:
        return []


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
            except Exception:
                pass

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

        # Parse version from description to filter out irrelevant CVEs
        detected_ver = _normalize_version(version)
        for vuln in all_vulns:
            cve = vuln["cve"]
            cve_id = cve["id"]
            score = _extract_score(cve)
            severity = _score_to_severity(score) if score else Severity.INFO
            desc = _extract_description(cve)
            refs = _extract_references(cve)

            # Skip CVEs that explicitly mention versions higher than detected
            if detected_ver:
                # If CVE mentions "Odoo 15.0 and earlier" and we're on 18, it's patched
                if f"{detected_ver}.0 and earlier" in desc and detected_ver != "15":
                    continue
                # Simple heuristic: if description says "Odoo X" and X < detected, skip low-severity
                import re
                ver_matches = re.findall(r'Odoo\s+(Community|Enterprise)?\s*(\d+)\.0', desc)
                if ver_matches:
                    max_mentioned = max(int(v[1]) for v in ver_matches)
                    if max_mentioned < int(detected_ver) and severity <= Severity.LOW:
                        continue

            self.add_finding(
                title=f"Known CVE: {cve_id}",
                description=f"{desc} (CVSS: {score if score else 'N/A'})",
                severity=severity,
                remediation="Apply the vendor patch or upgrade to a fixed version. Review the CVE references for specific workaround instructions.",
                cwe="CWE-1035",
                references=refs,
            )
