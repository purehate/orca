"""Exposure checks for dangerous modules and configurations."""

from orca.checks.base import BaseCheck
from orca.findings import Severity


class ExposureCheck(BaseCheck):
    name = "exposure"
    description = "Detect dangerous modules: dbfilter_from_header, oauth, database_anonymization, portal"
    requires_auth = False

    def run(self) -> None:
        self._check_dbfilter_module()
        self._check_oauth_module()
        self._check_anonymization_module()
        self._check_portal_computed_fields()
        self._check_payment_token_validation()
        self._check_asset_bundle_abuse()
        self._check_password_reset_race()

    def _check_dbfilter_module(self) -> None:
        """CVE-2018-14733: dbfilter_from_header ReDoS."""
        paths = [
            "/web/database/selector",
            "/web/database/manager",
        ]
        for path in paths:
            try:
                resp = self.target.get(path, timeout=8, allow_redirects=False)
                if resp.status_code == 200:
                    text = resp.text.lower()
                    if "dbfilter" in text or "db_filter" in text:
                        self.add_finding(
                            title="dbfilter_from_header module may be active",
                            description="The database selector/manager page contains references to dbfilter configuration. The dbfilter_from_header module (CVE-2018-14733) makes Odoo vulnerable to ReDoS under certain circumstances.",
                            severity=Severity.MEDIUM,
                            request=f"GET {path}",
                            response_snippet=resp.text[:400],
                            response_status=resp.status_code,
                            remediation="Remove dbfilter_from_header if not strictly required. Validate Host header values.",
                            cwe="CWE-400",
                            references=["https://nvd.nist.gov/vuln/detail/CVE-2018-14733"],
                        )
            except Exception:
                pass

    def _check_oauth_module(self) -> None:
        """CVE-2021-23178 / CVE-2019-11786 / CVE-2017-10805: OAuth token issues."""
        try:
            resp = self.target.get("/auth_oauth", timeout=8, allow_redirects=False)
            if resp.status_code in (200, 301, 302, 307, 308, 400, 401, 403):
                self.add_finding(
                    title="OAuth module endpoint detected",
                    description="The auth_oauth module is present. Multiple CVEs affect OAuth handling in Odoo: token hijacking (CVE-2017-10805), token export (CVE-2024-12368), and improper access control (CVE-2019-11786).",
                    severity=Severity.LOW,
                    request="GET /auth_oauth",
                    response_snippet=resp.text[:300] if hasattr(resp, 'text') else "",
                    response_status=resp.status_code,
                    remediation="Ensure OAuth tokens are scoped per-user and cannot be exported or reused across sessions.",
                    cwe="CWE-284",
                    references=[
                        "https://nvd.nist.gov/vuln/detail/CVE-2017-10805",
                        "https://nvd.nist.gov/vuln/detail/CVE-2024-12368",
                    ],
                )
        except Exception:
            pass

    def _check_anonymization_module(self) -> None:
        """CVE-2017-10803: Database Anonymization unsafe unpickle."""
        try:
            resp = self.target.get("/database_anonymization", timeout=8, allow_redirects=False)
            if resp.status_code == 200:
                self.add_finding(
                    title="Database Anonymization module exposed",
                    description="The database_anonymization module is present. CVE-2017-10803 allows authenticated privileged users to execute arbitrary Python code via unsafe unpickle of anonymization data.",
                    severity=Severity.HIGH,
                    request="GET /database_anonymization",
                    response_snippet=resp.text[:400],
                    response_status=resp.status_code,
                    remediation="Remove the Database Anonymization module if not required. If required, patch to use safe deserialization.",
                    cwe="CWE-502",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2017-10803"],
                )
        except Exception:
            pass

    def _check_portal_computed_fields(self) -> None:
        """CVE-2019-11780 / CVE-2019-11782: Portal computed fields / privilege escalation."""
        try:
            resp = self.target.get("/my", timeout=8, allow_redirects=False)
            if resp.status_code in (200, 301, 302):
                self.add_finding(
                    title="Portal module detected",
                    description="The portal module is present. CVE-2019-11780 (portal computed fields information disclosure) and CVE-2019-11782 (portal privilege escalation) affect portal components in Odoo 12/13.",
                    severity=Severity.LOW,
                    request="GET /my",
                    response_snippet=resp.text[:300] if hasattr(resp, 'text') else "",
                    response_status=resp.status_code,
                    remediation="Upgrade to a patched Odoo version. Ensure portal users have minimal access rights.",
                    cwe="CWE-284",
                    references=[
                        "https://nvd.nist.gov/vuln/detail/CVE-2019-11780",
                        "https://nvd.nist.gov/vuln/detail/CVE-2019-11782",
                    ],
                )
        except Exception:
            pass

    def _check_payment_token_validation(self) -> None:
        """CVE-2021-23178: Payment token validation bypass."""
        try:
            resp = self.target.get("/payment", timeout=8, allow_redirects=False)
            if resp.status_code in (200, 301, 302, 307, 308):
                self.add_finding(
                    title="Payment module detected (CVE-2021-23178)",
                    description="The payment module is present. CVE-2021-23178 allows attackers to validate online payments with a tokenized payment method that belongs to another user.",
                    severity=Severity.HIGH,
                    request="GET /payment",
                    response_snippet=resp.text[:300] if hasattr(resp, 'text') else "",
                    response_status=resp.status_code,
                    remediation="Upgrade to a patched Odoo version. Implement proper token ownership validation.",
                    cwe="CWE-284",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2021-23178"],
                )
        except Exception:
            pass

    def _check_asset_bundle_abuse(self) -> None:
        """CVE-2021-44475: Asset bundle generation abused to read local files."""
        try:
            # Try to trigger asset generation with a suspicious path
            resp = self.target.get("/web/assets/debug", timeout=8, allow_redirects=False)
            if resp.status_code == 200 and ("scss" in resp.text or "css" in resp.text):
                self.add_finding(
                    title="Asset bundle debug endpoint exposed (CVE-2021-44475)",
                    description="The /web/assets/debug endpoint is accessible. In vulnerable versions, asset bundle generation can be abused to read local files on the server.",
                    severity=Severity.MEDIUM,
                    request="GET /web/assets/debug",
                    response_snippet=resp.text[:400],
                    response_status=resp.status_code,
                    remediation="Restrict access to asset debug endpoints in production.",
                    cwe="CWE-22",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44475"],
                )
        except Exception:
            pass

    def _check_password_reset_race(self) -> None:
        """CVE-2018-14859: Password reset race condition."""
        try:
            resp = self.target.get("/web/reset_password", timeout=8)
            if resp.status_code == 200:
                self.add_finding(
                    title="Password reset endpoint exposed (CVE-2018-14859)",
                    description="The password reset page is accessible. CVE-2018-14859 allows authenticated users to reset the password of other users by being the first to use the secure token.",
                    severity=Severity.MEDIUM,
                    request="GET /web/reset_password",
                    response_snippet=resp.text[:300],
                    response_status=resp.status_code,
                    remediation="Ensure password reset tokens are single-use and rate-limited.",
                    cwe="CWE-362",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2018-14859"],
                )
        except Exception:
            pass
