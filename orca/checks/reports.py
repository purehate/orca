"""Unauthenticated report disclosure checks (PDF, CSV, FEC)."""

from orca.checks.base import BaseCheck
from orca.findings import Severity


class ReportsCheck(BaseCheck):
    name = "reports"
    description = "Test for unauthenticated report PDF/CSV/FEC download exposure"
    requires_auth = False

    def run(self) -> None:
        self._check_pdf_reports()
        self._check_csv_exports()
        self._check_fec_export()
        self._check_report_download()
        self._check_invoice_import_xss()

    def _check_pdf_reports(self) -> None:
        """CVE-2021-23203: PDF report disclosure."""
        paths = [
            "/report/pdf",
            "/report/pdf/",
            "/report/download",
            "/report/download/",
            "/web/pdf",
            "/web/pdf/",
        ]
        for path in paths:
            try:
                resp = self.target.get(path, timeout=8, allow_redirects=False)
                ct = resp.headers.get("Content-Type", "")
                if resp.status_code == 200 and ct == "application/pdf":
                    self.add_finding(
                        title="Unauthenticated PDF report access",
                        description=f"The endpoint {path} returned a PDF without authentication. This may allow downloading arbitrary reports (CVE-2021-23203).",
                        severity=Severity.HIGH,
                        request=f"GET {path}",
                        response_snippet=f"Content-Type: {ct}",
                        response_status=resp.status_code,
                        remediation="Restrict report endpoints to authenticated users with proper access controls.",
                        cwe="CWE-284",
                        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-23203"],
                    )
                    return
            except Exception:
                pass

    def _check_csv_exports(self) -> None:
        """CVE-2018-14861: CSV export of hashed passwords."""
        try:
            resp = self.target.get("/web/export", timeout=8, allow_redirects=False)
            if resp.status_code == 200 and ("export" in resp.text.lower() or "csv" in resp.text.lower()):
                self.add_finding(
                    title="CSV export endpoint exposed",
                    description="The /web/export endpoint is accessible. In vulnerable versions this allows CSV export of sensitive data including secure hashed passwords (CVE-2018-14861).",
                    severity=Severity.MEDIUM,
                    request="GET /web/export",
                    response_snippet=resp.text[:400],
                    response_status=resp.status_code,
                    remediation="Restrict export functionality to authorized roles only.",
                    cwe="CWE-284",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2018-14861"],
                )
        except Exception:
            pass

    def _check_fec_export(self) -> None:
        """CVE-2021-23176: l10n_fr_fec accounting export."""
        try:
            resp = self.target.get("/account/fec", timeout=8, allow_redirects=False)
            if resp.status_code == 200:
                self.add_finding(
                    title="French FEC accounting export endpoint exposed",
                    description="The /account/fec endpoint is accessible. In vulnerable versions this allows remote authenticated users to extract accounting information via crafted RPC packets (CVE-2021-23176).",
                    severity=Severity.MEDIUM,
                    request="GET /account/fec",
                    response_snippet=resp.text[:400],
                    response_status=resp.status_code,
                    remediation="Restrict FEC export to authorized accounting users.",
                    cwe="CWE-284",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2021-23176"],
                )
        except Exception:
            pass

    def _check_report_download(self) -> None:
        paths = [
            "/web/content",
            "/web/content/",
            "/base_import_module/login",
        ]
        for path in paths:
            try:
                resp = self.target.get(path, timeout=8, allow_redirects=False)
                if resp.status_code == 200 and len(resp.text) > 100:
                    if "base_import" in path:
                        self.add_finding(
                            title="base_import_module login route exposed",
                            description="The /base_import_module/login route is accessible. This has been abused in some Odoo SaaS versions to leak internal module information or enable unauthorized imports.",
                            severity=Severity.MEDIUM,
                            request=f"GET {path}",
                            response_snippet=resp.text[:400],
                            response_status=resp.status_code,
                            remediation="Disable or restrict the base_import_module route in production.",
                            cwe="CWE-200",
                        )
            except Exception:
                pass

    def _check_invoice_import_xss(self) -> None:
        """CVE-2021-44461: XSS via invoice import/email."""
        try:
            resp = self.target.get("/account", timeout=8, allow_redirects=False)
            if resp.status_code in (200, 301, 302):
                self.add_finding(
                    title="Accounting module detected (CVE-2021-44461)",
                    description="The accounting module is present. CVE-2021-44461 allows remote attackers to inject arbitrary web script via crafted invoice contents when an accountant opens the invoice.",
                    severity=Severity.MEDIUM,
                    request="GET /account",
                    response_snippet=resp.text[:300] if hasattr(resp, 'text') else "",
                    response_status=resp.status_code,
                    remediation="Sanitize invoice content before rendering. Upgrade to a patched version.",
                    cwe="CWE-79",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44461"],
                )
        except Exception:
            pass
