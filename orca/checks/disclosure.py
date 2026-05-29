"""Information disclosure checks."""

from orca.checks.base import BaseCheck
from orca.findings import Severity
from orca.utils.http import is_odoo_error_page, is_waf_block_page


class DisclosureCheck(BaseCheck):
    name = "disclosure"
    description = "Error page analysis, translation leaks, base_import_module leak"
    requires_auth = False

    def run(self) -> None:
        self._check_error_pages()
        self._check_website_info()
        self._check_base_import_leak()

    def _check_error_pages(self) -> None:
        try:
            resp = self.target.get("/web/404_ORCA_TEST_NONEXISTENT", timeout=10)
            # Skip WAF block pages — 503 from Cloudflare is not an Odoo error page
            if is_waf_block_page(resp):
                return
            if is_odoo_error_page(resp):
                self.add_finding(
                    title="Detailed error pages exposed",
                    description="The application returns detailed error pages (tracebacks, internal paths, or SQL queries) for 404/500 errors. This aids attackers in reconnaissance.",
                    severity=Severity.MEDIUM,
                    request="GET /web/404_ORCA_TEST_NONEXISTENT",
                    response_snippet=resp.text[:800],
                    response_status=resp.status_code,
                    remediation="Disable debug mode in production. Configure a generic error page via reverse proxy.",
                    cwe="CWE-209",
                )
        except Exception:
            pass

    def _check_website_info(self) -> None:
        try:
            resp = self.target.get("/website/info", timeout=10)
            if resp.status_code == 200 and len(resp.text) > 200:
                self.add_finding(
                    title="/website/info page exposed",
                    description="The /website/info page is accessible and may leak installed modules, version hints, or system metadata.",
                    severity=Severity.LOW,
                    request="GET /website/info",
                    response_snippet=resp.text[:500],
                    response_status=resp.status_code,
                    remediation="Restrict access to /website/info or remove the route in production.",
                    cwe="CWE-200",
                )
        except Exception:
            pass

    def _check_base_import_leak(self) -> None:
        try:
            resp = self.target.get("/base_import_module/login", timeout=8)
            if resp.status_code == 200:
                self.add_finding(
                    title="base_import_module login route exposed",
                    description="The /base_import_module/login route is accessible. In some Odoo SaaS versions this has leaked internal module information or enabled unauthorized imports.",
                    severity=Severity.MEDIUM,
                    request="GET /base_import_module/login",
                    response_snippet=resp.text[:400],
                    response_status=resp.status_code,
                    remediation="Disable or restrict the base_import_module route in production environments.",
                    cwe="CWE-200",
                )
        except Exception:
            pass
