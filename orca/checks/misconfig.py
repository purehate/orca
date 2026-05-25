"""Misconfiguration checks: debug mode, headers, database manager, CORS."""

from orca.checks.base import BaseCheck
from orca.findings import Severity


class MisconfigCheck(BaseCheck):
    name = "misconfig"
    description = "Detect debug mode, missing security headers, exposed database manager, CORS"
    requires_auth = False

    def run(self) -> None:
        self._check_debug_mode()
        self._check_database_manager()
        self._check_security_headers()
        self._check_cors_global()

    def _check_debug_mode(self) -> None:
        debug_params = ["?debug=1", "?debug=assets", "?debug=assets,tests"]
        for param in debug_params:
            try:
                resp = self.target.get(f"/web{param}", timeout=10)
                if resp.status_code == 200:
                    text = resp.text.lower()
                    # Specific debug indicators, not generic "assets"
                    debug_indicators = [
                        "debug manager",
                        "debug_menu",
                        "debug_mode",
                        "data-debug-mode",
                        "assets_debug",
                        "t-debug",
                        "assets debugging",
                        "bundle list",
                        "assets management",
                        "__debug__",
                        "traceback",
                        "werkzeug",
                        "/web/debug",
                    ]
                    # Also check for odoo.debug set to "1" or "assets" in script tags
                    import re
                    odoo_debug = re.search(r'odoo\.\s*debug\s*[=:]\s*["\']([^"\']+)["\']', text)
                    debug_in_script = odoo_debug and odoo_debug.group(1) in ("1", "assets", "assets,tests")
                    if debug_in_script or any(ind in text for ind in debug_indicators):
                        self.add_finding(
                            title="Debug mode accessible",
                            description=f"The URL /web{param} loaded successfully and appears to enable debug features. This may expose tracebacks, asset debugging info, and internal paths.",
                            severity=Severity.HIGH,
                            request=f"GET /web{param}",
                            response_snippet=resp.text[:600],
                            response_status=resp.status_code,
                            remediation="Set list_db = False and ensure debug mode is not enabled in production (remove debug from startup parameters).",
                            cwe="CWE-489",
                        )
                        break
            except Exception:
                pass

    def _check_database_manager(self) -> None:
        paths = ["/web/database/manager", "/web/database/selector"]
        for p in paths:
            try:
                resp = self.target.get(p, timeout=10)
                if resp.status_code == 200 and ("database" in resp.text.lower() or "backup" in resp.text.lower() or "restore" in resp.text.lower()):
                    self.add_finding(
                        title=f"Database manager exposed: {p}",
                        description=f"The database management interface is reachable at {p}. This allows database creation, backup, restore, and deletion if the master password is weak or known.",
                        severity=Severity.CRITICAL,
                        request=f"GET {p}",
                        response_snippet=resp.text[:400],
                        response_status=resp.status_code,
                        remediation="Disable the database manager in production: list_db = False in odoo.conf.",
                        cwe="CWE-284",
                        references=["https://www.odoo.com/documentation/master/administration/install/deploy.html#security"],
                    )
            except Exception:
                pass

    def _check_security_headers(self) -> None:
        try:
            resp = self.target.get("/", timeout=10)
            headers = resp.headers
            findings = []

            if "X-Frame-Options" not in headers and "Content-Security-Policy" not in headers:
                findings.append("Missing X-Frame-Options and CSP headers (clickjacking risk)")
            if "Strict-Transport-Security" not in headers:
                findings.append("Missing HSTS header")
            if "X-Content-Type-Options" not in headers:
                findings.append("Missing X-Content-Type-Options header")
            if "Referrer-Policy" not in headers:
                findings.append("Missing Referrer-Policy header")

            if findings:
                self.add_finding(
                    title="Missing security headers",
                    description="; ".join(findings) + ".",
                    severity=Severity.LOW,
                    request="GET /",
                    response_snippet="\n".join(f"{k}: {v}" for k, v in headers.items()),
                    response_status=resp.status_code,
                    remediation="Add X-Frame-Options, CSP, HSTS, X-Content-Type-Options, and Referrer-Policy headers via reverse proxy or Odoo configuration.",
                    cwe="CWE-693",
                )
        except Exception:
            pass

    def _check_cors_global(self) -> None:
        try:
            resp = self.target.get(
                "/",
                headers={"Origin": "https://evil.com"},
                timeout=8,
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                self.add_finding(
                    title="Permissive CORS wildcard on main site",
                    description="The site responds with Access-Control-Allow-Origin: * for arbitrary origins, allowing cross-origin requests to read responses.",
                    severity=Severity.MEDIUM,
                    request="GET / with Origin: https://evil.com",
                    response_snippet=f"Access-Control-Allow-Origin: {acao}",
                    response_status=resp.status_code,
                    remediation="Restrict CORS to specific trusted origins. Avoid wildcard in production.",
                    cwe="CWE-942",
                )
        except Exception:
            pass
