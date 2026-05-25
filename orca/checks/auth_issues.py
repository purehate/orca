"""Authentication and session security checks."""

from orca.checks.base import BaseCheck
from orca.findings import Severity


class AuthIssuesCheck(BaseCheck):
    name = "auth_issues"
    description = "Session cookie flags, open redirects, password reset behavior, signup analysis"
    requires_auth = False

    def run(self) -> None:
        self._check_session_cookie_flags()
        self._check_open_redirects()
        self._check_password_reset_enum()

    def _check_session_cookie_flags(self) -> None:
        flags = self.target.session_cookie_flags()
        if not flags:
            return
        issues = []
        if not flags.get("httponly"):
            issues.append("Missing HttpOnly flag")
        if not flags.get("secure"):
            issues.append("Missing Secure flag")
        samesite = flags.get("samesite")
        if not samesite or samesite.lower() not in ("strict", "lax"):
            issues.append(f"Weak SameSite={samesite or 'none'}")

        if issues:
            self.add_finding(
                title="Weak session cookie security flags",
                description=f"Session cookie flags: {', '.join(issues)}. This increases the risk of session hijacking and CSRF.",
                severity=Severity.MEDIUM,
                request="GET /web/login",
                response_snippet=flags.get("raw", ""),
                response_status=200,
                remediation="Set session cookie flags via reverse proxy or Odoo session configuration: Secure, HttpOnly, SameSite=Lax/Strict.",
                cwe="CWE-614",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"],
            )

    def _check_open_redirects(self) -> None:
        payloads = [
            "https://evil.com",
            "//evil.com",
        ]
        redirect_params = ["redirect", "login_success", "came_from", "r", "return_url"]
        for param in redirect_params:
            for payload in payloads:
                try:
                    resp = self.target.get("/web/login", params={param: payload}, timeout=8, allow_redirects=False)
                    loc = resp.headers.get("Location", "")
                    if self._is_external_redirect(loc, payload):
                        self.add_finding(
                            title=f"Open redirect via {param}",
                            description=f"The parameter '{param}' accepts external URLs ({payload}) and redirects to them. This can be abused for phishing.",
                            severity=Severity.LOW,
                            request=f"GET /web/login?{param}={payload}",
                            response_snippet=f"Location: {loc}",
                            response_status=resp.status_code,
                            remediation="Validate redirect URLs against a strict allowlist of local paths. Reject absolute URIs.",
                            cwe="CWE-601",
                        )
                        return
                except Exception:
                    pass

    @staticmethod
    def _is_external_redirect(location: str, payload: str) -> bool:
        if not location:
            return False
        if location.startswith(payload):
            return True
        if payload.startswith("//") and location.startswith(payload):
            return True
        if location.startswith("/"):
            return False
        from urllib.parse import urlparse
        parsed_loc = urlparse(location)
        parsed_payload = urlparse(payload)
        if parsed_loc.netloc and parsed_payload.netloc:
            return parsed_loc.netloc == parsed_payload.netloc
        return False

    def _check_password_reset_enum(self) -> None:
        try:
            # Some Odoo versions reveal if an email exists during password reset
            resp = self.target.get("/web/reset_password", timeout=8)
            if resp.status_code == 200:
                # Try submitting with non-existent vs existent email (if we had one)
                # For now, just note that the endpoint exists
                self.add_finding(
                    title="Password reset endpoint exposed",
                    description="The password reset page is accessible. Verify that it does not reveal whether an email address is registered (user enumeration).",
                    severity=Severity.INFO,
                    request="GET /web/reset_password",
                    response_snippet=resp.text[:300],
                    response_status=200,
                    remediation="Ensure password reset returns identical messages for registered and unregistered emails.",
                    cwe="CWE-204",
                )
        except Exception:
            pass
