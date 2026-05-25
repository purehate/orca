"""Cross-Site Scripting detection checks."""

from orca.checks.base import BaseCheck
from orca.findings import Severity
from orca.utils.http import reflection_contexts


# Context-aware XSS payloads (reduced set for speed)
XSS_PAYLOADS = [
    "<script>alert('ORCA_XSS')</script>",
    "<img src=x onerror=alert('ORCA_XSS')>",
    "\"><script>alert('ORCA_XSS')</script>",
    "'><img src=x onerror=alert('ORCA_XSS')>",
]

# Parameter targets (key paths only for speed)
PARAM_TARGETS = {
    "/web/login": ["redirect", "login"],
    "/web": ["debug", "action"],
    "/shop": ["search"],
    "/forum": ["search"],
    "/blog": ["search", "tag"],
    "/slides": ["search"],
    "/events": ["search"],
    "/contactus": ["name", "email"],
}


class XSSCheck(BaseCheck):
    name = "xss"
    description = "Reflected XSS probing on URL parameters and search fields"
    requires_auth = False

    def run(self) -> None:
        self._check_reflected_params()
        self._check_error_page_xss()
        self._check_open_redirect_xss()

    def _check_reflected_params(self) -> None:
        for path, params in PARAM_TARGETS.items():
            for param in params:
                hit = False
                for payload in XSS_PAYLOADS:
                    try:
                        resp = self.target.get(path, params={param: payload}, timeout=8, allow_redirects=False)
                        if resp.status_code == 200 and payload in resp.text:
                            contexts = reflection_contexts(resp.text, payload)
                            self.add_finding(
                                title=f"Reflected XSS in {path}?{param}",
                                description=f"Payload '{payload}' was reflected in the response for {path}?{param}. Reflection contexts: {', '.join(contexts)}.",
                                severity=Severity.HIGH if "javascript" in contexts or "html_attribute" in contexts else Severity.MEDIUM,
                                request=f"GET {path}?{param}={payload}",
                                response_snippet=resp.text[max(0, resp.text.find(payload)-100):resp.text.find(payload)+len(payload)+100],
                                response_status=resp.status_code,
                                remediation="Escape user input based on output context. Use Odoo's qweb t-esc for HTML contexts and t-js for JavaScript contexts.",
                                cwe="CWE-79",
                                references=["https://owasp.org/www-community/attacks/xss/"],
                            )
                            hit = True
                            break
                    except Exception:
                        pass
                if hit:
                    break

    def _check_error_page_xss(self) -> None:
        payload = "<script>alert('ORCA_ERR')</script>"
        try:
            resp = self.target.get(f"/web/404_ORCA_{payload}", timeout=10)
            if payload in resp.text:
                self.add_finding(
                    title="XSS via error page path",
                    description="The 404/error page reflects unsanitized input from the URL path, allowing XSS.",
                    severity=Severity.MEDIUM,
                    request=f"GET /web/404_ORCA_{payload}",
                    response_snippet=resp.text[:500],
                    response_status=resp.status_code,
                    remediation="Sanitize URL path segments before rendering them in error templates.",
                    cwe="CWE-79",
                )
        except Exception:
            pass

    def _check_open_redirect_xss(self) -> None:
        redirect_payloads = [
            "javascript:alert('ORCA_REDIRECT')",
            "//evil.com",
            "https://evil.com",
        ]
        for payload in redirect_payloads:
            try:
                resp = self.target.get("/web/login", params={"redirect": payload}, timeout=8, allow_redirects=False)
                loc = resp.headers.get("Location", "")
                if self._is_external_redirect(loc, payload):
                    self.add_finding(
                        title="Open redirect to JavaScript/external domain",
                        description=f"The redirect parameter accepts '{payload}', which can lead to phishing or XSS via javascript: URIs.",
                        severity=Severity.MEDIUM,
                        request=f"GET /web/login?redirect={payload}",
                        response_snippet=f"Location: {loc}",
                        response_status=resp.status_code,
                        remediation="Validate redirect URLs against an allowlist of trusted paths. Reject absolute URIs and javascript: schemes.",
                        cwe="CWE-601",
                    )
                    break
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
