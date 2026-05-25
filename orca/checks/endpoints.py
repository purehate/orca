"""Frontend attack surface discovery."""

from orca.checks.base import BaseCheck
from orca.findings import Severity


class EndpointsCheck(BaseCheck):
    name = "endpoints"
    description = "Discover controllers, QWeb assets, manifests, GraphQL, and RPC surface"
    requires_auth = False

    def run(self) -> None:
        self._check_qweb_assets()
        self._check_manifest()
        self._check_graphql()
        self._check_custom_routes()
        self._check_rpc_cors()

    def _check_qweb_assets(self) -> None:
        endpoints = [
            "/web/webclient/qweb",
            "/web/webclient/translations",
            "/web/webclient/bootstrap_translations",
        ]
        for ep in endpoints:
            try:
                resp = self.target.get(ep, timeout=10)
                if resp.status_code == 200 and len(resp.text) > 100:
                    self.add_finding(
                        title=f"QWeb/asset endpoint exposed: {ep}",
                        description=f"The endpoint {ep} returned a substantial response without authentication. This may leak business logic, field names, translations, or internal module names.",
                        severity=Severity.LOW,
                        request=f"GET {ep}",
                        response_snippet=resp.text[:500],
                        response_status=resp.status_code,
                        remediation="Ensure these endpoints require authentication if they expose sensitive internal data.",
                        cwe="CWE-200",
                    )
            except Exception:
                pass

    def _check_manifest(self) -> None:
        paths = ["/web/manifest", "/manifest.json", "/static/manifest.json"]
        for p in paths:
            try:
                resp = self.target.get(p, timeout=8)
                if resp.status_code == 200 and "name" in resp.text:
                    self.add_finding(
                        title=f"Manifest exposed: {p}",
                        description=f"A PWA/web manifest was found at {p} which may reveal application metadata.",
                        severity=Severity.INFO,
                        request=f"GET {p}",
                        response_snippet=resp.text[:400],
                        response_status=resp.status_code,
                        cwe="CWE-200",
                    )
            except Exception:
                pass

    def _check_graphql(self) -> None:
        paths = ["/graphql", "/api/graphql", "/gql", "/query"]
        for p in paths:
            try:
                resp = self.target.get(p, timeout=8)
                if resp.status_code in (200, 400) and ("graphql" in resp.text.lower() or "query" in resp.text.lower()):
                    self.add_finding(
                        title=f"GraphQL endpoint suspected: {p}",
                        description=f"The path {p} responded in a way consistent with a GraphQL API. Verify introspection is disabled.",
                        severity=Severity.MEDIUM,
                        request=f"GET {p}",
                        response_snippet=resp.text[:300],
                        response_status=resp.status_code,
                        remediation="Disable GraphQL introspection in production and enforce authentication.",
                        cwe="CWE-200",
                    )
            except Exception:
                pass

    def _check_custom_routes(self) -> None:
        candidates = [
            "/api", "/api/v1", "/api/v2", "/rest", "/restapi",
            "/json", "/jsonrpc", "/rpc", "/web/api", "/custom",
            "/connector", "/webhook", "/hooks", "/callback",
            "/mobile", "/app", "/sdk", "/export", "/import",
        ]
        found = []
        for p in candidates:
            try:
                resp = self.target.get(p, timeout=8, allow_redirects=False)
                if resp.status_code in (200, 401, 403, 405, 415, 500) and len(resp.text) > 0:
                    found.append(f"{p} (HTTP {resp.status_code})")
            except Exception:
                pass
        if found:
            self.add_finding(
                title="Custom/API routes detected",
                description=f"Non-standard controller paths responded unusually: {', '.join(found)}. These may expose additional attack surface.",
                severity=Severity.LOW,
                remediation="Audit all custom @route controllers for missing authentication and authorization checks.",
                cwe="CWE-200",
            )

    def _check_rpc_cors(self) -> None:
        try:
            resp = self.target.options(
                "/jsonrpc",
                headers={
                    "Origin": "https://evil.com",
                    "Access-Control-Request-Method": "POST",
                },
                timeout=8,
            )
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if "evil.com" in acao or acao == "*":
                self.add_finding(
                    title="CORS misconfiguration on JSON-RPC endpoint",
                    description=f"The /jsonrpc endpoint reflected the arbitrary Origin header ({acao}), allowing cross-origin RPC calls from any domain.",
                    severity=Severity.HIGH,
                    request="OPTIONS /jsonrpc with Origin: https://evil.com",
                    response_snippet=f"Access-Control-Allow-Origin: {acao}",
                    response_status=resp.status_code,
                    remediation="Restrict Access-Control-Allow-Origin to trusted domains only. Do not use wildcard (*) on RPC endpoints.",
                    cwe="CWE-942",
                    references=["https://portswigger.net/web-security/cors"],
                )
        except Exception:
            pass
