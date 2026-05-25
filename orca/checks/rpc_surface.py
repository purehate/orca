"""RPC endpoint exposure and abuse checks (unauthenticated)."""

from orca.checks.base import BaseCheck
from orca.findings import Severity


class RPCSurfaceCheck(BaseCheck):
    name = "rpc_surface"
    description = "Probe XML-RPC/JSON-RPC exposure and unauthenticated method access"
    requires_auth = False

    def run(self) -> None:
        self._check_xmlrpc_common()
        self._check_jsonrpc_common()
        self._check_jsonrpc_call_kw()

    def _check_xmlrpc_common(self) -> None:
        try:
            info = self.target.xmlrpc_common("version")
            if info:
                self.add_finding(
                    title="XML-RPC /xmlrpc/2/common exposed",
                    description="The XML-RPC common endpoint is accessible without authentication. It exposes version information and supports authentication attempts.",
                    severity=Severity.LOW,
                    request="POST /xmlrpc/2/common (version)",
                    response_snippet=str(info)[:300],
                    response_status=200,
                    remediation="If XML-RPC is not required, block it at the reverse proxy level.",
                    cwe="CWE-200",
                )
        except Exception:
            pass

    def _check_jsonrpc_common(self) -> None:
        try:
            result = self.target.jsonrpc("/jsonrpc", {"service": "common", "method": "version", "args": []})
            if result:
                self.add_finding(
                    title="JSON-RPC /jsonrpc exposed",
                    description="The JSON-RPC endpoint is accessible without authentication and exposes version information.",
                    severity=Severity.LOW,
                    request="POST /jsonrpc (common.version)",
                    response_snippet=str(result)[:300],
                    response_status=200,
                    remediation="Restrict /jsonrpc to authenticated clients if not required publicly.",
                    cwe="CWE-200",
                )
        except Exception:
            pass

    def _check_jsonrpc_call_kw(self) -> None:
        # Try calling public methods that should not be reachable unauthenticated
        dangerous = [
            ("res.users", "read", [[1]], {"fields": ["login"]}),
            ("ir.model", "search_read", [[]], {"fields": ["model"], "limit": 1}),
            ("ir.module.module", "search_read", [[["state", "=", "installed"]]], {"fields": ["name"], "limit": 1}),
        ]
        for model, method, args, kwargs in dangerous:
            try:
                result = self.target.jsonrpc("/web/dataset/call_kw", {
                    "model": model,
                    "method": method,
                    "args": args,
                    "kwargs": kwargs,
                })
                if isinstance(result, list) and len(result) > 0:
                    self.add_finding(
                        title=f"Unauthenticated JSON-RPC call_kw on {model}",
                        description=f"The method {model}.{method} was callable without authentication via JSON-RPC and returned data. This is a significant access control bypass.",
                        severity=Severity.CRITICAL,
                        request=f"POST /web/dataset/call_kw ({model}.{method})",
                        response_snippet=str(result)[:300],
                        response_status=200,
                        remediation="Disable public JSON-RPC access or enforce authentication middleware before allowing call_kw.",
                        cwe="CWE-284",
                    )
                    break
            except Exception:
                pass
