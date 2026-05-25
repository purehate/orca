"""IDOR and unauthorized access checks."""

from orca.checks.base import BaseCheck
from orca.findings import Severity


class IDORCheck(BaseCheck):
    name = "idor"
    description = "Test for unauthenticated access to attachments, images, PDFs, and records"
    requires_auth = False

    def run(self) -> None:
        self._check_web_content()
        self._check_web_image()
        self._check_web_pdf()
        self._check_unauthenticated_rpc_read()

    def _check_web_content(self) -> None:
        # Test a small range of attachment IDs
        leaked = []
        for aid in range(1, 15):
            try:
                resp = self.target.get("/web/content", params={"id": aid, "download": "1"}, timeout=8, allow_redirects=False)
                if resp.status_code == 200 and len(resp.content) > 100:
                    leaked.append(str(aid))
            except Exception:
                pass
        if leaked:
            self.add_finding(
                title="Unauthenticated attachment access (IDOR)",
                description=f"Attachments with IDs {', '.join(leaked)} were accessible via /web/content without authentication. This indicates missing access control on ir.attachment records.",
                severity=Severity.HIGH,
                request="GET /web/content?id=1&download=1",
                response_snippet=f"HTTP 200, {len(leaked)} leaked",
                response_status=200,
                remediation="Ensure attachment controllers check access rights via ir.attachment.check_access_rights() or use signed URLs for public attachments only.",
                cwe="CWE-639",
            )

    def _check_web_image(self) -> None:
        leaked = []
        for aid in range(1, 15):
            try:
                resp = self.target.get("/web/image", params={"id": aid}, timeout=8, allow_redirects=False)
                if resp.status_code == 200 and resp.headers.get("Content-Type", "").startswith("image/"):
                    leaked.append(str(aid))
            except Exception:
                pass
        if leaked:
            self.add_finding(
                title="Unauthenticated image access (IDOR)",
                description=f"Images with IDs {', '.join(leaked)} were accessible via /web/image without authentication.",
                severity=Severity.MEDIUM,
                request="GET /web/image?id=1",
                response_snippet=f"HTTP 200, {len(leaked)} leaked",
                response_status=200,
                remediation="Restrict /web/image to public records or require authentication for non-public images.",
                cwe="CWE-639",
            )

    def _check_web_pdf(self) -> None:
        try:
            resp = self.target.get("/web/pdf", params={"id": 1}, timeout=8, allow_redirects=False)
            if resp.status_code == 200 and resp.headers.get("Content-Type", "") == "application/pdf":
                self.add_finding(
                    title="Unauthenticated PDF report access",
                    description="The /web/pdf endpoint returned a PDF without authentication. This may allow downloading arbitrary reports.",
                    severity=Severity.HIGH,
                    request="GET /web/pdf?id=1",
                    response_snippet="Content-Type: application/pdf",
                    response_status=200,
                    remediation="Enforce authentication and authorization checks before generating or serving PDF reports.",
                    cwe="CWE-284",
                )
        except Exception:
            pass

    def _check_unauthenticated_rpc_read(self) -> None:
        public_models = ["res.partner", "product.template", "product.product", "crm.lead", "sale.order"]
        leaked_models = []
        for model in public_models:
            try:
                result = self.target.jsonrpc("/web/dataset/call_kw", {
                    "model": model,
                    "method": "search_read",
                    "args": [[]],
                    "kwargs": {"fields": ["name"], "limit": 1},
                })
                if isinstance(result, list) and len(result) > 0:
                    leaked_models.append(model)
            except Exception:
                pass
        if leaked_models:
            self.add_finding(
                title="Unauthenticated RPC read on sensitive models",
                description=f"JSON-RPC search_read succeeded without authentication for: {', '.join(leaked_models)}. This may expose business data.",
                severity=Severity.HIGH,
                request=f"JSON-RPC call_kw {leaked_models[0]}.search_read",
                response_snippet="",
                response_status=200,
                remediation="Ensure public controllers and RPC methods enforce proper access controls. Do not expose ORM methods without authentication.",
                cwe="CWE-284",
            )
