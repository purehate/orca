"""IDOR and unauthorized access checks."""

import hashlib
from typing import Dict, List, Tuple

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

    def _fetch_attachments(self, path: str, params: Dict, max_id: int = 15) -> List[Tuple[int, object]]:
        """Fetch attachments and return list of (id, response) tuples."""
        results = []
        for aid in range(1, max_id):
            try:
                resp = self.target.get(path, params={**params, "id": aid}, timeout=8, allow_redirects=False)
                results.append((aid, resp))
            except Exception:
                pass
        return results

    def _is_placeholder_image(self, responses: List[Tuple[int, object]]) -> bool:
        """Detect Odoo placeholder image false positive.

        Odoo returns the same placeholder image for ALL missing/inaccessible
        attachment IDs. If every 200 response has identical content, it's
        the placeholder, not leaked private data.
        """
        bodies = []
        for aid, resp in responses:
            if resp.status_code == 200:
                bodies.append(resp.content)
        if len(bodies) < 2:
            return False
        # Compare all bodies to the first one
        first = bodies[0]
        return all(b == first for b in bodies)

    def _check_web_content(self) -> None:
        responses = self._fetch_attachments("/web/content", {"download": "1"})
        leaked = []
        for aid, resp in responses:
            if resp.status_code == 200 and len(resp.content) > 100:
                leaked.append((aid, resp))

        # If all leaked attachments are identical, it's likely a public asset
        # or the placeholder image — not a real IDOR.
        if len(leaked) >= 2 and self._is_placeholder_image(leaked):
            return

        # A single small image is typically the placeholder or a public logo.
        if len(leaked) == 1:
            aid, resp = leaked[0]
            ct = resp.headers.get("Content-Type", "")
            if ct.startswith("image/") and len(resp.content) < 20000:
                return

        if leaked:
            # Build better evidence: show content-types and sizes
            evidence_parts = []
            for aid, resp in leaked[:5]:
                ct = resp.headers.get("Content-Type", "unknown")
                evidence_parts.append(f"ID {aid}: {ct} ({len(resp.content)} bytes)")

            ids = [str(aid) for aid, _ in leaked]
            self.add_finding(
                title="Unauthenticated attachment access (IDOR)",
                description=f"Attachments with IDs {', '.join(ids)} were accessible via /web/content without authentication. This indicates missing access control on ir.attachment records.",
                severity=Severity.HIGH,
                request="GET /web/content?id=1&download=1",
                response_snippet="; ".join(evidence_parts),
                response_status=200,
                remediation="Ensure attachment controllers check access rights via ir.attachment.check_access_rights() or use signed URLs for public attachments only.",
                cwe="CWE-639",
            )

    def _check_web_image(self) -> None:
        responses = self._fetch_attachments("/web/image", {})
        leaked = []
        for aid, resp in responses:
            if resp.status_code == 200 and resp.headers.get("Content-Type", "").startswith("image/"):
                leaked.append(aid)

        # Odoo returns the SAME placeholder image for every missing/inaccessible ID.
        if len(leaked) >= 2 and self._is_placeholder_image(responses):
            return

        if leaked:
            evidence_parts = []
            for aid in leaked[:5]:
                _, resp = next((r for r in responses if r[0] == aid), (aid, None))
                if resp:
                    ct = resp.headers.get("Content-Type", "unknown")
                    evidence_parts.append(f"ID {aid}: {ct} ({len(resp.content)} bytes)")

            self.add_finding(
                title="Unauthenticated image access (IDOR)",
                description=f"Images with IDs {', '.join(str(x) for x in leaked)} were accessible via /web/image without authentication.",
                severity=Severity.MEDIUM,
                request="GET /web/image?id=1",
                response_snippet="; ".join(evidence_parts),
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
