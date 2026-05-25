"""Source code leak checks (CVE-2024-45840, CVE-2021-44475)."""

from orca.checks.base import BaseCheck
from orca.findings import Severity


# Paths that attempt to retrieve source code via asset/static file serving
SOURCE_LEAK_PATHS = [
    # CVE-2024-45840: Arbitrary source code download via static asset management
    "/web/assets/odoo/addons/base/models/ir_attachment.py",
    "/web/assets/odoo/addons/web/controllers/main.py",
    "/web/assets/odoo/addons/mail/models/mail_message.py",
    "/web/assets/static/src/xml/base.xml",
    "/web/assets/static/src/js/core/dom.js",
    "/web/assets/1",
    "/web/assets/2",
    "/web/content/odoo/addons/base/models/ir_attachment.py",
    "/web/content/odoo/addons/web/controllers/main.py",
    "/base_import/static/odoo/addons/base/models/ir_attachment.py",
    "/web/static/odoo/addons/base/models/ir_attachment.py",
    # CVE-2021-44475: Asset bundle abuse
    "/web/assets/debug",
    "/web/assets/",
]


class SourceLeakCheck(BaseCheck):
    name = "source_leak"
    description = "Detect source code leaks via asset/static file path abuse (CVE-2024-45840, CVE-2021-44475)"
    requires_auth = False

    def run(self) -> None:
        for path in SOURCE_LEAK_PATHS:
            try:
                resp = self.target.get(path, timeout=8, allow_redirects=False)
                if resp.status_code == 200:
                    text = resp.text[:800]
                    # Look for Python source code indicators
                    py_indicators = [
                        "def ",
                        "import ",
                        "from ",
                        "class ",
                        "# -*- coding:",
                        "#!/usr/bin/env python",
                        "@api.model",
                        "@api.multi",
                        "self.env",
                        "_logger",
                    ]
                    # Look for XML indicators
                    xml_indicators = [
                        "<?xml",
                        "<template",
                        "<record",
                        "<field",
                        "<odoo>",
                        "<openerp>",
                    ]
                    if any(ind in text for ind in py_indicators) or any(ind in text for ind in xml_indicators):
                        self.add_finding(
                            title=f"Source code leak via {path}",
                            description=f"The endpoint {path} returned server-side source code files. This is CVE-2024-45840 / CVE-2021-44475.",
                            severity=Severity.CRITICAL,
                            request=f"GET {path}",
                            response_snippet=text[:600],
                            response_status=resp.status_code,
                            remediation="Restrict static asset serving to public resource files only. Do not serve .py, .xml, or other source files.",
                            cwe="CWE-552",
                            references=[
                                "https://nvd.nist.gov/vuln/detail/CVE-2024-45840",
                                "https://nvd.nist.gov/vuln/detail/CVE-2021-44475",
                            ],
                        )
                        break
            except Exception:
                pass
