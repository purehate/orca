"""Sensitive file and directory exposure checks."""

from orca.checks.base import BaseCheck
from orca.findings import Severity


SENSITIVE_PATHS = [
    # LFI static paths (CVE-2018-14860)
    "/base_import/static/etc/passwd",
    "/base_import/static/c:/windows/win.ini",
    "/web/static/etc/passwd",
    "/web/static/c:/windows/win.ini",
    "/base/static/etc/passwd",
    "/base/static/c:/windows/win.ini",
    "/web/static/../../../etc/passwd",
    "/base_import/static/../../../etc/passwd",
    # Asset bundle source code leak (CVE-2024-45840, CVE-2021-44475)
    "/web/assets/debug/static/src/xml/base.xml",
    "/web/assets/debug/odoo/addons/base/models/ir_attachment.py",
    "/web/assets/ir.attachment/1",
    # Standard sensitive paths
    ".git/HEAD",
    ".git/config",
    ".git/index",
    ".git/logs/HEAD",
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    "config/odoo.conf",
    "odoo.conf",
    "etc/odoo.conf",
    "database/",
    "backup/",
    "backups/",
    "dump/",
    "dumps/",
    "filestore/",
    "data/filestore/",
    "requirements.txt",
    "docker-compose.yml",
    "Dockerfile",
    "setup.py",
    "pyproject.toml",
    ".htaccess",
    ".htpasswd",
    "server-status",
    "server-info",
    "phpinfo.php",
    "info.php",
    "test.php",
    "api-docs",
    "swagger.json",
    "swagger-ui.html",
    "v1/api-docs",
    "openapi.json",
    "robots.txt",
    "sitemap.xml",
    "crossdomain.xml",
    ".well-known/security.txt",
]


class SensitiveFilesCheck(BaseCheck):
    name = "sensitive_files"
    description = "Probe for exposed sensitive files and directories"
    requires_auth = False

    def run(self) -> None:
        found = []
        for path in SENSITIVE_PATHS:
            try:
                resp = self.target.head(path, timeout=8, allow_redirects=False)
                if resp.status_code == 200:
                    # Confirm with GET for a snippet
                    get_resp = self.target.get(path, timeout=8, allow_redirects=False)
                    snippet = get_resp.text[:400]
                    found.append((path, snippet, get_resp.status_code))
            except Exception:
                pass

        for path, snippet, status in found:
            # robots.txt and sitemap.xml are intentionally public
            if path in ("robots.txt", "sitemap.xml"):
                self.add_finding(
                    title=f"Public file exposed: {path}",
                    description=f"The path {path} is accessible (HTTP {status}). This is normal but may reveal site structure.",
                    severity=Severity.INFO,
                    request=f"GET {path}",
                    response_snippet=snippet[:300],
                    response_status=status,
                    remediation="Review contents for sensitive paths. robots.txt can be used by attackers for reconnaissance.",
                    cwe="CWE-200",
                )
                continue
            self.add_finding(
                title=f"Sensitive file exposed: {path}",
                description=f"The path {path} is accessible without authentication (HTTP {status}). This may leak source code, credentials, or system configuration.",
                severity=Severity.HIGH if any(k in path for k in [".git", ".env", "config", "backup", "dump", "filestore"]) else Severity.MEDIUM,
                request=f"GET {path}",
                response_snippet=snippet,
                response_status=status,
                remediation="Restrict access to sensitive files via web server rules or move them outside the document root.",
                cwe="CWE-552",
            )
