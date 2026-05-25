"""Unauthenticated reconnaissance checks."""

from orca.checks.base import BaseCheck
from orca.findings import Severity
from orca.utils.http import detect_odoo_version, detect_waf, extract_title


class ReconCheck(BaseCheck):
    name = "recon"
    description = "Unauthenticated reconnaissance: version, databases, modules, WAF"
    requires_auth = False

    def run(self) -> None:
        self._check_version()
        self._check_databases()
        self._check_login_page()
        self._check_waf()
        self._check_registration()
        self._check_frontend_modules()

    def _check_version(self) -> None:
        version = self.target.version
        if version:
            self.result.target.version = version
            self.result.target.version_raw = self.target.version_raw
        # Additional HTML fallbacks
        for path in ["/web/login", "/web", "/"]:
            try:
                resp = self.target.get(path, timeout=8)
                if resp.status_code == 200:
                    html_version = detect_odoo_version(resp.text)
                    if html_version and not self.result.target.version:
                        self.result.target.version = html_version
                        self.result.target.version_raw = html_version
                    # Extract module hints from asset bundles
                    self._extract_modules_from_assets(resp.text)
            except Exception:
                pass

    def _check_databases(self) -> None:
        dbs = self.target.databases
        if dbs:
            self.result.target.databases = dbs
            self.add_finding(
                title="Database listing enabled",
                description=f"The Odoo instance exposes {len(dbs)} database(s) via XML-RPC or JSON-RPC: {', '.join(dbs)}.",
                severity=Severity.MEDIUM,
                request="XML-RPC db.list or JSON-RPC /web/database/list",
                response_snippet=f"Databases: {', '.join(dbs)}",
                response_status=200,
                remediation="Disable database listing in odoo.conf: list_db = False",
                cwe="CWE-200",
                references=["https://www.odoo.com/documentation/master/administration/install/deploy.html#security"],
            )

    def _check_login_page(self) -> None:
        try:
            resp = self.target.get("/web/login", timeout=10)
            if resp.status_code == 200:
                title = extract_title(resp)
                if title:
                    self.result.target.tech_stack.append(f"login_title:{title}")
                if "csrf_token" in resp.text:
                    self.result.target.csrf_token_present = True
        except Exception:
            pass

    def _check_waf(self) -> None:
        try:
            resp = self.target.get("/web/login", timeout=10)
            waf = detect_waf(resp)
            if waf:
                self.result.target.waf_detected = waf
                self.add_finding(
                    title=f"WAF/CDN detected: {waf}",
                    description=f"A {waf} presence was detected via response headers/body signatures.",
                    severity=Severity.INFO,
                    remediation="This is informational only; adjust testing cadence if needed.",
                )
        except Exception:
            pass

    def _check_registration(self) -> None:
        paths = [
            "/web/signup",
            "/auth_signup/sign_up",
            "/web/portal/register",
            "/web/register",
            "/website/signup",
            "/portal/signup",
            "/signup",
            "/web/login/signup",
        ]
        found = []
        for p in paths:
            try:
                resp = self.target.get(p, timeout=8, allow_redirects=False)
                # 200 = direct access; 301/302 redirect to login or signup form = likely enabled
                if resp.status_code in (200, 301, 302, 307, 308):
                    found.append(p)
            except Exception:
                pass
        if found:
            self.add_finding(
                title="Public registration/signup enabled",
                description=f"Signup-related paths responded or redirected: {', '.join(found)}. This may allow account creation abuse or stored XSS vectors.",
                severity=Severity.LOW,
                remediation="Disable auth_signup or restrict portal registration to invited users only.",
                cwe="CWE-200",
            )

    def _extract_modules_from_assets(self, html: str) -> None:
        """Parse CSS/JS bundle paths to infer installed modules."""
        import re
        patterns = [
            re.compile(r'/web/assets/[^"\']+/(\w+)/', re.I),
            re.compile(r'/web/content/[^"\']+/(\w+)[-_]', re.I),
            re.compile(r'src=["\'][^"\']*/(\w+)/static/', re.I),
            re.compile(r'href=["\'][^"\']*/(\w+)/static/', re.I),
        ]
        hash_like = re.compile(r'^[0-9a-f]{6,}$')
        for pat in patterns:
            for m in pat.finditer(html):
                mod = m.group(1).lower()
                if hash_like.match(mod):
                    continue
                if mod not in ("web", "web_editor", "base", "bus", "mail", "debug", "assets", "static") and mod not in self.result.target.detected_modules:
                    self.result.target.detected_modules.append(mod)

    def _check_frontend_modules(self) -> None:
        paths = {
            "/shop": "website_sale",
            "/forum": "website_forum",
            "/blog": "website_blog",
            "/slides": "website_slides",
            "/events": "website_event",
            "/jobs": "website_hr_recruitment",
            "/contactus": "website",
            "/website/info": "website",
            "/appointment": "appointment",
            "/calendar": "calendar",
            "/helpdesk": "helpdesk",
            "/project": "project",
            "/crm": "crm",
            "/pos": "point_of_sale",
            "/survey": "survey",
            "/rating": "rating",
            "/my": "portal",
            "/my/account": "portal",
            "/my/orders": "sale",
            "/my/invoices": "account",
            "/discuss": "mail",
            "/payment": "payment",
            "/livechat": "im_livechat",
            "/whatsapp": "whatsapp",
            "/sms": "sms",
            "/survey/start": "survey",
            "/discuss": "mail",
            "/discuss/channel": "mail",
            "/mail": "mail",
            "/mail/read": "mail",
            "/payment": "payment",
            "/payment/process": "payment",
            "/payment/confirmation": "payment",
            "/oauth": "auth_oauth",
            "/auth_oauth": "auth_oauth",
            "/portal/share": "portal",
            "/sms": "sms",
            "/whatsapp": "whatsapp",
            "/livechat": "im_livechat",
            "/livechat/channel": "im_livechat",
            "/im_livechat": "im_livechat",
            "/im_livechat/support": "im_livechat",
            "/website_iframe_editor": "website",
            "/website_force": "website",
            "/website/preview": "website",
            "/website/form": "website",
            "/website/attach": "website",
            "/website/lang": "website",
            "/database_anonymization": "database_anonymization",
        }
        detected = list(self.result.target.detected_modules)
        for path, module in paths.items():
            try:
                resp = self.target.get(path, timeout=8, allow_redirects=False)
                if resp.status_code in (200, 301, 302, 307, 308, 400, 401, 403, 405, 415, 500):
                    if module not in detected:
                        detected.append(module)
            except Exception:
                pass
        if detected:
            self.result.target.detected_modules = list(set(detected))
