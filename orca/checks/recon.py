"""Unauthenticated reconnaissance checks."""

import re
from typing import List, Set

from orca.checks.base import BaseCheck
from orca.findings import Severity
from orca.utils.http import detect_odoo_version, detect_waf, extract_title
from orca.data.module_fingerprints import (
    CSS_CLASS_PREFIXES,
    MODEL_TO_MODULE,
    ROUTE_TO_MODULE,
    BUNDLE_TO_MODULE,
)


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
        self._check_sitemap()
        self._check_frontend_modules()

    def _add_modules(self, modules: List[str]) -> None:
        """Add module names to detected modules, deduplicating."""
        current = set(self.result.target.detected_modules)
        for mod in modules:
            current.add(mod)
        self.result.target.detected_modules = sorted(current)

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
                    # Extract module hints from asset bundles, CSS, models
                    self._extract_modules_from_html(resp.text)
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

    def _extract_modules_from_html(self, html: str) -> None:
        """Multi-signal module extraction from raw HTML."""
        # 1. Static paths: /module_name/static/...
        self._extract_modules_from_static_paths(html)
        # 2. Asset bundle names
        self._extract_modules_from_bundles(html)
        # 3. CSS class fingerprints
        self._extract_modules_from_css_classes(html)
        # 4. Model references (data-main-object, etc.)
        self._extract_modules_from_model_refs(html)

    def _extract_modules_from_static_paths(self, html: str) -> None:
        """Parse /module_name/static/ references in HTML."""
        hash_like = re.compile(r'^[0-9a-f]{6,}$')
        for m in re.finditer(r'(?:src|href|data-src)=["\'][^"\']*/(\w+)/static/', html, re.I):
            mod = m.group(1).lower()
            if hash_like.match(mod):
                continue
            if mod not in ("web", "web_editor", "base", "bus", "mail", "debug", "assets", "static"):
                self._add_modules([mod])

    def _extract_modules_from_bundles(self, html: str) -> None:
        """Parse asset bundle names for module hints."""
        for m in re.finditer(r'/web/assets/\d+/[a-f0-9]+/([^"\'\s]+)', html):
            bundle = m.group(1)
            # Remove .min.css / .min.js suffix
            bundle_clean = re.sub(r'\.min\.(css|js)$', '', bundle)
            if bundle_clean in BUNDLE_TO_MODULE:
                self._add_modules(BUNDLE_TO_MODULE[bundle_clean])
            # Also try partial match: module_name.assets_*
            prefix_match = re.match(r'^(\w+)\.assets_', bundle_clean)
            if prefix_match:
                mod = prefix_match.group(1)
                if mod not in ("web", "assets", "static"):
                    self._add_modules([mod])

    def _extract_modules_from_css_classes(self, html: str) -> None:
        """Extract module names from Odoo CSS class prefixes."""
        classes: Set[str] = set()
        # Body classes
        for m in re.finditer(r'<body[^>]*class=["\']([^"\']+)["\']', html, re.I):
            classes.update(m.group(1).split())
        # Any o_ class anywhere
        classes.update(re.findall(r'o_[a-z_]+', html))

        found: Set[str] = set()
        for cls in classes:
            cls_lower = cls.lower()
            for prefix, modules in CSS_CLASS_PREFIXES.items():
                if cls_lower.startswith(prefix.lower()):
                    found.update(modules)
        if found:
            self._add_modules(sorted(found))

    def _extract_modules_from_model_refs(self, html: str) -> None:
        """Extract modules from model references like data-main-object."""
        # data-main-object="model.name(id,)"
        for m in re.finditer(r'data-main-object=["\']([^"\'(]+)', html):
            model_ref = m.group(1).strip()
            # Extract model name before (id,)
            model_name = model_ref.split('(')[0].strip()
            if model_name in MODEL_TO_MODULE:
                self._add_modules(MODEL_TO_MODULE[model_name])

        # Generic model= references in URLs
        for m in re.finditer(r'model=([^&"\'\s]+)', html):
            model_name = m.group(1).strip()
            if model_name in MODEL_TO_MODULE:
                self._add_modules(MODEL_TO_MODULE[model_name])

    def _check_sitemap(self) -> None:
        """Parse sitemap.xml for module-specific routes."""
        try:
            resp = self.target.get("/sitemap.xml", timeout=10)
            if resp.status_code != 200:
                return
            urls = re.findall(r'<loc>([^<]+)</loc>', resp.text)
            found_modules: Set[str] = set()
            for url in urls:
                path = url.replace(self.target.base_url.rstrip('/'), '')
                # Direct route match
                if path in ROUTE_TO_MODULE:
                    found_modules.update(ROUTE_TO_MODULE[path])
                # Base path match (e.g., /event/foo -> /event)
                parts = path.strip('/').split('/')
                if parts:
                    base = '/' + parts[0]
                    if base in ROUTE_TO_MODULE:
                        found_modules.update(ROUTE_TO_MODULE[base])
                    # Also check /base/sub for specific mappings
                    if len(parts) >= 2:
                        sub = '/' + '/'.join(parts[:2])
                        if sub in ROUTE_TO_MODULE:
                            found_modules.update(ROUTE_TO_MODULE[sub])
            if found_modules:
                self._add_modules(sorted(found_modules))
        except Exception:
            pass

    def _check_frontend_modules(self) -> None:
        """Probe known module routes and parse responses for additional hints."""
        detected: Set[str] = set(self.result.target.detected_modules)

        # Group routes to reduce requests — probe unique paths
        paths_to_probe = sorted(set(ROUTE_TO_MODULE.keys()))

        for path in paths_to_probe:
            try:
                resp = self.target.get(path, timeout=8, allow_redirects=False)
                status = resp.status_code

                # Any non-404 response suggests the route exists
                if status != 404:
                    modules = ROUTE_TO_MODULE.get(path, [])
                    detected.update(modules)

                    # Parse 200 responses for deeper module hints
                    if status == 200:
                        self._extract_modules_from_html(resp.text)

            except Exception:
                pass

        self.result.target.detected_modules = sorted(detected)
