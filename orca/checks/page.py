"""Focused, non-destructive assessment of explicitly included frontend pages."""

from __future__ import annotations

from typing import List
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from orca.checks.base import BaseCheck
from orca.findings import Severity


class PageCheck(BaseCheck):
    """Inspect explicitly authorized pages and their form security controls."""

    name = "page"
    description = "Assess explicitly included frontend pages and forms"
    requires_auth = False

    def run(self) -> None:
        if self.result.scan_config.get("crawl"):
            return
        paths = self.result.scan_config.get("include_paths", [])
        for path in paths:
            self._assess_page(path)

    def _assess_page(self, path: str) -> None:
        try:
            response = self.target.get(path, timeout=15, allow_redirects=False)
        except requests.RequestException as exc:
            self.add_finding(
                title=f"Included page could not be assessed: {path}",
                description="The authorized page request failed before a response was captured.",
                severity=Severity.INFO,
                request=f"GET {path}",
                notes=f"Request error type: {type(exc).__name__}",
            )
            return

        if response.status_code != 200:
            location = response.headers.get("Location", "")
            location_path = urlparse(location).path if location else ""
            self.add_finding(
                title=f"Included page returned HTTP {response.status_code}: {path}",
                description="The explicitly included page did not return a directly assessable HTML response.",
                severity=Severity.INFO,
                request=f"GET {path}",
                response_status=response.status_code,
                response_snippet=f"Redirect path: {location_path or 'none'}",
            )
            return

        self.assess_response(path, response, include_inventory=True)

    def assess_response(self, path: str, response, include_inventory: bool) -> None:
        """Assess an already-fetched page without repeating the HTTP request."""
        content_type = response.headers.get("Content-Type", "")
        if "html" not in content_type.lower():
            return

        soup = BeautifulSoup(response.text, "html.parser")
        forms = list(soup.find_all("form"))
        if include_inventory:
            self._add_inventory(path, response.status_code, soup, forms)
        self._check_post_csrf(path, forms)
        self._check_form_actions(path, forms)
        self._check_mixed_content(path, soup)
        self._check_content_security_policy(path, response.headers)

    def _add_inventory(self, path: str, status: int, soup, forms: List) -> None:
        title = soup.title.string.strip() if soup.title and soup.title.string else "Untitled"
        summaries = []
        for form in forms[:20]:
            method = (form.get("method") or "GET").upper()
            action = form.get("action") or path
            input_names = sorted(
                {
                    field.get("name")
                    for field in form.find_all(["input", "textarea", "select"])
                    if field.get("name")
                }
            )
            summaries.append(
                f"{method} {action} fields={','.join(input_names[:30]) or 'none'}"
            )
        self.add_finding(
            title=f"Included page assessed: {path}",
            description=f"The page '{title}' returned HTML with {len(forms)} form(s).",
            severity=Severity.INFO,
            request=f"GET {path}",
            response_status=status,
            response_snippet="; ".join(summaries) or "No HTML forms detected.",
            remediation="Review this inventory alongside the page-specific findings.",
        )

    def _check_post_csrf(self, path: str, forms: List) -> None:
        missing = []
        for index, form in enumerate(forms, start=1):
            if (form.get("method") or "GET").upper() != "POST":
                continue
            names = {
                field.get("name", "").lower()
                for field in form.find_all(["input", "textarea", "select"])
            }
            if not {"csrf_token", "_csrf"}.intersection(names):
                missing.append(f"form {index} action={form.get('action') or path}")
        if missing:
            self.add_finding(
                title=f"POST form has no explicit CSRF field on {path}",
                description="One or more POST forms do not contain a recognizable CSRF token field. Runtime validation is required because JavaScript may add a token before submission.",
                severity=Severity.MEDIUM,
                request=f"GET {path}",
                response_status=200,
                response_snippet="; ".join(missing),
                remediation="Use Odoo CSRF protection for every state-changing form and retain a regression test that rejects tokenless submissions.",
                cwe="CWE-352",
            )

    def _check_form_actions(self, path: str, forms: List) -> None:
        unsafe = []
        for index, form in enumerate(forms, start=1):
            action = form.get("action") or path
            current_url = urljoin(f"{self.target.url}/", path.lstrip("/"))
            resolved = urljoin(current_url, action)
            parsed = urlparse(resolved)
            if (
                parsed.netloc
                and parsed.netloc.lower() != self.target.parsed.netloc.lower()
            ):
                unsafe.append(f"form {index} external action={parsed.scheme}://{parsed.netloc}{parsed.path}")
            elif self.target.parsed.scheme == "https" and parsed.scheme == "http":
                unsafe.append(f"form {index} insecure action={parsed.path}")
        if unsafe:
            self.add_finding(
                title=f"Form submits outside the authorized HTTPS origin: {path}",
                description="A form action leaves the assessed HTTPS origin, which can disclose submitted customer data.",
                severity=Severity.HIGH,
                request=f"GET {path}",
                response_status=200,
                response_snippet="; ".join(unsafe),
                remediation="Submit forms only to same-origin HTTPS endpoints and validate the destination server-side.",
                cwe="CWE-319",
            )

    def _check_mixed_content(self, path: str, soup) -> None:
        if self.target.parsed.scheme != "https":
            return
        insecure = []
        for tag in soup.find_all(src=True):
            if str(tag.get("src", "")).lower().startswith("http://"):
                insecure.append(f"{tag.name}[src]")
        for tag in soup.find_all(href=True):
            if str(tag.get("href", "")).lower().startswith("http://"):
                insecure.append(f"{tag.name}[href]")
        if insecure:
            self.add_finding(
                title=f"Mixed-content resources on included page: {path}",
                description="The HTTPS page references resources over plaintext HTTP.",
                severity=Severity.MEDIUM,
                request=f"GET {path}",
                response_status=200,
                response_snippet=", ".join(insecure[:30]),
                remediation="Serve every page resource over HTTPS and add an enforcing Content Security Policy.",
                cwe="CWE-319",
            )

    def _check_content_security_policy(self, path: str, headers) -> None:
        policy = headers.get("Content-Security-Policy", "")
        lowered = policy.lower()
        if not policy or not any(
            directive in lowered for directive in ("default-src", "script-src")
        ):
            self.add_finding(
                title=f"Content Security Policy does not constrain scripts: {path}",
                description="The page CSP is missing or only controls unrelated directives, so it does not provide meaningful script-execution defense in depth.",
                severity=Severity.LOW,
                request=f"GET {path}",
                response_status=200,
                response_snippet=f"Content-Security-Policy: {policy or 'not present'}",
                remediation="Deploy a tested CSP with default-src and script-src directives, then reduce unsafe-inline and unsafe-eval dependencies.",
                cwe="CWE-693",
            )
