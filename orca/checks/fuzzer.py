"""Lightweight fuzzing engine: form discovery + parameter mutation."""

import re
from typing import Dict, List, Optional, Tuple

from bs4 import BeautifulSoup

from orca.checks.base import BaseCheck
from orca.findings import Severity

# Payloads mapped by intent
PAYLOADS = {
    "xss": [
        "<script>alert('ORCA')</script>",
        "<img src=x onerror=alert('ORCA')>",
        "\"><script>alert('ORCA')</script>",
        "'><img src=x onerror=alert('ORCA')>",
    ],
    "error": [
        "'",
        '"',
        "\\",
        "' OR '1'='1",
        "1/0",
        "../../../etc/passwd",
        "{{7*7}}",
    ],
    "redirect": [
        "https://evil.com",
        "//evil.com",
        "javascript:alert('ORCA')",
    ],
}

# Pages to crawl for forms
FORM_PAGES = [
    "/web/login",
    "/web/signup",
    "/contactus",
    "/shop",
    "/forum",
    "/blog",
    "/events",
    "/helpdesk",
]


class FuzzerCheck(BaseCheck):
    name = "fuzzer"
    description = "Discover HTML forms and fuzz parameters for XSS, errors, and open redirects"
    requires_auth = False

    def run(self) -> None:
        forms = self._discover_forms()
        for form in forms:
            self._fuzz_form(form)
        # Also fuzz known GET parameters
        self._fuzz_get_params()

    def _discover_forms(self) -> List[Dict[str, any]]:
        forms = []
        for path in FORM_PAGES:
            try:
                resp = self.target.get(path, timeout=8, allow_redirects=False)
                if resp.status_code != 200:
                    continue
                soup = BeautifulSoup(resp.text, "html.parser")
                for form_tag in soup.find_all("form"):
                    action = form_tag.get("action") or path
                    if action.startswith("/"):
                        action = action
                    elif action.startswith("http"):
                        continue  # skip external forms
                    else:
                        action = path.rstrip("/") + "/" + action

                    inputs = []
                    for inp in form_tag.find_all(["input", "textarea", "select"]):
                        name = inp.get("name")
                        if name and inp.get("type") not in ("submit", "button", "image", "reset", "file"):
                            inputs.append(name)

                    if inputs:
                        forms.append({
                            "path": path,
                            "action": action,
                            "method": (form_tag.get("method") or "get").upper(),
                            "inputs": inputs,
                        })
            except Exception:
                pass
        return forms

    def _fuzz_form(self, form: Dict[str, any]) -> None:
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        # XSS fuzz
        for payload in PAYLOADS["xss"]:
            data = {inp: payload for inp in inputs}
            try:
                if method == "POST":
                    resp = self.target.session.post(
                        self.target.base_url + action,
                        data=data,
                        timeout=8,
                        allow_redirects=False,
                    )
                else:
                    resp = self.target.session.get(
                        self.target.base_url + action,
                        params=data,
                        timeout=8,
                        allow_redirects=False,
                    )
                if payload in resp.text:
                    self.add_finding(
                        title=f"Reflected XSS in form on {action}",
                        description=f"Payload '{payload}' was reflected in the response when submitted to form on {action} via {method}.",
                        severity=Severity.HIGH,
                        request=f"{method} {action} {data}",
                        response_snippet=resp.text[max(0, resp.text.find(payload)-80):resp.text.find(payload)+len(payload)+80],
                        response_status=resp.status_code,
                        remediation="Escape all user input in HTML context. Use Odoo qweb t-esc for HTML output.",
                        cwe="CWE-79",
                    )
                    break
            except Exception:
                pass

        # Error-trigger fuzz
        for payload in PAYLOADS["error"]:
            data = {inp: payload for inp in inputs}
            try:
                if method == "POST":
                    resp = self.target.session.post(
                        self.target.base_url + action,
                        data=data,
                        timeout=8,
                        allow_redirects=False,
                    )
                else:
                    resp = self.target.session.get(
                        self.target.base_url + action,
                        params=data,
                        timeout=8,
                        allow_redirects=False,
                    )
                if self._is_interesting_error(resp):
                    self.add_finding(
                        title=f"Error disclosure via form fuzzing on {action}",
                        description=f"Payload '{payload}' triggered an error response on {action}. This may reveal SQL syntax, path traversal, or template injection.",
                        severity=Severity.MEDIUM,
                        request=f"{method} {action} {data}",
                        response_snippet=resp.text[:500],
                        response_status=resp.status_code,
                        remediation="Validate and sanitize all form inputs. Use parameterized queries and avoid raw string interpolation.",
                        cwe="CWE-20",
                    )
                    break
            except Exception:
                pass

    def _fuzz_get_params(self) -> None:
        # Fuzz known GET parameters on common pages
        targets = [
            ("/web/login", ["redirect"]),
            ("/web", ["redirect", "return_url"]),
            ("/shop", ["redirect"]),
            ("/forum", ["redirect"]),
        ]
        for path, params in targets:
            for param in params:
                for payload in PAYLOADS["redirect"]:
                    try:
                        resp = self.target.get(path, params={param: payload}, timeout=8, allow_redirects=False)
                        loc = resp.headers.get("Location", "")
                        if self._is_external_redirect(loc, payload):
                            self.add_finding(
                                title=f"Open redirect via {path}?{param}",
                                description=f"Parameter '{param}' on {path} accepts redirect payload '{payload}'.",
                                severity=Severity.LOW,
                                request=f"GET {path}?{param}={payload}",
                                response_snippet=f"Location: {loc}",
                                response_status=resp.status_code,
                                remediation="Validate redirect URLs against an allowlist of local paths.",
                                cwe="CWE-601",
                            )
                            break
                    except Exception:
                        pass

    @staticmethod
    def _is_external_redirect(location: str, payload: str) -> bool:
        """Check if Location header actually redirects to the external payload."""
        if not location:
            return False
        # Absolute redirect to payload
        if location.startswith(payload):
            return True
        # Protocol-relative redirect
        if payload.startswith("//") and location.startswith(payload):
            return True
        # If location is just a local path, it's not an external redirect
        # even if the payload appears as a query parameter
        if location.startswith("/"):
            return False
        # If location is an absolute URL not matching payload, check domain
        from urllib.parse import urlparse
        parsed_loc = urlparse(location)
        parsed_payload = urlparse(payload)
        if parsed_loc.netloc and parsed_payload.netloc:
            return parsed_loc.netloc == parsed_payload.netloc
        return False

    @staticmethod
    def _is_interesting_error(resp) -> bool:
        if resp.status_code >= 500:
            return True
        text = resp.text[:2000].lower()
        indicators = [
            "traceback", "odoo.exceptions", "psycopg2", "fatal:",
            "syntax error", "sql", "template", "qweb", "keyerror",
            "valueerror", "attributeerror", "typeerror",
        ]
        return any(ind in text for ind in indicators)
