"""HTTP helpers for response analysis and signature matching."""

import re
from typing import Dict, List, Optional, Tuple

import requests


# Odoo-specific error signatures (tracebacks, internal errors)
# These must NOT match normal HTML page content (data attributes, templates, etc.)
ODOO_ERROR_SIGNATURES = [
    re.compile(r"Traceback\s+\(most recent call last\)", re.I),
    re.compile(r"odoo\.(exceptions|models|http|api)\.", re.I),
    re.compile(r"psycopg2\.(OperationalError|ProgrammingError)", re.I),
    re.compile(r"FATAL:\s+database", re.I),
    # Only match ir.* in traceback/error contexts, not data-main-object attributes
    re.compile(r"ir\.(model|module|ui\.view|rule)\b[^>]*$", re.MULTILINE),
    re.compile(r"QWeb\s+template\s+not\s+found", re.I),
]

# WAF/CDN signatures
WAF_SIGNATURES: List[Tuple[str, re.Pattern]] = [
    ("Cloudflare", re.compile(r"cloudflare|cf-ray", re.I)),
    ("Akamai", re.compile(r"akamai|akamai-ghost", re.I)),
    ("AWS WAF", re.compile(r"aws-waf|awselb", re.I)),
    ("Sucuri", re.compile(r"sucuri|x-sucuri", re.I)),
    ("ModSecurity", re.compile(r"mod_security|modsecurity", re.I)),
    ("Imperva", re.compile(r"incapsula|imperva", re.I)),
    ("F5 BIG-IP", re.compile(r"bigip|f5", re.I)),
]

# Odoo version fingerprints in HTML/JS
VERSION_FINGERPRINTS = [
    re.compile(r'odoo\s*[=:]\s*["\']?(\d+\.\d+)'),
    re.compile(r'Odoo\s+v?(\d+\.\d+)'),
    re.compile(r'web\.client_version\s*[=:]\s*["\']?(\d+\.\d+)'),
    re.compile(r'window\.__odoo\s*=\s*\{[^}]*"version"\s*:\s*"(\d+\.\d+)"'),
]


def detect_waf(response: requests.Response) -> Optional[str]:
    """Detect WAF/CDN from response headers/body."""
    header_text = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
    combined = f"{header_text}\n{response.text[:4096]}"
    for name, pattern in WAF_SIGNATURES:
        if pattern.search(combined):
            return name
    return None


def detect_odoo_version(text: str) -> Optional[str]:
    """Attempt to extract Odoo version from HTML/JS text."""
    for pattern in VERSION_FINGERPRINTS:
        match = pattern.search(text)
        if match:
            return match.group(1)
    return None


def is_waf_block_page(response: requests.Response) -> bool:
    """Check if response is a WAF/CDN block page (503, 502, 504 with WAF signatures)."""
    if response.status_code in (502, 503, 504):
        if detect_waf(response):
            return True
    return False


def is_odoo_error_page(response: requests.Response) -> bool:
    """Check if response contains an Odoo traceback or error page.

    Ignores WAF/CDN block pages (502/503/504) to avoid false positives.
    Also ignores normal 404 pages — only flags actual debug/traceback output.
    """
    if is_waf_block_page(response):
        return False
    # 5xx responses are error pages; 404s are normal unless they contain tracebacks
    if response.status_code >= 500:
        return True
    if response.status_code == 404:
        return False
    text = response.text[:8192]
    for sig in ODOO_ERROR_SIGNATURES:
        if sig.search(text):
            return True
    return False


def extract_title(response: requests.Response) -> Optional[str]:
    """Extract <title> from HTML response."""
    from bs4 import BeautifulSoup
    try:
        soup = BeautifulSoup(response.text, "html.parser")
        if soup.title and soup.title.string:
            return soup.title.string.strip()
    except Exception:
        pass
    return None


def reflection_contexts(response_text: str, payload: str) -> List[str]:
    """Determine where a payload is reflected in the response."""
    contexts = []
    text = response_text
    idx = text.find(payload)
    if idx == -1:
        return contexts

    before = text[max(0, idx - 100):idx]

    if re.search(r'<[^>]*=["\']?[^"\']*$', before):
        contexts.append("html_attribute")
    if re.search(r'<script[^>]*>', before, re.I) and "</script>" not in before:
        contexts.append("javascript")
    if re.search(r'<[^>/]+\s', before):
        contexts.append("html_tag")
    if re.search(r'url\s*\(', before, re.I):
        contexts.append("css_url")
    if not contexts:
        contexts.append("html_body")

    return contexts
