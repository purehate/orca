"""Odoo host discovery engine for mass network scanning."""

from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import ssl
import time
import urllib3
from typing import Dict, Iterator, List, Optional, Tuple
from urllib.parse import urljoin

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Odoo-specific HTML markers
ODOO_MARKERS = [
    re.compile(r'var\s+odoo\s*=\s*\{', re.I),
    re.compile(r'csrf_token\s*:', re.I),
    re.compile(r'data-website-id', re.I),
    re.compile(r'odoo/addons/', re.I),
    re.compile(r'/web/static/', re.I),
    re.compile(r'/web/assets/', re.I),
    re.compile(r'<title>[^<]*Login\s*\|', re.I),
    re.compile(r'openerp\.', re.I),
    re.compile(r'class="o_[a-z]+"', re.I),
    re.compile(r'id="oe_'),
]

# Werkzeug is Odoo's default WSGI server
WERKZEUG_MARKER = re.compile(r'Werkzeug', re.I)

# Known Odoo ports
DEFAULT_PORTS = [80, 443, 8069, 8080, 8443]


class DiscoveryResult:
    def __init__(self, url: str, version: Optional[str] = None,
                 title: Optional[str] = None, db_hint: Optional[str] = None,
                 werkzeug: bool = False, waf: Optional[str] = None,
                 confidence: str = "low", response_time_ms: float = 0.0):
        self.url = url
        self.version = version
        self.title = title
        self.db_hint = db_hint
        self.werkzeug = werkzeug
        self.waf = waf
        self.confidence = confidence
        self.response_time_ms = response_time_ms

    def to_dict(self) -> Dict[str, Optional[str]]:
        return {
            "url": self.url,
            "version": self.version,
            "title": self.title,
            "db_hint": self.db_hint,
            "werkzeug": str(self.werkzeug),
            "waf": self.waf,
            "confidence": self.confidence,
            "response_time_ms": f"{self.response_time_ms:.0f}",
        }


def _build_urls(host: str, ports: List[int]) -> Iterator[str]:
    """Generate candidate URLs for a host."""
    for port in ports:
        if port == 443:
            yield f"https://{host}"
        elif port == 80:
            yield f"http://{host}"
        elif port == 8443:
            yield f"https://{host}:{port}"
        else:
            yield f"http://{host}:{port}"


def _probe_host(url: str, timeout: float = 3.0, verify_ssl: bool = False) -> Optional[DiscoveryResult]:
    """Fast single-host Odoo probe."""
    start = time.time()
    try:
        resp = requests.get(
            f"{url}/web/login",
            timeout=timeout,
            verify=verify_ssl,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
        )
        elapsed = (time.time() - start) * 1000
    except Exception:
        return None

    text = resp.text
    lower_text = text.lower()
    headers = resp.headers

    # Quick reject: if it's tiny or clearly not HTML, skip
    if len(text) < 200:
        return None

    # Count Odoo-specific markers
    marker_hits = sum(1 for pat in ODOO_MARKERS if pat.search(text))
    werkzeug = bool(WERKZEUG_MARKER.search(headers.get("Server", "")))

    # Determine confidence
    if marker_hits >= 4 or (marker_hits >= 2 and werkzeug):
        confidence = "high"
    elif marker_hits >= 2 or werkzeug:
        confidence = "medium"
    elif marker_hits >= 1:
        confidence = "low"
    else:
        return None

    # Extract title
    title = None
    m = re.search(r'<title>([^<]+)</title>', text, re.I)
    if m:
        title = m.group(1).strip()

    # Extract db hint from title (common: "Login | DatabaseName")
    db_hint = None
    if title and "|" in title:
        parts = title.split("|")
        if len(parts) >= 2:
            db_hint = parts[-1].strip()

    # Try fast version extraction from HTML
    version = None
    ver_patterns = [
        re.compile(r'odoo\s*[=:]\s*["\']?(\d+\.\d+)'),
        re.compile(r'Odoo\s+v?(\d+\.\d+)'),
        re.compile(r'window\.__odoo\s*=\s*\{[^}]*"version"\s*:\s*"(\d+\.\d+)"'),
    ]
    for pat in ver_patterns:
        vm = pat.search(text)
        if vm:
            version = vm.group(1)
            break

    # WAF detection
    waf = None
    from orca.utils.http import detect_waf
    waf = detect_waf(resp)

    return DiscoveryResult(
        url=url,
        version=version,
        title=title,
        db_hint=db_hint,
        werkzeug=werkzeug,
        waf=waf,
        confidence=confidence,
        response_time_ms=elapsed,
    )


def _xmlrpc_version_probe(url: str, timeout: float = 3.0) -> Optional[str]:
    """Lightweight XML-RPC version probe for ambiguous hosts."""
    try:
        import xmlrpc.client
        ssl_context = ssl._create_unverified_context()
        transport = xmlrpc.client.SafeTransport(context=ssl_context, timeout=int(timeout))
        proxy = xmlrpc.client.ServerProxy(f"{url}/xmlrpc/2/common", transport=transport)
        info = proxy.version()
        if isinstance(info, dict):
            return info.get("server_version") or info.get("server_serie")
        return str(info)
    except Exception:
        return None


def discover_hosts(
    hosts: List[str],
    ports: Optional[List[int]] = None,
    threads: int = 100,
    timeout: float = 3.0,
    verify_ssl: bool = False,
    probe_xmlrpc: bool = True,
) -> List[DiscoveryResult]:
    """
    Discover Odoo instances across a list of hosts/IPs.
    Returns sorted list of DiscoveryResult objects (high confidence first).
    """
    ports = ports or DEFAULT_PORTS
    urls = []
    for host in hosts:
        urls.extend(_build_urls(host, ports))

    results: List[DiscoveryResult] = []
    seen: set = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_url = {executor.submit(_probe_host, url, timeout, verify_ssl): url for url in urls}
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                result = future.result()
                if result and result.url not in seen:
                    seen.add(result.url)
                    # Boost confidence with XML-RPC if ambiguous
                    if probe_xmlrpc and result.confidence in ("low", "medium"):
                        ver = _xmlrpc_version_probe(result.url, timeout)
                        if ver:
                            result.version = str(ver)
                            result.confidence = "high"
                    results.append(result)
            except Exception:
                pass

    results.sort(key=lambda r: (r.confidence != "high", r.confidence != "medium", r.response_time_ms))
    return results


def expand_network(network: str) -> List[str]:
    """Expand CIDR notation (e.g., 192.168.0.0/16) to list of IPs."""
    try:
        net = ipaddress.ip_network(network, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return []
