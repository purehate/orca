"""Shadow dev box detection for ORCA.

Flags unauthorized/development Odoo instances based on:
- Werkzeug dev server (not behind reverse proxy)
- Debug mode enabled
- Database manager exposed
- Default/demo database names
- Self-signed/invalid SSL
- Port 8069 (default Odoo dev port)
- No WAF
- Open public registration
- Database listing enabled
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_DEV_PORTS = [8069, 8080, 80, 443]
SHADOW_INDICATORS = [
    "werkzeug",
    "debug_mode",
    "db_manager",
    "default_db_name",
    "self_signed_ssl",
    "dev_port",
    "no_waf",
    "open_registration",
    "db_listing",
]


@dataclass
class ShadowResult:
    url: str
    confidence: str = "low"  # low, medium, high
    indicators: List[str] = field(default_factory=list)
    version: Optional[str] = None
    db_name: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "url": self.url,
            "confidence": self.confidence,
            "indicators": self.indicators,
            "version": self.version,
            "db_name": self.db_name,
            "notes": self.notes,
        }


def _probe_shadow_indicators(url: str, timeout: float = 5.0) -> ShadowResult:
    result = ShadowResult(url=url)

    # 1. Check for Werkzeug
    try:
        resp = requests.get(
            f"{url}/web/login",
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        server = resp.headers.get("Server", "")
        if "Werkzeug" in server:
            result.indicators.append("werkzeug")
            result.notes.append("Running Werkzeug dev server (no reverse proxy)")
    except Exception:
        pass

    # 2. Check for debug mode
    try:
        resp = requests.get(
            f"{url}/web?debug=1",
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
        if resp.status_code == 200:
            text = resp.text.lower()
            debug_sigs = [
                "debug manager", "debug_menu", "debug_mode",
                "data-debug-mode", "assets_debug", "__debug__",
            ]
            if any(s in text for s in debug_sigs):
                result.indicators.append("debug_mode")
                result.notes.append("Debug mode is enabled")
    except Exception:
        pass

    # 3. Check for database manager
    try:
        resp = requests.get(
            f"{url}/web/database/manager",
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
        if resp.status_code == 200 and "database" in resp.text.lower():
            result.indicators.append("db_manager")
            result.notes.append("Database manager is exposed")
    except Exception:
        pass

    # 4. Check for database listing
    try:
        import json
        resp = requests.post(
            f"{url}/web/database/list",
            json={"jsonrpc": "2.0", "method": "call", "params": {}, "id": 1},
            timeout=timeout,
            verify=False,
            headers={"Content-Type": "application/json"},
        )
        if resp.status_code == 200:
            data = resp.json()
            dbs = data.get("result", [])
            if isinstance(dbs, list) and len(dbs) > 0:
                result.db_name = dbs[0]
                # Check for default/dev database names
                dev_names = {"odoo", "demo", "test", "dev", "development", "staging", "localhost", "trial", "temp", "tmp", "sandbox", "playground"}
                prod_names = {"production", "prod", "live", "master"}
                has_dev_db = False
                for db in dbs:
                    db_lower = db.lower()
                    if any(d in db_lower for d in dev_names) and not any(p in db_lower for p in prod_names):
                        has_dev_db = True
                        result.indicators.append("default_db_name")
                        result.notes.append(f"Default/dev database name detected: {db}")
                        break
                if has_dev_db:
                    result.indicators.append("db_listing")
                    result.notes.append(f"Database listing enabled: {', '.join(dbs)}")
    except Exception:
        pass

    # 5. Check SSL validity (self-signed)
    if url.startswith("https://"):
        try:
            requests.get(f"{url}/web/login", timeout=timeout, verify=True, allow_redirects=True)
        except requests.exceptions.SSLError:
            result.indicators.append("self_signed_ssl")
            result.notes.append("Self-signed or invalid SSL certificate")
        except Exception:
            pass

    # 6. Check dev port
    from urllib.parse import urlparse
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port in (8069, 8080):
        result.indicators.append("dev_port")
        result.notes.append(f"Running on dev port {port}")

    # 7. Check for open registration
    try:
        resp = requests.get(
            f"{url}/web/signup",
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
        if resp.status_code == 200 and ("name=\"login\"" in resp.text or "csrf_token" in resp.text):
            result.indicators.append("open_registration")
            result.notes.append("Public registration is enabled")
    except Exception:
        pass

    # Calculate confidence
    score = len(result.indicators)
    if score >= 4:
        result.confidence = "high"
    elif score >= 2:
        result.confidence = "medium"

    return result


def hunt_shadow_instances(urls: List[str], threads: int = 50, timeout: float = 5.0) -> List[ShadowResult]:
    """Run shadow-hunt probes against a list of discovered Odoo URLs."""
    import concurrent.futures

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_probe_shadow_indicators, url, timeout): url for url in urls}
        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result.indicators:
                    results.append(result)
            except Exception:
                pass

    results.sort(key=lambda r: (r.confidence != "high", r.confidence != "medium", -len(r.indicators)))
    return results
