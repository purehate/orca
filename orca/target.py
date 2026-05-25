"""Target connection layer with throttling, session management, and metadata."""

import random
import ssl
import time
import urllib3
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# Disable SSL warnings globally (scanner context)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ThrottledSession(requests.Session):
    """requests.Session with configurable rate limiting and jitter."""

    def __init__(
        self,
        rate_limit: Optional[float] = None,
        jitter: Optional[float] = None,
        proxy: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        verify: bool = False,
    ):
        super().__init__()
        self.rate_limit = rate_limit
        self.jitter = jitter
        self.last_request_time = 0.0
        self.verify = verify

        if proxy:
            self.proxies = {"http": proxy, "https": proxy}
        if headers:
            self.headers.update(headers)

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        self._throttle()
        return super().request(method, url, **kwargs)

    def _throttle(self) -> None:
        if not self.rate_limit or self.rate_limit <= 0:
            return

        current_time = time.time()
        if self.last_request_time == 0:
            self.last_request_time = current_time
            return

        time_since_last = current_time - self.last_request_time
        min_interval = 1.0 / self.rate_limit

        if self.jitter and self.jitter > 0:
            jitter_factor = 1.0 + (random.uniform(-self.jitter, self.jitter) / 100.0)
            min_interval *= jitter_factor

        if time_since_last < min_interval:
            time.sleep(min_interval - time_since_last)

        self.last_request_time = time.time()


class Target:
    """Represents an Odoo target and manages HTTP/RPC communication."""

    def __init__(
        self,
        url: str,
        rate_limit: Optional[float] = None,
        jitter: Optional[float] = None,
        proxy: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        verify_ssl: bool = False,
    ):
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        self.url = url.rstrip("/")
        self.parsed = urlparse(self.url)
        self.base_url = f"{self.parsed.scheme}://{self.parsed.netloc}"

        self.session = ThrottledSession(
            rate_limit=rate_limit,
            jitter=jitter,
            proxy=proxy,
            headers=headers,
            verify=verify_ssl,
        )

        self._version_raw: Optional[Any] = None
        self._version: Optional[str] = None
        self._databases: Optional[List[str]] = None
        self._csrf_token: Optional[str] = None

    # ------------------------------------------------------------------
    # Basic HTTP helpers
    # ------------------------------------------------------------------

    def get(self, path: str, **kwargs) -> requests.Response:
        return self.session.get(urljoin(self.base_url, path), **kwargs)

    def post(self, path: str, **kwargs) -> requests.Response:
        return self.session.post(urljoin(self.base_url, path), **kwargs)

    def head(self, path: str, **kwargs) -> requests.Response:
        return self.session.head(urljoin(self.base_url, path), **kwargs)

    def options(self, path: str, **kwargs) -> requests.Response:
        return self.session.options(urljoin(self.base_url, path), **kwargs)

    # ------------------------------------------------------------------
    # Odoo-specific helpers
    # ------------------------------------------------------------------

    def jsonrpc(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """Send a JSON-RPC 2.0 call."""
        payload = {
            "jsonrpc": "2.0",
            "method": "call",
            "id": random.randint(1, 1_000_000),
            "params": params or {},
        }
        resp = self.session.post(
            urljoin(self.base_url, endpoint),
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=15,
        )
        resp.raise_for_status()
        body = resp.json()
        if "error" in body:
            err = body["error"]
            msg = err.get("data", {}).get("message") or err.get("message", str(err))
            raise Exception(f"JSON-RPC error: {msg}")
        return body.get("result")

    def xmlrpc_common(self, method: str, *args) -> Any:
        """Call XML-RPC /xmlrpc/2/common with timeout."""
        import xmlrpc.client

        ssl_context = ssl._create_unverified_context()
        transport = xmlrpc.client.SafeTransport(context=ssl_context, timeout=10)
        proxy = xmlrpc.client.ServerProxy(
            f"{self.base_url}/xmlrpc/2/common", transport=transport
        )
        return getattr(proxy, method)(*args)

    def xmlrpc_db(self, method: str, *args) -> Any:
        """Call XML-RPC /xmlrpc/2/db with timeout."""
        import xmlrpc.client

        ssl_context = ssl._create_unverified_context()
        transport = xmlrpc.client.SafeTransport(context=ssl_context, timeout=10)
        proxy = xmlrpc.client.ServerProxy(
            f"{self.base_url}/xmlrpc/2/db", transport=transport
        )
        return getattr(proxy, method)(*args)

    # ------------------------------------------------------------------
    # Metadata accessors (with lazy caching)
    # ------------------------------------------------------------------

    @property
    def version(self) -> Optional[str]:
        if self._version is None:
            self._probe_version()
        return self._version

    @property
    def version_raw(self) -> Optional[Any]:
        if self._version_raw is None:
            self._probe_version()
        return self._version_raw

    @property
    def databases(self) -> List[str]:
        if self._databases is None:
            self._probe_databases()
        return self._databases or []

    def _probe_version(self) -> None:
        # 1. Try /web/webclient/version_info JSON endpoint (fast)
        try:
            result = self.jsonrpc("/web/webclient/version_info")
            if isinstance(result, dict):
                v = result.get("server_version_info") or result.get("server_version") or result.get("server_serie")
                if v:
                    self._version = str(v[0]) if isinstance(v, list) else str(v)
                    self._version_raw = result
                    return
        except Exception:
            pass

        # 2. Try HTTP fingerprint from login page
        try:
            from orca.utils.http import detect_odoo_version
            resp = self.get("/web/login", timeout=10)
            if resp.status_code == 200:
                v = detect_odoo_version(resp.text)
                if v:
                    self._version = v
                    self._version_raw = v
                    return
        except Exception:
            pass

        # 3. Try JSON-RPC common.version
        try:
            result = self.jsonrpc("/jsonrpc", {"service": "common", "method": "version", "args": []})
            if result:
                if isinstance(result, dict):
                    self._version = str(result.get("server_version") or result.get("server_serie"))
                else:
                    self._version = str(result)
                self._version_raw = result
                return
        except Exception:
            pass

        # 4. Fallback to XML-RPC
        try:
            info = self.xmlrpc_common("version")
            self._version_raw = info
            if isinstance(info, dict):
                self._version = info.get("server_version") or info.get("server_serie")
            elif isinstance(info, str):
                self._version = info
            else:
                self._version = str(info)
        except Exception:
            self._version_raw = None
            self._version = None

    def _probe_databases(self) -> None:
        dbs: List[str] = []
        try:
            dbs = self.xmlrpc_db("list")
        except Exception:
            pass
        if not dbs:
            try:
                result = self.jsonrpc("/web/database/list")
                if isinstance(result, list):
                    dbs = result
            except Exception:
                pass
        self._databases = dbs

    def fetch_csrf_token(self, path: str = "/web/login") -> Optional[str]:
        """Parse a CSRF token from an HTML form."""
        try:
            resp = self.get(path, timeout=10)
            if resp.status_code == 200 and "csrf_token" in resp.text:
                soup = BeautifulSoup(resp.text, "html.parser")
                token_input = soup.find("input", {"name": "csrf_token"})
                if token_input:
                    self._csrf_token = token_input.get("value")
                    return self._csrf_token
        except Exception:
            pass
        return None

    def session_cookie_flags(self) -> Dict[str, Any]:
        """Analyze session cookie security flags."""
        try:
            resp = self.get("/web/login", timeout=10, allow_redirects=True)
            cookie = resp.cookies.get("session_id")
            if cookie is None:
                return {}
            for ck in resp.raw._original_response.headers.get_all("Set-Cookie"):
                if "session_id" in ck:
                    return {
                        "httponly": "HttpOnly" in ck,
                        "secure": "secure" in ck.lower(),
                        "samesite": self._extract_samesite(ck),
                        "raw": ck,
                    }
        except Exception:
            pass
        return {}

    @staticmethod
    def _extract_samesite(cookie_header: str) -> Optional[str]:
        for part in cookie_header.split(";"):
            part = part.strip()
            if part.lower().startswith("samesite="):
                return part.split("=", 1)[1]
        return None
