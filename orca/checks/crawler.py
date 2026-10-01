"""Bounded same-origin crawler for custom Odoo pages and endpoint inventory."""

from __future__ import annotations

import re
from collections import deque
from typing import Deque, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from orca.checks.base import BaseCheck
from orca.checks.page import PageCheck
from orca.findings import Severity


SCRIPT_ENDPOINT_PATTERNS = (
    (re.compile(r"\bfetch\(\s*['\"]([^'\"]+)['\"]"), "GET"),
    (
        re.compile(
            r"\baxios\.(get|post|put|patch|delete)\(\s*['\"]([^'\"]+)['\"]",
            re.IGNORECASE,
        ),
        None,
    ),
    (re.compile(r"\b(?:jsonRpc|rpc)\(\s*['\"]([^'\"]+)['\"]"), "RPC"),
    (
        re.compile(r"\b(?:url|route|endpoint)\s*:\s*['\"](/[^'\"]+)['\"]"),
        "UNKNOWN",
    ),
)

BLOCKED_PATH_PARTS = (
    "/logout",
    "/signout",
    "/delete",
    "/remove",
    "/unsubscribe",
    "/payment",
    "/checkout",
    "/confirm",
    "/cancel",
    "/cart/update",
)

SKIPPED_EXTENSIONS = (
    ".css",
    ".js",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".pdf",
    ".zip",
)


class CrawlerCheck(BaseCheck):
    """Crawl authorized pages with safe GETs and inventory referenced endpoints."""

    name = "crawler"
    description = "Map same-origin custom pages, forms, and API/RPC endpoints"
    requires_auth = False

    def run(self) -> None:
        if not self.result.scan_config.get("crawl"):
            return
        seeds = self.result.scan_config.get("include_paths") or ["/"]
        max_pages = int(self.result.scan_config.get("crawl_max_pages", 50))
        max_depth = int(self.result.scan_config.get("crawl_depth", 2))
        pages, endpoints = self._crawl(seeds, max_pages, max_depth)
        self.result.artifacts["crawl"] = {
            "seeds": list(seeds),
            "max_pages": max_pages,
            "max_depth": max_depth,
            "pages": pages,
            "endpoints": endpoints,
        }
        self._add_surface_finding(pages, endpoints)

    def _crawl(
        self, seeds: List[str], max_pages: int, max_depth: int
    ) -> Tuple[List[Dict], List[Dict]]:
        queue: Deque[Tuple[str, int, str]] = deque(
            (seed, 0, "seed") for seed in seeds
        )
        queued: Set[str] = set(seeds)
        visited: Set[str] = set()
        pages: List[Dict] = []
        endpoints: Dict[str, Dict[str, Set[str]]] = {}
        page_check = PageCheck(self.target, self.result)

        while queue and len(visited) < max_pages:
            path, depth, source = queue.popleft()
            if path in visited or not self._is_safe_path(path):
                continue
            visited.add(path)
            response = self._get(path)
            if response is None:
                pages.append(
                    {"path": path, "depth": depth, "status": 0, "source": source}
                )
                continue
            content_type = response.headers.get("Content-Type", "")
            page_record = {
                "path": path,
                "depth": depth,
                "status": response.status_code,
                "content_type": content_type.split(";", 1)[0],
                "source": source,
            }
            pages.append(page_record)
            if response.status_code != 200 or "html" not in content_type.lower():
                continue

            page_check.assess_response(path, response, include_inventory=depth == 0)
            soup = BeautifulSoup(response.text, "html.parser")
            if soup.title and soup.title.string:
                page_record["title"] = soup.title.string.strip()[:300]
            self._collect_forms(path, soup, endpoints, queue, queued, depth, max_depth)
            self._collect_script_endpoints(path, soup, endpoints)
            if depth < max_depth:
                self._collect_links(path, soup, queue, queued, depth)

        endpoint_records = []
        for endpoint_path in sorted(endpoints):
            record = endpoints[endpoint_path]
            endpoint_records.append(
                {
                    "path": endpoint_path,
                    "methods": sorted(record["methods"]),
                    "kinds": sorted(record["kinds"]),
                    "sources": sorted(record["sources"]),
                }
            )
        return pages, endpoint_records

    def _get(self, path: str):
        try:
            return self.target.get(path, timeout=15, allow_redirects=False)
        except requests.RequestException:
            return None

    def _collect_links(
        self,
        current_path: str,
        soup,
        queue: Deque[Tuple[str, int, str]],
        queued: Set[str],
        depth: int,
    ) -> None:
        for tag in soup.find_all("a", href=True):
            path = self._same_origin_path(tag.get("href"), current_path)
            if path and path not in queued and self._is_safe_path(path):
                queued.add(path)
                queue.append((path, depth + 1, f"link:{current_path}"))

    def _collect_forms(
        self,
        current_path: str,
        soup,
        endpoints: Dict[str, Dict[str, Set[str]]],
        queue: Deque[Tuple[str, int, str]],
        queued: Set[str],
        depth: int,
        max_depth: int,
    ) -> None:
        for form in soup.find_all("form"):
            action = form.get("action") or current_path
            path = self._same_origin_path(action, current_path)
            if not path:
                continue
            method = (form.get("method") or "GET").upper()
            self._record_endpoint(endpoints, path, method, "form", current_path)
            if (
                method == "GET"
                and depth < max_depth
                and path not in queued
                and self._is_safe_path(path)
            ):
                queued.add(path)
                queue.append((path, depth + 1, f"form:{current_path}"))

    def _collect_script_endpoints(
        self,
        current_path: str,
        soup,
        endpoints: Dict[str, Dict[str, Set[str]]],
    ) -> None:
        scripts = "\n".join(
            script.string or script.get_text(" ")
            for script in soup.find_all("script")
            if not script.get("src")
        )
        for pattern, fixed_method in SCRIPT_ENDPOINT_PATTERNS:
            for match in pattern.finditer(scripts):
                if fixed_method is None:
                    method = match.group(1).upper()
                    raw_path = match.group(2)
                else:
                    method = fixed_method
                    raw_path = match.group(1)
                path = self._same_origin_path(raw_path, current_path)
                if path:
                    self._record_endpoint(
                        endpoints, path, method, "javascript", current_path
                    )

    @staticmethod
    def _record_endpoint(
        endpoints: Dict[str, Dict[str, Set[str]]],
        path: str,
        method: str,
        kind: str,
        source: str,
    ) -> None:
        record = endpoints.setdefault(
            path, {"methods": set(), "kinds": set(), "sources": set()}
        )
        record["methods"].add(method)
        record["kinds"].add(kind)
        record["sources"].add(source)

    def _same_origin_path(
        self, raw_url: Optional[str], current_path: str
    ) -> Optional[str]:
        if not raw_url or raw_url.startswith(
            ("#", "mailto:", "tel:", "javascript:", "data:")
        ):
            return None
        current_url = urljoin(f"{self.target.url}/", current_path.lstrip("/"))
        resolved = urlparse(urljoin(current_url, raw_url))
        if resolved.netloc.lower() != self.target.parsed.netloc.lower():
            return None
        path = resolved.path or "/"
        return path if path.startswith("/") else f"/{path}"

    @staticmethod
    def _is_safe_path(path: str) -> bool:
        lowered = path.lower()
        if ".." in path or lowered.endswith(SKIPPED_EXTENSIONS):
            return False
        return not any(part in lowered for part in BLOCKED_PATH_PARTS)

    def _add_surface_finding(self, pages: List[Dict], endpoints: List[Dict]) -> None:
        endpoint_summary = "; ".join(
            f"{','.join(item['methods'])} {item['path']}" for item in endpoints[:50]
        )
        self.add_finding(
            title="Custom frontend crawl inventory",
            description=f"The bounded crawler visited {len(pages)} page(s) and discovered {len(endpoints)} form/API/RPC endpoint(s). Full structured inventory is stored in scan.json under artifacts.crawl.",
            severity=Severity.INFO,
            request="GET-only same-origin crawl",
            response_status=200,
            response_snippet=endpoint_summary
            or "No form or script endpoints discovered.",
            remediation="Review every discovered state-changing endpoint for authentication, authorization, CSRF protection, input validation, and safe error handling.",
        )
