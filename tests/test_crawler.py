from urllib.parse import urlparse

import requests

from orca.checks.crawler import CrawlerCheck
from orca.checks.page import PageCheck
from orca.findings import ScanResult


def _response(body: str, content_type: str = "text/html") -> requests.Response:
    response = requests.Response()
    response.status_code = 200
    response.headers["Content-Type"] = content_type
    response._content = body.encode("utf-8")
    response.encoding = "utf-8"
    return response


class FakeTarget:
    def __init__(self, responses):
        self.url = "https://example.test"
        self.parsed = urlparse(self.url)
        self.responses = responses
        self.requests = []

    def get(self, path, **kwargs):
        self.requests.append(("GET", path, kwargs))
        response = self.responses.get(path)
        if response is None:
            response = _response("missing", "text/plain")
            response.status_code = 404
        return response


def test_page_check_reports_controls_without_persisting_field_values() -> None:
    target = FakeTarget(
        {
            "/quoteengine": _response(
                """
                <html><head><title>Quote Engine</title></head><body>
                <form method="post" action="/quote/submit">
                  <input name="customer_email" value="person@example.test">
                  <input name="private_note" value="do-not-persist">
                </form>
                </body></html>
                """
            )
        }
    )
    result = ScanResult(scan_config={"include_paths": ["/quoteengine"]})

    PageCheck(target, result).run()

    titles = {finding.title for finding in result.findings}
    serialized = result.to_json()
    assert "Included page assessed: /quoteengine" in titles
    assert "POST form has no explicit CSRF field on /quoteengine" in titles
    assert "Content Security Policy does not constrain scripts: /quoteengine" in titles
    assert "do-not-persist" not in serialized
    assert "person@example.test" not in serialized


def test_crawler_maps_same_origin_pages_forms_and_script_endpoints() -> None:
    root = _response(
        """
        <html><head><title>Quote Engine</title></head><body>
          <a href="/about">About</a>
          <a href="https://outside.test/escape">Outside</a>
          <a href="/logout">Logout</a>
          <form method="post" action="/quote/submit"></form>
          <form method="get" action="/quote/search"></form>
          <script>
            fetch('/api/options');
            axios.post('/api/quote');
            jsonRpc('/quote/rpc');
          </script>
        </body></html>
        """
    )
    target = FakeTarget(
        {
            "/quoteengine": root,
            "/about": _response("<html><title>About</title></html>"),
            "/quote/search": _response("<html><title>Search</title></html>"),
        }
    )
    result = ScanResult(
        scan_config={
            "crawl": True,
            "include_paths": ["/quoteengine"],
            "crawl_max_pages": 10,
            "crawl_depth": 1,
        }
    )

    CrawlerCheck(target, result).run()

    requested_paths = [path for method, path, _ in target.requests]
    endpoints = {item["path"]: item for item in result.artifacts["crawl"]["endpoints"]}
    assert requested_paths == ["/quoteengine", "/quote/search", "/about"]
    assert "/logout" not in requested_paths
    assert "/escape" not in requested_paths
    assert endpoints["/quote/submit"]["methods"] == ["POST"]
    assert endpoints["/api/options"]["methods"] == ["GET"]
    assert endpoints["/api/quote"]["methods"] == ["POST"]
    assert endpoints["/quote/rpc"]["methods"] == ["RPC"]
    assert {method for method, _, _ in target.requests} == {"GET"}


def test_crawler_honors_page_cap() -> None:
    target = FakeTarget(
        {
            "/": _response('<a href="/one">One</a><a href="/two">Two</a>'),
            "/one": _response("<html>One</html>"),
            "/two": _response("<html>Two</html>"),
        }
    )
    result = ScanResult(
        scan_config={
            "crawl": True,
            "include_paths": ["/"],
            "crawl_max_pages": 2,
            "crawl_depth": 2,
        }
    )

    CrawlerCheck(target, result).run()

    assert len(result.artifacts["crawl"]["pages"]) == 2
    assert len(target.requests) == 2
