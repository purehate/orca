import argparse

from orca.cli import _build_replay_command, _exit_code, _validate_scan_scope
from orca.findings import Finding, Severity


def test_replay_command_excludes_credentials_and_ai_connection_details() -> None:
    args = argparse.Namespace(
        url="https://operator:password@example.test/odoo",
        checks="idor,misconfig",
        skip_checks=None,
        min_severity="medium",
        rate=2.0,
        jitter=None,
        threads=4,
        timeout=10,
        verify_ssl=True,
        include_path=["/quoteengine"],
        crawl=True,
        crawl_max_pages=25,
        crawl_depth=2,
        password="private-password",
        proxy="http://proxy-user:proxy-pass@proxy.test",
        ai_endpoint="http://private-model.test/v1",
    )

    command = _build_replay_command(args)

    assert "operator" not in command
    assert "password" not in command
    assert "private-password" not in command
    assert "proxy-pass" not in command
    assert "private-model" not in command
    assert "[REDACTED]@example.test/odoo" in command
    assert "--checks idor,misconfig" in command
    assert "--include-path /quoteengine" in command
    assert "--crawl" in command


def test_crawler_scope_defaults_to_policy_rate() -> None:
    args = argparse.Namespace(
        crawl=True,
        crawl_max_pages=50,
        crawl_depth=2,
        include_path=["/quoteengine"],
        rate=None,
    )

    assert _validate_scan_scope(args) is None
    assert args.rate == 1.0


def test_crawler_scope_rejects_external_or_unbounded_inputs() -> None:
    external = argparse.Namespace(
        crawl=True,
        crawl_max_pages=50,
        crawl_depth=2,
        include_path=["https://other.test/page"],
        rate=1.0,
    )
    too_fast = argparse.Namespace(
        crawl=True,
        crawl_max_pages=50,
        crawl_depth=2,
        include_path=["/quoteengine"],
        rate=5.1,
    )

    assert "same-origin" in _validate_scan_scope(external)
    assert "no more than 5" in _validate_scan_scope(too_fast)


def test_exit_code_preserves_scanner_severity_contract() -> None:
    high = Finding("test", "high", "", Severity.HIGH)
    medium = Finding("test", "medium", "", Severity.MEDIUM)
    low = Finding("test", "low", "", Severity.LOW)

    assert _exit_code([high]) == 2
    assert _exit_code([medium]) == 1
    assert _exit_code([low]) == 0
