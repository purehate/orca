import argparse

from orca.cli import _build_replay_command, _exit_code
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


def test_exit_code_preserves_scanner_severity_contract() -> None:
    high = Finding("test", "high", "", Severity.HIGH)
    medium = Finding("test", "medium", "", Severity.MEDIUM)
    low = Finding("test", "low", "", Severity.LOW)

    assert _exit_code([high]) == 2
    assert _exit_code([medium]) == 1
    assert _exit_code([low]) == 0
