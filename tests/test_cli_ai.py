import argparse

from orca.cli import _build_replay_command


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
