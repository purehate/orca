import os
import shutil
import subprocess
from pathlib import Path

import pytest


def test_agent_assets_have_host_specific_argument_syntax() -> None:
    skill = Path("skills/orca-security-scan/SKILL.md").read_text(encoding="utf-8")
    claude = Path("commands/orca-security-scan.md").read_text(encoding="utf-8")
    pi = Path("prompts/orca-security-scan.md").read_text(encoding="utf-8")

    assert "name: orca-security-scan" in skill
    assert "$ARGUMENTS" in claude
    assert "$@" in pi
    assert "prompt injection" in skill


def test_assets_only_installer_wires_claude_codex_and_pi(tmp_path: Path) -> None:
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(tmp_path),
            "CLAUDE_HOME": str(tmp_path / "claude"),
            "AGENTS_HOME": str(tmp_path / "agents"),
            "PI_CODING_AGENT_DIR": str(tmp_path / "pi"),
        }
    )

    result = subprocess.run(
        ["bash", "install.sh", "--assets-only"],
        capture_output=True,
        text=True,
        env=env,
        timeout=15,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert (tmp_path / "agents/skills/orca-security-scan/SKILL.md").is_file()
    assert (tmp_path / "claude/skills/orca-security-scan/SKILL.md").is_file()
    assert (tmp_path / "claude/commands/orca-security-scan.md").is_file()
    assert (tmp_path / "pi/prompts/orca-security-scan.md").is_file()


def _run_installer_with_fake_tools(
    tmp_path: Path, externally_managed: bool, tools: tuple[str, ...], pip_exit: int = 0
) -> tuple[subprocess.CompletedProcess, list[str]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for utility in ("cp", "date", "dirname", "mkdir", "rm"):
        (bin_dir / utility).symlink_to(shutil.which(utility))

    calls = tmp_path / "calls.log"
    probe_exit = 0 if externally_managed else 1
    fakes = {
        "python3": (f'[ "$1" = "-" ] && exit {probe_exit}\n', pip_exit),
        **{tool: ("", 0) for tool in tools},
    }
    for name, (prelude, exit_code) in fakes.items():
        fake = bin_dir / name
        fake.write_text(
            f'#!/bin/sh\n{prelude}echo "{name} $*" >> "{calls}"\nexit {exit_code}\n',
            encoding="utf-8",
        )
        fake.chmod(0o755)

    result = subprocess.run(
        [shutil.which("bash"), "install.sh"],
        capture_output=True,
        text=True,
        env={
            "HOME": str(tmp_path),
            "CLAUDE_HOME": str(tmp_path / "claude"),
            "AGENTS_HOME": str(tmp_path / "agents"),
            "PI_CODING_AGENT_DIR": str(tmp_path / "pi"),
            "PATH": str(bin_dir),
        },
        timeout=15,
        check=False,
    )
    logged = calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []
    return result, logged


@pytest.mark.parametrize(
    ("externally_managed", "tools", "expected_call"),
    [
        (False, ("uv", "pipx"), "python3 -m pip install -e {root}"),
        (True, ("uv", "pipx"), "uv tool install --editable {root}"),
        (True, ("pipx",), "pipx install --force --editable {root}"),
        # pip still installs when the user opted out of PEP 668.
        (True, (), "python3 -m pip install -e {root}"),
    ],
    ids=["pip", "uv", "pipx", "pip-opt-out"],
)
def test_installer_picks_cli_install_method(
    tmp_path: Path, externally_managed: bool, tools: tuple[str, ...], expected_call: str
) -> None:
    result, calls = _run_installer_with_fake_tools(tmp_path, externally_managed, tools)

    assert result.returncode == 0, result.stderr
    assert calls == [expected_call.format(root=Path.cwd())]
    assert (tmp_path / "agents/skills/orca-security-scan/SKILL.md").is_file()


def test_installer_explains_managed_python_without_uv_or_pipx(tmp_path: Path) -> None:
    result, calls = _run_installer_with_fake_tools(tmp_path, True, (), pip_exit=1)

    assert result.returncode == 1
    assert "install uv or pipx" in result.stderr
    assert calls == [f"python3 -m pip install -e {Path.cwd()}"]
