import os
import shutil
import subprocess
from pathlib import Path

import pytest

# Paths below are relative to the sandboxed HOME.
INSTALLED_FILES = (
    Path("claude/skills/orca-security-scan/SKILL.md"),
    Path("agents/skills/orca-security-scan/SKILL.md"),
    Path("claude/commands/orca-security-scan.md"),
    Path("pi/prompts/orca-security-scan.md"),
)
# Older installers left these beside the installed files, where agents load them as duplicates.
LEGACY_BACKUPS = (
    Path("claude/skills/orca-security-scan.bak.20200101000000/SKILL.md"),
    Path("agents/skills/orca-security-scan.bak.20200101000000/SKILL.md"),
    Path("claude/commands/orca-security-scan.md.bak.20200101000000"),
    Path("pi/prompts/orca-security-scan.md.bak.20200101000000"),
)


def _run_assets_only_installer(home: Path) -> subprocess.CompletedProcess:
    env = {key: value for key, value in os.environ.items() if key != "XDG_STATE_HOME"}
    env.update(
        {
            "HOME": str(home),
            "CLAUDE_HOME": str(home / "claude"),
            "AGENTS_HOME": str(home / "agents"),
            "PI_CODING_AGENT_DIR": str(home / "pi"),
        }
    )
    return subprocess.run(
        ["bash", "install.sh", "--assets-only"],
        capture_output=True,
        text=True,
        env=env,
        timeout=15,
        check=False,
    )


def test_agent_assets_have_host_specific_argument_syntax() -> None:
    skill = Path("skills/orca-security-scan/SKILL.md").read_text(encoding="utf-8")
    claude = Path("commands/orca-security-scan.md").read_text(encoding="utf-8")
    pi = Path("prompts/orca-security-scan.md").read_text(encoding="utf-8")

    assert "name: orca-security-scan" in skill
    assert "$ARGUMENTS" in claude
    assert "$@" in pi
    assert "prompt injection" in skill


def test_assets_only_installer_wires_claude_codex_and_pi(tmp_path: Path) -> None:
    result = _run_assets_only_installer(tmp_path)

    assert result.returncode == 0, result.stderr
    for installed in INSTALLED_FILES:
        assert (tmp_path / installed).is_file(), installed


def test_reinstall_keeps_backups_out_of_agent_directories(tmp_path: Path) -> None:
    """A backup beside an installed skill loads as a duplicate skill."""
    for legacy in LEGACY_BACKUPS:
        (tmp_path / legacy).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / legacy).write_text("legacy backup\n", encoding="utf-8")

    # The second run replaces an existing install, which is what writes backups.
    first = _run_assets_only_installer(tmp_path)
    second = _run_assets_only_installer(tmp_path)

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert "Moved 4 old backup(s)" in first.stdout
    for installed in INSTALLED_FILES:
        agent_dir = tmp_path / installed.parts[0] / installed.parts[1]
        # Anything else in an agent directory would load as a second orca-security-scan skill.
        assert os.listdir(agent_dir) == [installed.parts[2]], agent_dir

    backups = tmp_path / ".local/state/orca/backups"
    for legacy in LEGACY_BACKUPS:
        moved = backups / "legacy" / legacy
        assert moved.read_text(encoding="utf-8") == "legacy backup\n", legacy

    assert str(backups) in second.stdout
    reinstall_backups = [path for path in backups.iterdir() if path.name != "legacy"]
    assert len(reinstall_backups) == 1, reinstall_backups
    for installed in INSTALLED_FILES:
        assert (reinstall_backups[0] / installed).is_file(), installed


def test_installer_prints_plain_text_when_piped(tmp_path: Path) -> None:
    result = _run_assets_only_installer(tmp_path)

    assert result.returncode == 0, result.stderr
    assert "\x1b[" not in result.stdout


def _run_installer_with_fake_tools(
    tmp_path: Path, externally_managed: bool, tools: tuple[str, ...], pip_exit: int = 0
) -> tuple[subprocess.CompletedProcess, list[str]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for utility in ("cp", "date", "dirname", "mkdir", "rm"):
        (bin_dir / utility).symlink_to(shutil.which(utility))

    calls = tmp_path / "calls.log"
    probe_exit = 0 if externally_managed else 1
    # Each fake answers its bin-dir query; only install commands are logged.
    queries = {
        "python3": "- orca",
        "uv": "tool dir --bin",
        "pipx": "environment --value PIPX_BIN_DIR",
    }
    fakes = {
        "python3": (f'[ "$1" = "-" ] && exit {probe_exit}\n', pip_exit),
        **{tool: ("", 0) for tool in tools},
    }
    for name, (prelude, exit_code) in fakes.items():
        answer = f'[ "$*" = "{queries[name]}" ] && echo /{name}/bin && exit 0\n'
        fake = bin_dir / name
        fake.write_text(
            f'#!/bin/sh\n{answer}{prelude}echo "{name} $*" >> "{calls}"\nexit {exit_code}\n',
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


@pytest.mark.parametrize(
    ("externally_managed", "tools", "bin_dir"),
    [
        (False, ("uv", "pipx"), "/python3/bin"),
        (True, ("uv", "pipx"), "/uv/bin"),
        (True, ("pipx",), "/pipx/bin"),
        (True, (), "/python3/bin"),
    ],
    ids=["pip", "uv", "pipx", "pip-opt-out"],
)
def test_installer_path_hint_names_the_installer_bin_dir(
    tmp_path: Path, externally_managed: bool, tools: tuple[str, ...], bin_dir: str
) -> None:
    result, _ = _run_installer_with_fake_tools(tmp_path, externally_managed, tools)

    assert result.returncode == 0, result.stderr
    assert f'export PATH="{bin_dir}:$PATH"' in result.stdout


def test_installer_explains_managed_python_without_uv_or_pipx(tmp_path: Path) -> None:
    result, calls = _run_installer_with_fake_tools(tmp_path, True, (), pip_exit=1)

    assert result.returncode == 1
    assert "install uv or pipx" in result.stderr
    assert calls == [f"python3 -m pip install -e {Path.cwd()}"]
