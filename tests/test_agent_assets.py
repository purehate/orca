import os
import subprocess
from pathlib import Path


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
