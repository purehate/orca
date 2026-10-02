#!/usr/bin/env bash
set -euo pipefail

# Colors for output, only on a terminal so piped or logged output stays plain
RED='' GREEN='' YELLOW='' BLUE='' NC=''
if [[ -t 1 ]]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  BLUE='\033[0;34m'
  NC='\033[0m' # No Color
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORCA_CLAUDE_DIR="${CLAUDE_HOME:-$HOME/.claude}"
ORCA_AGENTS_DIR="${AGENTS_HOME:-$HOME/.agents}"
ORCA_PI_AGENT_DIR="${PI_CODING_AGENT_DIR:-$HOME/.pi/agent}"
# Backups live outside the agent directories: a copy left beside a skill loads as a duplicate skill.
BACKUP_ROOT="${XDG_STATE_HOME:-$HOME/.local/state}/orca/backups"
BACKUP_DIR="$BACKUP_ROOT/$(date +%Y%m%d%H%M%S)-$$"
MOVED_BACKUPS=0
ASSETS_ONLY=false
PYTHON_PACKAGE="not installed (--assets-only)"

# Track missing tools
MISSING_TOOLS=()
MISSING_REQUIRED=()

if [[ "${1:-}" == "--assets-only" ]]; then
  ASSETS_ONLY=true
elif [[ $# -gt 0 ]]; then
  echo "Usage: ./install.sh [--assets-only]" >&2
  exit 2
fi

echo -e "${BLUE}ORCA (Odoo Recon & Configuration Analyzer) - Installer${NC}"
echo "======================================================"
echo ""

# ---- Python version check ----
check_python() {
  if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${RED}ERROR: python3 is required but not installed.${NC}"
    exit 1
  fi

  PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
  PYTHON_MAJOR="${PYTHON_VERSION%%.*}"
  PYTHON_MINOR="${PYTHON_VERSION#*.}"

  echo "Python version: $PYTHON_VERSION"

  if [[ "$PYTHON_MAJOR" -lt 3 ]] || { [[ "$PYTHON_MAJOR" -eq 3 ]] && [[ "$PYTHON_MINOR" -lt 9 ]]; }; then
    echo -e "${RED}ERROR: Python 3.9+ is required. Found $PYTHON_VERSION${NC}"
    exit 1
  fi
}

# Only the CLI install needs Python; the agent files are plain copies.
if [[ "$ASSETS_ONLY" == false ]]; then
  check_python
  echo ""
fi

# ---- Prerequisite check ----
check_tool() {
  local name="$1" tier="$2" note="$3"
  if command -v "$name" >/dev/null 2>&1; then
    printf "  ${GREEN}%-12s${NC} %-8s %s\n" "$name" "ok" "$note"
  else
    printf "  ${RED}%-12s${NC} %-8s %s\n" "$name" "MISSING" "$note"
    MISSING_TOOLS+=("$name ($tier)")
    if [[ "$tier" == "required" ]]; then
      MISSING_REQUIRED+=("$name")
    fi
  fi
}

echo "Prerequisite check:"
printf "  %-12s %-8s %s\n" "Tool" "Status" "Purpose"
printf "  %-12s %-8s %s\n" "----" "------" "-------"
check_tool python3 required "runs the orca CLI"
check_tool ollama  optional "local model for --ai (default provider)"

echo ""
if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
  echo -e "${YELLOW}Note: ${#MISSING_TOOLS[@]} tool(s) missing.${NC}"
  if [[ ${#MISSING_REQUIRED[@]} -gt 0 ]]; then
    echo -e "${RED}WARNING: ${#MISSING_REQUIRED[@]} required tool(s) missing: ${MISSING_REQUIRED[*]}${NC}"
    echo "The agent files will install, but orca cannot run without ${MISSING_REQUIRED[*]}."
  fi
  if ! command -v ollama >/dev/null 2>&1; then
    echo "Scans run without ollama; --ai needs it or an OpenAI-compatible endpoint."
    echo "See README 'AI-Assisted Evidence Review' for model setup."
  fi
else
  echo -e "${GREEN}All tools available!${NC}"
fi
echo ""

# Mirror an installed path under a backup root, relative to HOME when it lives there.
backup_path() {
  local root="$1"
  local rel="${2#"$HOME"/}"
  printf '%s/%s\n' "$root" "${rel#/}"
}

backup() {
  local dst="$1"
  local bak
  bak="$(backup_path "$BACKUP_DIR" "$dst")"
  mkdir -p "$(dirname "$bak")"
  cp -R "$dst" "$bak"
}

# Older installers wrote "$dst.bak.<timestamp>" beside the installed file; move those out too.
migrate_legacy_backups() {
  local dst="$1"
  local legacy target
  for legacy in "$dst".bak.*; do
    [[ -e "$legacy" || -L "$legacy" ]] || continue
    target="$(backup_path "$BACKUP_ROOT/legacy" "$legacy")"
    if [[ -e "$target" || -L "$target" ]]; then
      echo -e "${YELLOW}WARNING: left $legacy in place because $target already exists.${NC}"
      continue
    fi
    mkdir -p "$(dirname "$target")"
    mv "$legacy" "$target"
    MOVED_BACKUPS=$((MOVED_BACKUPS + 1))
  done
}

install_file() {
  local src="$1"
  local dst="$2"
  migrate_legacy_backups "$dst"
  if [[ -e "$dst" || -L "$dst" ]]; then
    backup "$dst"
  fi
  cp "$src" "$dst"
}

install_dir() {
  local src="$1"
  local dst="$2"
  migrate_legacy_backups "$dst"
  if [[ -e "$dst" || -L "$dst" ]]; then
    backup "$dst"
    rm -rf "$dst"
  fi
  cp -R "$src" "$dst"
}

# Same check pip uses to refuse installs (PEP 668); virtualenvs are exempt.
python_is_externally_managed() {
  python3 - <<'PY'
import os
import sys
import sysconfig

marker = os.path.join(sysconfig.get_path("stdlib"), "EXTERNALLY-MANAGED")
sys.exit(0 if sys.prefix == sys.base_prefix and os.path.isfile(marker) else 1)
PY
}

# Run one CLI install method; on failure, name it and let the caller stop.
run_install() {
  local method="$1"
  shift
  PYTHON_PACKAGE="$method, editable from $ROOT"
  echo "Installing Python package with $method ..."
  if ! "$@"; then
    echo -e "${RED}ERROR: $method install failed. See the $method output above.${NC}"
    return 1
  fi
}

# ---- Install the orca CLI ----
# PEP 668 interpreters (Homebrew, Debian/Ubuntu) refuse pip installs outside a virtualenv,
# so those get an isolated uv or pipx tool install instead.
install_cli() {
  CLI_INSTALLER=pip
  if ! python_is_externally_managed; then
    run_install pip python3 -m pip install --quiet -e "$ROOT" || exit 1
  elif command -v uv >/dev/null 2>&1; then
    CLI_INSTALLER=uv
    run_install "uv tool" uv tool install --quiet --editable "$ROOT" || exit 1
  elif command -v pipx >/dev/null 2>&1; then
    CLI_INSTALLER=pipx
    # No --quiet here: older pipx releases on Debian/Ubuntu reject it.
    run_install pipx pipx install --force --editable "$ROOT" || exit 1
  # pip still succeeds when the user opted out of PEP 668 (break-system-packages).
  elif ! run_install pip python3 -m pip install --quiet -e "$ROOT"; then
    echo "hint: install uv or pipx, or activate a virtualenv, then re-run ./install.sh." >&2
    exit 1
  fi
  echo -e "${GREEN}Python package installed.${NC}"
  echo ""
}

# Ask the tool that installed orca where it put the command.
cli_bin_dir() {
  case "$CLI_INSTALLER" in
    uv) uv tool dir --bin ;;
    pipx) pipx environment --value PIPX_BIN_DIR ;;
    # pip may fall back to a per-user install, so read the script path from its record.
    pip)
      python3 - orca <<'PY'
import os
import sys
from importlib.metadata import PackageNotFoundError, distribution

name = sys.argv[1]
try:
    files = distribution(name).files or []
except PackageNotFoundError:
    files = []
for file in files:
    if file.name == name and file.parent.name == "bin":
        print(os.path.dirname(os.path.normpath(file.locate())))
        break
PY
      ;;
  esac
}

if [[ "$ASSETS_ONLY" == false ]]; then
  install_cli
  # Fail here, not mid-scan, if the orca on PATH cannot start.
  if command -v orca >/dev/null 2>&1 && ! orca --version >/dev/null 2>&1; then
    echo -e "${RED}ERROR: $(command -v orca) failed to start. Run 'orca --version' to see why.${NC}"
    exit 1
  fi
fi

mkdir -p \
  "$ORCA_CLAUDE_DIR/commands" \
  "$ORCA_CLAUDE_DIR/skills" \
  "$ORCA_AGENTS_DIR/skills" \
  "$ORCA_PI_AGENT_DIR/prompts"

install_file "$ROOT/commands/orca-security-scan.md" "$ORCA_CLAUDE_DIR/commands/orca-security-scan.md"
install_file "$ROOT/prompts/orca-security-scan.md" "$ORCA_PI_AGENT_DIR/prompts/orca-security-scan.md"
install_dir "$ROOT/skills/orca-security-scan" "$ORCA_AGENTS_DIR/skills/orca-security-scan"
install_dir "$ROOT/skills/orca-security-scan" "$ORCA_CLAUDE_DIR/skills/orca-security-scan"
if [[ $MOVED_BACKUPS -gt 0 ]]; then
  echo "Moved $MOVED_BACKUPS old backup(s) out of the agent directories into $BACKUP_ROOT/legacy"
fi

echo ""
echo -e "${GREEN}✓ Installation complete!${NC}"
echo ""
echo "Agent integration:"
echo "  Claude Code: /orca-security-scan"
echo "  Pi:          /orca-security-scan"
echo '  Codex:       $orca-security-scan'
echo ""
echo "Installed to:"
echo "  Shared skill:   $ORCA_AGENTS_DIR/skills/orca-security-scan"
echo "  Claude skill:   $ORCA_CLAUDE_DIR/skills/orca-security-scan"
echo "  Claude command: $ORCA_CLAUDE_DIR/commands/orca-security-scan.md"
echo "  Pi prompt:      $ORCA_PI_AGENT_DIR/prompts/orca-security-scan.md"
echo "  Python package: $PYTHON_PACKAGE"
echo "  Backups:        $BACKUP_ROOT"
echo ""
echo "Available commands:"
echo "  orca - Unauthenticated Odoo frontend security scanner"
echo ""

if command -v orca >/dev/null 2>&1; then
  echo -e "${GREEN}✓ Commands are available in PATH${NC}"
elif [[ "$ASSETS_ONLY" == true ]]; then
  echo -e "${YELLOW}⚠ orca is not in PATH. Run ./install.sh without --assets-only to install it.${NC}"
elif bin_dir="$(cli_bin_dir 2>/dev/null)" && [[ -n "$bin_dir" ]]; then
  echo -e "${YELLOW}⚠ Commands not in PATH. Add this to your shell profile:${NC}"
  echo "  export PATH=\"$bin_dir:\$PATH\""
else
  echo -e "${YELLOW}⚠ Commands not in PATH. Add the bin directory named in the $CLI_INSTALLER output above to PATH.${NC}"
fi

# Show quickstart
if [[ ${#MISSING_REQUIRED[@]} -eq 0 ]]; then
  echo ""
  echo "Quick start:"
  echo "  orca -u https://odoo.example.com"
  echo ""
  echo "Or from Claude Code:"
  echo "  /orca-security-scan https://odoo.example.com"
fi
