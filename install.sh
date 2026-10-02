#!/usr/bin/env bash
set -euo pipefail

# Colors for output, only on a terminal so piped or logged output stays plain
GREEN='' YELLOW='' NC=''
if [[ -t 1 ]]; then
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
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

if [[ "${1:-}" == "--assets-only" ]]; then
  ASSETS_ONLY=true
elif [[ $# -gt 0 ]]; then
  echo "Usage: ./install.sh [--assets-only]" >&2
  exit 2
fi

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

install_cli() {
  CLI_INSTALLER=pip
  if ! python_is_externally_managed; then
    python3 -m pip install -e "$ROOT"
  elif command -v uv >/dev/null 2>&1; then
    CLI_INSTALLER=uv
    uv tool install --editable "$ROOT"
  elif command -v pipx >/dev/null 2>&1; then
    CLI_INSTALLER=pipx
    pipx install --force --editable "$ROOT"
  # pip still succeeds when the user opted out of PEP 668 (break-system-packages).
  elif ! python3 -m pip install -e "$ROOT"; then
    echo "hint: install uv or pipx, or activate a virtualenv, then re-run ./install.sh." >&2
    exit 1
  fi
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

echo ""
echo "Quick start:"
echo "  orca -u https://odoo.example.com"
echo ""
echo "Or from Claude Code:"
echo "  /orca-security-scan https://odoo.example.com"
