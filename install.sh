#!/usr/bin/env bash
set -euo pipefail

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORCA_CLAUDE_DIR="${CLAUDE_HOME:-$HOME/.claude}"
ORCA_AGENTS_DIR="${AGENTS_HOME:-$HOME/.agents}"
ORCA_PI_AGENT_DIR="${PI_CODING_AGENT_DIR:-$HOME/.pi/agent}"
# Backups go outside the agent dirs, where a copied SKILL.md would load as a duplicate skill.
ORCA_BACKUP_DIR="$HOME/.orca/install-backups/$(date +%Y%m%d%H%M%S)"
ASSETS_ONLY=false
BACKED_UP=false

if [[ "${1:-}" == "--assets-only" ]]; then
  ASSETS_ONLY=true
elif [[ $# -gt 0 ]]; then
  echo "Usage: ./install.sh [--assets-only]" >&2
  exit 2
fi

back_up() {
  local dst="$1"
  local rel="${dst#"$HOME"/}"
  local copy="$ORCA_BACKUP_DIR/${rel#/}"
  mkdir -p "$(dirname "$copy")"
  cp -R "$dst" "$copy"
  BACKED_UP=true
}

install_file() {
  local src="$1"
  local dst="$2"
  if [[ -e "$dst" || -L "$dst" ]]; then
    back_up "$dst"
  fi
  cp "$src" "$dst"
}

install_dir() {
  local src="$1"
  local dst="$2"
  if [[ -e "$dst" || -L "$dst" ]]; then
    back_up "$dst"
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
  if ! python_is_externally_managed; then
    python3 -m pip install -e "$ROOT"
  elif command -v uv >/dev/null 2>&1; then
    uv tool install --editable "$ROOT"
  elif command -v pipx >/dev/null 2>&1; then
    pipx install --force --editable "$ROOT"
  # pip still succeeds when the user opted out of PEP 668 (break-system-packages).
  elif ! python3 -m pip install -e "$ROOT"; then
    echo "hint: install uv or pipx, or activate a virtualenv, then re-run ./install.sh." >&2
    exit 1
  fi
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
if [[ "$BACKED_UP" == true ]]; then
  echo "  Backups:        $ORCA_BACKUP_DIR"
fi
echo ""
echo "Available commands:"
echo "  orca - Unauthenticated Odoo frontend security scanner"
echo ""

if command -v orca >/dev/null 2>&1; then
  echo -e "${GREEN}✓ Commands are available in PATH${NC}"
elif [[ "$ASSETS_ONLY" == true ]]; then
  echo -e "${YELLOW}⚠ orca is not in PATH. Run ./install.sh without --assets-only to install it.${NC}"
else
  echo -e "${YELLOW}⚠ Commands not in PATH. Add this to your shell profile:${NC}"
  echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

echo ""
echo "Quick start:"
echo "  orca -u https://odoo.example.com"
echo ""
echo "Or from Claude Code:"
echo "  /orca-security-scan https://odoo.example.com"
