#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORCA_CLAUDE_DIR="${CLAUDE_HOME:-$HOME/.claude}"
ORCA_AGENTS_DIR="${AGENTS_HOME:-$HOME/.agents}"
ORCA_PI_AGENT_DIR="${PI_CODING_AGENT_DIR:-$HOME/.pi/agent}"
ASSETS_ONLY=false

if [[ "${1:-}" == "--assets-only" ]]; then
  ASSETS_ONLY=true
elif [[ $# -gt 0 ]]; then
  echo "Usage: ./install.sh [--assets-only]" >&2
  exit 2
fi

install_file() {
  local src="$1"
  local dst="$2"
  if [[ -e "$dst" || -L "$dst" ]]; then
    cp -R "$dst" "$dst.bak.$(date +%Y%m%d%H%M%S)"
  fi
  cp "$src" "$dst"
}

install_dir() {
  local src="$1"
  local dst="$2"
  if [[ -e "$dst" || -L "$dst" ]]; then
    cp -R "$dst" "$dst.bak.$(date +%Y%m%d%H%M%S)"
    rm -rf "$dst"
  fi
  cp -R "$src" "$dst"
}

if [[ "$ASSETS_ONLY" == false ]]; then
  python3 -m pip install -e "$ROOT"
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

echo "ORCA agent integration installed."
echo "  Claude Code: /orca-security-scan"
echo "  Pi:          /orca-security-scan"
echo '  Codex:       $orca-security-scan'
