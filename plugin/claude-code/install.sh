#!/usr/bin/env bash
# ShieldPilot installer for Claude Code
#
# What this script does:
#   1. Verifies Python 3.9+ is available
#   2. Installs the sentinelai package (pip install -e . or pip install sentinelai)
#   3. Creates a default sentinel.yaml if none exists
#   4. Configures the PreToolUse hook in .claude/settings.json
#   5. Verifies the installation works
#
# Usage:
#   bash plugin/claude-code/install.sh          # Install from local source
#   bash plugin/claude-code/install.sh --pypi   # Install from PyPI
#
# To uninstall: bash plugin/claude-code/uninstall.sh

set -euo pipefail

# ── Colors ──────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m' # No color

info()  { echo -e "${CYAN}[ShieldPilot]${NC} $*"; }
ok()    { echo -e "${GREEN}[ShieldPilot]${NC} $*"; }
warn()  { echo -e "${YELLOW}[ShieldPilot]${NC} $*"; }
error() { echo -e "${RED}[ShieldPilot]${NC} $*" >&2; }

# ── Resolve paths ──────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
HOOK_SCRIPT="$SCRIPT_DIR/hook.sh"
SETTINGS_DIR="$PROJECT_ROOT/.claude"
SETTINGS_FILE="$SETTINGS_DIR/settings.json"
CONFIG_FILE="$PROJECT_ROOT/sentinel.yaml"

# ── Step 1: Check Python ──────────────────────────────────────
info "Checking Python version..."
if ! command -v python3 &>/dev/null; then
    error "python3 not found. Please install Python 3.9+ first."
    exit 1
fi

PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 9 ]); then
    error "Python 3.9+ required, found $PY_VERSION"
    exit 1
fi
ok "Python $PY_VERSION detected"

# ── Step 2: Install sentinelai package ────────────────────────
INSTALL_MODE="${1:-local}"

if [ "$INSTALL_MODE" = "--pypi" ]; then
    info "Installing sentinelai from PyPI..."
    pip3 install sentinelai --quiet --upgrade
else
    info "Installing sentinelai from local source..."
    pip3 install -e "$PROJECT_ROOT" --quiet
fi

# Verify the package is importable
if python3 -c "from sentinelai.hooks.sentinel_hook import main; print('OK')" 2>/dev/null; then
    ok "sentinelai package installed successfully"
else
    error "Failed to import sentinelai. Check the installation."
    exit 1
fi

# ── Step 3: Ensure sentinel.yaml exists ──────────────────────
if [ ! -f "$CONFIG_FILE" ]; then
    info "Creating default sentinel.yaml..."
    cat > "$CONFIG_FILE" << 'YAML'
# ShieldPilot Configuration
# Documentation: https://github.com/maxwalser001-del/Cyber-Security-

mode: enforce  # enforce | audit | disabled

risk_thresholds:
  block: 80
  warn: 40
  allow: 0

auth:
  local_first: true  # Skip auth for localhost connections

billing:
  enabled: false

logging:
  database: sentinel.db
  chain_hashing: true
YAML
    ok "Created sentinel.yaml with safe defaults"
else
    ok "sentinel.yaml already exists"
fi

# ── Step 4: Configure Claude Code hook ────────────────────────
info "Configuring Claude Code PreToolUse hook..."

# Make hook.sh executable
chmod +x "$HOOK_SCRIPT"

# Create .claude directory if needed
mkdir -p "$SETTINGS_DIR"

# Build the hook path relative to project root
HOOK_REL_PATH="plugin/claude-code/hook.sh"

if [ -f "$SETTINGS_FILE" ]; then
    # settings.json exists — merge our hook in
    # Use python3 for safe JSON manipulation
    python3 << PYEOF
import json, sys

settings_path = "$SETTINGS_FILE"
hook_cmd = "$HOOK_REL_PATH"

with open(settings_path, "r") as f:
    settings = json.load(f)

# Ensure hooks.PreToolUse exists
hooks = settings.setdefault("hooks", {})
pre_hooks = hooks.setdefault("PreToolUse", [])

# Check if ShieldPilot hook is already configured
already_configured = any(
    isinstance(h, dict) and "shieldpilot" in h.get("command", "").lower()
    or isinstance(h, dict) and "sentinel_hook" in h.get("command", "").lower()
    or isinstance(h, dict) and hook_cmd in h.get("command", "")
    for h_entry in pre_hooks
    for h in (h_entry.get("hooks", []) if isinstance(h_entry, dict) and "hooks" in h_entry else [h_entry])
)

if not already_configured:
    pre_hooks.insert(0, {
        "matcher": ".*",
        "hooks": [{
            "type": "command",
            "command": hook_cmd,
            "timeout": 10
        }]
    })

with open(settings_path, "w") as f:
    json.dump(settings, f, indent=2)
    f.write("\n")
PYEOF
    ok "Hook added to existing .claude/settings.json"
else
    # Create new settings.json with the hook
    python3 << PYEOF
import json

settings = {
    "hooks": {
        "PreToolUse": [{
            "matcher": ".*",
            "hooks": [{
                "type": "command",
                "command": "$HOOK_REL_PATH",
                "timeout": 10
            }]
        }]
    }
}

with open("$SETTINGS_FILE", "w") as f:
    json.dump(settings, f, indent=2)
    f.write("\n")
PYEOF
    ok "Created .claude/settings.json with ShieldPilot hook"
fi

# ── Step 5: Verification ─────────────────────────────────────
info "Running verification..."

# Test that the hook can process a simple allow command
TEST_RESULT=$(echo '{"tool_name":"Read","tool_input":{"file_path":"test.txt"},"cwd":"/tmp"}' | bash "$HOOK_SCRIPT" 2>/dev/null || echo "FAIL")

if echo "$TEST_RESULT" | python3 -c "import json,sys; d=json.load(sys.stdin); assert d['hookSpecificOutput']['permissionDecision']=='allow'" 2>/dev/null; then
    ok "Hook verification passed"
else
    warn "Hook verification returned unexpected output: $TEST_RESULT"
    warn "The hook may still work — check sentinel.yaml configuration"
fi

echo ""
ok "============================================="
ok "  ShieldPilot installed successfully!"
ok "============================================="
echo ""
info "Configuration: $CONFIG_FILE"
info "Hook script:   $HOOK_SCRIPT"
info "Settings:      $SETTINGS_FILE"
echo ""
info "Next steps:"
info "  1. Review sentinel.yaml to customize risk thresholds"
info "  2. Start Claude Code — ShieldPilot will automatically guard every tool call"
info "  3. View the dashboard: python3 -m uvicorn sentinelai.api.app:app --port 8420"
echo ""
