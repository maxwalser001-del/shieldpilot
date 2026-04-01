#!/usr/bin/env bash
# ShieldPilot uninstaller for Claude Code
#
# What this script does:
#   1. Removes the PreToolUse hook from .claude/settings.json
#   2. Optionally uninstalls the sentinelai Python package
#   3. Preserves sentinel.yaml and the database (your audit logs)
#
# Usage:
#   bash plugin/claude-code/uninstall.sh              # Remove hook only
#   bash plugin/claude-code/uninstall.sh --full        # Also uninstall Python package

set -euo pipefail

# ── Colors ──────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${CYAN}[ShieldPilot]${NC} $*"; }
ok()    { echo -e "${GREEN}[ShieldPilot]${NC} $*"; }
warn()  { echo -e "${YELLOW}[ShieldPilot]${NC} $*"; }
error() { echo -e "${RED}[ShieldPilot]${NC} $*" >&2; }

# ── Resolve paths ──────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SETTINGS_FILE="$PROJECT_ROOT/.claude/settings.json"
UNINSTALL_MODE="${1:-hook-only}"

# ── Step 1: Remove hook from settings.json ────────────────────
info "Removing ShieldPilot hook from Claude Code settings..."

if [ -f "$SETTINGS_FILE" ]; then
    python3 << 'PYEOF'
import json, sys

settings_path = sys.argv[1] if len(sys.argv) > 1 else ""
PYEOF

    python3 << PYEOF
import json

settings_path = "$SETTINGS_FILE"

with open(settings_path, "r") as f:
    settings = json.load(f)

hooks = settings.get("hooks", {})
pre_hooks = hooks.get("PreToolUse", [])

# Filter out ShieldPilot hooks
filtered = []
for entry in pre_hooks:
    if isinstance(entry, dict) and "hooks" in entry:
        inner = [
            h for h in entry["hooks"]
            if not (
                isinstance(h, dict)
                and (
                    "shieldpilot" in h.get("command", "").lower()
                    or "sentinel_hook" in h.get("command", "").lower()
                    or "plugin/claude-code/hook.sh" in h.get("command", "")
                )
            )
        ]
        if inner:
            entry["hooks"] = inner
            filtered.append(entry)
    else:
        filtered.append(entry)

if filtered:
    hooks["PreToolUse"] = filtered
else:
    hooks.pop("PreToolUse", None)

if hooks:
    settings["hooks"] = hooks
else:
    settings.pop("hooks", None)

with open(settings_path, "w") as f:
    json.dump(settings, f, indent=2)
    f.write("\n")
PYEOF
    ok "Hook removed from .claude/settings.json"
else
    info "No .claude/settings.json found — nothing to remove"
fi

# ── Step 2: Optionally uninstall Python package ───────────────
if [ "$UNINSTALL_MODE" = "--full" ]; then
    info "Uninstalling sentinelai Python package..."
    pip3 uninstall sentinelai -y 2>/dev/null && ok "Package uninstalled" || warn "Package was not installed"
else
    info "Keeping sentinelai package installed (use --full to remove)"
fi

# ── Done ──────────────────────────────────────────────────────
echo ""
ok "============================================="
ok "  ShieldPilot uninstalled"
ok "============================================="
echo ""
info "Preserved (not deleted):"
info "  - sentinel.yaml (your configuration)"
info "  - sentinel.db (your audit logs)"
info "  - plugin/ directory (re-run install.sh to reinstall)"
echo ""
