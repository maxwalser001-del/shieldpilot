#!/usr/bin/env bash
set -euo pipefail

# ShieldPilot OpenClaw Plugin Uninstaller
# Usage: ./uninstall.sh [--full]
#
# Default: removes hook registration only (preserves DB and config)
# --full:  also removes config file and Python package

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FULL_REMOVE=false
CONFIG_PATH="${SHIELDPILOT_CONFIG:-sentinel.yaml}"
PYTHON="${SHIELDPILOT_PYTHON:-python3}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()   { echo -e "${CYAN}[ShieldPilot]${NC} $*"; }
ok()    { echo -e "${GREEN}[ok]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --full) FULL_REMOVE=true; shift ;;
    --help|-h)
      echo "Usage: ./uninstall.sh [--full]"
      echo ""
      echo "Default: removes hook registration only"
      echo "  --full  Also removes config and Python package"
      echo ""
      echo "The database (sentinel.db) is always preserved."
      exit 0
      ;;
    *) warn "Unknown argument: $1"; shift ;;
  esac
done

echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  ShieldPilot OpenClaw Plugin Uninstall ${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

if [[ "$FULL_REMOVE" == "true" ]]; then
  warn "Full removal mode: will remove config and Python package"
else
  log "Standard removal: hook registration only"
fi

# Step 1: Remove hook registration
log "Removing hook registration..."
# Note: The user needs to manually remove the plugin entry from their
# OpenClaw config since we don't know where it is.
warn "Please remove the ShieldPilot plugin entry from your OpenClaw config:"
echo -e "  ${CYAN}# Remove this block:${NC}"
echo -e "  ${CYAN}plugins:${NC}"
echo -e "  ${CYAN}  - path: $SCRIPT_DIR${NC}"
echo ""
ok "Hook scripts remain in $SCRIPT_DIR (remove directory manually if desired)"

# Step 2: Remove node_modules (if present)
if [[ -d "$SCRIPT_DIR/node_modules" ]]; then
  log "Removing node_modules..."
  rm -rf "$SCRIPT_DIR/node_modules"
  ok "node_modules removed"
fi

# Step 3: Full removal (optional)
if [[ "$FULL_REMOVE" == "true" ]]; then
  # Remove config file
  if [[ -f "$CONFIG_PATH" ]]; then
    log "Removing config file..."
    rm -f "$CONFIG_PATH"
    ok "Config removed: $CONFIG_PATH"
  fi

  # Uninstall Python package
  log "Uninstalling ShieldPilot Python package..."
  if "$PYTHON" -c "import sentinelai" &>/dev/null; then
    "$PYTHON" -m pip uninstall shieldpilot -y --quiet 2>/dev/null || warn "pip uninstall failed (may need sudo)"
    ok "Python package uninstalled"
  else
    ok "Python package not installed (nothing to remove)"
  fi
fi

# Step 4: Confirm database preserved
if [[ -f "sentinel.db" ]] || [[ -f "$SCRIPT_DIR/../../sentinel.db" ]]; then
  ok "Database preserved (sentinel.db) -- delete manually if needed"
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Uninstall Complete                    ${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
if [[ "$FULL_REMOVE" == "true" ]]; then
  echo -e "  Removed: config, Python package, node_modules"
else
  echo -e "  Removed: node_modules (if present)"
fi
echo -e "  Preserved: database (sentinel.db), plugin files"
echo -e "  ${YELLOW}Manual step:${NC} Remove plugin from OpenClaw config"
echo ""
