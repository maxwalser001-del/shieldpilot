#!/usr/bin/env bash
set -euo pipefail

# ShieldPilot OpenClaw Plugin Installer
# Usage: ./install.sh [--python /path/to/python3] [--config /path/to/sentinel.yaml] [--hook-type node|bash]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${SHIELDPILOT_PYTHON:-python3}"
CONFIG_PATH="${SHIELDPILOT_CONFIG:-sentinel.yaml}"
HOOK_TYPE="${SHIELDPILOT_HOOK_TYPE:-bash}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()   { echo -e "${CYAN}[ShieldPilot]${NC} $*"; }
ok()    { echo -e "${GREEN}[ok]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[x]${NC} $*"; exit 1; }

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --python)    PYTHON="$2"; shift 2 ;;
    --config)    CONFIG_PATH="$2"; shift 2 ;;
    --hook-type) HOOK_TYPE="$2"; shift 2 ;;
    --help|-h)
      echo "Usage: ./install.sh [--python PATH] [--config PATH] [--hook-type node|bash]"
      echo ""
      echo "Options:"
      echo "  --python     Path to Python 3.8+ interpreter (default: python3)"
      echo "  --config     Path to sentinel.yaml config (default: sentinel.yaml)"
      echo "  --hook-type  Hook implementation: bash (default) or node"
      exit 0
      ;;
    *) warn "Unknown argument: $1"; shift ;;
  esac
done

echo ""
echo -e "${CYAN}========================================${NC}"
echo -e "${CYAN}  ShieldPilot OpenClaw Plugin Installer ${NC}"
echo -e "${CYAN}========================================${NC}"
echo ""

# Step 1: Check Python
log "Checking Python installation..."
if ! command -v "$PYTHON" &>/dev/null; then
  fail "Python not found at '$PYTHON'. Install Python 3.8+ or set --python /path/to/python3"
fi

PY_VERSION=$("$PYTHON" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$("$PYTHON" -c "import sys; print(sys.version_info.major)")
PY_MINOR=$("$PYTHON" -c "import sys; print(sys.version_info.minor)")

if [[ "$PY_MAJOR" -lt 3 ]] || [[ "$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 8 ]]; then
  fail "Python 3.8+ required, found $PY_VERSION"
fi
ok "Python $PY_VERSION found at $(command -v "$PYTHON")"

# Step 2: Check Node.js (optional, only for node hook type)
if [[ "$HOOK_TYPE" == "node" ]]; then
  log "Checking Node.js installation (required for node hook type)..."
  if ! command -v node &>/dev/null; then
    fail "Node.js not found. Install Node.js 18+ or use --hook-type bash"
  fi
  NODE_VERSION=$(node -v)
  ok "Node.js $NODE_VERSION found"
else
  if command -v node &>/dev/null; then
    ok "Node.js $(node -v) found (optional)"
  else
    log "Node.js not found (not required for bash hook type)"
  fi
fi

# Step 3: Install ShieldPilot Python package
log "Installing ShieldPilot Python package..."
if "$PYTHON" -c "import sentinelai" &>/dev/null; then
  ok "ShieldPilot Python package already installed"
else
  "$PYTHON" -m pip install shieldpilot --quiet || fail "Failed to install shieldpilot via pip"
  ok "ShieldPilot Python package installed"
fi

# Step 4: Check/create config
log "Checking configuration..."
if [[ -f "$CONFIG_PATH" ]]; then
  ok "Config found at $CONFIG_PATH"
else
  warn "No config found at $CONFIG_PATH"
  if [[ -f "$SCRIPT_DIR/../../sentinel.yaml" ]]; then
    cp "$SCRIPT_DIR/../../sentinel.yaml" "$CONFIG_PATH"
    ok "Copied default config to $CONFIG_PATH"
  else
    warn "Create sentinel.yaml manually or run: shieldpilot init"
  fi
fi

# Step 5: Make hook.sh executable
log "Setting up hook scripts..."
chmod +x "$SCRIPT_DIR/hook.sh"
ok "hook.sh is executable"

if [[ "$HOOK_TYPE" == "node" ]] && [[ -f "$SCRIPT_DIR/package.json" ]]; then
  log "Installing Node.js dependencies..."
  cd "$SCRIPT_DIR" && npm install --production --quiet 2>/dev/null
  ok "Node.js dependencies installed"
fi

# Step 6: Validate installation
log "Validating installation..."
TEST_EVENT='{"event":"preToolExecution","tool":{"name":"shell","parameters":{"command":"echo hello"}},"context":{"workingDir":"/tmp"}}'

if [[ "$HOOK_TYPE" == "bash" ]]; then
  RESULT=$(echo "$TEST_EVENT" | SHIELDPILOT_PYTHON="$PYTHON" bash "$SCRIPT_DIR/hook.sh" 2>/dev/null) || true
else
  RESULT=$(echo "$TEST_EVENT" | "$PYTHON" -m sentinelai.hooks.sentinel_hook 2>/dev/null) || true
fi

if [[ -n "$RESULT" ]]; then
  ok "Hook validation passed"
  echo -e "  ${CYAN}Test response:${NC} $RESULT"
else
  warn "Hook validation returned empty response (this may be OK if sentinelai needs configuration)"
fi

# Step 7: Print success summary
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Installation Complete!                ${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "  Python:    ${CYAN}$(command -v "$PYTHON")${NC} ($PY_VERSION)"
echo -e "  Hook type: ${CYAN}$HOOK_TYPE${NC}"
echo -e "  Plugin:    ${CYAN}$SCRIPT_DIR${NC}"
echo -e "  Config:    ${CYAN}$CONFIG_PATH${NC}"
echo ""
echo -e "  To register with OpenClaw, add to your OpenClaw config:"
echo ""
if [[ "$HOOK_TYPE" == "bash" ]]; then
  echo -e "  ${CYAN}plugins:${NC}"
  echo -e "  ${CYAN}  - path: $SCRIPT_DIR${NC}"
  echo -e "  ${CYAN}    hooks:${NC}"
  echo -e "  ${CYAN}      preToolExecution: ./hook.sh${NC}"
else
  echo -e "  ${CYAN}plugins:${NC}"
  echo -e "  ${CYAN}  - path: $SCRIPT_DIR${NC}"
  echo -e "  ${CYAN}    hooks:${NC}"
  echo -e "  ${CYAN}      preToolExecution: ./index.js${NC}"
fi
echo ""
