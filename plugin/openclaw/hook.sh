#!/usr/bin/env bash
# ShieldPilot OpenClaw Hook (Pure Bash)
#
# Reads JSON event from stdin, pipes to ShieldPilot's Python risk engine,
# returns JSON decision to stdout.
#
# Fail-open: if anything goes wrong, outputs {"action": "allow"} so the
# user is never blocked by a hook failure.
#
# Usage:
#   echo '{"event":"preToolExecution","tool":{"name":"shell","parameters":{"command":"ls"}}}' | ./hook.sh
#
# Environment:
#   SHIELDPILOT_PYTHON  - Python interpreter (default: python3)
#   SHIELDPILOT_CONFIG  - Config file path (default: sentinel.yaml)
#   SHIELDPILOT_MODE    - enforce/audit/disabled (default: enforce)
#   SHIELDPILOT_TIMEOUT - Timeout in seconds (default: 10)

set -uo pipefail

PYTHON="${SHIELDPILOT_PYTHON:-python3}"
CONFIG="${SHIELDPILOT_CONFIG:-sentinel.yaml}"
MODE="${SHIELDPILOT_MODE:-enforce}"
TIMEOUT="${SHIELDPILOT_TIMEOUT:-10}"

# Fail-open response -- always valid JSON
FAIL_OPEN='{"action":"allow"}'

# Disabled mode: skip everything
if [[ "$MODE" == "disabled" ]]; then
  echo "$FAIL_OPEN"
  exit 0
fi

# Read stdin (the OpenClaw event JSON)
INPUT=""
if ! INPUT=$(cat); then
  echo "$FAIL_OPEN"
  exit 0
fi

# Empty input: fail-open
if [[ -z "$INPUT" ]]; then
  echo "$FAIL_OPEN"
  exit 0
fi

# Ensure Python is available
if ! command -v "$PYTHON" &>/dev/null; then
  echo '{"action":"allow","_error":"python not found"}'
  exit 0
fi

# Set PYTHONPATH to include the project root (two levels up from hook.sh)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
export PYTHONPATH="${PROJECT_ROOT}:${PYTHONPATH:-}"
export SHIELDPILOT_CONFIG="$CONFIG"
export SHIELDPILOT_MODE="$MODE"

# Pipe to Python hook with timeout
RESULT=""
if command -v timeout &>/dev/null; then
  # GNU/Linux timeout
  RESULT=$(echo "$INPUT" | timeout "${TIMEOUT}s" "$PYTHON" -m sentinelai.hooks.sentinel_hook 2>/dev/null) || true
elif command -v gtimeout &>/dev/null; then
  # macOS with coreutils
  RESULT=$(echo "$INPUT" | gtimeout "${TIMEOUT}s" "$PYTHON" -m sentinelai.hooks.sentinel_hook 2>/dev/null) || true
else
  # No timeout command: run without timeout
  RESULT=$(echo "$INPUT" | "$PYTHON" -m sentinelai.hooks.sentinel_hook 2>/dev/null) || true
fi

# If Python hook returned empty or failed, fail-open
if [[ -z "$RESULT" ]]; then
  echo "$FAIL_OPEN"
  exit 0
fi

# Validate response is JSON (basic check: starts with {)
if [[ "$RESULT" != "{"* ]]; then
  echo "$FAIL_OPEN"
  exit 0
fi

# Output the result
echo "$RESULT"
exit 0
