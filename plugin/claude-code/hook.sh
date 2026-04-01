#!/usr/bin/env bash
# ShieldPilot hook entry-point for Claude Code
#
# This script is the bridge between Claude Code's pre-tool-use hook system
# and ShieldPilot's Python-based risk engine.
#
# Protocol:
#   - Claude Code pipes JSON on stdin (tool_name, tool_input, cwd)
#   - This script forwards it to the ShieldPilot hook
#   - The hook returns a JSON decision on stdout (allow/deny/ask)
#
# Failure policy: controlled by SENTINEL_FAIL_MODE environment variable.
#   SENTINEL_FAIL_MODE=open   (default) — allow on crash (fail-open)
#   SENTINEL_FAIL_MODE=closed           — deny on crash  (fail-closed, security-first)

set -euo pipefail

# Resolve the directory this script lives in (follows symlinks)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Ensure the project root is on PYTHONPATH so sentinelai can be imported
export PYTHONPATH="${PROJECT_ROOT}:${PYTHONPATH:-}"

# Read stdin into a variable (Claude Code sends JSON on stdin)
INPUT=$(cat)

# Execute the ShieldPilot hook, forwarding stdin and capturing stdout
# If python3 is not available or the hook fails, fall through to fail-open
if command -v python3 &>/dev/null; then
    echo "$INPUT" | python3 -m sentinelai.hooks.sentinel_hook 2>/dev/null && exit 0
fi

# Fallback decision based on SENTINEL_FAIL_MODE
if [ "${SENTINEL_FAIL_MODE:-open}" = "closed" ]; then
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"ShieldPilot hook unavailable (fail-closed)"}}'
else
    echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"ShieldPilot hook unavailable (fail-open)"}}'
fi
