"""Claude Code platform adapter for ShieldPilot.

Translates between Claude Code's pre-tool-use hook JSON protocol and
ShieldPilot's universal CommandInput / CommandResult types.

Claude Code Hook Protocol
-------------------------

**Input** (stdin):
    {
        "tool_name": "Bash",
        "tool_input": {"command": "ls -la"},
        "tool_use_id": "toolu_abc123",
        "session_id": "sess_xyz789",
        "cwd": "/home/user/project"
    }

**Output** (stdout) -- allow:
    {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow"
        }
    }

**Output** (stdout) -- deny:
    {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "Destructive command detected"
        }
    }

**Output** (stdout) -- ask:
    {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": "Elevated risk detected"
        }
    }
"""

from __future__ import annotations

import json
import os
from typing import Any

from sentinelai.adapters.base import BaseAdapter, CommandInput, CommandResult


class ClaudeCodeAdapter(BaseAdapter):
    """Adapter for the Claude Code pre-tool-use hook protocol.

    Claude Code sends a JSON object on stdin before every tool invocation.
    ShieldPilot responds on stdout with a hookSpecificOutput JSON that
    tells Claude Code whether to allow, deny, or prompt the user.

    This adapter preserves full backward compatibility with the existing
    ``sentinel_hook.py`` behaviour -- switching to the adapter layer
    produces byte-identical output for the same inputs.
    """

    # Claude Code decision mapping: internal -> Claude Code protocol
    _DECISION_MAP: dict[str, str] = {
        "allow": "allow",
        "deny": "deny",
        "ask": "ask",
    }

    def parse_input(self, raw: str) -> CommandInput:
        """Parse Claude Code stdin JSON into a universal CommandInput.

        Args:
            raw: Raw JSON string from Claude Code's stdin pipe.

        Returns:
            CommandInput with tool_name, tool_input, cwd, and metadata
            containing any extra fields (tool_use_id, session_id, etc.).

        Raises:
            ValueError: If the raw string is empty or not valid JSON.
        """
        stripped = raw.strip()
        if not stripped:
            raise ValueError("Empty input received from Claude Code stdin")

        try:
            data: dict[str, Any] = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON from Claude Code stdin: {exc}") from exc

        tool_name = data.get("tool_name", "")
        tool_input = data.get("tool_input", {})
        cwd = data.get("cwd", os.getcwd())

        # Collect platform-specific metadata (everything not in the universal schema)
        metadata: dict[str, Any] = {}
        for key in ("tool_use_id", "session_id"):
            if key in data:
                metadata[key] = data[key]

        # Preserve any additional unknown keys in metadata
        known_keys = {"tool_name", "tool_input", "cwd", "tool_use_id", "session_id"}
        for key, value in data.items():
            if key not in known_keys:
                metadata[key] = value

        return CommandInput(
            tool_name=tool_name,
            tool_input=tool_input if isinstance(tool_input, dict) else {},
            cwd=cwd,
            metadata=metadata,
        )

    def format_output(self, result: CommandResult) -> str:
        """Format a CommandResult into Claude Code's expected stdout JSON.

        The output format matches exactly what the existing sentinel_hook.py
        produces via its ``_allow``, ``_deny``, and ``_ask`` functions.

        Args:
            result: Universal risk decision from the engine.

        Returns:
            JSON string conforming to the Claude Code hook protocol.
        """
        permission = self._DECISION_MAP.get(result.decision, "allow")

        hook_output: dict[str, Any] = {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission,
        }

        # Add reason for deny and ask decisions (matches existing hook behaviour)
        if result.decision in ("deny", "ask") and result.reasons:
            hook_output["permissionDecisionReason"] = "\n".join(result.reasons)
        elif result.decision == "allow" and result.reasons:
            # Allow with reason (e.g. audit mode, usage warnings)
            hook_output["permissionDecisionReason"] = "\n".join(result.reasons)

        response: dict[str, Any] = {
            "hookSpecificOutput": hook_output,
        }

        return json.dumps(response)

    def get_platform(self) -> str:
        """Return the canonical platform identifier.

        Returns:
            ``"claude_code"``
        """
        return "claude_code"
