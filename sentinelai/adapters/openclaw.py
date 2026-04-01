"""OpenClaw platform adapter for ShieldPilot.

Translates between OpenClaw's preToolExecution hook event format and
ShieldPilot's universal CommandInput / CommandResult types.

OpenClaw Hook Protocol
----------------------

**Input** (preToolExecution event):
    {
        "event": "preToolExecution",
        "tool": {
            "name": "shell",
            "parameters": {"command": "ls -la"}
        },
        "context": {
            "workingDir": "/home/user/project",
            "sessionId": "oc-sess-abc123"
        }
    }

**Output** -- allow:
    {"action": "allow"}

**Output** -- deny:
    {"action": "deny", "message": "Destructive command detected", "riskScore": 85}

**Output** -- ask (review):
    {"action": "review", "message": "Elevated risk detected", "riskScore": 55}

Tool Name Mapping
-----------------
OpenClaw uses different tool names than ShieldPilot's canonical names:
    - ``shell``     -> ``Bash``
    - ``writeFile`` -> ``Write``
    - ``editFile``  -> ``Edit``
    - ``readFile``  -> ``Read``
    - ``search``    -> ``Grep``

Unknown tool names are passed through as-is.
"""

from __future__ import annotations

import json
from typing import Any

from sentinelai.adapters.base import BaseAdapter, CommandInput, CommandResult


class OpenClawAdapter(BaseAdapter):
    """Adapter for the OpenClaw preToolExecution hook protocol.

    OpenClaw sends a JSON event object containing tool metadata and execution
    context. ShieldPilot responds with a JSON action object that tells
    OpenClaw whether to allow, deny, or prompt the user for review.
    """

    # OpenClaw tool name -> ShieldPilot canonical name
    _TOOL_NAME_MAP: dict[str, str] = {
        "shell": "Bash",
        "bash": "Bash",
        "writeFile": "Write",
        "write_file": "Write",
        "editFile": "Edit",
        "edit_file": "Edit",
        "readFile": "Read",
        "read_file": "Read",
        "search": "Grep",
        "glob": "Glob",
        "webSearch": "WebSearch",
        "webFetch": "WebFetch",
    }

    # ShieldPilot decision -> OpenClaw action
    _DECISION_MAP: dict[str, str] = {
        "allow": "allow",
        "deny": "deny",
        "ask": "review",  # OpenClaw uses "review" instead of "ask"
    }

    def parse_input(self, raw: str) -> CommandInput:
        """Parse an OpenClaw preToolExecution event into a universal CommandInput.

        Args:
            raw: Raw JSON string from OpenClaw's hook mechanism.

        Returns:
            CommandInput with normalised tool_name, tool parameters, working
            directory, and OpenClaw-specific metadata (sessionId, event type).

        Raises:
            ValueError: If the raw string is empty, not valid JSON, or
                        missing the required ``tool`` field.
        """
        stripped = raw.strip()
        if not stripped:
            raise ValueError("Empty input received from OpenClaw")

        try:
            data: dict[str, Any] = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON from OpenClaw: {exc}") from exc

        # Extract tool information
        tool_block = data.get("tool")
        if not isinstance(tool_block, dict):
            raise ValueError(
                "OpenClaw event missing required 'tool' object. "
                f"Got keys: {list(data.keys())}"
            )

        raw_tool_name = tool_block.get("name", "")
        tool_params = tool_block.get("parameters", {})

        # Normalise tool name to ShieldPilot canonical name
        tool_name = self._TOOL_NAME_MAP.get(raw_tool_name, raw_tool_name)

        # Extract context
        context = data.get("context", {})
        cwd = context.get("workingDir", "") if isinstance(context, dict) else ""

        # Build metadata from platform-specific fields
        metadata: dict[str, Any] = {
            "event": data.get("event", "preToolExecution"),
            "original_tool_name": raw_tool_name,
        }
        if isinstance(context, dict):
            session_id = context.get("sessionId")
            if session_id:
                metadata["session_id"] = session_id
            # Preserve any extra context fields
            for key, value in context.items():
                if key not in ("workingDir", "sessionId"):
                    metadata[f"context_{key}"] = value

        # Preserve any extra top-level fields
        known_keys = {"event", "tool", "context"}
        for key, value in data.items():
            if key not in known_keys:
                metadata[key] = value

        return CommandInput(
            tool_name=tool_name,
            tool_input=tool_params if isinstance(tool_params, dict) else {},
            cwd=cwd,
            metadata=metadata,
        )

    def format_output(self, result: CommandResult) -> str:
        """Format a CommandResult into OpenClaw's expected response JSON.

        Args:
            result: Universal risk decision from the engine.

        Returns:
            JSON string conforming to the OpenClaw hook response protocol.
        """
        action = self._DECISION_MAP.get(result.decision, "allow")

        response: dict[str, Any] = {"action": action}

        # Add message and riskScore for non-allow decisions
        if result.decision in ("deny", "ask"):
            if result.reasons:
                response["message"] = "\n".join(result.reasons)
            response["riskScore"] = result.risk_score

        # Include incident ID if an incident was logged
        if result.incident_id is not None:
            response["incidentId"] = result.incident_id

        return json.dumps(response)

    def get_platform(self) -> str:
        """Return the canonical platform identifier.

        Returns:
            ``"openclaw"``
        """
        return "openclaw"
