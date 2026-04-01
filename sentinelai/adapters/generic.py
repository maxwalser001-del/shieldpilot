"""Generic platform adapter for ShieldPilot.

Provides the simplest possible JSON stdin/stdout protocol for any tool
that wants to integrate with ShieldPilot's risk engine without
implementing a platform-specific adapter.

Generic Hook Protocol
---------------------

**Input** (stdin):
    {
        "command": "ls -la",
        "cwd": "/home/user/project",
        "tool": "Bash"
    }

    Only ``command`` is required. ``cwd`` defaults to empty string and
    ``tool`` defaults to ``"Bash"`` when omitted.

**Output** -- allow:
    {"allowed": true, "risk_score": 0, "reasons": [], "incident_id": null}

**Output** -- deny:
    {"allowed": false, "risk_score": 85, "reasons": ["Destructive command detected"], "incident_id": 42}

**Output** -- ask (review):
    {"allowed": false, "risk_score": 55, "reasons": ["Elevated risk"], "incident_id": null, "review": true}

This adapter is the fallback for ``detect_platform()`` when the input
format does not match any known platform.
"""

from __future__ import annotations

import json
from typing import Any

from sentinelai.adapters.base import BaseAdapter, CommandInput, CommandResult


class GenericAdapter(BaseAdapter):
    """Adapter for the generic JSON stdin/stdout protocol.

    Designed as the lowest-barrier integration path: any tool that can
    write a JSON object with a ``command`` field to stdin and read a
    JSON response from stdout can use ShieldPilot.
    """

    def parse_input(self, raw: str) -> CommandInput:
        """Parse generic JSON input into a universal CommandInput.

        The minimal valid input is ``{"command": "..."}``.  All other
        fields are optional.

        Args:
            raw: Raw JSON string from stdin.

        Returns:
            CommandInput with the command wrapped in tool_input, plus
            any optional fields (cwd, tool name) extracted.

        Raises:
            ValueError: If the raw string is empty or not valid JSON.
        """
        stripped = raw.strip()
        if not stripped:
            raise ValueError("Empty input received on generic adapter stdin")

        try:
            data: dict[str, Any] = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON on generic adapter stdin: {exc}") from exc

        # Extract the command -- the only required field
        command = data.get("command", "")
        tool_name = data.get("tool", "Bash")
        cwd = data.get("cwd", "")

        # Build tool_input: put the command in the standard format
        tool_input: dict[str, Any] = {"command": command} if command else {}

        # Collect any extra fields into metadata
        metadata: dict[str, Any] = {}
        known_keys = {"command", "tool", "cwd"}
        for key, value in data.items():
            if key not in known_keys:
                metadata[key] = value

        return CommandInput(
            tool_name=tool_name,
            tool_input=tool_input,
            cwd=cwd,
            metadata=metadata,
        )

    def format_output(self, result: CommandResult) -> str:
        """Format a CommandResult into the generic JSON response.

        Args:
            result: Universal risk decision from the engine.

        Returns:
            JSON string with ``allowed``, ``risk_score``, ``reasons``,
            and ``incident_id`` fields. Adds ``review: true`` for
            ask decisions to distinguish them from hard denials.
        """
        allowed = result.decision == "allow"

        response: dict[str, Any] = {
            "allowed": allowed,
            "risk_score": result.risk_score,
            "reasons": list(result.reasons),
            "incident_id": result.incident_id,
        }

        # Distinguish "ask" (soft denial / review) from "deny" (hard block)
        if result.decision == "ask":
            response["review"] = True

        return json.dumps(response)

    def get_platform(self) -> str:
        """Return the canonical platform identifier.

        Returns:
            ``"generic"``
        """
        return "generic"
