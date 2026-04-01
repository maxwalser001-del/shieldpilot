"""Base adapter interface and universal data types for ShieldPilot platform adapters.

This module defines the contract that every platform adapter must implement,
plus the two universal data classes (CommandInput, CommandResult) that decouple
the risk engine from any specific tool-calling platform.

Supported platforms:
  - Claude Code (stdin/stdout JSON hooks)
  - OpenClaw (preToolExecution event hooks)
  - Generic (simple JSON stdin/stdout for any tool)

Usage:
    from sentinelai.adapters.base import BaseAdapter, CommandInput, CommandResult
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CommandInput:
    """Universal representation of a tool invocation, independent of platform.

    Every platform adapter parses its own raw JSON into this format so that
    the risk engine, scanner, and logging pipeline receive a single consistent
    shape regardless of where the command originated.

    Attributes:
        tool_name: Canonical tool name (e.g. "Bash", "Write", "Edit").
                   Adapters normalise platform-specific names to ShieldPilot
                   canonical names where possible.
        tool_input: Tool parameters as a dict.  For Bash commands this is
                    typically ``{"command": "..."}``.  For file-write tools
                    it contains ``file_path``, ``content``, etc.
        cwd:        Working directory at the time the command was issued.
                    Falls back to an empty string when the platform does not
                    provide it.
        metadata:   Arbitrary platform-specific fields that don't map to the
                    universal schema (session IDs, tool-use IDs, etc.).
                    Preserved for logging but never used in risk decisions.
    """

    tool_name: str
    tool_input: dict[str, Any]
    cwd: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CommandResult:
    """Universal representation of a ShieldPilot risk decision.

    Produced by the risk engine and consumed by the platform adapter's
    ``format_output`` method to generate a platform-specific response.

    Attributes:
        decision:    One of ``"allow"``, ``"deny"``, or ``"ask"``.
                     - ``allow``: command runs without user prompt.
                     - ``deny``:  command is rejected outright.
                     - ``ask``:   user is shown a confirmation prompt.
        risk_score:  Aggregate risk score from the engine (0-100).
        reasons:     Human-readable explanations for the decision.  May
                     contain signal descriptions, scanner findings, etc.
        incident_id: Database ID of a logged incident, or ``None`` when
                     no incident was created (i.e. on allow/ask decisions).
    """

    decision: str  # "allow" | "deny" | "ask"
    risk_score: int = 0
    reasons: list[str] = field(default_factory=list)
    incident_id: int | None = None

    def __post_init__(self) -> None:
        """Validate that decision is one of the three allowed values."""
        allowed = ("allow", "deny", "ask")
        if self.decision not in allowed:
            raise ValueError(
                f"CommandResult.decision must be one of {allowed}, "
                f"got {self.decision!r}"
            )


class BaseAdapter(ABC):
    """Abstract base class for platform-specific adapters.

    Each adapter translates between a platform's native hook protocol and
    ShieldPilot's universal ``CommandInput`` / ``CommandResult`` types.

    Subclasses must implement three methods:

    - ``parse_input``   -- platform JSON -> CommandInput
    - ``format_output`` -- CommandResult -> platform JSON string
    - ``get_platform``  -- human-readable platform identifier

    Example:
        adapter = ClaudeCodeAdapter()
        cmd = adapter.parse_input(raw_stdin)
        # ... run risk engine on cmd ...
        print(adapter.format_output(result))
    """

    @abstractmethod
    def parse_input(self, raw: str) -> CommandInput:
        """Parse platform-specific raw input into a universal CommandInput.

        Args:
            raw: The raw string read from stdin (or received from the
                 platform's hook mechanism).  Expected to be valid JSON
                 but implementations should handle malformed input
                 gracefully.

        Returns:
            A ``CommandInput`` instance with tool name, parameters, working
            directory, and any extra metadata extracted from the raw input.

        Raises:
            ValueError: If the raw input cannot be parsed into the
                        expected platform format.
        """

    @abstractmethod
    def format_output(self, result: CommandResult) -> str:
        """Format a universal CommandResult into a platform-specific response.

        Args:
            result: The risk decision produced by the engine.

        Returns:
            A JSON string that the platform's hook mechanism expects on
            stdout (or as a response body).
        """

    @abstractmethod
    def get_platform(self) -> str:
        """Return the canonical platform identifier.

        Returns:
            A short, lowercase string identifying the platform
            (e.g. ``"claude_code"``, ``"openclaw"``, ``"generic"``).
        """
