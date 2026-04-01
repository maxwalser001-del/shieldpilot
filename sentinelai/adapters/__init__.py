"""ShieldPilot Adapter Layer -- multi-platform hook support.

This package provides platform adapters that translate between different
AI coding agent protocols and ShieldPilot's universal risk engine.

Supported Platforms
-------------------
- **Claude Code**: ``ClaudeCodeAdapter`` -- hookSpecificOutput JSON protocol
- **OpenClaw**: ``OpenClawAdapter`` -- preToolExecution event protocol
- **Generic**: ``GenericAdapter`` -- simple JSON stdin/stdout for any tool

Auto-Detection
--------------
Use ``detect_platform(raw)`` to automatically select the correct adapter
based on the shape of the incoming JSON:

    from sentinelai.adapters import detect_platform

    adapter = detect_platform(raw_stdin)
    cmd = adapter.parse_input(raw_stdin)
    # ... run risk engine ...
    print(adapter.format_output(result))

Exports
-------
- ``BaseAdapter``       -- abstract base class
- ``CommandInput``      -- universal input dataclass
- ``CommandResult``     -- universal output dataclass
- ``ClaudeCodeAdapter`` -- Claude Code adapter
- ``OpenClawAdapter``   -- OpenClaw adapter
- ``GenericAdapter``    -- generic fallback adapter
- ``detect_platform``   -- auto-detection function
"""

from __future__ import annotations

import json
import logging
from typing import Any

from sentinelai.adapters.base import BaseAdapter, CommandInput, CommandResult
from sentinelai.adapters.claude_code import ClaudeCodeAdapter
from sentinelai.adapters.openclaw import OpenClawAdapter
from sentinelai.adapters.generic import GenericAdapter

logger = logging.getLogger(__name__)

__all__ = [
    "BaseAdapter",
    "CommandInput",
    "CommandResult",
    "ClaudeCodeAdapter",
    "OpenClawAdapter",
    "GenericAdapter",
    "detect_platform",
]


def detect_platform(raw: str) -> BaseAdapter:
    """Auto-detect the originating platform and return the matching adapter.

    Inspects the top-level keys of the incoming JSON to determine which
    platform sent the hook event.

    Detection logic (evaluated in order):
        1. Has ``tool_name`` AND ``tool_input``  -> Claude Code
        2. Has ``event`` AND ``tool`` (dict)      -> OpenClaw
        3. Has ``command``                        -> Generic
        4. Fallback                               -> Generic

    Args:
        raw: The raw JSON string received on stdin (or from the hook
             mechanism).  Does not need to be pre-validated -- malformed
             input falls through to the Generic adapter.

    Returns:
        An instantiated adapter matching the detected platform.

    Examples:
        >>> adapter = detect_platform('{"tool_name": "Bash", "tool_input": {}}')
        >>> adapter.get_platform()
        'claude_code'

        >>> adapter = detect_platform('{"event": "preToolExecution", "tool": {"name": "shell"}}')
        >>> adapter.get_platform()
        'openclaw'

        >>> adapter = detect_platform('{"command": "ls"}')
        >>> adapter.get_platform()
        'generic'
    """
    try:
        data: dict[str, Any] = json.loads(raw.strip())
    except (json.JSONDecodeError, AttributeError, ValueError):
        logger.debug("detect_platform: could not parse JSON, falling back to GenericAdapter")
        return GenericAdapter()

    if not isinstance(data, dict):
        logger.debug("detect_platform: parsed value is not a dict, falling back to GenericAdapter")
        return GenericAdapter()

    # 1. Claude Code: has tool_name + tool_input
    if "tool_name" in data and "tool_input" in data:
        logger.debug("detect_platform: detected Claude Code format")
        return ClaudeCodeAdapter()

    # 2. OpenClaw: has event + tool (as a dict object)
    if "event" in data and isinstance(data.get("tool"), dict):
        logger.debug("detect_platform: detected OpenClaw format")
        return OpenClawAdapter()

    # 3. Generic: has command field
    if "command" in data:
        logger.debug("detect_platform: detected Generic format")
        return GenericAdapter()

    # 4. Fallback
    logger.debug("detect_platform: no known format detected, falling back to GenericAdapter")
    return GenericAdapter()
