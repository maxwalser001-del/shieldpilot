"""Canonical path containment utilities.

All path-under-parent checks in ShieldPilot must use these functions
to ensure consistent, secure behavior across the codebase.
"""

from __future__ import annotations

from pathlib import Path


def is_path_under(child: str, parent: str) -> bool:
    """Return True if child path is equal to or under the parent path.

    Handles:
    - Tilde expansion (~)
    - Symlink resolution
    - Directory traversal (..)
    - Platform-specific separators

    Uses Path.relative_to() which is immune to prefix-matching bugs
    (e.g. /etc_backup will NOT match /etc).
    """
    try:
        resolved_child = Path(child).expanduser().resolve()
        resolved_parent = Path(parent).expanduser().resolve()
        resolved_child.relative_to(resolved_parent)
        return True
    except (ValueError, OSError):
        return False
