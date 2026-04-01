"""Path traversal prevention and protected-path enforcement."""

from __future__ import annotations

import logging
import os
import re
import shlex
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from sentinelai.core.config import SentinelConfig
from sentinelai.core.path_utils import is_path_under

logger = logging.getLogger(__name__)

# Tokens that typically precede file-path arguments in shell commands.
_PATH_FLAGS: set = {
    "-o", "--output", "-f", "--file", "-d", "--directory",
    "-i", "--input", "-c", "--config", "-p", "--path",
    ">", ">>",
}


class PathGuard:
    """Validate file-system paths referenced in shell commands.

    PathGuard detects:
    * Paths that escape a given *allowed_root* via ``..`` or symlinks.
    * Paths that touch locations listed in
      ``config.protected_paths`` (e.g. ``/etc/shadow``).

    It is intentionally conservative -- when in doubt it flags a violation so
    the caller can decide whether to block the command.
    """

    def __init__(self, config: Optional[SentinelConfig] = None) -> None:
        if config is None:
            # Provide sensible defaults when no config is available.
            self._protected_paths: List[str] = []
        else:
            self._protected_paths = list(config.protected_paths)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_path(self, path: str, allowed_root: str = ".") -> bool:
        """Return ``True`` if *path* is safely contained within *allowed_root*.

        The check resolves symlinks and normalises both paths to absolute form
        before comparing.  A path that escapes the root (e.g. via ``..``)
        returns ``False``.
        """
        return is_path_under(path, allowed_root)

    def is_protected(self, path: str) -> bool:
        """Return ``True`` if *path* overlaps any configured protected path.

        A path is considered protected if, after resolution, it is equal to or
        a child of any entry in the protected-paths list.
        """
        if not self._protected_paths:
            return False

        try:
            Path(path).resolve()
        except (OSError, ValueError):
            # If we cannot resolve the path, err on the side of caution.
            return True

        return any(is_path_under(path, pp) for pp in self._protected_paths)

    def extract_paths_from_command(self, command: str) -> List[str]:
        """Heuristically extract file-system paths from a shell *command*.

        This is a best-effort extraction.  It looks for:
        * Tokens that look like absolute or relative paths.
        * Arguments that follow common flag patterns (``-o``, ``--file``, etc.).
        * Redirection targets (``>`` / ``>>``).
        """
        paths: List[str] = []

        try:
            tokens = shlex.split(command)
        except ValueError:
            # Fall back to naive whitespace split on malformed input.
            tokens = command.split()

        expect_path = False
        for token in tokens:
            if expect_path:
                paths.append(token)
                expect_path = False
                continue

            if token in _PATH_FLAGS:
                expect_path = True
                continue

            # Heuristic: anything that looks like a file path.
            if self._looks_like_path(token):
                paths.append(token)

        return paths

    def check_command(self, command: str) -> List[dict]:
        """Analyse *command* and return a list of path violations.

        Each violation is a dict with keys ``path``, ``reason``, and
        ``severity`` (one of ``"critical"``, ``"high"``, ``"medium"``).
        """
        violations: List[dict] = []
        extracted = self.extract_paths_from_command(command)

        for raw_path in extracted:
            # Check protected paths first (higher priority).
            if self.is_protected(raw_path):
                violations.append({
                    "path": raw_path,
                    "reason": "Path touches a protected location",
                    "severity": "critical",
                })

            # Check for traversal via ".."
            if ".." in raw_path:
                violations.append({
                    "path": raw_path,
                    "reason": "Path contains directory traversal sequence (..)",
                    "severity": "high",
                })

            # Check for home-directory references to sensitive dot-files.
            if self._is_sensitive_dotfile(raw_path):
                violations.append({
                    "path": raw_path,
                    "reason": "Path references a sensitive dot-file or directory",
                    "severity": "high",
                })

        return violations

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _looks_like_path(token: str) -> bool:
        """Return ``True`` if *token* looks like a file-system path."""
        # Skip obviously non-path tokens.
        if token.startswith("-"):
            return False

        # Absolute paths.
        if token.startswith("/") or token.startswith("~"):
            return True

        # Relative paths containing a separator.
        if os.sep in token or "/" in token:
            return True

        # Tokens with common file extensions.
        if re.search(r"\.\w{1,5}$", token):
            return True

        return False

    @staticmethod
    def _is_sensitive_dotfile(path: str) -> bool:
        """Return ``True`` if *path* references a well-known sensitive dotfile."""
        sensitive = {
            ".ssh", ".gnupg", ".aws", ".azure", ".kube",
            ".config", ".bash_history", ".zsh_history",
            ".netrc", ".npmrc", ".pypirc", ".docker",
            ".git-credentials", ".env",
        }
        parts = Path(path).parts
        for part in parts:
            if part in sensitive:
                return True
        return False
