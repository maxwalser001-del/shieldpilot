"""Example plugin: file integrity monitor.

Tracks file changes in the project directory after command execution.
Logs new, modified, and deleted files to the blackbox logger.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Dict, Optional

from sentinelai.core.models import RiskAssessment
from sentinelai.plugins.interface import SentinelPlugin

logger = logging.getLogger(__name__)


class FileIntegrityPlugin(SentinelPlugin):
    """Monitors file system changes after command execution."""

    @property
    def name(self) -> str:
        return "file_integrity"

    @property
    def version(self) -> str:
        return "1.0.0"

    def on_load(self, config) -> None:
        self.watch_dir = Path(".")
        self._snapshot: Dict[str, str] = {}
        self._take_snapshot()

    def _take_snapshot(self) -> None:
        """Record hashes of all files in the watch directory."""
        self._snapshot = {}
        try:
            for p in self.watch_dir.rglob("*"):
                if p.is_file() and not self._should_skip(p):
                    try:
                        h = hashlib.sha256(p.read_bytes()).hexdigest()
                        self._snapshot[str(p)] = h
                    except (PermissionError, OSError):
                        continue
        except Exception as e:
            logger.debug(f"Snapshot error: {e}")

    def _should_skip(self, path: Path) -> bool:
        """Skip common directories that change frequently."""
        skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox"}
        for part in path.parts:
            if part in skip_dirs:
                return True
        return False

    def post_execute(self, command: str, output: str, exit_code: int) -> None:
        """Compare file state after command execution."""
        old_snapshot = self._snapshot.copy()
        self._take_snapshot()

        changes = []

        # Detect new and modified files
        for path, new_hash in self._snapshot.items():
            old_hash = old_snapshot.get(path)
            if old_hash is None:
                changes.append({"path": path, "type": "created"})
            elif old_hash != new_hash:
                changes.append({"path": path, "type": "modified"})

        # Detect deleted files
        for path in old_snapshot:
            if path not in self._snapshot:
                changes.append({"path": path, "type": "deleted"})

        if changes:
            logger.info(
                f"File integrity: {len(changes)} changes detected after: "
                f"{command[:50]}"
            )
            for change in changes[:10]:  # Log first 10
                logger.info(f"  {change['type']}: {change['path']}")
