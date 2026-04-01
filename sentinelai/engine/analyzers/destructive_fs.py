"""Destructive filesystem operations analyzer.

Detects commands that destroy, overwrite, or corrupt filesystem data,
including recursive deletions, disk formatting, device overwrites,
and permission removal on critical paths.
"""

from __future__ import annotations

import re
from typing import List, NamedTuple

from sentinelai.core.constants import RiskCategory
from sentinelai.core.models import RiskSignal
from sentinelai.core.path_utils import is_path_under
from sentinelai.engine.base import AnalysisContext, BaseAnalyzer


class _Pattern(NamedTuple):
    """Internal descriptor for a compiled regex and its associated risk metadata."""

    regex: re.Pattern[str]
    score: int
    weight: float
    description: str


# ---------------------------------------------------------------------------
# Compiled regex patterns ordered from most to least severe.
# ---------------------------------------------------------------------------

_PATTERNS: List[_Pattern] = [
    # rm -rf on root or root wildcard  (catastrophic)
    _Pattern(
        regex=re.compile(r"\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)\s+/\s*\*?\s*(?:;|&&|\||\s*$)", re.IGNORECASE),
        score=100,
        weight=1.0,
        description="Recursive forced deletion of root filesystem",
    ),
    # rm -rf on home directory
    _Pattern(
        regex=re.compile(r"\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)\s+~(?:/|\s|;|&&|\||$)", re.IGNORECASE),
        score=95,
        weight=1.0,
        description="Recursive forced deletion of home directory",
    ),
    # rm -rf on /home paths
    _Pattern(
        regex=re.compile(r"\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)\s+/home\b"),
        score=95,
        weight=1.0,
        description="Recursive forced deletion of /home directory",
    ),
    # Direct device overwrites via redirection (e.g. "> /dev/sda")
    _Pattern(
        regex=re.compile(r">\s*/dev/(?:sd[a-z]|nvme\d|hd[a-z]|vd[a-z])\b"),
        score=100,
        weight=1.0,
        description="Direct write to block device via redirection",
    ),
    # mkfs / format commands
    _Pattern(
        regex=re.compile(r"\b(?:mkfs(?:\.\w+)?|mke2fs|mkswap)\b"),
        score=95,
        weight=1.0,
        description="Filesystem format command detected",
    ),
    # dd zeroing or device overwrite
    _Pattern(
        regex=re.compile(r"\bdd\b.*\bif=/dev/(?:zero|urandom|random)\b"),
        score=95,
        weight=1.0,
        description="dd with destructive zero/random source",
    ),
    _Pattern(
        regex=re.compile(r"\bdd\b.*\bof=/dev/(?:sd[a-z]|nvme\d|hd[a-z]|vd[a-z])\b"),
        score=95,
        weight=1.0,
        description="dd writing directly to block device",
    ),
    # shred
    _Pattern(
        regex=re.compile(r"\bshred\b"),
        score=70,
        weight=0.8,
        description="Secure file shredding detected",
    ),
    # rm -rf on arbitrary paths (still dangerous)
    _Pattern(
        regex=re.compile(r"\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*|-[a-zA-Z]*f[a-zA-Z]*r[a-zA-Z]*)\s+\S+"),
        score=60,
        weight=0.8,
        description="Recursive forced deletion on a path",
    ),
    # truncate
    _Pattern(
        regex=re.compile(r"\btruncate\b"),
        score=50,
        weight=0.7,
        description="File truncation command detected",
    ),
    # chmod 000 on important paths
    _Pattern(
        regex=re.compile(r"\bchmod\s+000\s+(?:/etc|/usr|/var|/boot|/bin|/sbin|/lib)\b"),
        score=50,
        weight=0.7,
        description="Removing all permissions on a critical system path",
    ),
    # rm without -rf (low risk)
    _Pattern(
        regex=re.compile(r"\brm\s+(?!.*-[a-zA-Z]*r[a-zA-Z]*f)"),
        score=20,
        weight=0.5,
        description="File removal command detected",
    ),
]

# Pattern used to extract target paths from a command for protected-path checking.
_PATH_EXTRACT_RE = re.compile(r"(?:^|\s)(/\S+)")


class DestructiveFSAnalyzer(BaseAnalyzer):
    """Analyzes commands for destructive filesystem operations.

    Checks for recursive deletions, disk formatting, device overwrites,
    file shredding, truncation, and permission removal.  Also flags
    operations that target any path listed in
    ``context.config.protected_paths``.
    """

    @property
    def name(self) -> str:
        return "destructive_fs"

    @property
    def category(self) -> RiskCategory:
        return RiskCategory.DESTRUCTIVE_FS

    def analyze(self, command: str, context: AnalysisContext) -> List[RiskSignal]:
        """Return risk signals for destructive filesystem patterns in *command*."""
        signals: List[RiskSignal] = []

        for pattern in _PATTERNS:
            match = pattern.regex.search(command)
            if match:
                signals.append(
                    RiskSignal(
                        category=RiskCategory.DESTRUCTIVE_FS,
                        score=pattern.score,
                        weight=pattern.weight,
                        description=pattern.description,
                        evidence=match.group(0).strip(),
                        analyzer=self.name,
                    )
                )

        # ------------------------------------------------------------------
        # Protected-path check: any absolute path in the command that falls
        # under a configured protected path triggers an additional signal.
        # ------------------------------------------------------------------
        if context.config and context.config.protected_paths:
            target_paths = _PATH_EXTRACT_RE.findall(command)
            for target in target_paths:
                for protected in context.config.protected_paths:
                    if is_path_under(target, protected):
                        signals.append(
                            RiskSignal(
                                category=RiskCategory.DESTRUCTIVE_FS,
                                score=80,
                                weight=0.9,
                                description=f"Operation targets protected path: {protected}",
                                evidence=target,
                                analyzer=self.name,
                            )
                        )
                        break  # one signal per target path is enough

        return signals
