"""Persistence mechanism analyzer.

Detects commands that install persistence mechanisms such as cron jobs,
systemd services, shell profile modifications, SSH authorized_keys
manipulation, macOS LaunchAgent/LaunchDaemon loading, and at/batch
job scheduling.
"""

from __future__ import annotations

import re
from typing import List, NamedTuple

from sentinelai.core.constants import RiskCategory
from sentinelai.core.models import RiskSignal
from sentinelai.engine.base import AnalysisContext, BaseAnalyzer


class _Pattern(NamedTuple):
    """Internal descriptor for a compiled regex and its associated risk metadata."""

    regex: re.Pattern[str]
    score: int
    weight: float
    description: str


# ---------------------------------------------------------------------------
# Compiled regex patterns for persistence mechanism detection.
# ---------------------------------------------------------------------------

_PATTERNS: List[_Pattern] = [
    # SSH authorized_keys modification  (highest risk — grants remote access)
    _Pattern(
        regex=re.compile(
            r"(?:>>?\s*~?/?(?:\.ssh|home/\S+/\.ssh)/authorized_keys"
            r"|tee\s+.*authorized_keys"
            r"|cp\s+\S+\s+\S*authorized_keys"
            r"|echo\s+.*>>?\s*\S*authorized_keys)",
            re.IGNORECASE,
        ),
        score=80,
        weight=0.9,
        description="SSH authorized_keys modification detected",
    ),
    # Writing/appending to crontab via echo, redirection, or piping
    _Pattern(
        regex=re.compile(
            r"(?:echo\s+.*\|\s*crontab"
            r"|>>?\s*/(?:var/spool/cron|etc/cron)"
            r"|printf\s+.*\|\s*crontab)",
            re.IGNORECASE,
        ),
        score=70,
        weight=0.8,
        description="Crontab write via echo/redirect detected",
    ),
    # /etc/rc.local modification
    _Pattern(
        regex=re.compile(
            r"(?:>>?\s*/etc/rc\.local"
            r"|tee\s+.*(?:-a\s+)?/etc/rc\.local"
            r"|echo\s+.*>>?\s*/etc/rc\.local"
            r"|chmod\s+\+x\s+/etc/rc\.local)",
            re.IGNORECASE,
        ),
        score=70,
        weight=0.8,
        description="/etc/rc.local persistence mechanism detected",
    ),
    # systemctl enable / systemd service creation
    _Pattern(
        regex=re.compile(
            r"(?:\bsystemctl\s+enable\b"
            r"|>>?\s*/etc/systemd/system/\S+\.service"
            r"|cp\s+\S+\s+/etc/systemd/system/"
            r"|tee\s+.*(?:-a\s+)?/etc/systemd/system/)",
            re.IGNORECASE,
        ),
        score=65,
        weight=0.7,
        description="Systemd service persistence mechanism detected",
    ),
    # macOS launchctl load / LaunchAgents / LaunchDaemons
    _Pattern(
        regex=re.compile(
            r"(?:\blaunchctl\s+load\b"
            r"|>>?\s*~/Library/LaunchAgents/"
            r"|>>?\s*/Library/Launch(?:Agents|Daemons)/"
            r"|cp\s+\S+\s+\S*Library/Launch(?:Agents|Daemons)/"
            r"|tee\s+.*Library/Launch(?:Agents|Daemons)/)",
            re.IGNORECASE,
        ),
        score=65,
        weight=0.7,
        description="macOS LaunchAgent/LaunchDaemon persistence detected",
    ),
    # crontab -e or direct crontab invocation for editing
    _Pattern(
        regex=re.compile(
            r"\bcrontab\s+(?:-[a-zA-Z]*e|-[a-zA-Z]*l|\S+)",
            re.IGNORECASE,
        ),
        score=60,
        weight=0.7,
        description="Crontab modification detected",
    ),
    # Writing to shell profile files (.bashrc, .bash_profile, .zshrc, .profile)
    _Pattern(
        regex=re.compile(
            r"(?:>>?\s*~?/?(?:\.bashrc|\.bash_profile|\.zshrc|\.profile)"
            r"|tee\s+.*(?:\.bashrc|\.bash_profile|\.zshrc|\.profile)"
            r"|echo\s+.*>>?\s*\S*(?:\.bashrc|\.bash_profile|\.zshrc|\.profile))",
            re.IGNORECASE,
        ),
        score=55,
        weight=0.7,
        description="Shell profile modification detected (startup persistence)",
    ),
    # at / batch job scheduling
    _Pattern(
        regex=re.compile(
            r"(?:\bat\s+(?:now|\d|midnight|noon|teatime)"
            r"|\bbatch\b"
            r"|echo\s+.*\|\s*at\b)",
            re.IGNORECASE,
        ),
        score=50,
        weight=0.6,
        description="Scheduled at/batch job creation detected",
    ),
]


class PersistenceAnalyzer(BaseAnalyzer):
    """Analyzes commands for persistence mechanism installation.

    Checks for crontab manipulation, systemd service creation, shell
    profile writes, rc.local modification, macOS LaunchAgent/LaunchDaemon
    loading, SSH authorized_keys modification, and at/batch job scheduling.
    """

    @property
    def name(self) -> str:
        return "persistence"

    @property
    def category(self) -> RiskCategory:
        return RiskCategory.PERSISTENCE

    def analyze(self, command: str, context: AnalysisContext) -> List[RiskSignal]:
        """Return risk signals for persistence mechanism patterns in *command*."""
        signals: List[RiskSignal] = []

        for pattern in _PATTERNS:
            match = pattern.regex.search(command)
            if match:
                signals.append(
                    RiskSignal(
                        category=RiskCategory.PERSISTENCE,
                        score=pattern.score,
                        weight=pattern.weight,
                        description=pattern.description,
                        evidence=match.group(0).strip(),
                        analyzer=self.name,
                    )
                )

        return signals
