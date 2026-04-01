"""Privilege escalation analyzer.

Detects commands that attempt to gain elevated privileges, modify
authentication/authorisation files, load kernel modules, or set
dangerous file capabilities.
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


# A set of commands considered dangerous when run via sudo.
_DANGEROUS_SUDO_CMDS = re.compile(
    r"\bsudo\s+(?:"
    r"rm\b|chmod\b|chown\b|dd\b|mkfs\b|fdisk\b|mount\b|umount\b"
    r"|iptables\b|systemctl\b|service\b|kill\b|pkill\b|reboot\b"
    r"|shutdown\b|init\b|telinit\b|bash\b|sh\b|zsh\b|python\b"
    r"|perl\b|ruby\b|tee\b|vi\b|vim\b|nano\b|cat\b"
    r")"
)

# ---------------------------------------------------------------------------
# Compiled patterns ordered from most to least severe.
# ---------------------------------------------------------------------------

_PATTERNS: List[_Pattern] = [
    # Writing to /etc/sudoers
    _Pattern(
        regex=re.compile(r"(?:>\s*|tee\s+(?:-a\s+)?|cp\s+\S+\s+|mv\s+\S+\s+|chmod\s+\S+\s+|vi(?:m)?\s+|nano\s+)/etc/sudoers\b"),
        score=95,
        weight=1.0,
        description="Attempt to modify /etc/sudoers",
    ),
    _Pattern(
        regex=re.compile(r"\bvisudo\b"),
        score=95,
        weight=1.0,
        description="sudoers editing via visudo",
    ),
    # Writing to /etc/passwd
    _Pattern(
        regex=re.compile(r"(?:>\s*|tee\s+(?:-a\s+)?|cp\s+\S+\s+|mv\s+\S+\s+|vi(?:m)?\s+|nano\s+)/etc/passwd\b"),
        score=90,
        weight=1.0,
        description="Attempt to modify /etc/passwd",
    ),
    # chmod u+s (setuid bit)
    _Pattern(
        regex=re.compile(r"\bchmod\s+[0-7]*[4-7][0-7]{2}\b|\bchmod\s+u\+s\b"),
        score=80,
        weight=0.9,
        description="Setting setuid bit on a file",
    ),
    # setcap
    _Pattern(
        regex=re.compile(r"\bsetcap\b"),
        score=75,
        weight=0.8,
        description="Setting file capabilities via setcap",
    ),
    # Kernel module loading
    _Pattern(
        regex=re.compile(r"\b(?:insmod|modprobe)\b"),
        score=70,
        weight=0.8,
        description="Kernel module loading detected",
    ),
    # sudo with dangerous commands
    _Pattern(
        regex=_DANGEROUS_SUDO_CMDS,
        score=70,
        weight=0.8,
        description="sudo invoked with a dangerous command",
    ),
    # su - / su root
    _Pattern(
        regex=re.compile(r"\bsu\s+(?:-\s*$|-\s+root\b|root\b)", re.MULTILINE),
        score=60,
        weight=0.7,
        description="Switching to root user via su",
    ),
    # chown root
    _Pattern(
        regex=re.compile(r"\bchown\s+(?:\S+:)?root\b|\bchown\s+root\b"),
        score=60,
        weight=0.7,
        description="Changing file ownership to root",
    ),
    # pkexec
    _Pattern(
        regex=re.compile(r"\bpkexec\b"),
        score=60,
        weight=0.7,
        description="pkexec privilege escalation utility detected",
    ),
    # Plain sudo (catch-all, lower score)
    _Pattern(
        regex=re.compile(r"\bsudo\b"),
        score=30,
        weight=0.5,
        description="Command executed with sudo",
    ),
]


class PrivilegeEscalationAnalyzer(BaseAnalyzer):
    """Analyzes commands for privilege escalation attempts.

    Checks for sudo misuse, user switching to root, setuid bit changes,
    modifications to ``/etc/passwd`` or ``/etc/sudoers``, kernel module
    loading, capability assignment, and pkexec usage.
    """

    @property
    def name(self) -> str:
        return "privilege_escalation"

    @property
    def category(self) -> RiskCategory:
        return RiskCategory.PRIVILEGE_ESCALATION

    def analyze(self, command: str, context: AnalysisContext) -> List[RiskSignal]:
        """Return risk signals for privilege escalation patterns in *command*."""
        signals: List[RiskSignal] = []
        matched_descriptions: set[str] = set()

        for pattern in _PATTERNS:
            match = pattern.regex.search(command)
            if match:
                # Avoid duplicate signals when a more specific pattern
                # already fired (e.g. "sudo rm" matches both the dangerous-
                # sudo pattern and the plain-sudo catch-all).
                if pattern.description in matched_descriptions:
                    continue
                matched_descriptions.add(pattern.description)

                signals.append(
                    RiskSignal(
                        category=RiskCategory.PRIVILEGE_ESCALATION,
                        score=pattern.score,
                        weight=pattern.weight,
                        description=pattern.description,
                        evidence=match.group(0).strip(),
                        analyzer=self.name,
                    )
                )

                # If we already matched the specific dangerous-sudo pattern,
                # suppress the generic sudo catch-all.
                if pattern.description == "sudo invoked with a dangerous command":
                    matched_descriptions.add("Command executed with sudo")

        return signals
