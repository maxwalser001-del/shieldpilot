"""Credential access analyzer.

Detects commands that read, copy, or exfiltrate credentials and secrets
from well-known locations such as SSH keys, AWS credentials, GPG
keyrings, environment variables, .env files, macOS Keychain, and
browser credential stores.
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
# Compiled regex patterns ordered from most to least severe.
# ---------------------------------------------------------------------------

_PATTERNS: List[_Pattern] = [
    # /etc/shadow access (highest severity -- password hashes)
    _Pattern(
        regex=re.compile(
            r"\b(?:cat|less|more|head|tail|cp|mv|scp|rsync|vi|vim|nano|grep)\b"
            r"[^|;&]*\b/etc/shadow\b",
            re.IGNORECASE,
        ),
        score=90,
        weight=1.0,
        description="Reading /etc/shadow (password hashes)",
    ),
    # AWS credentials
    _Pattern(
        regex=re.compile(
            r"\b(?:cat|less|more|head|tail|cp|mv|grep)\b"
            r"[^|;&]*~\/\.aws\/(?:credentials|config)\b",
            re.IGNORECASE,
        ),
        score=85,
        weight=0.9,
        description="Reading AWS credentials or config file",
    ),
    # SSH private keys and authorized_keys
    _Pattern(
        regex=re.compile(
            r"\b(?:cat|less|more|head|tail|cp|mv|scp|rsync|grep)\b"
            r"[^|;&]*~\/\.ssh\/(?:id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys)\b",
            re.IGNORECASE,
        ),
        score=80,
        weight=0.9,
        description="Reading SSH key or authorized_keys file",
    ),
    # SSH directory wildcard (cat ~/.ssh/*)
    _Pattern(
        regex=re.compile(
            r"\b(?:cat|less|more|head|tail|cp|mv|grep)\b"
            r"[^|;&]*~\/\.ssh\/\*",
            re.IGNORECASE,
        ),
        score=80,
        weight=0.9,
        description="Reading all files in SSH directory",
    ),
    # GPG keyring
    _Pattern(
        regex=re.compile(
            r"\b(?:cat|less|more|head|tail|cp|mv|grep)\b"
            r"[^|;&]*~\/\.gnupg\/",
            re.IGNORECASE,
        ),
        score=75,
        weight=0.8,
        description="Reading GPG keyring files",
    ),
    # Browser credential stores (Chrome/Firefox)
    _Pattern(
        regex=re.compile(
            r"\b(?:cat|cp|sqlite3|strings)\b[^|;&]*(?:"
            r"(?:\.config/google-chrome|Library/Application\s*Support/Google/Chrome)"
            r"[^|;&]*(?:Login\s*Data|Cookies|Web\s*Data)"
            r"|(?:\.mozilla/firefox|Library/Application\s*Support/Firefox)"
            r"[^|;&]*(?:logins\.json|cookies\.sqlite|key[34]\.db)"
            r")",
            re.IGNORECASE,
        ),
        score=75,
        weight=0.8,
        description="Accessing browser credential/cookie store",
    ),
    # macOS Keychain access
    _Pattern(
        regex=re.compile(
            r"\bsecurity\s+find-generic-password\b",
            re.IGNORECASE,
        ),
        score=70,
        weight=0.8,
        description="macOS Keychain credential extraction",
    ),
    # .env file reading
    _Pattern(
        regex=re.compile(
            r"\b(?:cat|less|more|head|tail|cp|mv|grep|source|\.)\b"
            r"[^|;&]*\.env\b",
            re.IGNORECASE,
        ),
        score=60,
        weight=0.7,
        description="Reading .env file (may contain secrets)",
    ),
    # git credential helpers
    _Pattern(
        regex=re.compile(
            r"\bgit\s+(?:credential(?:\s+\w+)?|config\s+[^|;&]*credential)\b",
            re.IGNORECASE,
        ),
        score=50,
        weight=0.7,
        description="Git credential access or configuration",
    ),
    # Full environment variable dump
    _Pattern(
        regex=re.compile(
            r"(?:^|\s|;|&&|\|)\s*(?:env|printenv)\s*(?:$|\s*[;|>&])"
            r"|(?:^|\s|;|&&|\|)\s*export\s+-p\b",
            re.IGNORECASE,
        ),
        score=40,
        weight=0.6,
        description="Full environment variable dump (may expose secrets)",
    ),
]


class CredentialAccessAnalyzer(BaseAnalyzer):
    """Analyzes commands for credential access indicators.

    Checks for reads of SSH keys, AWS credentials, GPG keyrings,
    /etc/shadow, .env files, git credentials, macOS Keychain, browser
    stores, and full environment dumps.
    """

    @property
    def name(self) -> str:
        return "credential_access"

    @property
    def category(self) -> RiskCategory:
        return RiskCategory.CREDENTIAL_ACCESS

    def analyze(self, command: str, context: AnalysisContext) -> List[RiskSignal]:
        """Return risk signals for credential access patterns in *command*."""
        signals: List[RiskSignal] = []

        for pattern in _PATTERNS:
            match = pattern.regex.search(command)
            if match:
                signals.append(
                    RiskSignal(
                        category=RiskCategory.CREDENTIAL_ACCESS,
                        score=pattern.score,
                        weight=pattern.weight,
                        description=pattern.description,
                        evidence=match.group(0).strip(),
                        analyzer=self.name,
                    )
                )

        return signals
