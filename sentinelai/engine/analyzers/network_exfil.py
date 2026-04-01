"""Network exfiltration analyzer.

Detects commands that transmit data to external destinations, including
outbound HTTP uploads, netcat listeners, reverse connections, /dev/tcp
abuse, and encoded-data exfiltration via curl or nc.
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
    # base64 piped to curl (encoded exfiltration)
    _Pattern(
        regex=re.compile(
            r"base64\b.*\|\s*(?:curl|wget)\b"
            r"|(?:curl|wget)\b.*\|\s*base64\b",
            re.IGNORECASE,
        ),
        score=85,
        weight=0.9,
        description="Base64-encoded data piped to HTTP client (likely exfiltration)",
    ),
    # tar piped to curl or nc (archive exfiltration)
    _Pattern(
        regex=re.compile(
            r"\btar\b.*\|\s*(?:curl|nc|ncat|netcat)\b",
            re.IGNORECASE,
        ),
        score=80,
        weight=0.9,
        description="Tar archive piped to network tool (bulk data exfiltration)",
    ),
    # Sensitive file content piped to curl/wget (cat ~/.ssh/* | curl ...)
    _Pattern(
        regex=re.compile(
            r"\b(?:cat|less|more|head|tail)\s+[^\|]*"
            r"(?:~\/\.ssh|~\/\.aws|~\/\.gnupg|/etc/shadow|/etc/passwd|\.env\b)"
            r"[^\|]*\|\s*(?:curl|wget|nc|ncat|netcat)\b",
            re.IGNORECASE,
        ),
        score=80,
        weight=0.9,
        description="Sensitive file content piped to network tool",
    ),
    # curl/wget uploading sensitive file via -d @file or --data @file
    _Pattern(
        regex=re.compile(
            r"\b(?:curl|wget)\b[^|;&]*(?:-d\s*@|--data(?:-\w+)?\s*@|--upload-file\s+)"
            r"[^\s|;&]*(?:~\/\.ssh|~\/\.aws|~\/\.gnupg|/etc/shadow|/etc/passwd"
            r"|\.env\b|id_rsa|id_ed25519|credentials|\.pem\b|\.key\b)",
            re.IGNORECASE,
        ),
        score=90,
        weight=1.0,
        description="Curl/wget uploading sensitive file (direct exfiltration)",
    ),
    # /dev/tcp usage (bash built-in network redirection)
    _Pattern(
        regex=re.compile(r"/dev/tcp/", re.IGNORECASE),
        score=80,
        weight=0.9,
        description="Bash /dev/tcp network redirection detected",
    ),
    # nc/netcat listener (-l flag)
    _Pattern(
        regex=re.compile(
            r"\b(?:nc|ncat|netcat)\b[^|;&]*\s-[a-zA-Z]*l",
            re.IGNORECASE,
        ),
        score=70,
        weight=0.8,
        description="Netcat listener detected (potential data receiver)",
    ),
    # python -c with socket (scripted network access)
    _Pattern(
        regex=re.compile(
            r"\bpython[23]?\s+-c\s+.*\bsocket\b",
            re.IGNORECASE,
        ),
        score=60,
        weight=0.7,
        description="Python one-liner with socket module (scripted network access)",
    ),
    # curl -X POST or curl with --data/-d (HTTP upload)
    _Pattern(
        regex=re.compile(
            r"\bcurl\b[^\|;]*(?:-X\s*POST|--data(?:-\w+)?[\s=]|-d\s)",
            re.IGNORECASE,
        ),
        score=50,
        weight=0.7,
        description="Curl POST request or data upload detected",
    ),
    # nc/netcat outbound (no -l flag)
    _Pattern(
        regex=re.compile(
            r"\b(?:nc|ncat|netcat)\b(?![^|;&]*\s-[a-zA-Z]*l)",
            re.IGNORECASE,
        ),
        score=50,
        weight=0.7,
        description="Netcat outbound connection detected",
    ),
    # scp/rsync to remote host
    _Pattern(
        regex=re.compile(
            r"\b(?:scp|rsync)\b[^\|;]*\S+@\S+:",
            re.IGNORECASE,
        ),
        score=40,
        weight=0.6,
        description="SCP/rsync transfer to remote host",
    ),
]

# Pattern to extract hostnames/domains from a command.
_DOMAIN_EXTRACT_RE = re.compile(
    r"(?:https?://|@)([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+)"
)


class NetworkExfilAnalyzer(BaseAnalyzer):
    """Analyzes commands for network exfiltration indicators.

    Checks for outbound HTTP uploads, netcat listeners and connections,
    /dev/tcp abuse, sensitive-file piping, archive exfiltration, and
    transfers to blacklisted domains.
    """

    @property
    def name(self) -> str:
        return "network_exfiltration"

    @property
    def category(self) -> RiskCategory:
        return RiskCategory.NETWORK_EXFILTRATION

    def analyze(self, command: str, context: AnalysisContext) -> List[RiskSignal]:
        """Return risk signals for network exfiltration patterns in *command*."""
        signals: List[RiskSignal] = []

        for pattern in _PATTERNS:
            match = pattern.regex.search(command)
            if match:
                signals.append(
                    RiskSignal(
                        category=RiskCategory.NETWORK_EXFILTRATION,
                        score=pattern.score,
                        weight=pattern.weight,
                        description=pattern.description,
                        evidence=match.group(0).strip(),
                        analyzer=self.name,
                    )
                )

        # ------------------------------------------------------------------
        # Blacklisted-domain check: any domain in the command that appears
        # in the configured blacklist triggers an additional signal.
        # ------------------------------------------------------------------
        if context.config and context.config.blacklist.domains:
            found_domains = _DOMAIN_EXTRACT_RE.findall(command)
            blacklisted = {d.lower() for d in context.config.blacklist.domains}
            for domain in found_domains:
                if domain.lower() in blacklisted:
                    signals.append(
                        RiskSignal(
                            category=RiskCategory.NETWORK_EXFILTRATION,
                            score=75,
                            weight=0.9,
                            description=f"Communication with blacklisted domain: {domain}",
                            evidence=domain,
                            analyzer=self.name,
                        )
                    )

        return signals
