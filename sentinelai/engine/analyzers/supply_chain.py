"""Supply chain analyzer.

Detects commands that install packages from untrusted sources, use
custom registries, pipe downloads to package managers, install
pre-release packages, and potentially exploit typosquatting of popular
package names.
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
    # curl/wget piped to pip install (remote dropper to package manager)
    _Pattern(
        regex=re.compile(
            r"\b(?:curl|wget)\b[^\|]*\|\s*(?:pip[23]?|pip3?)\s+install\b",
            re.IGNORECASE,
        ),
        score=75,
        weight=0.8,
        description="Remote script piped directly to pip install (supply chain risk)",
    ),
    # pip install from arbitrary URL (not PyPI)
    _Pattern(
        regex=re.compile(
            r"\bpip[23]?\s+install\b[^|;&]*https?://",
            re.IGNORECASE,
        ),
        score=55,
        weight=0.7,
        description="Pip install from direct URL (bypassing PyPI)",
    ),
    # Install from raw.githubusercontent.com specifically
    _Pattern(
        regex=re.compile(
            r"\b(?:pip[23]?|npm|yarn)\s+install\b[^|;&]*raw\.githubusercontent\.com",
            re.IGNORECASE,
        ),
        score=55,
        weight=0.7,
        description="Package install from raw GitHub content (unverified source)",
    ),
    # pip install --index-url (custom registry)
    _Pattern(
        regex=re.compile(
            r"\bpip[23]?\s+install\b[^|;&]*--(?:index-url|extra-index-url)\b",
            re.IGNORECASE,
        ),
        score=50,
        weight=0.6,
        description="Pip install using custom package index (potential dependency confusion)",
    ),
    # npm install from git URL
    _Pattern(
        regex=re.compile(
            r"\bnpm\s+install\b[^|;&]*(?:git(?:\+https?|\+ssh)?://|github:)",
            re.IGNORECASE,
        ),
        score=45,
        weight=0.6,
        description="NPM install from git URL (unverified source)",
    ),
    # npm with postinstall script reference
    _Pattern(
        regex=re.compile(
            r"\bnpm\b[^|;&]*\bpostinstall\b"
            r"|\bnpm\s+run\s+postinstall\b",
            re.IGNORECASE,
        ),
        score=40,
        weight=0.5,
        description="NPM postinstall script execution (common attack vector)",
    ),
    # pip install --pre (pre-release)
    _Pattern(
        regex=re.compile(
            r"\bpip[23]?\s+install\b[^|;&]*--pre\b",
            re.IGNORECASE,
        ),
        score=30,
        weight=0.4,
        description="Pip install with --pre flag (pre-release, less reviewed)",
    ),
]

# ---------------------------------------------------------------------------
# Typosquatting detection
# ---------------------------------------------------------------------------

# Popular packages to check against for typosquatting.
_POPULAR_PACKAGES: List[str] = [
    "requests",
    "flask",
    "django",
    "numpy",
    "pandas",
    "boto3",
    "tensorflow",
    "torch",
    "cryptography",
    "pillow",
    "beautifulsoup4",
    "scrapy",
    "celery",
    "fastapi",
    "sqlalchemy",
]

# Regex to extract package names from pip install commands.
# Matches package names (allowing hyphens and underscores) after `pip install`.
_PIP_PACKAGE_RE = re.compile(
    r"\bpip[23]?\s+install\s+(?:(?:-[^\s]+\s+)*)"  # skip flags
    r"([a-zA-Z0-9](?:[a-zA-Z0-9._-]*[a-zA-Z0-9])?)",
    re.IGNORECASE,
)

# Regex to extract package names from npm install commands.
_NPM_PACKAGE_RE = re.compile(
    r"\bnpm\s+(?:install|i|add)\s+(?:(?:-[^\s]+\s+)*)"
    r"([a-zA-Z0-9](?:[a-zA-Z0-9._-]*[a-zA-Z0-9])?)",
    re.IGNORECASE,
)


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Compute the Levenshtein (edit) distance between two strings.

    Uses the standard dynamic-programming matrix approach.  Implemented
    inline to avoid external library dependencies.
    """
    if len(s1) < len(s2):
        return _levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            # Insertion, deletion, substitution
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (0 if c1 == c2 else 1)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]


class SupplyChainAnalyzer(BaseAnalyzer):
    """Analyzes commands for supply chain attack indicators.

    Checks for installs from untrusted URLs, custom registries,
    piped downloads to package managers, pre-release installs,
    postinstall scripts, and potential typosquatting of popular
    package names.
    """

    @property
    def name(self) -> str:
        return "supply_chain"

    @property
    def category(self) -> RiskCategory:
        return RiskCategory.SUPPLY_CHAIN

    def analyze(self, command: str, context: AnalysisContext) -> List[RiskSignal]:
        """Return risk signals for supply chain patterns in *command*."""
        signals: List[RiskSignal] = []

        for pattern in _PATTERNS:
            match = pattern.regex.search(command)
            if match:
                signals.append(
                    RiskSignal(
                        category=RiskCategory.SUPPLY_CHAIN,
                        score=pattern.score,
                        weight=pattern.weight,
                        description=pattern.description,
                        evidence=match.group(0).strip(),
                        analyzer=self.name,
                    )
                )

        # ------------------------------------------------------------------
        # Typosquatting check: extract package names from pip/npm install
        # commands and compare against popular packages using Levenshtein
        # distance.  A distance of 1-2 (but not 0, which is an exact
        # match) triggers a signal.
        # ------------------------------------------------------------------
        installed_packages: List[str] = []

        for pip_match in _PIP_PACKAGE_RE.finditer(command):
            installed_packages.append(pip_match.group(1).lower())

        for npm_match in _NPM_PACKAGE_RE.finditer(command):
            installed_packages.append(npm_match.group(1).lower())

        for pkg_name in installed_packages:
            for popular in _POPULAR_PACKAGES:
                distance = _levenshtein_distance(pkg_name, popular)
                if 1 <= distance <= 2:
                    signals.append(
                        RiskSignal(
                            category=RiskCategory.SUPPLY_CHAIN,
                            score=65,
                            weight=0.8,
                            description=(
                                f"Possible typosquatting: '{pkg_name}' is "
                                f"{distance} edit(s) from popular package '{popular}'"
                            ),
                            evidence=pkg_name,
                            analyzer=self.name,
                        )
                    )
                    break  # one typosquat warning per installed package

        return signals
