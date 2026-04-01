"""Obfuscation analyzer.

Detects commands that employ obfuscation techniques to hide their true
intent, including base64-decode-and-execute, eval with encoded input,
hex escapes, string reversal, excessive piping, nested subshells,
history tampering, and high Shannon entropy strings.
"""

from __future__ import annotations

import math
import re
from collections import Counter
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
    # base64 -d piped to sh/bash (decode-and-execute)
    _Pattern(
        regex=re.compile(
            r"\bbase64\s+(?:-d|--decode)\b.*\|\s*(?:ba)?sh\b"
            r"|\bbase64\s+(?:-d|--decode)\b.*\|\s*bash\b",
            re.IGNORECASE,
        ),
        score=70,
        weight=0.8,
        description="Base64 decode piped to shell execution",
    ),
    # history tampering (anti-forensics)
    _Pattern(
        regex=re.compile(
            r"\bhistory\s+-c\b"
            r"|\bunset\s+HISTFILE\b"
            r"|\bHISTSIZE\s*=\s*0\b"
            r"|\bHISTFILESIZE\s*=\s*0\b"
            r"|\bexport\s+HISTFILE\s*=\s*/dev/null\b",
            re.IGNORECASE,
        ),
        score=60,
        weight=0.8,
        description="Shell history tampering detected (anti-forensics)",
    ),
    # eval with variable or encoded input
    _Pattern(
        regex=re.compile(
            r"\beval\b\s+(?:\$[\({]|\".*\$|'.*\$|\$\w+|`)",
            re.IGNORECASE,
        ),
        score=60,
        weight=0.7,
        description="Eval with variable or encoded input",
    ),
    # $'\x41' hex escape sequences
    _Pattern(
        regex=re.compile(
            r"\$'(?:[^']*\\x[0-9a-fA-F]{2}){2,}",
        ),
        score=50,
        weight=0.7,
        description="Hex escape sequences in string literal",
    ),
    # python/perl -e with exec/eval
    _Pattern(
        regex=re.compile(
            r"\b(?:python[23]?|perl)\s+-[a-zA-Z]*e[a-zA-Z]*\s+['\"].*\b(?:exec|eval)\b",
            re.IGNORECASE,
        ),
        score=45,
        weight=0.6,
        description="Python/Perl one-liner with exec/eval",
    ),
    # rev command (string reversal for obfuscation)
    _Pattern(
        regex=re.compile(
            r"\brev\b",
            re.IGNORECASE,
        ),
        score=40,
        weight=0.6,
        description="String reversal via rev (potential obfuscation)",
    ),
    # Nested subshells $( $( )) or backtick nesting
    _Pattern(
        regex=re.compile(
            r"\$\([^)]*\$\(",
        ),
        score=35,
        weight=0.5,
        description="Nested subshell execution detected",
    ),
    # More than 3 pipes (excessive piping)
    _Pattern(
        regex=re.compile(
            r"(?:[^|]\|(?!\|)[^|]*){4,}",
        ),
        score=30,
        weight=0.5,
        description="Excessive piping (>3 pipes) may indicate obfuscation",
    ),
]

# Threshold for Shannon entropy flagging.
_ENTROPY_THRESHOLD = 4.5


def _shannon_entropy(text: str) -> float:
    """Calculate the Shannon entropy of *text*.

    Uses the standard formula: -sum(p * log2(p)) over the frequency of
    each character.  Returns 0.0 for empty strings.
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )
    return entropy


class ObfuscationAnalyzer(BaseAnalyzer):
    """Analyzes commands for obfuscation techniques.

    Checks for base64-decode-and-execute, eval abuse, hex escapes,
    string reversal, excessive piping, nested subshells, history
    tampering, scripted exec/eval, and high Shannon entropy.
    """

    @property
    def name(self) -> str:
        return "obfuscation"

    @property
    def category(self) -> RiskCategory:
        return RiskCategory.OBFUSCATION

    def analyze(self, command: str, context: AnalysisContext) -> List[RiskSignal]:
        """Return risk signals for obfuscation patterns in *command*."""
        signals: List[RiskSignal] = []

        for pattern in _PATTERNS:
            match = pattern.regex.search(command)
            if match:
                signals.append(
                    RiskSignal(
                        category=RiskCategory.OBFUSCATION,
                        score=pattern.score,
                        weight=pattern.weight,
                        description=pattern.description,
                        evidence=match.group(0).strip(),
                        analyzer=self.name,
                    )
                )

        # ------------------------------------------------------------------
        # Shannon entropy check: high entropy may indicate encoded or
        # obfuscated payloads embedded in the command.
        # ------------------------------------------------------------------
        entropy = _shannon_entropy(command)
        if entropy > _ENTROPY_THRESHOLD:
            signals.append(
                RiskSignal(
                    category=RiskCategory.OBFUSCATION,
                    score=35,
                    weight=0.5,
                    description=f"High Shannon entropy ({entropy:.2f}) suggests obfuscated content",
                    evidence=f"entropy={entropy:.2f} (threshold={_ENTROPY_THRESHOLD})",
                    analyzer=self.name,
                )
            )

        return signals
