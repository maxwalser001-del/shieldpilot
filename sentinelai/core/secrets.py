"""Secrets masking utility.

Compiles regex patterns from config and replaces matches with [REDACTED].
Applied to all data before it reaches persistent storage.
"""

from __future__ import annotations

import re
from typing import List, Optional, Pattern


# Default patterns used when no config patterns are provided
DEFAULT_PATTERNS = [
    r'(?i)(api[_-]?key|secret|password|token|credential)\s*[=:]\s*[\'"]?[A-Za-z0-9+/=]{16,}',
    r'AKIA[0-9A-Z]{16}',
    r'sk-[a-zA-Z0-9]{20,}',
    r'ghp_[a-zA-Z0-9]{36}',
    r'(?i)bearer\s+[a-zA-Z0-9._\-]{20,}',
]

REDACTED = "[REDACTED]"


class SecretsMasker:
    """Masks sensitive values in text using configurable regex patterns.

    Usage:
        masker = SecretsMasker(patterns=config.secrets_patterns)
        safe_text = masker.mask(potentially_sensitive_text)
    """

    def __init__(self, patterns: Optional[List[str]] = None):
        raw_patterns = patterns or DEFAULT_PATTERNS
        self._compiled: List[Pattern] = []
        for p in raw_patterns:
            try:
                self._compiled.append(re.compile(p))
            except re.error:
                # Skip invalid patterns rather than crashing
                continue

    def mask(self, text: str) -> str:
        """Replace all secret patterns in text with [REDACTED]."""
        if not text:
            return text
        result = text
        for pattern in self._compiled:
            result = pattern.sub(REDACTED, result)
        return result

    def contains_secret(self, text: str) -> bool:
        """Check if text contains any secret patterns."""
        if not text:
            return False
        for pattern in self._compiled:
            if pattern.search(text):
                return True
        return False
