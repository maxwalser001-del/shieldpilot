"""Output validation for LLM responses and API outputs.

Detects system prompt leakage, API key exposure, and other
sensitive information in model outputs before they reach users.
Also provides HTML escaping for XSS prevention.
"""

from __future__ import annotations

import html
import re
from typing import List


# Maximum response length
MAX_RESPONSE_LENGTH = 50_000

# Patterns that indicate sensitive information leakage
_LEAKAGE_PATTERNS = [
    re.compile(r'SYSTEM\s*[:]\s*You\s+are', re.IGNORECASE),
    re.compile(r'(?:API[_\s]?KEY|SECRET[_\s]?KEY|ACCESS[_\s]?TOKEN)\s*[=:]\s*\S{8,}', re.IGNORECASE),
    re.compile(r'instructions?\s*:\s*\d+\.', re.IGNORECASE),
    re.compile(r'system\s*prompt\s*[:=]', re.IGNORECASE),
    re.compile(r'(?:password|passwd|secret)\s*[=:]\s*\S{4,}', re.IGNORECASE),
    re.compile(r'AKIA[0-9A-Z]{16}'),  # AWS key
    re.compile(r'sk-[a-zA-Z0-9]{20,}'),  # OpenAI key
    re.compile(r'ghp_[a-zA-Z0-9]{36}'),  # GitHub token
    re.compile(r'Bearer\s+[a-zA-Z0-9._\-]{20,}', re.IGNORECASE),
]

# Dangerous HTML tags to strip from output
_DANGEROUS_HTML = re.compile(
    r'<\s*(?:script|iframe|object|embed|form|input|button|meta|link|base|svg|math)'
    r'[^>]*>.*?</\s*(?:script|iframe|object|embed|form|input|button|meta|link|base|svg|math)\s*>|'
    r'<\s*(?:script|iframe|object|embed|form|input|button|meta|link|base|svg|math)[^>]*/?\s*>|'
    r'<\s*img\s+[^>]*src\s*=\s*["\']?(?:javascript:|data:)[^>]*>',
    re.IGNORECASE | re.DOTALL,
)

# Event handlers in HTML attributes
_EVENT_HANDLERS = re.compile(
    r'\bon\w+\s*=\s*["\'][^"\']*["\']',
    re.IGNORECASE,
)

SECURITY_RESPONSE = "I cannot provide that information for security reasons."


class OutputValidator:
    """Validate and sanitize LLM outputs.

    Checks for:
    - System prompt leakage
    - API key / credential exposure
    - Instruction list leakage
    - Excessive response length
    - Dangerous HTML/XSS content
    """

    def validate_output(self, output: str) -> bool:
        """Check if output contains suspicious leakage patterns.

        Returns True if the output is safe, False if leakage is detected.
        """
        if not output:
            return True

        if len(output) > MAX_RESPONSE_LENGTH:
            return False

        for pattern in _LEAKAGE_PATTERNS:
            if pattern.search(output):
                return False

        return True

    def get_leakage_details(self, output: str) -> List[str]:
        """Return descriptions of all leakage patterns found."""
        details = []
        if not output:
            return details

        if len(output) > MAX_RESPONSE_LENGTH:
            details.append(f"Response exceeds maximum length ({len(output)} > {MAX_RESPONSE_LENGTH})")

        for pattern in _LEAKAGE_PATTERNS:
            match = pattern.search(output)
            if match:
                details.append(f"Leakage pattern detected: {pattern.pattern[:60]}...")

        return details

    def filter_response(self, response: str) -> str:
        """Filter a response, replacing it if leakage is detected."""
        if not self.validate_output(response):
            return SECURITY_RESPONSE
        return response

    @staticmethod
    def escape_html(text: str) -> str:
        """Escape HTML special characters to prevent XSS.

        Converts <, >, &, ", ' to their HTML entity equivalents.
        """
        if not text:
            return text
        return html.escape(text, quote=True)

    @staticmethod
    def strip_dangerous_html(text: str) -> str:
        """Remove dangerous HTML tags and event handlers.

        Strips <script>, <iframe>, <img src=javascript:>, onclick=, etc.
        """
        if not text:
            return text
        result = _DANGEROUS_HTML.sub('', text)
        result = _EVENT_HANDLERS.sub('', result)
        return result

    def sanitize_for_display(self, text: str) -> str:
        """Full sanitization pipeline for user-facing output.

        Strips dangerous HTML, then escapes remaining special chars.
        """
        if not text:
            return text
        result = self.strip_dangerous_html(text)
        result = self.escape_html(result)
        return result
