"""Tests for encoding bypass detection patterns.

Verifies that the scanner detects encoded injection attempts via
URL-encoding, HTML entities, Unicode escapes, hex escapes, octal escapes,
and mixed-encoding chains.
"""

from __future__ import annotations

import pytest

from sentinelai.scanner.scanner import PromptScanner


@pytest.fixture
def scanner():
    return PromptScanner()


# ── URL Encoding ─────────────────────────────────────────────────────

class TestURLEncoding:
    """Tests for url_encoded_sequence pattern."""

    def test_detects_url_encoded_ignore(self, scanner):
        # "ignore" → %69%67%6E%6F%72%65
        result = scanner.scan("%69%67%6E%6F%72%65")
        names = [t.pattern_name for t in result.threats]
        assert "url_encoded_sequence" in names

    def test_detects_url_encoded_system(self, scanner):
        # "system" → %73%79%73%74%65%6D
        result = scanner.scan("%73%79%73%74%65%6D")
        names = [t.pattern_name for t in result.threats]
        assert "url_encoded_sequence" in names

    def test_ignores_short_url_encoding(self, scanner):
        # Only 2 encoded chars — should NOT trigger (threshold is 4+)
        result = scanner.scan("%41%42 normal text")
        names = [t.pattern_name for t in result.threats]
        assert "url_encoded_sequence" not in names

    def test_detects_url_encoded_in_context(self, scanner):
        result = scanner.scan("Please run %69%67%6E%6F%72%65 previous instructions")
        names = [t.pattern_name for t in result.threats]
        assert "url_encoded_sequence" in names


# ── HTML Entity Hex ──────────────────────────────────────────────────

class TestHTMLEntityHex:
    """Tests for html_entity_hex pattern."""

    def test_detects_hex_entities(self, scanner):
        # "ign" → &#x49;&#x67;&#x6E;
        result = scanner.scan("&#x49;&#x67;&#x6E;")
        names = [t.pattern_name for t in result.threats]
        assert "html_entity_hex" in names

    def test_detects_longer_hex_entities(self, scanner):
        # "ignore" → &#x69;&#x67;&#x6E;&#x6F;&#x72;&#x65;
        result = scanner.scan("&#x69;&#x67;&#x6E;&#x6F;&#x72;&#x65;")
        names = [t.pattern_name for t in result.threats]
        assert "html_entity_hex" in names

    def test_ignores_single_hex_entity(self, scanner):
        result = scanner.scan("Use &#x41; for A")
        names = [t.pattern_name for t in result.threats]
        assert "html_entity_hex" not in names


# ── HTML Entity Decimal ──────────────────────────────────────────────

class TestHTMLEntityDecimal:
    """Tests for html_entity_decimal pattern."""

    def test_detects_decimal_entities(self, scanner):
        # "ign" → &#73;&#103;&#110;
        result = scanner.scan("&#73;&#103;&#110;")
        names = [t.pattern_name for t in result.threats]
        assert "html_entity_decimal" in names

    def test_detects_longer_decimal_entities(self, scanner):
        # "ignore" → &#105;&#103;&#110;&#111;&#114;&#101;
        result = scanner.scan("&#105;&#103;&#110;&#111;&#114;&#101;")
        names = [t.pattern_name for t in result.threats]
        assert "html_entity_decimal" in names

    def test_ignores_short_decimal_entities(self, scanner):
        result = scanner.scan("Use &#65; for A")
        names = [t.pattern_name for t in result.threats]
        assert "html_entity_decimal" not in names


# ── Unicode Escapes ──────────────────────────────────────────────────

class TestUnicodeEscapes:
    """Tests for unicode_escape_sequence pattern."""

    def test_detects_unicode_escapes(self, scanner):
        # "ign" → \u0049\u0067\u006E
        result = scanner.scan("\\u0049\\u0067\\u006E")
        names = [t.pattern_name for t in result.threats]
        assert "unicode_escape_sequence" in names

    def test_detects_longer_unicode_escapes(self, scanner):
        # "ignore" → \u0069\u0067\u006E\u006F\u0072\u0065
        result = scanner.scan("\\u0069\\u0067\\u006E\\u006F\\u0072\\u0065")
        names = [t.pattern_name for t in result.threats]
        assert "unicode_escape_sequence" in names

    def test_ignores_short_unicode_escape(self, scanner):
        result = scanner.scan("\\u0041 is A")
        names = [t.pattern_name for t in result.threats]
        assert "unicode_escape_sequence" not in names


# ── Hex Escapes ──────────────────────────────────────────────────────

class TestHexEscapes:
    """Tests for hex_escape_sequence pattern."""

    def test_detects_hex_escapes(self, scanner):
        # "ign" → \x69\x67\x6E
        result = scanner.scan("\\x69\\x67\\x6E")
        names = [t.pattern_name for t in result.threats]
        assert "hex_escape_sequence" in names

    def test_detects_longer_hex_escapes(self, scanner):
        # "ignore" → \x69\x67\x6E\x6F\x72\x65
        result = scanner.scan("\\x69\\x67\\x6E\\x6F\\x72\\x65")
        names = [t.pattern_name for t in result.threats]
        assert "hex_escape_sequence" in names

    def test_ignores_single_hex_escape(self, scanner):
        result = scanner.scan("\\x41 is A")
        names = [t.pattern_name for t in result.threats]
        assert "hex_escape_sequence" not in names


# ── Octal Escapes ────────────────────────────────────────────────────

class TestOctalEscapes:
    """Tests for octal_escape_sequence pattern."""

    def test_detects_octal_escapes(self, scanner):
        # "ign" → \111\147\156
        result = scanner.scan("\\111\\147\\156")
        names = [t.pattern_name for t in result.threats]
        assert "octal_escape_sequence" in names

    def test_detects_longer_octal_escapes(self, scanner):
        # "ignore" → \151\147\156\157\162\145
        result = scanner.scan("\\151\\147\\156\\157\\162\\145")
        names = [t.pattern_name for t in result.threats]
        assert "octal_escape_sequence" in names

    def test_ignores_short_octal_escape(self, scanner):
        result = scanner.scan("\\101 is A")
        names = [t.pattern_name for t in result.threats]
        assert "octal_escape_sequence" not in names


# ── Mixed Encoding ───────────────────────────────────────────────────

class TestMixedEncoding:
    """Tests for mixed_encoding_chain pattern."""

    def test_detects_url_plus_unicode(self, scanner):
        result = scanner.scan("%69%67 then \\u006E\\u006F")
        names = [t.pattern_name for t in result.threats]
        assert "mixed_encoding_chain" in names

    def test_detects_html_plus_hex(self, scanner):
        result = scanner.scan("&#x69;&#x67; and \\x6E\\x6F")
        names = [t.pattern_name for t in result.threats]
        assert "mixed_encoding_chain" in names

    def test_detects_triple_mix(self, scanner):
        result = scanner.scan("%69 &#x67; \\u006E")
        names = [t.pattern_name for t in result.threats]
        assert "mixed_encoding_chain" in names

    def test_no_mixed_in_plain_text(self, scanner):
        result = scanner.scan("This is perfectly normal text with no encoding")
        names = [t.pattern_name for t in result.threats]
        assert "mixed_encoding_chain" not in names


# ── Existing patterns still work ─────────────────────────────────────

class TestExistingEncodingPatterns:
    """Regression tests for pre-existing encoding bypass patterns."""

    def test_base64_still_detected(self, scanner):
        payload = "QWxsIHlvdXIgYmFzZSBhcmUgYmVsb25nIHRvIHVzISEh"
        result = scanner.scan(payload)
        names = [t.pattern_name for t in result.threats]
        assert "base64_payload" in names

    def test_rot13_still_detected(self, scanner):
        result = scanner.scan("decode this with rot13 please")
        names = [t.pattern_name for t in result.threats]
        assert "rot13_reference" in names

    def test_bidi_still_detected(self, scanner):
        result = scanner.scan("text \u202e reversed")
        names = [t.pattern_name for t in result.threats]
        assert "bidi_override" in names

    def test_pattern_count_increased(self, scanner):
        """Ensure we now have more patterns than before (was 25, now 32)."""
        from sentinelai.scanner.patterns import PATTERNS
        assert len(PATTERNS) >= 32
