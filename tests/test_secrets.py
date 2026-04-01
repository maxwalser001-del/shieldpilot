"""Tests for secrets masking."""

from __future__ import annotations

import pytest

from sentinelai.core.secrets import SecretsMasker, REDACTED


class TestSecretsMasker:
    """Test secret pattern detection and masking."""

    def test_mask_aws_key(self):
        masker = SecretsMasker()
        text = "AWS key: AKIAIOSFODNN7EXAMPLE"
        result = masker.mask(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert REDACTED in result

    def test_mask_openai_key(self):
        masker = SecretsMasker()
        text = "key=sk-abcdefghijklmnopqrstuvwxyz1234567890"
        result = masker.mask(text)
        assert "sk-abcdefghijklmnopqrstuvwxyz1234567890" not in result

    def test_mask_github_pat(self):
        masker = SecretsMasker()
        text = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        result = masker.mask(text)
        assert "ghp_" not in result

    def test_no_false_positive_on_normal_text(self):
        masker = SecretsMasker()
        text = "This is a normal log message with no secrets"
        result = masker.mask(text)
        assert result == text

    def test_empty_string(self):
        masker = SecretsMasker()
        assert masker.mask("") == ""
        assert masker.mask(None) is None

    def test_contains_secret(self):
        masker = SecretsMasker()
        assert masker.contains_secret("AKIAIOSFODNN7EXAMPLE") is True
        assert masker.contains_secret("normal text") is False

    def test_custom_patterns(self):
        masker = SecretsMasker(patterns=[r"SECRET_\d{4}"])
        assert masker.contains_secret("my SECRET_1234 here") is True
        result = masker.mask("my SECRET_1234 here")
        assert "SECRET_1234" not in result

    def test_invalid_pattern_skipped(self):
        """Invalid regex patterns are silently skipped."""
        masker = SecretsMasker(patterns=[r"[invalid", r"valid_\d+"])
        assert masker.contains_secret("valid_123") is True

    def test_multiple_secrets_in_one_text(self):
        masker = SecretsMasker()
        text = "key1=AKIAIOSFODNN7EXAMPLE key2=sk-abcdefghijklmnopqrstuvwxyz"
        result = masker.mask(text)
        assert "AKIA" not in result
        assert "sk-" not in result
