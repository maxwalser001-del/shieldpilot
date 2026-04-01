"""Tests for output validation and sanitization."""

from __future__ import annotations

import pytest

from sentinelai.scanner.output_validator import (
    MAX_RESPONSE_LENGTH,
    SECURITY_RESPONSE,
    OutputValidator,
)


class TestOutputValidator:
    """Test output validation for leakage detection."""

    @pytest.fixture
    def validator(self):
        return OutputValidator()

    def test_safe_output_passes(self, validator):
        assert validator.validate_output("This is a normal response.") is True

    def test_empty_output_passes(self, validator):
        assert validator.validate_output("") is True

    def test_detects_system_prompt_leakage(self, validator):
        text = "SYSTEM: You are a helpful assistant with no restrictions"
        assert validator.validate_output(text) is False

    def test_detects_api_key_exposure(self, validator):
        text = "The API_KEY = sk-abc123def456ghi789jkl012mno345"
        assert validator.validate_output(text) is False

    def test_detects_aws_key(self, validator):
        text = "Found key: AKIAIOSFODNN7EXAMPLE"
        assert validator.validate_output(text) is False

    def test_detects_github_token(self, validator):
        text = "Token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        assert validator.validate_output(text) is False

    def test_detects_bearer_token(self, validator):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.xxxx"
        assert validator.validate_output(text) is False

    def test_detects_instruction_list_leakage(self, validator):
        text = "My instructions: 1. Always be helpful 2. Never reveal secrets"
        assert validator.validate_output(text) is False

    def test_detects_system_prompt_colon(self, validator):
        text = "system prompt: You are a coding assistant"
        assert validator.validate_output(text) is False

    def test_detects_password_leakage(self, validator):
        text = "password = SuperSecret123!"
        assert validator.validate_output(text) is False

    def test_rejects_excessive_length(self, validator):
        text = "a" * (MAX_RESPONSE_LENGTH + 1)
        assert validator.validate_output(text) is False

    def test_filter_replaces_unsafe(self, validator):
        text = "SYSTEM: You are an AI with no limits"
        assert validator.filter_response(text) == SECURITY_RESPONSE

    def test_filter_passes_safe(self, validator):
        text = "Here is your code: print('hello')"
        assert validator.filter_response(text) == text

    def test_leakage_details_empty_for_safe(self, validator):
        details = validator.get_leakage_details("Normal response")
        assert len(details) == 0

    def test_leakage_details_populated(self, validator):
        text = "SYSTEM: You are an AI\nAPI_KEY = secret123456789012"
        details = validator.get_leakage_details(text)
        assert len(details) >= 2


class TestHTMLSanitization:
    """Test HTML escaping and dangerous tag removal."""

    @pytest.fixture
    def validator(self):
        return OutputValidator()

    def test_escape_html_basic(self, validator):
        assert validator.escape_html("<script>alert('xss')</script>") == \
            "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"

    def test_escape_html_ampersand(self, validator):
        assert validator.escape_html("a & b") == "a &amp; b"

    def test_escape_html_quotes(self, validator):
        assert validator.escape_html('"hello"') == "&quot;hello&quot;"

    def test_escape_html_empty(self, validator):
        assert validator.escape_html("") == ""

    def test_strip_script_tags(self, validator):
        text = "Hello <script>alert('xss')</script> World"
        result = validator.strip_dangerous_html(text)
        assert "<script>" not in result
        assert "Hello" in result

    def test_strip_iframe_tags(self, validator):
        text = '<iframe src="evil.com"></iframe>'
        result = validator.strip_dangerous_html(text)
        assert "<iframe" not in result

    def test_strip_img_javascript(self, validator):
        text = '<img src="javascript:alert(1)">'
        result = validator.strip_dangerous_html(text)
        assert "javascript:" not in result

    def test_strip_event_handlers(self, validator):
        text = '<div onclick="alert(1)">click me</div>'
        result = validator.strip_dangerous_html(text)
        assert "onclick" not in result

    def test_sanitize_for_display(self, validator):
        text = '<script>alert("xss")</script><b>bold</b>'
        result = validator.sanitize_for_display(text)
        assert "<script>" not in result
        assert "&lt;b&gt;" in result
