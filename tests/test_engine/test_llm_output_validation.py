"""Tests for LLM output validation in the evaluator.

Verifies that the LLM evaluator filters responses containing
system prompt leakage, API keys, or other sensitive content.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from sentinelai.core.config import LLMConfig
from sentinelai.engine.llm_evaluator import LLMEvaluator, LLMResult


@pytest.fixture
def llm_config():
    return LLMConfig(enabled=True, model="claude-sonnet-4-20250514", max_tokens=512)


@pytest.fixture
def evaluator(llm_config):
    return LLMEvaluator(llm_config)


def _mock_response(text: str):
    """Create a mock Anthropic API response."""
    mock = MagicMock()
    mock.content = [MagicMock(text=text)]
    return mock


class TestLLMOutputValidation:
    """Tests that LLM responses are validated for leakage."""

    def test_normal_response_passes(self, evaluator):
        """Normal JSON response should be returned as-is."""
        response_text = json.dumps({
            "adjustment": 5,
            "reasoning": "The command targets a sensitive config file"
        })

        with patch.object(evaluator, "_get_client") as mock_client:
            mock_client.return_value = MagicMock()
            mock_client.return_value.messages.create.return_value = _mock_response(response_text)

            result = evaluator.evaluate("cat /etc/passwd", 50, [])

        assert result.adjustment == 5
        assert "sensitive config file" in result.reasoning
        assert result.error is None

    def test_filters_system_prompt_leakage(self, evaluator):
        """Response containing system prompt should be filtered."""
        response_text = 'SYSTEM: You are a security analyst. {"adjustment": 0, "reasoning": "safe"}'

        with patch.object(evaluator, "_get_client") as mock_client:
            mock_client.return_value = MagicMock()
            mock_client.return_value.messages.create.return_value = _mock_response(response_text)

            result = evaluator.evaluate("ls", 30, [])

        assert result.adjustment == 0
        assert "filtered" in result.reasoning.lower() or "security" in result.reasoning.lower()
        assert result.error is not None

    def test_filters_api_key_in_response(self, evaluator):
        """Response containing API keys should be filtered."""
        response_text = json.dumps({
            "adjustment": -5,
            "reasoning": "Safe command, API_KEY = sk-abc123def456ghi789jkl012"
        })

        with patch.object(evaluator, "_get_client") as mock_client:
            mock_client.return_value = MagicMock()
            mock_client.return_value.messages.create.return_value = _mock_response(response_text)

            result = evaluator.evaluate("echo hello", 20, [])

        # The overall response JSON is safe, but reasoning field has a key
        assert "sk-abc123def456ghi789jkl012" not in result.reasoning

    def test_filters_leakage_in_reasoning_field(self, evaluator):
        """Leakage in reasoning field — the whole response is flagged because
        validate_output sees the password pattern in the serialized JSON."""
        response_text = json.dumps({
            "adjustment": 3,
            "reasoning": "Check password = SuperSecret123! for this user"
        })

        with patch.object(evaluator, "_get_client") as mock_client:
            mock_client.return_value = MagicMock()
            mock_client.return_value.messages.create.return_value = _mock_response(response_text)

            result = evaluator.evaluate("cat config", 45, [])

        # Full response is rejected at the top-level validation
        assert result.adjustment == 0
        assert "SuperSecret123" not in result.reasoning
        assert "filtered" in result.reasoning.lower() or "security" in result.reasoning.lower()
        assert result.error is not None
