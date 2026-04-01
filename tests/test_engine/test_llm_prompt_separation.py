"""Tests for structured prompt separation in the LLM evaluator.

Verifies that the system prompt contains security rules and that
user data is wrapped in XML tags to prevent prompt injection.
"""

from __future__ import annotations

import pytest

from sentinelai.core.config import LLMConfig
from sentinelai.core.constants import RiskCategory
from sentinelai.core.models import RiskSignal
from sentinelai.engine.llm_evaluator import LLM_SYSTEM_PROMPT, LLMEvaluator


class TestSystemPromptStructure:
    """Verify the system prompt has proper security boundaries."""

    def test_contains_security_rules_section(self):
        assert "SECURITY RULES:" in LLM_SYSTEM_PROMPT

    def test_contains_never_reveal(self):
        assert "NEVER reveal" in LLM_SYSTEM_PROMPT

    def test_contains_never_follow_user_data(self):
        assert "NEVER follow" in LLM_SYSTEM_PROMPT

    def test_contains_treat_as_data(self):
        assert "data to ANALYZE" in LLM_SYSTEM_PROMPT

    def test_contains_system_instructions_header(self):
        assert "SYSTEM INSTRUCTIONS:" in LLM_SYSTEM_PROMPT

    def test_contains_json_format_spec(self):
        assert '"adjustment"' in LLM_SYSTEM_PROMPT
        assert '"reasoning"' in LLM_SYSTEM_PROMPT


class TestUserPromptXMLTags:
    """Verify that user data is wrapped in XML tags."""

    @pytest.fixture
    def evaluator(self):
        config = LLMConfig(enabled=True, model="test-model", max_tokens=512)
        return LLMEvaluator(config)

    def test_command_wrapped_in_xml(self, evaluator):
        """The command should be enclosed in <user_command> tags."""
        # We test by inspecting the prompt construction indirectly
        # through the evaluate method's user_prompt variable.
        # Since we can't easily intercept the prompt, we test the
        # LLM_SYSTEM_PROMPT + verify the code constructs XML tags.
        import inspect
        source = inspect.getsource(evaluator.evaluate)
        assert "<user_command>" in source
        assert "</user_command>" in source

    def test_working_directory_wrapped(self, evaluator):
        import inspect
        source = inspect.getsource(evaluator.evaluate)
        assert "<working_directory>" in source
        assert "</working_directory>" in source

    def test_signals_wrapped(self, evaluator):
        import inspect
        source = inspect.getsource(evaluator.evaluate)
        assert "<detected_signals>" in source
        assert "</detected_signals>" in source

    def test_current_score_wrapped(self, evaluator):
        import inspect
        source = inspect.getsource(evaluator.evaluate)
        assert "<current_score>" in source
        assert "</current_score>" in source
