"""Tests for hook failure handling -- Spec 2 (Failure-Policy-Spec).

Covers:
- Analyzer exceptions (crashing analyzer does not break the engine)
- All analyzers crashing returns score 0
- Usage limit checks (billing disabled, unlimited tier)
"""

from __future__ import annotations

from typing import List

import pytest

from sentinelai.core.constants import Action, RiskCategory
from sentinelai.core.models import RiskSignal
from sentinelai.engine import RiskEngine
from sentinelai.engine.base import AnalysisContext, BaseAnalyzer


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


class CrashingAnalyzer(BaseAnalyzer):
    """Analyzer that always raises an exception."""

    @property
    def name(self) -> str:
        return "crashing_test"

    @property
    def category(self) -> RiskCategory:
        return RiskCategory.DESTRUCTIVE_FS

    def analyze(self, command: str, context: AnalysisContext) -> List[RiskSignal]:
        raise RuntimeError("Analyzer crashed!")


# ---------------------------------------------------------------------------
# Analyzer failure resilience
# ---------------------------------------------------------------------------


class TestAnalyzerFailure:
    """Test that analyzer exceptions don't break the engine."""

    def test_crashing_analyzer_continues(self, test_config, mock_context):
        """A crashing analyzer should not prevent other analyzers from running."""
        from sentinelai.engine.analyzers.destructive_fs import DestructiveFSAnalyzer

        engine = RiskEngine(
            test_config,
            analyzers=[CrashingAnalyzer(), DestructiveFSAnalyzer()],
        )
        # This should not raise -- the crashing analyzer is caught internally
        result = engine.assess("rm -rf /home", mock_context)
        # DestructiveFSAnalyzer should still produce signals
        assert len(result.signals) > 0

    def test_all_analyzers_crash_returns_zero(self, test_config, mock_context):
        """If ALL analyzers crash, score should be 0 (no signals)."""
        engine = RiskEngine(test_config, analyzers=[CrashingAnalyzer()])
        result = engine.assess("any command", mock_context)
        assert result.final_score == 0
        assert result.action == Action.ALLOW
        assert len(result.signals) == 0

    def test_multiple_crashing_analyzers(self, test_config, mock_context):
        """Multiple crashing analyzers should all be caught gracefully."""
        engine = RiskEngine(
            test_config,
            analyzers=[CrashingAnalyzer(), CrashingAnalyzer(), CrashingAnalyzer()],
        )
        result = engine.assess("any command", mock_context)
        assert result.final_score == 0
        assert result.action == Action.ALLOW


# ---------------------------------------------------------------------------
# Usage limit check
# ---------------------------------------------------------------------------


class TestUsageLimitCheck:
    """Test _check_usage_limit behavior."""

    def test_billing_disabled_no_limit(self, test_config):
        from sentinelai.hooks.sentinel_hook import _check_usage_limit

        test_config.billing.enabled = False
        reached, msg = _check_usage_limit(test_config)
        assert reached is False
        assert msg == ""

    def test_unlimited_tier_no_limit(self, test_config):
        from sentinelai.hooks.sentinel_hook import _check_usage_limit

        test_config.billing.enabled = True
        test_config.billing.tier = "unlimited"
        reached, msg = _check_usage_limit(test_config)
        assert reached is False
        assert msg == ""

    def test_pro_plus_tier_no_limit(self, test_config):
        from sentinelai.hooks.sentinel_hook import _check_usage_limit

        test_config.billing.enabled = True
        test_config.billing.tier = "pro_plus"
        reached, msg = _check_usage_limit(test_config)
        assert reached is False
        assert msg == ""


# ---------------------------------------------------------------------------
# Empty / missing input resilience
# ---------------------------------------------------------------------------


class TestEmptyInputResilience:
    """Test engine behavior with edge-case inputs."""

    def test_empty_command_string(self, test_config, mock_context):
        """Empty command should produce score 0 and ALLOW."""
        engine = RiskEngine(test_config)
        result = engine.assess("", mock_context)
        assert result.action == Action.ALLOW
        assert result.final_score == 0

    def test_whitespace_only_command(self, test_config, mock_context):
        """Whitespace-only command should produce score 0 and ALLOW."""
        engine = RiskEngine(test_config)
        result = engine.assess("   ", mock_context)
        assert result.action == Action.ALLOW
        assert result.final_score == 0

    def test_no_context_provided(self, test_config):
        """assess() without context should create defaults internally."""
        engine = RiskEngine(test_config)
        # Should not raise
        result = engine.assess("echo hello")
        assert result.action == Action.ALLOW


# ---------------------------------------------------------------------------
# Mode-dependent behavior
# ---------------------------------------------------------------------------


class TestModeSpecificBehavior:
    """Test that config mode affects engine/hook behavior correctly."""

    def test_enforce_mode_blocks_high_risk(self, test_config, mock_context):
        """In enforce mode, high-risk commands get BLOCK."""
        from tests.test_hook.test_hook_decisions import FixedScoreAnalyzer

        test_config.mode = "enforce"
        engine = RiskEngine(test_config, analyzers=[FixedScoreAnalyzer(90)])
        result = engine.assess("dangerous command", mock_context)
        assert result.action == Action.BLOCK

    def test_engine_returns_action_regardless_of_mode(self, test_config, mock_context):
        """The engine itself always returns the computed action.

        It is the hook's main() that converts BLOCK->ALLOW in audit mode.
        The engine does not inspect config.mode for its decision.
        """
        from tests.test_hook.test_hook_decisions import FixedScoreAnalyzer

        test_config.mode = "audit"
        engine = RiskEngine(test_config, analyzers=[FixedScoreAnalyzer(90)])
        result = engine.assess("dangerous command", mock_context)
        # Engine still returns BLOCK -- the hook is what converts this
        assert result.action == Action.BLOCK
