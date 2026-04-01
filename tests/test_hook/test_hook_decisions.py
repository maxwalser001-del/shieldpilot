"""Tests for hook decision logic -- Spec 1 (Hook-Entscheidungs-Spec).

Covers:
- Boundary values at risk thresholds (39/40/79/80)
- _determine_action direct tests
- Tool type classification (_check_protected_path)
"""

from __future__ import annotations

import pytest

from sentinelai.core.constants import Action, RiskCategory
from sentinelai.core.models import RiskSignal
from sentinelai.engine import RiskEngine
from sentinelai.engine.base import AnalysisContext, BaseAnalyzer


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


class FixedScoreAnalyzer(BaseAnalyzer):
    """Test analyzer that returns a fixed score."""

    def __init__(self, fixed_score: int, fixed_weight: float = 1.0):
        self._score = fixed_score
        self._weight = fixed_weight

    @property
    def name(self) -> str:
        return "fixed_score_test"

    @property
    def category(self) -> RiskCategory:
        return RiskCategory.DESTRUCTIVE_FS

    def analyze(self, command, context):
        if command.strip():
            return [
                RiskSignal(
                    category=RiskCategory.DESTRUCTIVE_FS,
                    score=self._score,
                    weight=self._weight,
                    description=f"Fixed test signal (score={self._score})",
                    evidence=command,
                    analyzer=self.name,
                )
            ]
        return []


# ---------------------------------------------------------------------------
# Boundary value tests
# ---------------------------------------------------------------------------


class TestBoundaryValues:
    """Test risk score boundary values at thresholds 39/40/79/80."""

    def test_score_39_allows(self, test_config, mock_context):
        """Score 39 is just below warn threshold -> ALLOW."""
        engine = RiskEngine(test_config, analyzers=[FixedScoreAnalyzer(39)])
        result = engine.assess("test command", mock_context)
        assert result.action == Action.ALLOW
        assert result.final_score == 39

    def test_score_40_warns(self, test_config, mock_context):
        """Score 40 is exactly at warn threshold -> WARN."""
        engine = RiskEngine(test_config, analyzers=[FixedScoreAnalyzer(40)])
        result = engine.assess("test command", mock_context)
        assert result.action == Action.WARN
        assert result.final_score == 40

    def test_score_79_warns(self, test_config, mock_context):
        """Score 79 is just below block threshold -> WARN."""
        engine = RiskEngine(test_config, analyzers=[FixedScoreAnalyzer(79)])
        result = engine.assess("test command", mock_context)
        assert result.action == Action.WARN
        assert result.final_score == 79

    def test_score_80_blocks(self, test_config, mock_context):
        """Score 80 is exactly at block threshold -> BLOCK."""
        engine = RiskEngine(test_config, analyzers=[FixedScoreAnalyzer(80)])
        result = engine.assess("test command", mock_context)
        assert result.action == Action.BLOCK
        assert result.final_score == 80

    def test_score_0_allows(self, test_config, mock_context):
        """Score 0 (empty command) -> ALLOW."""
        engine = RiskEngine(test_config, analyzers=[FixedScoreAnalyzer(0)])
        result = engine.assess("test command", mock_context)
        assert result.action == Action.ALLOW
        assert result.final_score == 0

    def test_score_100_blocks(self, test_config, mock_context):
        """Score 100 -> BLOCK."""
        engine = RiskEngine(test_config, analyzers=[FixedScoreAnalyzer(100)])
        result = engine.assess("test command", mock_context)
        assert result.action == Action.BLOCK
        assert result.final_score == 100


# ---------------------------------------------------------------------------
# _determine_action direct tests
# ---------------------------------------------------------------------------


class TestDetermineAction:
    """Test _determine_action directly."""

    def test_block_threshold_exact(self, risk_engine):
        assert risk_engine._determine_action(80) == Action.BLOCK

    def test_warn_threshold_exact(self, risk_engine):
        assert risk_engine._determine_action(40) == Action.WARN

    def test_below_warn(self, risk_engine):
        assert risk_engine._determine_action(39) == Action.ALLOW

    def test_between_warn_and_block(self, risk_engine):
        assert risk_engine._determine_action(60) == Action.WARN

    def test_above_block(self, risk_engine):
        assert risk_engine._determine_action(95) == Action.BLOCK

    def test_zero(self, risk_engine):
        assert risk_engine._determine_action(0) == Action.ALLOW


# ---------------------------------------------------------------------------
# Tool-type / protected-path classification
# ---------------------------------------------------------------------------


class TestToolTypeDecisions:
    """Test that different tool types get correct treatment in the hook.

    These test the classification logic, not the full hook stdin pipeline.
    We test the helper functions directly.
    """

    def test_check_protected_path_blocks_etc(self, test_config):
        from sentinelai.hooks.sentinel_hook import _check_protected_path

        assert _check_protected_path("/etc/shadow", test_config) is True

    def test_check_protected_path_allows_tmp(self, test_config):
        from sentinelai.hooks.sentinel_hook import _check_protected_path

        assert _check_protected_path("/tmp/safe_file.txt", test_config) is False

    def test_check_protected_path_blocks_ssh(self, test_config):
        from sentinelai.hooks.sentinel_hook import _check_protected_path

        assert _check_protected_path("~/.ssh/id_rsa", test_config) is True

    def test_check_protected_path_allows_home_dir(self, test_config):
        from sentinelai.hooks.sentinel_hook import _check_protected_path

        assert _check_protected_path("/home/user/project/file.py", test_config) is False


# ---------------------------------------------------------------------------
# Composite score algorithm tests
# ---------------------------------------------------------------------------


class TestComputeScore:
    """Test the maximum-weighted + diminishing tail scoring algorithm."""

    def test_single_signal(self, risk_engine):
        """Single signal: score = signal_score * weight."""
        signals = [
            RiskSignal(
                category=RiskCategory.DESTRUCTIVE_FS,
                score=60,
                weight=1.0,
                description="test",
                evidence="test",
                analyzer="test",
            )
        ]
        assert risk_engine._compute_score(signals) == 60

    def test_two_signals_diminishing_tail(self, risk_engine):
        """Two signals: highest dominates, second adds 50%."""
        signals = [
            RiskSignal(
                category=RiskCategory.DESTRUCTIVE_FS,
                score=60,
                weight=1.0,
                description="high",
                evidence="test",
                analyzer="test",
            ),
            RiskSignal(
                category=RiskCategory.NETWORK_EXFILTRATION,
                score=40,
                weight=1.0,
                description="low",
                evidence="test",
                analyzer="test",
            ),
        ]
        # weighted = [60, 40] -> 60 + 40 * 0.5 = 80
        assert risk_engine._compute_score(signals) == 80

    def test_no_signals_returns_zero(self, risk_engine):
        """No signals -> score 0."""
        assert risk_engine._compute_score([]) == 0

    def test_score_capped_at_100(self, risk_engine):
        """Score should never exceed 100."""
        signals = [
            RiskSignal(
                category=RiskCategory.DESTRUCTIVE_FS,
                score=100,
                weight=1.0,
                description="max",
                evidence="test",
                analyzer="test",
            ),
            RiskSignal(
                category=RiskCategory.NETWORK_EXFILTRATION,
                score=100,
                weight=1.0,
                description="also max",
                evidence="test",
                analyzer="test",
            ),
        ]
        assert risk_engine._compute_score(signals) <= 100

    def test_weight_affects_score(self, risk_engine):
        """Weight < 1.0 reduces effective score."""
        signals = [
            RiskSignal(
                category=RiskCategory.DESTRUCTIVE_FS,
                score=80,
                weight=0.5,
                description="half weight",
                evidence="test",
                analyzer="test",
            )
        ]
        # weighted = [80 * 0.5] = [40] -> score = 40
        assert risk_engine._compute_score(signals) == 40


# ---------------------------------------------------------------------------
# Whitelist / blacklist integration tests
# ---------------------------------------------------------------------------


class TestWhitelistBlacklist:
    """Test that whitelist caps scores and blacklist forces BLOCK."""

    def test_whitelisted_command_capped(self, test_config, mock_context):
        """Whitelisted command ('ls') has its score capped at 10."""
        engine = RiskEngine(test_config, analyzers=[FixedScoreAnalyzer(60)])
        result = engine.assess("ls -la /etc/shadow", mock_context)
        assert result.final_score <= 10
        assert result.action == Action.ALLOW

    def test_blacklisted_command_blocks(self, test_config, mock_context):
        """Blacklisted command always produces score 100 + BLOCK."""
        engine = RiskEngine(test_config, analyzers=[FixedScoreAnalyzer(0)])
        result = engine.assess("rm -rf /", mock_context)
        assert result.final_score == 100
        assert result.action == Action.BLOCK
