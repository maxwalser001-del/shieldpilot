"""Tests for ML rollout modes (off / shadow / enforce).

Verifies:
- off: ml_status is skipped_off, no model load, no ML blocking
- shadow: ml_recommendation is computed, but decision never becomes deny due to ML
- enforce: ML can deny when ml_injection_prob >= block threshold
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from unittest.mock import patch, MagicMock

import pytest


# ── Fakes ──────────────────────────────────────────────────────


@dataclass
class FakeScanResult:
    overall_score: int = 5
    threats: list = field(default_factory=list)
    threat_count: int = 0


@dataclass
class FakeMlResult:
    scores: dict = field(default_factory=lambda: {
        "clean": 0.05, "hard": 0.05, "injection": 0.90,
    })
    status: str = "ok"


@dataclass
class FakeAssessment:
    final_score: int = 10
    signals: list = field(default_factory=list)

    class _Action:
        value = "allow"
        BLOCK = "BLOCK"
        WARN = "WARN"
        def __eq__(self, other):
            return False  # never matches BLOCK or WARN

    action = _Action()


def _make_hook_input(command: str = "echo test") -> str:
    return json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })


def _run_hook(monkeypatch, ml_mode: str, command: str = "echo test",
              ml_injection_prob: float = 0.90,
              scanner_score: int = 5,
              block_threshold: float = 0.80,
              review_threshold: float = 0.60) -> dict:
    """Run sentinel_hook.main() and capture the JSON output.

    Returns the parsed hook response dict.
    """
    from sentinelai.scanner.scanner import PromptScanner

    # Fake scanner result
    fake_scan = FakeScanResult(overall_score=scanner_score)
    monkeypatch.setattr(PromptScanner, "scan",
                        lambda self, text, source="": fake_scan)

    # Fake ML stage
    fake_ml = FakeMlResult(
        scores={"clean": 0.05, "hard": 0.05, "injection": ml_injection_prob},
        status="ok",
    )
    fake_ml_stage = MagicMock()
    fake_ml_stage.predict.return_value = fake_ml

    # Env vars
    monkeypatch.setenv("SENTINEL_ML_MODE", ml_mode)
    monkeypatch.setenv("SENTINEL_ML_BLOCK_THRESHOLD", str(block_threshold))
    monkeypatch.setenv("SENTINEL_ML_REVIEW_THRESHOLD", str(review_threshold))
    monkeypatch.delenv("SENTINEL_ACTIVE_LEARNING_PATH", raising=False)

    captured_output = []

    with patch("sys.stdin") as mock_stdin, \
         patch("builtins.print", side_effect=lambda x: captured_output.append(x)), \
         patch("sentinelai.hooks.sentinel_hook._get_ml_stage", return_value=fake_ml_stage), \
         patch("sentinelai.hooks.sentinel_hook._load_sentinel") as mock_load, \
         patch("sentinelai.hooks.sentinel_hook._increment_usage"), \
         patch("sentinelai.hooks.sentinel_hook._check_usage_limit", return_value=(False, "")), \
         patch("sentinelai.hooks.sentinel_hook._check_injection_rate", return_value=(False, "")), \
         patch("sentinelai.hooks.sentinel_hook._log_assessment"), \
         patch("sentinelai.engine.base.AnalysisContext", side_effect=lambda **kw: MagicMock()):

        mock_stdin.read.return_value = _make_hook_input(command)

        # Fake config + engine
        fake_config = MagicMock()
        fake_config.mode = "enforce"  # sentinel mode, not ML mode
        fake_config.billing.enabled = False

        from sentinelai.core.constants import Action
        fake_assessment = MagicMock()
        fake_assessment.final_score = 10
        fake_assessment.action = Action.ALLOW
        fake_assessment.signals = []

        fake_engine = MagicMock()
        fake_engine.assess.return_value = fake_assessment

        mock_load.return_value = (fake_config, fake_engine, Action)

        from sentinelai.hooks.sentinel_hook import main
        try:
            main()
        except SystemExit:
            pass

    assert captured_output, "Hook produced no output"
    return json.loads(captured_output[0])


# ── Tests: off mode ───────────────────────────────────────────


class TestMlModeOff:
    """When SENTINEL_ML_MODE=off, ML is completely skipped."""

    def test_off_mode_skips_ml(self, monkeypatch):
        result = _run_hook(monkeypatch, ml_mode="off")
        output = result["hookSpecificOutput"]
        assert output["permissionDecision"] == "allow"

    def test_off_mode_ml_status_skipped_off(self, monkeypatch):
        result = _run_hook(monkeypatch, ml_mode="off")
        output = result["hookSpecificOutput"]
        assert output.get("ml_status") == "skipped_off"

    def test_off_mode_no_model_load(self, monkeypatch):
        """In off mode, _get_ml_stage().predict should never be called."""
        from sentinelai.scanner.scanner import PromptScanner

        fake_scan = FakeScanResult(overall_score=5)
        monkeypatch.setattr(PromptScanner, "scan",
                            lambda self, text, source="": fake_scan)

        fake_ml_stage = MagicMock()
        monkeypatch.setenv("SENTINEL_ML_MODE", "off")
        monkeypatch.delenv("SENTINEL_ACTIVE_LEARNING_PATH", raising=False)

        captured = []

        with patch("sys.stdin") as mock_stdin, \
             patch("builtins.print", side_effect=lambda x: captured.append(x)), \
             patch("sentinelai.hooks.sentinel_hook._get_ml_stage", return_value=fake_ml_stage) as mock_get, \
             patch("sentinelai.hooks.sentinel_hook._load_sentinel") as mock_load, \
             patch("sentinelai.hooks.sentinel_hook._increment_usage"), \
             patch("sentinelai.hooks.sentinel_hook._check_usage_limit", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._check_injection_rate", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._log_assessment"), \
             patch("sentinelai.engine.base.AnalysisContext", side_effect=lambda **kw: MagicMock()):

            mock_stdin.read.return_value = _make_hook_input("echo safe")

            fake_config = MagicMock()
            fake_config.mode = "enforce"
            fake_config.billing.enabled = False

            from sentinelai.core.constants import Action
            fake_assessment = MagicMock()
            fake_assessment.final_score = 10
            fake_assessment.action = Action.ALLOW
            fake_assessment.signals = []

            fake_engine = MagicMock()
            fake_engine.assess.return_value = fake_assessment

            mock_load.return_value = (fake_config, fake_engine, Action)

            from sentinelai.hooks.sentinel_hook import main
            try:
                main()
            except SystemExit:
                pass

        # predict() should NOT have been called
        fake_ml_stage.predict.assert_not_called()

    def test_off_mode_never_blocks_via_ml(self, monkeypatch):
        """Even with high injection prob, off mode allows."""
        result = _run_hook(monkeypatch, ml_mode="off", ml_injection_prob=0.99)
        output = result["hookSpecificOutput"]
        assert output["permissionDecision"] == "allow"


# ── Tests: shadow mode ────────────────────────────────────────


class TestMlModeShadow:
    """When SENTINEL_ML_MODE=shadow (default), ML runs but never blocks."""

    def test_shadow_mode_allows_high_injection(self, monkeypatch):
        """Shadow mode: even injection_prob=0.95 must NOT deny."""
        result = _run_hook(monkeypatch, ml_mode="shadow", ml_injection_prob=0.95)
        output = result["hookSpecificOutput"]
        assert output["permissionDecision"] == "allow"

    def test_shadow_mode_computes_recommendation_block(self, monkeypatch):
        """Shadow mode should still compute ml_recommendation=block."""
        result = _run_hook(monkeypatch, ml_mode="shadow", ml_injection_prob=0.90)
        output = result["hookSpecificOutput"]
        assert output.get("ml_recommendation") == "block"

    def test_shadow_mode_computes_recommendation_review(self, monkeypatch):
        result = _run_hook(monkeypatch, ml_mode="shadow", ml_injection_prob=0.65)
        output = result["hookSpecificOutput"]
        assert output.get("ml_recommendation") == "review"

    def test_shadow_mode_computes_recommendation_allow(self, monkeypatch):
        result = _run_hook(monkeypatch, ml_mode="shadow", ml_injection_prob=0.30)
        output = result["hookSpecificOutput"]
        assert output.get("ml_recommendation") == "allow"

    def test_shadow_mode_includes_ml_scores(self, monkeypatch):
        result = _run_hook(monkeypatch, ml_mode="shadow", ml_injection_prob=0.85)
        output = result["hookSpecificOutput"]
        assert "ml_scores" in output
        assert output["ml_status"] == "ok"
        assert output["ml_mode"] == "shadow"


# ── Tests: enforce mode ───────────────────────────────────────


class TestMlModeEnforce:
    """When SENTINEL_ML_MODE=enforce, ML can block above threshold."""

    def test_enforce_blocks_above_threshold(self, monkeypatch):
        """injection_prob=0.90 >= block_threshold=0.80 => deny."""
        result = _run_hook(monkeypatch, ml_mode="enforce", ml_injection_prob=0.90)
        output = result["hookSpecificOutput"]
        assert output["permissionDecision"] == "deny"

    def test_enforce_allows_below_threshold(self, monkeypatch):
        """injection_prob=0.50 < block_threshold=0.80 => allow."""
        result = _run_hook(monkeypatch, ml_mode="enforce", ml_injection_prob=0.50)
        output = result["hookSpecificOutput"]
        assert output["permissionDecision"] == "allow"

    def test_enforce_blocks_at_exact_threshold(self, monkeypatch):
        """injection_prob=0.80 == block_threshold=0.80 => deny."""
        result = _run_hook(monkeypatch, ml_mode="enforce",
                          ml_injection_prob=0.80, block_threshold=0.80)
        output = result["hookSpecificOutput"]
        assert output["permissionDecision"] == "deny"

    def test_enforce_custom_threshold(self, monkeypatch):
        """Custom block_threshold=0.70: injection_prob=0.75 => deny."""
        result = _run_hook(monkeypatch, ml_mode="enforce",
                          ml_injection_prob=0.75, block_threshold=0.70)
        output = result["hookSpecificOutput"]
        assert output["permissionDecision"] == "deny"

    def test_enforce_allows_when_scanner_score_high(self, monkeypatch):
        """If scanner_score >= 20, ML doesn't run (skipped), scanner handles it."""
        result = _run_hook(monkeypatch, ml_mode="enforce",
                          ml_injection_prob=0.90, scanner_score=25)
        output = result["hookSpecificOutput"]
        # scanner_score=25 < 70, so scanner doesn't block
        # ML skipped because scanner_score >= 20
        assert output["permissionDecision"] == "allow"
        assert output.get("ml_status") == "skipped"

    def test_enforce_includes_ml_recommendation(self, monkeypatch):
        result = _run_hook(monkeypatch, ml_mode="enforce", ml_injection_prob=0.90)
        output = result["hookSpecificOutput"]
        assert output.get("ml_recommendation") == "block"


# ── Tests: threshold configuration ────────────────────────────


class TestThresholdConfig:
    """Verify threshold env vars are respected."""

    def test_default_block_threshold(self, monkeypatch):
        """Default block threshold is 0.80."""
        monkeypatch.delenv("SENTINEL_ML_BLOCK_THRESHOLD", raising=False)
        from sentinelai.hooks.sentinel_hook import _get_ml_block_threshold
        assert _get_ml_block_threshold() == 0.80

    def test_custom_block_threshold(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_ML_BLOCK_THRESHOLD", "0.70")
        from sentinelai.hooks.sentinel_hook import _get_ml_block_threshold
        assert _get_ml_block_threshold() == 0.70

    def test_invalid_block_threshold_falls_back(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_ML_BLOCK_THRESHOLD", "not_a_number")
        from sentinelai.hooks.sentinel_hook import _get_ml_block_threshold
        assert _get_ml_block_threshold() == 0.80

    def test_default_review_threshold(self, monkeypatch):
        monkeypatch.delenv("SENTINEL_ML_REVIEW_THRESHOLD", raising=False)
        from sentinelai.hooks.sentinel_hook import _get_ml_review_threshold
        assert _get_ml_review_threshold() == 0.60

    def test_compute_recommendation_block(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_ML_BLOCK_THRESHOLD", "0.80")
        monkeypatch.setenv("SENTINEL_ML_REVIEW_THRESHOLD", "0.60")
        from sentinelai.hooks.sentinel_hook import _compute_ml_recommendation
        assert _compute_ml_recommendation(0.85) == "block"

    def test_compute_recommendation_review(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_ML_BLOCK_THRESHOLD", "0.80")
        monkeypatch.setenv("SENTINEL_ML_REVIEW_THRESHOLD", "0.60")
        from sentinelai.hooks.sentinel_hook import _compute_ml_recommendation
        assert _compute_ml_recommendation(0.65) == "review"

    def test_compute_recommendation_allow(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_ML_BLOCK_THRESHOLD", "0.80")
        monkeypatch.setenv("SENTINEL_ML_REVIEW_THRESHOLD", "0.60")
        from sentinelai.hooks.sentinel_hook import _compute_ml_recommendation
        assert _compute_ml_recommendation(0.40) == "allow"
