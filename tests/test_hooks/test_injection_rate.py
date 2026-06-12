"""Tests for injection rate limiting in the hook.

Repeat-discrimination semantics (2026-06-12): the limiter groups threat-flagged
PromptScanLog rows by content_hash and trips only when a SINGLE payload repeats
>= threshold times within the window — an actual Best-of-N retry. Reading diverse
content that merely *mentions* injection (security docs, a vault of prompt-injection
concepts) produces many DISTINCT hashes, each low-count, and must NOT trip the
limiter. This file pins both the false-positive fix and the true-positive.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from sentinelai.core.config import SentinelConfig
from sentinelai.hooks.sentinel_hook import (
    _check_injection_rate,
    _injection_rate_triggered,
)


def _make_config(action: str = "block"):
    """Create a minimal config for testing (optionally overriding the action)."""
    config = SentinelConfig()
    config.injection_rate_limit.action = action
    return config


def _mock_query_rows(rows):
    """Mock the grouped query chain: query().filter().group_by().all() -> rows.

    ``rows`` is a list of (content_hash, count) tuples, mirroring the
    GROUP BY content_hash result the real code consumes.
    """
    mock_session = MagicMock()
    mock_query = MagicMock()
    mock_session.query.return_value = mock_query
    mock_query.filter.return_value = mock_query
    mock_query.group_by.return_value = mock_query
    mock_query.all.return_value = rows
    return mock_session


class TestInjectionRateTriggeredPure:
    """The pure, DB-free repeat-discrimination core."""

    def test_diverse_content_does_not_trigger(self):
        # Six distinct payloads, each seen once — the false-positive case.
        # (Total threat-flagged scans = 6, which the OLD logic would have blocked.)
        assert _injection_rate_triggered([1, 1, 1, 1, 1, 1], threshold=5) is False

    def test_single_payload_repeat_triggers(self):
        assert _injection_rate_triggered([5], threshold=5) is True

    def test_repeat_above_threshold_triggers(self):
        assert _injection_rate_triggered([6, 1, 1], threshold=5) is True

    def test_mixed_below_threshold_does_not_trigger(self):
        # High TOTAL (10) but no single payload reaches 5 → not an attack.
        assert _injection_rate_triggered([4, 3, 2, 1], threshold=5) is False

    def test_empty_does_not_trigger(self):
        assert _injection_rate_triggered([], threshold=5) is False

    def test_nonpositive_threshold_never_triggers(self):
        assert _injection_rate_triggered([10], threshold=0) is False


class TestCheckInjectionRate:
    """The DB-querying wrapper, with the session mocked."""

    @patch("sentinelai.logger.BlackboxLogger")
    def test_diverse_threat_content_not_blocked(self, MockLogger):
        """REGRESSION: many distinct payloads (legit security-doc reads) must NOT block.

        This is the exact false positive that blocked the trusted Hermes agent:
        reading a vault full of prompt-injection concepts produced 6 threat-flagged
        scans with 6 distinct content hashes.
        """
        rows = [(f"hash{i}", 1) for i in range(6)]
        MockLogger.return_value._get_session.return_value = _mock_query_rows(rows)

        blocked, msg = _check_injection_rate(_make_config())
        assert blocked is False
        assert msg == ""

    @patch("sentinelai.logger.BlackboxLogger")
    def test_repeated_payload_blocked_at_threshold(self, MockLogger):
        """Same payload retried 5x in window should block (true positive)."""
        MockLogger.return_value._get_session.return_value = _mock_query_rows([("samehash", 5)])

        blocked, msg = _check_injection_rate(_make_config())
        assert blocked is True
        assert "5" in msg

    @patch("sentinelai.logger.BlackboxLogger")
    def test_repeated_payload_blocked_above_threshold(self, MockLogger):
        """Same payload hammered 12x blocks; surrounding diverse noise is ignored."""
        rows = [("samehash", 12), ("other", 1), ("other2", 1)]
        MockLogger.return_value._get_session.return_value = _mock_query_rows(rows)

        blocked, msg = _check_injection_rate(_make_config())
        assert blocked is True
        assert "12" in msg

    @patch("sentinelai.logger.BlackboxLogger")
    def test_zero_detections(self, MockLogger):
        MockLogger.return_value._get_session.return_value = _mock_query_rows([])

        blocked, msg = _check_injection_rate(_make_config())
        assert blocked is False
        assert msg == ""

    @patch("sentinelai.logger.BlackboxLogger")
    def test_detection_independent_of_action(self, MockLogger):
        """Detection is policy-free: action=warn still DETECTS the retry.

        warn vs block is decided at the call site, not in detection.
        """
        MockLogger.return_value._get_session.return_value = _mock_query_rows([("h", 5)])

        blocked, _ = _check_injection_rate(_make_config(action="warn"))
        assert blocked is True


class TestInjectionRateConfig:
    """Defaults stay production-safe (block / 5 / 60s)."""

    def test_defaults(self):
        cfg = SentinelConfig()
        assert cfg.injection_rate_limit.action == "block"
        assert cfg.injection_rate_limit.threshold == 5
        assert cfg.injection_rate_limit.window_seconds == 60
