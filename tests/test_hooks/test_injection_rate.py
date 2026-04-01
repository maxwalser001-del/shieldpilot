"""Tests for injection rate limiting in the hook.

Verifies that _check_injection_rate() detects repeated injection
attempts by querying PromptScanLog entries in a sliding window.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from sentinelai.core.config import SentinelConfig
from sentinelai.hooks.sentinel_hook import _check_injection_rate


def _make_config():
    """Create a minimal config for testing."""
    return SentinelConfig()


def _mock_query_count(count: int):
    """Create a mock session chain that returns the given count."""
    mock_session = MagicMock()
    mock_query = MagicMock()
    mock_session.query.return_value = mock_query
    mock_query.filter.return_value = mock_query
    mock_query.count.return_value = count
    return mock_session


class TestCheckInjectionRate:
    """Test the _check_injection_rate function."""

    @patch("sentinelai.logger.BlackboxLogger")
    def test_not_blocked_below_threshold(self, MockLogger):
        """Under 5 detections in 60s should not block."""
        mock_session = _mock_query_count(4)
        MockLogger.return_value._get_session.return_value = mock_session

        config = _make_config()
        blocked, msg = _check_injection_rate(config)
        assert blocked is False
        assert msg == ""

    @patch("sentinelai.logger.BlackboxLogger")
    def test_blocked_at_threshold(self, MockLogger):
        """5 or more detections in 60s should block."""
        mock_session = _mock_query_count(5)
        MockLogger.return_value._get_session.return_value = mock_session

        config = _make_config()
        blocked, msg = _check_injection_rate(config)
        assert blocked is True
        assert "injection" in msg.lower()
        assert "5" in msg

    @patch("sentinelai.logger.BlackboxLogger")
    def test_blocked_above_threshold(self, MockLogger):
        """Well above threshold should also block."""
        mock_session = _mock_query_count(12)
        MockLogger.return_value._get_session.return_value = mock_session

        config = _make_config()
        blocked, msg = _check_injection_rate(config)
        assert blocked is True
        assert "12" in msg

    @patch("sentinelai.logger.BlackboxLogger")
    def test_zero_detections(self, MockLogger):
        """No detections at all should not block."""
        mock_session = _mock_query_count(0)
        MockLogger.return_value._get_session.return_value = mock_session

        config = _make_config()
        blocked, msg = _check_injection_rate(config)
        assert blocked is False
        assert msg == ""
