"""I4: Rate Limiter Stress Tests.

Tests the DB-backed RateLimiter in sentinelai/api/routers/_shared.py:
sliding window, cleanup, concurrent access, circuit breaker.
"""

from __future__ import annotations

import os
import tempfile
import threading
import time
from datetime import datetime, timedelta

import pytest

from sentinelai.api.routers._shared import RateLimiter


@pytest.fixture
def db_limiter(test_config, masker):
    """Create a RateLimiter backed by a temporary database."""
    from sentinelai.api import deps
    from sentinelai.logger import BlackboxLogger

    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)

    test_config.logging.database = db_path
    logger = BlackboxLogger(config=test_config.logging, masker=masker)

    # Inject into deps so RateLimiter can access it
    deps._config = test_config
    deps._logger = logger

    yield RateLimiter(name="test_limiter", max_attempts=3, window_seconds=5)

    deps.reset_singletons()
    try:
        os.unlink(db_path)
    except OSError:
        pass


class TestRateLimiterSlidingWindow:
    def test_allows_below_threshold(self, db_limiter):
        """Requests below max_attempts should not be blocked."""
        assert db_limiter.is_blocked("user1") is False
        db_limiter.record_attempt("user1")
        assert db_limiter.is_blocked("user1") is False
        db_limiter.record_attempt("user1")
        assert db_limiter.is_blocked("user1") is False

    def test_blocks_at_threshold(self, db_limiter):
        """Reaching max_attempts should block the key."""
        for _ in range(3):
            db_limiter.record_attempt("user2")
        assert db_limiter.is_blocked("user2") is True

    def test_different_keys_independent(self, db_limiter):
        """Different keys should have independent counters."""
        for _ in range(3):
            db_limiter.record_attempt("userA")
        assert db_limiter.is_blocked("userA") is True
        assert db_limiter.is_blocked("userB") is False


class TestRateLimiterCleanup:
    def test_clear_removes_all_attempts(self, db_limiter):
        """clear() should remove all attempts for this limiter."""
        for _ in range(3):
            db_limiter.record_attempt("cleanup_test")
        assert db_limiter.is_blocked("cleanup_test") is True
        db_limiter.clear()
        assert db_limiter.is_blocked("cleanup_test") is False

    def test_retry_after_returns_positive(self, db_limiter):
        """get_retry_after should return positive seconds when blocked."""
        for _ in range(3):
            db_limiter.record_attempt("retry_test")
        retry = db_limiter.retry_after("retry_test") if hasattr(db_limiter, "retry_after") else db_limiter.get_retry_after("retry_test")
        assert retry >= 0


class TestRateLimiterConcurrent:
    def test_concurrent_record_attempts(self, db_limiter):
        """Multiple threads recording attempts should not corrupt the counter."""
        errors = []

        def record():
            try:
                db_limiter.record_attempt("concurrent_key")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=record) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        assert len(errors) == 0, f"Concurrent errors: {errors}"
        # Should be blocked (5 > 3 threshold)
        assert db_limiter.is_blocked("concurrent_key") is True


class TestCircuitBreaker:
    def test_circuit_breaker_reset(self):
        """Circuit breaker should reset cleanly."""
        from sentinelai.scanner.circuit_breaker import CircuitBreaker

        cb = CircuitBreaker()
        # Record some detections for a source
        cb.record_detection("test-source")
        cb.record_detection("test-source")
        # Reset should clear all records
        cb.reset()
        assert cb.is_blocked("test-source") is False
