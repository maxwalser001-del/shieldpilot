"""Shared utilities for API route modules.

Contains rate limiters, sanitizers, circuit breaker, and helper functions
used across multiple route modules.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta

from sentinelai.api.deps import get_logger
from sentinelai.scanner.circuit_breaker import CircuitBreaker
from sentinelai.scanner.output_validator import OutputValidator

# ToS version -- update when Terms of Service change
TOS_VERSION = "2026-02-01"

_start_time = time.time()

# Shared output sanitizer for API responses
_display_sanitizer = OutputValidator()

# Circuit breaker for repeated injection attempts via scan endpoint
_circuit_breaker = CircuitBreaker()

_rate_limit_logger = logging.getLogger(__name__)


def _sanitize_text(text: str | None) -> str | None:
    """Sanitize user-controlled text for safe display in the frontend."""
    if text is None:
        return None
    return _display_sanitizer.sanitize_for_display(text)


# ── Rate Limiting (database-backed, persists across restarts) ────


class RateLimiter:
    """Database-backed rate limiter for auth endpoints.

    Tracks attempts by key (IP or email) and blocks if threshold exceeded.
    Uses a sliding window approach with automatic cleanup.
    Persists across restarts and works across multiple workers.
    """

    def __init__(self, name: str, max_attempts: int, window_seconds: int):
        self.name = name
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds

    def _get_recent_count(self, key: str) -> int:
        """Count recent attempts from DB within the sliding window."""
        from sentinelai.logger.database import RateLimitAttempt
        logger = get_logger()
        session = logger._get_session()
        try:
            cutoff = datetime.utcnow() - timedelta(seconds=self.window_seconds)
            count = (
                session.query(RateLimitAttempt)
                .filter(
                    RateLimitAttempt.limiter_name == self.name,
                    RateLimitAttempt.key == key,
                    RateLimitAttempt.attempted_at > cutoff,
                )
                .count()
            )
            return count
        finally:
            session.close()

    def is_blocked(self, key: str) -> bool:
        """Check if key is currently blocked (does not record)."""
        count = self._get_recent_count(key)
        if count >= self.max_attempts:
            _rate_limit_logger.warning(f"Rate limit exceeded for {key}")
            return True
        return False

    def record_attempt(self, key: str) -> None:
        """Record a new attempt for the key."""
        from sentinelai.logger.database import RateLimitAttempt
        logger = get_logger()
        session = logger._get_session()
        try:
            session.add(RateLimitAttempt(
                limiter_name=self.name,
                key=key,
            ))
            # Cleanup old entries for this limiter+key (keep window clean)
            cutoff = datetime.utcnow() - timedelta(seconds=self.window_seconds)
            session.query(RateLimitAttempt).filter(
                RateLimitAttempt.limiter_name == self.name,
                RateLimitAttempt.key == key,
                RateLimitAttempt.attempted_at < cutoff,
            ).delete()
            session.commit()
        finally:
            session.close()

    def get_retry_after(self, key: str) -> int:
        """Get seconds until the oldest attempt expires."""
        from sentinelai.logger.database import RateLimitAttempt
        logger = get_logger()
        session = logger._get_session()
        try:
            cutoff = datetime.utcnow() - timedelta(seconds=self.window_seconds)
            oldest = (
                session.query(RateLimitAttempt.attempted_at)
                .filter(
                    RateLimitAttempt.limiter_name == self.name,
                    RateLimitAttempt.key == key,
                    RateLimitAttempt.attempted_at > cutoff,
                )
                .order_by(RateLimitAttempt.attempted_at.asc())
                .first()
            )
            if oldest:
                expire_at = oldest[0] + timedelta(seconds=self.window_seconds)
                remaining = (expire_at - datetime.utcnow()).total_seconds()
                return max(1, int(remaining))
            return 0
        finally:
            session.close()

    def clear(self) -> None:
        """Clear all attempts for this limiter (used in tests)."""
        from sentinelai.logger.database import RateLimitAttempt
        logger = get_logger()
        session = logger._get_session()
        try:
            session.query(RateLimitAttempt).filter(
                RateLimitAttempt.limiter_name == self.name,
            ).delete()
            session.commit()
        finally:
            session.close()


# Rate limiters for auth endpoints
_login_limiter = RateLimiter(name="login", max_attempts=5, window_seconds=60)
_password_reset_limiter = RateLimiter(name="password_reset", max_attempts=3, window_seconds=3600)
_registration_limiter = RateLimiter(name="registration", max_attempts=5, window_seconds=3600)


# OAuth state expiry: 10 minutes
_OAUTH_STATE_EXPIRY_SECONDS = 600


def _cleanup_expired_oauth_states():
    """Remove expired OAuth states from the database."""
    from sentinelai.logger.database import OAuthState
    logger = get_logger()
    session = logger._get_session()
    try:
        cutoff = datetime.utcnow() - timedelta(seconds=_OAUTH_STATE_EXPIRY_SECONDS)
        session.query(OAuthState).filter(OAuthState.created_at < cutoff).delete()
        session.commit()
    finally:
        session.close()
