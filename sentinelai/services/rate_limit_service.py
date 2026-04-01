"""Per-tenant API rate limiting service for ShieldPilot.

Provides configurable rate limits per billing tier. Each tier has
different API request limits (per minute and per day).

Tier limits:
- free:       60 req/min,    1000 req/day
- pro:        300 req/min,   10000 req/day
- enterprise: 1000 req/min,  100000 req/day
- unlimited:  no limits
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from threading import Lock
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


# Per-tier rate limits: (requests_per_minute, requests_per_day)
TIER_RATE_LIMITS: Dict[str, Tuple[int, int]] = {
    "free": (60, 1_000),
    "pro": (300, 10_000),
    "pro_plus": (1_000, 100_000),
    "enterprise": (1_000, 100_000),  # Legacy alias for pro_plus
    "unlimited": (-1, -1),  # -1 = no limit
}


class TenantRateLimiter:
    """In-memory per-tenant rate limiter using sliding window counters.

    Uses two windows:
    - Per-minute: sliding window of 60 seconds
    - Per-day: sliding window of 86400 seconds

    Thread-safe via a single lock.
    """

    def __init__(self) -> None:
        # key -> list of timestamps
        self._minute_windows: Dict[str, list[float]] = defaultdict(list)
        self._day_windows: Dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def check_and_record(
        self, tenant_id: Optional[str], tier: str
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Check if request is allowed and record it.

        Args:
            tenant_id: The tenant identifier (or "global" for non-tenant requests)
            tier: The billing tier (free/pro/enterprise/unlimited)

        Returns:
            Tuple of (allowed: bool, info: Optional[dict]).
            If blocked, info contains retry_after and limit details.
        """
        limits = TIER_RATE_LIMITS.get(tier, TIER_RATE_LIMITS["free"])
        rpm_limit, daily_limit = limits

        # Unlimited tier bypasses all checks
        if rpm_limit < 0:
            return True, None

        key = tenant_id or "global"
        now = time.time()

        with self._lock:
            # Clean expired entries
            minute_ago = now - 60
            day_ago = now - 86400

            self._minute_windows[key] = [
                t for t in self._minute_windows[key] if t > minute_ago
            ]
            self._day_windows[key] = [
                t for t in self._day_windows[key] if t > day_ago
            ]

            # Check per-minute limit
            if len(self._minute_windows[key]) >= rpm_limit:
                oldest = self._minute_windows[key][0]
                retry_after = int(60 - (now - oldest)) + 1
                return False, {
                    "error": "rate_limit_exceeded",
                    "message": "Rate limit exceeded",
                    "limit": rpm_limit,
                    "window": "per_minute",
                    "retry_after": max(1, retry_after),
                    "tier": tier,
                }

            # Check per-day limit
            if daily_limit > 0 and len(self._day_windows[key]) >= daily_limit:
                oldest = self._day_windows[key][0]
                retry_after = int(86400 - (now - oldest)) + 1
                return False, {
                    "error": "daily_rate_limit_exceeded",
                    "message": "Daily rate limit exceeded",
                    "limit": daily_limit,
                    "window": "per_day",
                    "retry_after": max(1, retry_after),
                    "tier": tier,
                }

            # Record the request
            self._minute_windows[key].append(now)
            self._day_windows[key].append(now)

            return True, None

    def get_usage(self, tenant_id: Optional[str], tier: str) -> Dict[str, Any]:
        """Get current rate limit usage for a tenant."""
        limits = TIER_RATE_LIMITS.get(tier, TIER_RATE_LIMITS["free"])
        rpm_limit, daily_limit = limits
        key = tenant_id or "global"
        now = time.time()

        with self._lock:
            minute_count = len([
                t for t in self._minute_windows.get(key, []) if t > now - 60
            ])
            day_count = len([
                t for t in self._day_windows.get(key, []) if t > now - 86400
            ])

        return {
            "tier": tier,
            "minute": {"used": minute_count, "limit": rpm_limit},
            "daily": {"used": day_count, "limit": daily_limit},
        }

    def reset(self, tenant_id: Optional[str] = None) -> None:
        """Reset rate limit counters. If tenant_id is None, reset all."""
        with self._lock:
            if tenant_id is None:
                self._minute_windows.clear()
                self._day_windows.clear()
            else:
                key = tenant_id or "global"
                self._minute_windows.pop(key, None)
                self._day_windows.pop(key, None)


# Module-level singleton
_tenant_limiter = TenantRateLimiter()


def get_tenant_limiter() -> TenantRateLimiter:
    """Get the singleton tenant rate limiter."""
    return _tenant_limiter
