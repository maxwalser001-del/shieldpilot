"""Circuit breaker for Best-of-N and repeated injection attacks.

Tracks injection detection events per source (IP/user) and blocks
sources that exhibit systematic attack patterns. Uses a sliding
window approach similar to the RateLimiter in routes.py.
"""

from __future__ import annotations

import time
from collections import defaultdict
from threading import Lock
from typing import Dict, List, Optional, Tuple


# Default thresholds
DEFAULT_MAX_DETECTIONS = 5      # Max injection detections before tripping
DEFAULT_WINDOW_SECONDS = 60     # Sliding window
DEFAULT_BLOCK_SECONDS = 300     # Block duration (5 minutes)


class CircuitBreaker:
    """Track and block sources with repeated injection attempts.

    Usage::

        breaker = CircuitBreaker()

        # Check before scanning
        if breaker.is_blocked(source_id):
            return "Temporarily blocked due to repeated injection attempts"

        # After detection
        if scan_result.threats:
            breaker.record_detection(source_id)
    """

    def __init__(
        self,
        max_detections: int = DEFAULT_MAX_DETECTIONS,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        block_seconds: int = DEFAULT_BLOCK_SECONDS,
    ):
        self.max_detections = max_detections
        self.window_seconds = window_seconds
        self.block_seconds = block_seconds

        # Timestamps of detection events per source
        self._detections: Dict[str, List[float]] = defaultdict(list)
        # Block expiry timestamps per source
        self._blocked: Dict[str, float] = {}
        self._lock = Lock()

    def is_blocked(self, source_id: str) -> bool:
        """Check if a source is currently blocked."""
        with self._lock:
            if source_id not in self._blocked:
                return False

            expiry = self._blocked[source_id]
            if time.time() >= expiry:
                # Block expired, clean up
                del self._blocked[source_id]
                return False

            return True

    def record_detection(self, source_id: str) -> bool:
        """Record an injection detection event.

        Returns True if the circuit breaker tripped (source is now blocked).
        """
        now = time.time()

        with self._lock:
            # Clean old entries outside the window
            cutoff = now - self.window_seconds
            events = self._detections[source_id]
            self._detections[source_id] = [t for t in events if t > cutoff]

            # Record new event
            self._detections[source_id].append(now)

            # Check if threshold is exceeded
            if len(self._detections[source_id]) >= self.max_detections:
                self._blocked[source_id] = now + self.block_seconds
                self._detections[source_id] = []  # Reset counter
                return True

            return False

    def get_block_remaining(self, source_id: str) -> int:
        """Get remaining block time in seconds, or 0 if not blocked."""
        with self._lock:
            if source_id not in self._blocked:
                return 0
            remaining = self._blocked[source_id] - time.time()
            return max(0, int(remaining))

    def get_detection_count(self, source_id: str) -> int:
        """Get current detection count within the window."""
        now = time.time()
        with self._lock:
            cutoff = now - self.window_seconds
            events = self._detections.get(source_id, [])
            return len([t for t in events if t > cutoff])

    def reset(self, source_id: Optional[str] = None) -> None:
        """Reset tracking for a source, or all sources if None."""
        with self._lock:
            if source_id:
                self._detections.pop(source_id, None)
                self._blocked.pop(source_id, None)
            else:
                self._detections.clear()
                self._blocked.clear()


def jaccard_similarity(text_a: str, text_b: str) -> float:
    """Compute Jaccard similarity between two texts on token level.

    Returns a value between 0.0 (completely different) and 1.0 (identical).
    Used to detect Best-of-N attacks where the attacker sends many
    slight variations of the same injection attempt.
    """
    tokens_a = set(text_a.lower().split())
    tokens_b = set(text_b.lower().split())

    if not tokens_a and not tokens_b:
        return 1.0
    if not tokens_a or not tokens_b:
        return 0.0

    intersection = tokens_a & tokens_b
    union = tokens_a | tokens_b

    return len(intersection) / len(union)
