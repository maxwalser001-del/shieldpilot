"""Scan service: business logic extracted from scan route handlers."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List

from fastapi import HTTPException, status

from sentinelai.api.auth import TokenData
from sentinelai.core.config import SentinelConfig
from sentinelai.logger import BlackboxLogger
from sentinelai.scanner import PromptScanner

_logger = logging.getLogger(__name__)


def _get_shared():
    """Lazy import to avoid circular dependency with routers package."""
    from sentinelai.api.routers._shared import _circuit_breaker, _sanitize_text

    return _circuit_breaker, _sanitize_text


class ScanService:
    """Business logic for prompt scan operations.

    Accepts logger and config as constructor params.
    Raises HTTPException directly for pragmatic compatibility with existing tests.
    """

    def __init__(self, logger: BlackboxLogger, config: SentinelConfig):
        self.logger = logger
        self.config = config

    def list_scans(
        self, *, limit: int = 50, offset: int = 0
    ) -> Dict[str, Any]:
        """Return paginated list of prompt scan logs."""
        scans, total = self.logger.query_scans(limit=limit, offset=offset)

        items: List[Dict[str, Any]] = []
        for scan in scans:
            items.append(
                {
                    "id": scan.id,
                    "timestamp": (
                        scan.timestamp.isoformat() if scan.timestamp else None
                    ),
                    "source": scan.source,
                    "overall_score": scan.overall_score,
                    "threat_count": scan.threat_count,
                    "threats": (
                        json.loads(scan.threats_json)
                        if scan.threats_json
                        else []
                    ),
                    "recommendation": scan.recommendation,
                }
            )

        return {"items": items, "total": total}

    def scan_prompt(
        self, *, content: str, source: str, user: TokenData
    ) -> Dict[str, Any]:
        """Run a prompt injection scan.

        Checks circuit breaker, invokes PromptScanner, logs result,
        and sanitizes user-controlled fields for safe rendering.
        """
        from sentinelai.api.deps import (
            check_scan_limit_for_user,
            increment_scan_usage,
        )

        # 1. Check scan limit (super-admin bypasses)
        check_scan_limit_for_user(user, self.config, self.logger)

        # 2. Circuit breaker: block sources with repeated injection attempts
        circuit_breaker, sanitize_text = _get_shared()
        source_key = user.email or user.username
        if circuit_breaker.is_blocked(source_key):
            remaining = circuit_breaker.get_block_remaining(source_key)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "error": "Temporarily blocked due to repeated injection attempts",
                    "retry_after": remaining,
                },
                headers={"Retry-After": str(remaining)},
            )

        # 3. Increment usage counter (per-user)
        increment_scan_usage(self.logger, user_email=user.email)

        # 4. Run the scanner
        scanner = PromptScanner()
        result = scanner.scan(content, source=source)

        # 5. Record injection detection for circuit breaker
        if result.threats:
            circuit_breaker.record_detection(source_key)

        # 6. Log the scan result
        try:
            self.logger.log_prompt_scan(result)
        except Exception:
            _logger.debug("Failed to log scan result", exc_info=True)

        # 7. Sanitize user-controlled fields for safe frontend rendering
        response = result.model_dump(mode="json")
        for threat in response.get("threats", []):
            threat["matched_text"] = sanitize_text(
                threat.get("matched_text", "")
            )
            threat["description"] = sanitize_text(
                threat.get("description", "")
            )

        return response
