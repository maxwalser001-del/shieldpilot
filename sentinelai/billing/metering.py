"""Usage metering for SaaS billing.

Tracks command evaluations, scans, LLM calls, and API requests per tenant.
Enforces tier-based rate limits.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from sentinelai.core.config import BillingConfig
from sentinelai.core.exceptions import RateLimitError
from sentinelai.logger.database import UsageRecord


# Tier limits — derived from canonical source in config.py
from sentinelai.core.config import TIER_LIMITS as _CANONICAL_LIMITS

TIER_LIMITS = {
    tier: {
        "commands_per_day": lim.commands_per_day,
        "scans_per_day": lim.scans_per_day,
        "llm_calls_per_day": -1 if tier in ("pro_plus", "unlimited") else (10 if tier == "free" else 1000),
    }
    for tier, lim in _CANONICAL_LIMITS.items()
}


class UsageMeter:
    """Tracks and enforces usage limits per tenant."""

    def __init__(self, session_factory, billing_config: Optional[BillingConfig] = None):
        self._Session = session_factory
        self.config = billing_config

    def _today(self) -> str:
        return datetime.utcnow().strftime("%Y-%m-%d")

    def _get_or_create_record(
        self, session: Session, tenant_id: str
    ) -> UsageRecord:
        """Get or create today's usage record for a tenant."""
        today = self._today()
        record = (
            session.query(UsageRecord)
            .filter(
                UsageRecord.tenant_id == tenant_id,
                UsageRecord.date == today,
            )
            .first()
        )

        if record is None:
            record = UsageRecord(
                tenant_id=tenant_id,
                date=today,
                commands_evaluated=0,
                scans_performed=0,
                llm_calls=0,
                api_requests=0,
            )
            session.add(record)

        return record

    def record_command(self, tenant_id: str, tier: str = "free") -> None:
        """Record a command evaluation. Raises RateLimitError if over limit."""
        session = self._Session()
        try:
            record = self._get_or_create_record(session, tenant_id)
            limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])

            if limits["commands_per_day"] > 0 and record.commands_evaluated >= limits["commands_per_day"]:
                raise RateLimitError("commands_per_day", limits["commands_per_day"])

            record.commands_evaluated += 1
            session.commit()
        finally:
            session.close()

    def record_scan(self, tenant_id: str, tier: str = "free") -> None:
        """Record a prompt scan."""
        session = self._Session()
        try:
            record = self._get_or_create_record(session, tenant_id)
            limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])

            if limits["scans_per_day"] > 0 and record.scans_performed >= limits["scans_per_day"]:
                raise RateLimitError("scans_per_day", limits["scans_per_day"])

            record.scans_performed += 1
            session.commit()
        finally:
            session.close()

    def record_llm_call(self, tenant_id: str, tier: str = "free") -> None:
        """Record an LLM API call."""
        session = self._Session()
        try:
            record = self._get_or_create_record(session, tenant_id)
            limits = TIER_LIMITS.get(tier, TIER_LIMITS["free"])

            if limits["llm_calls_per_day"] > 0 and record.llm_calls >= limits["llm_calls_per_day"]:
                raise RateLimitError("llm_calls_per_day", limits["llm_calls_per_day"])

            record.llm_calls += 1
            session.commit()
        finally:
            session.close()

    def record_api_request(self, tenant_id: str) -> None:
        """Record an API request (no limit enforced)."""
        session = self._Session()
        try:
            record = self._get_or_create_record(session, tenant_id)
            record.api_requests += 1
            session.commit()
        finally:
            session.close()

    def get_usage(self, tenant_id: str) -> dict:
        """Get today's usage for a tenant."""
        session = self._Session()
        try:
            record = self._get_or_create_record(session, tenant_id)
            return {
                "date": record.date,
                "commands_evaluated": record.commands_evaluated,
                "scans_performed": record.scans_performed,
                "llm_calls": record.llm_calls,
                "api_requests": record.api_requests,
            }
        finally:
            session.close()
