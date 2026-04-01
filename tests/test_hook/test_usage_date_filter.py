"""Tests for date-based usage counting in sentinel_hook.

Verifies that _check_usage_limit() and _increment_usage() correctly
operate on today's date only, so yesterday's usage does not count
against today's limit.
"""

from __future__ import annotations

import os
import tempfile
from datetime import date, timedelta
from unittest.mock import patch

import pytest

from sentinelai.core.config import (
    AuthConfig,
    BillingConfig,
    LoggingConfig,
    SentinelConfig,
    WhitelistConfig,
)
from sentinelai.logger.database import Base, UsageRecord, init_database


@pytest.fixture
def usage_db():
    """Create a temporary database with usage table for testing."""
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine, Session = init_database(db_path)
    Base.metadata.create_all(engine)
    yield db_path, Session
    try:
        os.unlink(db_path)
    except OSError:
        pass


@pytest.fixture
def billing_config(usage_db):
    """Config with billing enabled and a known DB path."""
    db_path, _ = usage_db
    return SentinelConfig(
        mode="enforce",
        whitelist=WhitelistConfig(commands=["ls", "cat"]),
        logging=LoggingConfig(database=db_path, chain_hashing=True),
        auth=AuthConfig(secret_key="test-key", local_first=False),
        billing=BillingConfig(enabled=True, tier="free"),  # 50 commands/day
    )


class TestUsageDateFiltering:
    """Verify that usage counting is date-scoped."""

    def test_yesterdays_usage_does_not_count_today(self, usage_db, billing_config):
        """Commands from yesterday should not affect today's limit check."""
        from sentinelai.hooks.sentinel_hook import _check_usage_limit

        db_path, Session = usage_db
        session = Session()

        # Insert 100 commands for yesterday (exceeds free tier limit of 50)
        yesterday = (date.today() - timedelta(days=1)).isoformat()
        old_usage = UsageRecord(
            tenant_id=None,
            date=yesterday,
            commands_evaluated=100,
            scans_performed=0,
            llm_calls=0,
            api_requests=0,
        )
        session.add(old_usage)
        session.commit()
        session.close()

        # Today should not be limited
        reached, msg = _check_usage_limit(billing_config)
        assert reached is False
        assert msg == ""

    def test_todays_usage_counts_correctly(self, usage_db, billing_config):
        """Commands from today should count towards today's limit."""
        from sentinelai.hooks.sentinel_hook import _check_usage_limit

        db_path, Session = usage_db
        session = Session()

        # Insert 50 commands for today (exactly at free tier limit)
        today = date.today().isoformat()
        usage = UsageRecord(
            tenant_id=None,
            date=today,
            commands_evaluated=50,
            scans_performed=0,
            llm_calls=0,
            api_requests=0,
        )
        session.add(usage)
        session.commit()
        session.close()

        # Today should be limited
        reached, msg = _check_usage_limit(billing_config)
        assert reached is True
        assert "50" in msg

    def test_increment_creates_new_row_per_day(self, usage_db, billing_config):
        """_increment_usage() should create separate rows for each day."""
        from sentinelai.hooks.sentinel_hook import _increment_usage

        db_path, Session = usage_db
        session = Session()

        # Insert yesterday's row
        yesterday = (date.today() - timedelta(days=1)).isoformat()
        old_usage = UsageRecord(
            tenant_id=None,
            date=yesterday,
            commands_evaluated=42,
            scans_performed=0,
            llm_calls=0,
            api_requests=0,
        )
        session.add(old_usage)
        session.commit()
        session.close()

        # Increment today
        _increment_usage(billing_config)

        # Verify: yesterday untouched, today has 1
        session = Session()
        today = date.today().isoformat()

        yesterday_row = (
            session.query(UsageRecord)
            .filter(UsageRecord.date == yesterday, UsageRecord.tenant_id == None)
            .first()
        )
        today_row = (
            session.query(UsageRecord)
            .filter(UsageRecord.date == today, UsageRecord.tenant_id == None)
            .first()
        )
        session.close()

        assert yesterday_row is not None
        assert yesterday_row.commands_evaluated == 42  # Unchanged
        assert today_row is not None
        assert today_row.commands_evaluated == 1  # New row for today

    def test_increment_adds_to_existing_today_row(self, usage_db, billing_config):
        """_increment_usage() should increment existing today row, not create duplicate."""
        from sentinelai.hooks.sentinel_hook import _increment_usage

        db_path, Session = usage_db

        # Increment twice
        _increment_usage(billing_config)
        _increment_usage(billing_config)

        session = Session()
        today = date.today().isoformat()
        rows = (
            session.query(UsageRecord)
            .filter(UsageRecord.date == today, UsageRecord.tenant_id == None)
            .all()
        )
        session.close()

        assert len(rows) == 1  # Only one row, not two
        assert rows[0].commands_evaluated == 2

    def test_billing_disabled_skips_limit_check(self, usage_db):
        """When billing is disabled, limit check always returns False."""
        from sentinelai.hooks.sentinel_hook import _check_usage_limit

        db_path, _ = usage_db
        config = SentinelConfig(
            mode="enforce",
            logging=LoggingConfig(database=db_path),
            auth=AuthConfig(secret_key="test-key"),
            billing=BillingConfig(enabled=False),
        )
        reached, msg = _check_usage_limit(config)
        assert reached is False

    def test_unlimited_tier_never_limited(self, usage_db):
        """Unlimited tier (commands_per_day = -1) should never be limited."""
        from sentinelai.hooks.sentinel_hook import _check_usage_limit

        db_path, Session = usage_db
        config = SentinelConfig(
            mode="enforce",
            logging=LoggingConfig(database=db_path),
            auth=AuthConfig(secret_key="test-key"),
            billing=BillingConfig(enabled=True, tier="unlimited"),
        )

        # Even with huge usage count, unlimited should not be limited
        session = Session()
        today = date.today().isoformat()
        usage = UsageRecord(
            tenant_id=None,
            date=today,
            commands_evaluated=999999,
            scans_performed=0,
            llm_calls=0,
            api_requests=0,
        )
        session.add(usage)
        session.commit()
        session.close()

        reached, msg = _check_usage_limit(config)
        assert reached is False
