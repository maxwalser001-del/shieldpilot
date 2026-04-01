"""Tests for the 80% billing approaching-limit warning.

Verifies that UsageInfo includes approaching_limit=True when usage
reaches 80% of the daily limit, and that it respects billing state.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentinelai.api.app import create_app
from sentinelai.api import deps
from sentinelai.core.config import SentinelConfig
from sentinelai.core.secrets import SecretsMasker
from sentinelai.logger import BlackboxLogger


@pytest.fixture
def app(test_config, db_path):
    """Create a test FastAPI app with test config."""
    deps.reset_singletons()
    masker = SecretsMasker(test_config.secrets_patterns)
    logger = BlackboxLogger(config=test_config.logging, masker=masker, db_path=db_path)
    deps._config = test_config
    deps._logger = logger
    application = create_app()
    yield application
    deps.reset_singletons()


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def auth_headers(client, test_config):
    """Get auth headers by logging in."""
    response = client.post("/api/auth/login", json={
        "username": test_config.auth.default_admin_user,
        "password": test_config.auth.default_admin_password,
    })
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _set_usage(logger, commands: int, scans: int = 0):
    """Set today's usage to specific values."""
    from datetime import date
    from sentinelai.logger.database import UsageRecord

    session = logger._get_session()
    today = date.today().isoformat()

    usage = (
        session.query(UsageRecord)
        .filter(UsageRecord.date == today, UsageRecord.tenant_id == None)
        .first()
    )
    if usage:
        usage.commands_evaluated = commands
        usage.scans_performed = scans
    else:
        usage = UsageRecord(
            tenant_id=None,
            date=today,
            commands_evaluated=commands,
            scans_performed=scans,
            llm_calls=0,
            api_requests=0,
        )
        session.add(usage)
    session.commit()
    session.close()


class TestApproachingLimit:
    """Test the approaching_limit field in /api/usage response."""

    def test_below_80_percent(self, client, auth_headers, test_config):
        """Usage at 79% should NOT trigger approaching_limit."""
        test_config.billing.enabled = True
        logger = deps._logger
        # Free tier: 50 commands/day. 79% = 39 commands
        _set_usage(logger, commands=39)

        resp = client.get("/api/usage", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["approaching_limit"] is False

    def test_at_80_percent(self, client, auth_headers, test_config):
        """Usage at exactly 80% should trigger approaching_limit."""
        test_config.billing.enabled = True
        logger = deps._logger
        # Free tier: 50 commands/day. 80% = 40 commands
        _set_usage(logger, commands=40)

        resp = client.get("/api/usage", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["approaching_limit"] is True
        assert data["limit_reached"] is False

    def test_at_100_percent(self, client, auth_headers, test_config):
        """Usage at 100% should have both approaching_limit and limit_reached."""
        test_config.billing.enabled = True
        logger = deps._logger
        _set_usage(logger, commands=50)

        resp = client.get("/api/usage", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["approaching_limit"] is True
        assert data["limit_reached"] is True

    def test_billing_disabled(self, client, auth_headers, test_config):
        """With billing disabled, approaching_limit should always be False."""
        test_config.billing.enabled = False
        logger = deps._logger
        _set_usage(logger, commands=45)

        resp = client.get("/api/usage", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["approaching_limit"] is False
        assert data["limit_reached"] is False

    def test_zero_usage(self, client, auth_headers, test_config):
        """No usage should not trigger approaching_limit."""
        test_config.billing.enabled = True
        logger = deps._logger
        _set_usage(logger, commands=0)

        resp = client.get("/api/usage", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["approaching_limit"] is False
