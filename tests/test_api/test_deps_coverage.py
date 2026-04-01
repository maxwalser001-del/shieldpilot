"""Coverage-hardening tests for sentinelai/api/deps.py.

Targets: get_current_user (API key, Bearer, local-first, no creds),
require_verified_email, require_admin, is_super_admin, get_user_tier_limits,
get_daily_usage_for_user, increment_command_usage, increment_scan_usage,
check_command_limit_for_user, check_scan_limit_for_user, require_feature,
reset_singletons.
"""

from __future__ import annotations

import hashlib
import os
import tempfile

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from sentinelai.api import deps
from sentinelai.api.auth import TokenData, create_access_token, hash_password
from sentinelai.core.config import (
    AuthConfig,
    BillingConfig,
    LoggingConfig,
    SentinelConfig,
    TIER_LIMITS,
)
from sentinelai.core.secrets import SecretsMasker
from sentinelai.logger import BlackboxLogger
from sentinelai.logger.database import Base, User, UsageRecord


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass


@pytest.fixture
def base_config():
    """Minimal config with auth secret, billing disabled, local_first off."""
    return SentinelConfig(
        logging=LoggingConfig(database=":memory:", chain_hashing=True),
        auth=AuthConfig(
            secret_key="test-deps-secret-key",
            default_admin_user="admin",
            default_admin_password="testpass",
            local_first=False,
            super_admin_email="super@example.com",
        ),
        billing=BillingConfig(enabled=False),
    )


@pytest.fixture
def app_and_logger(base_config, db_path):
    """Create a FastAPI app wired up with test config + logger, return (app, logger)."""
    deps.reset_singletons()
    masker = SecretsMasker(base_config.secrets_patterns)
    logger = BlackboxLogger(config=base_config.logging, masker=masker, db_path=db_path)
    deps._config = base_config
    deps._logger = logger
    from sentinelai.api.app import create_app
    application = create_app()
    yield application, logger
    deps.reset_singletons()


@pytest.fixture
def app(app_and_logger):
    return app_and_logger[0]


@pytest.fixture
def logger(app_and_logger):
    return app_and_logger[1]


@pytest.fixture
def client(app):
    return TestClient(app)


def _make_token(config: SentinelConfig, **overrides) -> str:
    """Helper: create a JWT for the given overrides."""
    data = TokenData(
        username=overrides.get("username", "testuser"),
        email=overrides.get("email", "test@example.com"),
        role=overrides.get("role", "viewer"),
        tier=overrides.get("tier", "free"),
        is_super_admin=overrides.get("is_super_admin", False),
        email_verified=overrides.get("email_verified", True),
    )
    token = create_access_token(data, config.auth)
    return token.access_token


def _seed_user(logger, **kwargs):
    """Insert a User row into the test DB. Returns the User object."""
    session = logger._get_session()
    try:
        user = User(
            username=kwargs.get("username", "testuser"),
            email=kwargs.get("email", "test@example.com"),
            password_hash=kwargs.get("password_hash"),
            role=kwargs.get("role", "viewer"),
            tier=kwargs.get("tier", "free"),
            is_super_admin=kwargs.get("is_super_admin", False),
            email_verified=kwargs.get("email_verified", True),
            api_key_hash=kwargs.get("api_key_hash"),
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        return user
    finally:
        session.close()


# ===================================================================
# 1. get_current_user — API key auth
# ===================================================================

class TestGetCurrentUserAPIKey:
    """get_current_user() with X-API-Key header."""

    def test_valid_api_key_returns_user(self, client, logger):
        raw_key = "sk-testapikey123456"
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        _seed_user(logger, username="apiuser", email="api@test.com",
                   api_key_hash=key_hash, role="analyst")

        resp = client.get("/api/auth/me", headers={"X-API-Key": raw_key})
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == "apiuser"
        assert data["email"] == "api@test.com"
        assert data["role"] == "analyst"

    def test_invalid_api_key_returns_401(self, client):
        resp = client.get("/api/auth/me", headers={"X-API-Key": "sk-bogus"})
        assert resp.status_code == 401
        assert "Invalid API key" in resp.json()["detail"]["error"]


# ===================================================================
# 2. get_current_user — Bearer token
# ===================================================================

class TestGetCurrentUserBearer:
    """get_current_user() with Authorization: Bearer <token>."""

    def test_valid_bearer_returns_user(self, client, base_config):
        token = _make_token(base_config, username="jwtuser", email="jwt@test.com", role="admin")
        resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["username"] == "jwtuser"

    def test_expired_token_returns_401(self, client, base_config):
        from datetime import timedelta
        data = TokenData(username="exp", email="exp@test.com", role="viewer")
        token = create_access_token(data, base_config.auth, expires_delta=timedelta(seconds=-1))
        resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token.access_token}"})
        assert resp.status_code == 401

    def test_garbage_token_returns_401(self, client):
        resp = client.get("/api/auth/me", headers={"Authorization": "Bearer not-a-jwt"})
        assert resp.status_code == 401


# ===================================================================
# 3. get_current_user — local-first bypass
# ===================================================================

class TestGetCurrentUserLocalFirst:
    """get_current_user() local-first bypass for localhost requests."""

    def test_local_first_enabled_returns_local_admin(self, db_path):
        """When local_first=True and request from localhost, no creds needed."""
        from unittest.mock import patch

        deps.reset_singletons()
        config = SentinelConfig(
            logging=LoggingConfig(database=":memory:", chain_hashing=True),
            auth=AuthConfig(
                secret_key="local-secret",
                local_first=True,
            ),
            billing=BillingConfig(enabled=False),
        )
        masker = SecretsMasker(config.secrets_patterns)
        lgr = BlackboxLogger(config=config.logging, masker=masker, db_path=db_path)
        deps._config = config
        deps._logger = lgr

        from sentinelai.api.app import create_app
        application = create_app()
        c = TestClient(application)

        # TestClient does not send from 127.0.0.1, so we patch the check
        with patch("sentinelai.api.deps._is_local_request", return_value=True):
            resp = c.get("/api/auth/me")
        assert resp.status_code == 200
        data = resp.json()
        assert data["username"] == "local-admin"
        assert data["role"] == "admin"

        deps.reset_singletons()


# ===================================================================
# 4. get_current_user — no credentials, not local
# ===================================================================

class TestGetCurrentUserNoCreds:
    """No credentials + not localhost = 401."""

    def test_no_creds_returns_401(self, client):
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401


# ===================================================================
# 5. require_verified_email
# ===================================================================

class TestRequireVerifiedEmail:
    """require_verified_email() dependency."""

    def test_unverified_user_gets_403(self, client, base_config):
        token = _make_token(base_config, email_verified=False)
        # /api/commands uses require_verified_email
        resp = client.get("/api/commands", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403

    def test_super_admin_bypasses_verification(self, client, base_config):
        token = _make_token(
            base_config,
            username="super",
            email="super@example.com",
            is_super_admin=True,
            email_verified=False,
            role="admin",
        )
        resp = client.get("/api/commands", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    def test_verified_user_passes(self, client, base_config):
        token = _make_token(base_config, email_verified=True, role="admin")
        resp = client.get("/api/commands", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200


# ===================================================================
# 6. require_admin
# ===================================================================

class TestRequireAdmin:
    """require_admin() dependency."""

    def test_non_admin_gets_403(self, client, base_config):
        token = _make_token(base_config, role="viewer", email_verified=True)
        # /api/config/summary requires admin role
        resp = client.get("/api/config/summary", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403

    def test_admin_passes(self, client, base_config):
        token = _make_token(base_config, role="admin", email_verified=True)
        resp = client.get("/api/config/summary", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200


# ===================================================================
# 7. is_super_admin
# ===================================================================

class TestIsSuperAdmin:
    """is_super_admin() logic."""

    def test_by_flag(self, base_config):
        user = TokenData(username="x", is_super_admin=True)
        assert deps.is_super_admin(user, base_config) is True

    def test_by_username_match(self, base_config):
        user = TokenData(username="super@example.com", is_super_admin=False)
        assert deps.is_super_admin(user, base_config) is True

    def test_by_email_match(self, base_config):
        user = TokenData(username="other", email="super@example.com", is_super_admin=False)
        assert deps.is_super_admin(user, base_config) is True

    def test_not_super_admin(self, base_config):
        user = TokenData(username="nobody", email="nobody@test.com", is_super_admin=False)
        assert deps.is_super_admin(user, base_config) is False


# ===================================================================
# 8. get_user_tier_limits
# ===================================================================

class TestGetUserTierLimits:
    """get_user_tier_limits() resolution."""

    def test_super_admin_gets_unlimited(self, base_config, logger):
        user = TokenData(username="super@example.com", is_super_admin=True, tier="free")
        tier, limits = deps.get_user_tier_limits(user, base_config, logger)
        assert tier == "unlimited"
        assert limits.commands_per_day == -1

    def test_billing_disabled_uses_token_tier(self, base_config, logger):
        user = TokenData(username="u", email="u@test.com", tier="pro")
        tier, limits = deps.get_user_tier_limits(user, base_config, logger)
        assert tier == "pro"
        assert limits == TIER_LIMITS["pro"]

    def test_billing_disabled_unknown_tier_falls_back_to_free(self, base_config, logger):
        user = TokenData(username="u", email="u@test.com", tier="nonexistent")
        tier, limits = deps.get_user_tier_limits(user, base_config, logger)
        assert tier == "nonexistent"
        assert limits == TIER_LIMITS["free"]

    def test_billing_enabled_reads_db(self, db_path):
        """When billing is enabled, tier is read from DB user row."""
        deps.reset_singletons()
        config = SentinelConfig(
            logging=LoggingConfig(database=":memory:", chain_hashing=True),
            auth=AuthConfig(secret_key="s", super_admin_email="sa@x.com"),
            billing=BillingConfig(enabled=True, tier="free"),
        )
        masker = SecretsMasker(config.secrets_patterns)
        lgr = BlackboxLogger(config=config.logging, masker=masker, db_path=db_path)

        # Seed a pro user with active subscription
        session = lgr._get_session()
        try:
            user_row = User(
                username="prouser", email="pro@test.com",
                role="viewer", tier="pro", subscription_status="active",
            )
            session.add(user_row)
            session.commit()
        finally:
            session.close()

        user = TokenData(username="prouser", email="pro@test.com", tier="free")
        tier, limits = deps.get_user_tier_limits(user, config, lgr)
        assert tier == "pro"
        assert limits == TIER_LIMITS["pro"]
        deps.reset_singletons()

    def test_billing_enabled_inactive_sub_downgrades_to_free(self, db_path):
        """Pro user with canceled subscription is downgraded to free."""
        deps.reset_singletons()
        config = SentinelConfig(
            logging=LoggingConfig(database=":memory:", chain_hashing=True),
            auth=AuthConfig(secret_key="s", super_admin_email="sa@x.com"),
            billing=BillingConfig(enabled=True, tier="free"),
        )
        masker = SecretsMasker(config.secrets_patterns)
        lgr = BlackboxLogger(config=config.logging, masker=masker, db_path=db_path)

        session = lgr._get_session()
        try:
            user_row = User(
                username="canceleduser", email="canceled@test.com",
                role="viewer", tier="pro", subscription_status="canceled",
            )
            session.add(user_row)
            session.commit()
        finally:
            session.close()

        user = TokenData(username="canceleduser", email="canceled@test.com", tier="free")
        tier, limits = deps.get_user_tier_limits(user, config, lgr)
        assert tier == "free"
        assert limits == TIER_LIMITS["free"]
        deps.reset_singletons()


# ===================================================================
# 9. get_daily_usage_for_user
# ===================================================================

class TestGetDailyUsageForUser:
    """get_daily_usage_for_user() usage stats."""

    def test_super_admin_gets_unlimited_usage_info(self, base_config, logger):
        user = TokenData(username="sa", email="super@example.com", is_super_admin=True, role="admin")
        info = deps.get_daily_usage_for_user(user, logger, base_config)
        assert info.tier == "unlimited"
        assert info.commands_limit == -1
        assert info.scans_limit == -1
        assert info.limit_reached is False
        assert info.is_admin is True

    def test_regular_user_queries_db(self, base_config, logger):
        user = TokenData(username="reg", email="reg@test.com", tier="free", role="viewer")
        info = deps.get_daily_usage_for_user(user, logger, base_config)
        assert info.tier == "free"
        assert info.commands_used == 0
        assert info.scans_used == 0
        assert info.is_admin is False


# ===================================================================
# 10. increment_command_usage
# ===================================================================

class TestIncrementCommandUsage:
    """increment_command_usage() creates or updates usage record."""

    def test_creates_new_record(self, logger):
        from datetime import date
        deps.increment_command_usage(logger)

        session = logger._get_session()
        try:
            today = date.today().isoformat()
            usage = session.query(UsageRecord).filter(
                UsageRecord.date == today, UsageRecord.tenant_id == None
            ).first()
            assert usage is not None
            assert usage.commands_evaluated == 1
        finally:
            session.close()

    def test_increments_existing_record(self, logger):
        from datetime import date
        # First call creates
        deps.increment_command_usage(logger)
        # Second call increments
        deps.increment_command_usage(logger)

        session = logger._get_session()
        try:
            today = date.today().isoformat()
            usage = session.query(UsageRecord).filter(
                UsageRecord.date == today, UsageRecord.tenant_id == None
            ).first()
            assert usage.commands_evaluated == 2
        finally:
            session.close()


# ===================================================================
# 11. increment_scan_usage
# ===================================================================

class TestIncrementScanUsage:
    """increment_scan_usage() creates or updates usage record."""

    def test_creates_new_record(self, logger):
        from datetime import date
        deps.increment_scan_usage(logger)

        session = logger._get_session()
        try:
            today = date.today().isoformat()
            usage = session.query(UsageRecord).filter(
                UsageRecord.date == today, UsageRecord.tenant_id == None
            ).first()
            assert usage is not None
            assert usage.scans_performed == 1
        finally:
            session.close()

    def test_increments_existing_record(self, logger):
        from datetime import date
        deps.increment_scan_usage(logger)
        deps.increment_scan_usage(logger)

        session = logger._get_session()
        try:
            today = date.today().isoformat()
            usage = session.query(UsageRecord).filter(
                UsageRecord.date == today, UsageRecord.tenant_id == None
            ).first()
            assert usage.scans_performed == 2
        finally:
            session.close()


# ===================================================================
# 12. check_command_limit_for_user
# ===================================================================

class TestCheckCommandLimitForUser:
    """check_command_limit_for_user() billing enforcement."""

    def test_super_admin_bypasses(self, base_config, logger):
        user = TokenData(username="sa", is_super_admin=True)
        # Should not raise, even if billing is on
        deps.check_command_limit_for_user(user, base_config, logger)

    def test_billing_disabled_no_enforcement(self, base_config, logger):
        user = TokenData(username="u", email="u@test.com", tier="free")
        # Billing is disabled in base_config, so no exception
        deps.check_command_limit_for_user(user, base_config, logger)

    def test_limit_exceeded_raises_429(self, db_path):
        """When billing is enabled and limit is hit, raises 429."""
        deps.reset_singletons()
        config = SentinelConfig(
            logging=LoggingConfig(database=":memory:", chain_hashing=True),
            auth=AuthConfig(secret_key="s", super_admin_email="sa@x.com"),
            billing=BillingConfig(enabled=True, tier="free"),
        )
        masker = SecretsMasker(config.secrets_patterns)
        lgr = BlackboxLogger(config=config.logging, masker=masker, db_path=db_path)

        # Seed usage to exceed free tier limit (50 commands)
        from datetime import date
        session = lgr._get_session()
        try:
            usage = UsageRecord(
                user_email="u@test.com",
                date=date.today().isoformat(),
                commands_evaluated=50,
                scans_performed=0,
                llm_calls=0,
                api_requests=0,
            )
            session.add(usage)
            session.commit()
        finally:
            session.close()

        user = TokenData(username="u", email="u@test.com", tier="free")
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            deps.check_command_limit_for_user(user, config, lgr)
        assert exc_info.value.status_code == 429
        deps.reset_singletons()


# ===================================================================
# 13. check_scan_limit_for_user
# ===================================================================

class TestCheckScanLimitForUser:
    """check_scan_limit_for_user() billing enforcement."""

    def test_super_admin_bypasses(self, base_config, logger):
        user = TokenData(username="sa", is_super_admin=True)
        deps.check_scan_limit_for_user(user, base_config, logger)

    def test_billing_disabled_no_enforcement(self, base_config, logger):
        user = TokenData(username="u", email="u@test.com", tier="free")
        deps.check_scan_limit_for_user(user, base_config, logger)

    def test_limit_exceeded_raises_429(self, db_path):
        """When billing is enabled and scan limit is hit, raises 429."""
        deps.reset_singletons()
        config = SentinelConfig(
            logging=LoggingConfig(database=":memory:", chain_hashing=True),
            auth=AuthConfig(secret_key="s", super_admin_email="sa@x.com"),
            billing=BillingConfig(enabled=True, tier="free"),
        )
        masker = SecretsMasker(config.secrets_patterns)
        lgr = BlackboxLogger(config=config.logging, masker=masker, db_path=db_path)

        # Seed per-user usage record to exceed free tier scan limit (10 scans)
        from datetime import date as _date

        session = lgr._get_session()
        try:
            usage = UsageRecord(
                user_email="u@test.com",
                date=_date.today().isoformat(),
                commands_evaluated=0,
                scans_performed=10,
                llm_calls=0,
                api_requests=0,
            )
            session.add(usage)
            session.commit()
        finally:
            session.close()

        user = TokenData(username="u", email="u@test.com", tier="free")
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            deps.check_scan_limit_for_user(user, config, lgr)
        assert exc_info.value.status_code == 429
        deps.reset_singletons()


# ===================================================================
# 14. require_feature
# ===================================================================

class TestRequireFeature:
    """require_feature() dependency factory."""

    def test_feature_disabled_raises_403(self, db_path):
        """Free tier user cannot access export_enabled feature."""
        deps.reset_singletons()
        config = SentinelConfig(
            logging=LoggingConfig(database=":memory:", chain_hashing=True),
            auth=AuthConfig(secret_key="feat-secret", local_first=False),
            billing=BillingConfig(enabled=True, tier="free"),
        )
        masker = SecretsMasker(config.secrets_patterns)
        lgr = BlackboxLogger(config=config.logging, masker=masker, db_path=db_path)
        deps._config = config
        deps._logger = lgr

        # Build a minimal app with a route guarded by require_feature
        test_app = FastAPI()

        @test_app.get("/feature-test", dependencies=[Depends(deps.require_feature("export_enabled"))])
        async def feature_endpoint(user=Depends(deps.get_current_user)):
            return {"ok": True}

        # Include the deps overrides
        c = TestClient(test_app)
        token = _make_token(config, tier="free", email_verified=True)
        resp = c.get("/feature-test", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403
        assert "export_enabled" in resp.json()["detail"]["error"]
        deps.reset_singletons()

    def test_super_admin_bypasses_feature_check(self, db_path):
        """Super admin can access any feature regardless of tier."""
        deps.reset_singletons()
        config = SentinelConfig(
            logging=LoggingConfig(database=":memory:", chain_hashing=True),
            auth=AuthConfig(
                secret_key="feat-secret",
                local_first=False,
                super_admin_email="sa@test.com",
            ),
            billing=BillingConfig(enabled=True, tier="free"),
        )
        masker = SecretsMasker(config.secrets_patterns)
        lgr = BlackboxLogger(config=config.logging, masker=masker, db_path=db_path)
        deps._config = config
        deps._logger = lgr

        test_app = FastAPI()

        @test_app.get("/feature-test", dependencies=[Depends(deps.require_feature("export_enabled"))])
        async def feature_endpoint(user=Depends(deps.get_current_user)):
            return {"ok": True}

        c = TestClient(test_app)
        token = _make_token(
            config, tier="free", email="sa@test.com", is_super_admin=True,
        )
        resp = c.get("/feature-test", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        deps.reset_singletons()

    def test_billing_disabled_allows_all_features(self, client, base_config):
        """When billing is disabled, all features are allowed."""
        token = _make_token(base_config, tier="free", email_verified=True, role="admin")
        # Export endpoint requires export_enabled feature
        resp = client.get("/api/export/commands?format=csv", headers={"Authorization": f"Bearer {token}"})
        # Should not return 403 (may return 200 or other non-403 status)
        assert resp.status_code != 403


# ===================================================================
# 15. reset_singletons
# ===================================================================

class TestResetSingletons:
    """reset_singletons() clears cached config and logger."""

    def test_resets_to_none(self):
        # Set something
        deps._config = "fake_config"
        deps._logger = "fake_logger"

        deps.reset_singletons()

        assert deps._config is None
        assert deps._logger is None
