"""Tests for Phase 8 — Account Management: Tier-Lifecycle & Stripe-Integration."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from sentinelai.api.app import create_app
from sentinelai.api import deps
from sentinelai.api.auth import TokenData
from sentinelai.core.config import load_config, TIER_LIMITS, BillingConfig


@pytest.fixture
def billing_config(test_config):
    """Test config with billing enabled so tier enforcement is active."""
    test_config.billing.enabled = True
    # Set super-admin credentials so admin login works
    test_config.auth.super_admin_email = "admin@shieldpilot.dev"
    test_config.auth.super_admin_password = "TestAdminPass123!"
    test_config.auth.super_admin_username = "MaxtheCreator"
    return test_config


@pytest.fixture
def app(billing_config, db_path):
    """Create a test FastAPI app with billing-enabled config."""
    from sentinelai.core.secrets import SecretsMasker
    from sentinelai.logger import BlackboxLogger

    deps.reset_singletons()

    masker = SecretsMasker(billing_config.secrets_patterns)
    logger = BlackboxLogger(config=billing_config.logging, masker=masker, db_path=db_path)

    deps._config = billing_config
    deps._logger = logger

    application = create_app()
    yield application

    deps.reset_singletons()


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
def admin_headers(client):
    """Login as super-admin."""
    resp = client.post("/api/auth/login", json={
        "username": "admin@shieldpilot.dev",
        "password": "TestAdminPass123!",
    })
    assert resp.status_code == 200, f"Admin login failed: {resp.text}"
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def user_headers(client, db_path):
    """Register and login as a normal user with verified email."""
    email = f"billing-test-{uuid.uuid4().hex[:8]}@test.com"
    resp = client.post("/api/auth/register", json={
        "email": email,
        "password": "testpass123",
        "tos_accepted": True,
    })
    assert resp.status_code == 200, f"Register failed: {resp.text}"
    token = resp.json()["access_token"]

    # Mark user email as verified so endpoints that require it work
    from sentinelai.logger.database import init_database, User
    _, Session = init_database(db_path)
    session = Session()
    try:
        db_user = session.query(User).filter(User.email == email).first()
        db_user.email_verified = True
        session.commit()
    finally:
        session.close()

    # Re-login to get a token with email_verified=True
    resp = client.post("/api/auth/login", json={
        "username": email,
        "password": "testpass123",
    })
    assert resp.status_code == 200, f"Re-login failed: {resp.text}"
    token = resp.json()["access_token"]

    return {"Authorization": f"Bearer {token}", "_email": email}


def _get_session(db_path):
    """Get a DB session for assertions."""
    from sentinelai.logger.database import init_database
    _, Session = init_database(db_path)
    return Session()


# ── Grace Period Tests ───────────────────────────────────────────


class TestGracePeriod:
    """Test that past_due does NOT immediately downgrade tier (grace period)."""

    def test_past_due_keeps_tier(self, client, user_headers, db_path):
        """User with tier=pro and subscription_status=past_due should keep pro access."""
        from sentinelai.logger.database import User

        session = _get_session(db_path)
        try:
            email = user_headers["_email"]
            db_user = session.query(User).filter(User.email == email).first()
            assert db_user is not None
            db_user.tier = "pro"
            db_user.subscription_status = "past_due"
            db_user.stripe_subscription_id = "sub_test_123"
            session.commit()

            # Verify via settings API that tier is still pro
            resp = client.get("/api/settings", headers=user_headers)
            assert resp.status_code == 200
            data = resp.json()
            assert data["tier"] == "pro"
            assert data["subscription_status"] == "past_due"
        finally:
            session.close()

    def test_unpaid_downgrades_tier(self, client, user_headers, db_path):
        """User with subscription_status=unpaid should be downgraded to free."""
        from sentinelai.logger.database import User

        session = _get_session(db_path)
        try:
            email = user_headers["_email"]
            db_user = session.query(User).filter(User.email == email).first()
            db_user.tier = "pro"
            db_user.subscription_status = "unpaid"
            db_user.stripe_subscription_id = "sub_test_456"
            session.commit()

            # The usage endpoint should resolve to free because unpaid is not in active_statuses
            resp = client.get("/api/usage", headers=user_headers)
            assert resp.status_code == 200
            data = resp.json()
            assert data["tier"] == "free"
        finally:
            session.close()

    def test_active_keeps_tier(self, client, user_headers, db_path):
        """User with subscription_status=active should keep their tier (enterprise→pro_plus)."""
        from sentinelai.logger.database import User

        session = _get_session(db_path)
        try:
            email = user_headers["_email"]
            db_user = session.query(User).filter(User.email == email).first()
            db_user.tier = "pro_plus"
            db_user.subscription_status = "active"
            db_user.stripe_subscription_id = "sub_test_789"
            session.commit()

            resp = client.get("/api/usage", headers=user_headers)
            assert resp.status_code == 200
            data = resp.json()
            assert data["tier"] == "pro_plus"
        finally:
            session.close()

    def test_enterprise_maps_to_pro_plus(self, client, user_headers, db_path):
        """Legacy enterprise tier should map to pro_plus."""
        from sentinelai.logger.database import User

        session = _get_session(db_path)
        try:
            email = user_headers["_email"]
            db_user = session.query(User).filter(User.email == email).first()
            db_user.tier = "enterprise"
            db_user.subscription_status = "active"
            db_user.stripe_subscription_id = "sub_test_legacy"
            session.commit()

            resp = client.get("/api/usage", headers=user_headers)
            assert resp.status_code == 200
            data = resp.json()
            assert data["tier"] == "pro_plus"
        finally:
            session.close()


# ── Admin Tier Override Tests ────────────────────────────────────


class TestAdminTierOverride:
    """Test admin tier override endpoint."""

    def test_admin_can_set_tier(self, client, admin_headers, user_headers, db_path):
        """Admin can manually set a user's tier."""
        email = user_headers["_email"]
        resp = client.post("/api/admin/users/tier", json={
            "email": email,
            "tier": "pro",
            "reason": "testing",
        }, headers=admin_headers)
        assert resp.status_code == 200
        assert "pro" in resp.json()["message"]

        # Verify the tier was changed
        from sentinelai.logger.database import User
        session = _get_session(db_path)
        try:
            db_user = session.query(User).filter(User.email == email).first()
            assert db_user.tier == "pro"
            assert db_user.subscription_status == "active"  # Manual override sets active
        finally:
            session.close()

    def test_non_admin_rejected(self, client, user_headers):
        """Non-admin users cannot set tiers."""
        resp = client.post("/api/admin/users/tier", json={
            "email": "someone@test.com",
            "tier": "pro",
        }, headers=user_headers)
        assert resp.status_code == 403

    def test_cannot_modify_super_admin(self, client, admin_headers):
        """Cannot modify super-admin's tier."""
        resp = client.post("/api/admin/users/tier", json={
            "email": "admin@shieldpilot.dev",
            "tier": "free",
        }, headers=admin_headers)
        assert resp.status_code == 400
        assert "super-admin" in resp.json()["detail"]["error"].lower()

    def test_invalid_tier_rejected(self, client, admin_headers, user_headers):
        """Invalid tier names are rejected."""
        email = user_headers["_email"]
        resp = client.post("/api/admin/users/tier", json={
            "email": email,
            "tier": "platinum",
        }, headers=admin_headers)
        assert resp.status_code == 400


# ── Settings Subscription Info Tests ─────────────────────────────


class TestSettingsSubscriptionInfo:
    """Test that settings endpoint includes subscription info."""

    def test_settings_includes_subscription_fields(self, client, user_headers):
        """Settings response should include subscription-related fields."""
        resp = client.get("/api/settings", headers=user_headers)
        assert resp.status_code == 200
        data = resp.json()
        # These fields should exist (even if None/False for free users)
        assert "subscription_status" in data
        assert "cancel_at_period_end" in data
        assert "current_period_end" in data
        assert "has_subscription" in data

    def test_settings_tier_from_db(self, client, user_headers, db_path):
        """Settings tier should come from DB, not JWT."""
        from sentinelai.logger.database import User

        # Modify the DB tier directly (simulating a webhook update)
        session = _get_session(db_path)
        try:
            email = user_headers["_email"]
            db_user = session.query(User).filter(User.email == email).first()
            db_user.tier = "pro"
            db_user.subscription_status = "active"
            db_user.stripe_subscription_id = "sub_test_db"
            session.commit()
        finally:
            session.close()

        # JWT still has "free" but settings should return "pro"
        resp = client.get("/api/settings", headers=user_headers)
        assert resp.status_code == 200
        assert resp.json()["tier"] == "pro"


# ── Pricing DB Tier Tests ────────────────────────────────────────


class TestPricingDbTier:
    """Test that pricing endpoint reads tier from DB."""

    def test_pricing_reads_db_tier(self, client, user_headers, db_path):
        """Pricing should show current_tier from DB (enterprise→pro_plus)."""
        from sentinelai.logger.database import User

        session = _get_session(db_path)
        try:
            email = user_headers["_email"]
            db_user = session.query(User).filter(User.email == email).first()
            db_user.tier = "pro_plus"
            db_user.subscription_status = "active"
            db_user.stripe_subscription_id = "sub_test_pricing"
            session.commit()
        finally:
            session.close()

        resp = client.get("/api/billing/pricing", headers=user_headers)
        assert resp.status_code == 200
        assert resp.json()["current_tier"] == "pro_plus"

    def test_pricing_enterprise_maps_to_pro_plus(self, client, user_headers, db_path):
        """Legacy enterprise tier should display as pro_plus in pricing."""
        from sentinelai.logger.database import User

        session = _get_session(db_path)
        try:
            email = user_headers["_email"]
            db_user = session.query(User).filter(User.email == email).first()
            db_user.tier = "enterprise"
            db_user.subscription_status = "active"
            db_user.stripe_subscription_id = "sub_test_legacy_pricing"
            session.commit()
        finally:
            session.close()

        resp = client.get("/api/billing/pricing", headers=user_headers)
        assert resp.status_code == 200
        assert resp.json()["current_tier"] == "pro_plus"

    def test_pricing_has_three_tiers(self, client, user_headers):
        """Pricing should return exactly 3 tiers: free, pro, pro_plus."""
        resp = client.get("/api/billing/pricing", headers=user_headers)
        assert resp.status_code == 200
        tiers = resp.json()["tiers"]
        assert set(tiers.keys()) == {"free", "pro", "pro_plus"}
        assert tiers["pro"]["price_monthly"] == 19.99
        assert tiers["pro_plus"]["price_monthly"] == 29.99
        assert tiers["pro_plus"]["name"] == "Pro+"


# ── Delete Account + Stripe Tests ────────────────────────────────


class TestDeleteAccountStripe:
    """Test that account deletion cancels Stripe subscription."""

    def test_delete_cancels_stripe(self, billing_config, db_path):
        """Deleting an account with a Stripe subscription should cancel it."""
        from unittest.mock import patch, MagicMock
        from sentinelai.core.secrets import SecretsMasker
        from sentinelai.logger import BlackboxLogger
        from sentinelai.logger.database import User

        # Need a config with stripe_secret_key set so the deletion code path fires
        billing_config.billing.stripe_secret_key = "sk_test_fake_key"

        deps.reset_singletons()
        masker = SecretsMasker(billing_config.secrets_patterns)
        logger = BlackboxLogger(config=billing_config.logging, masker=masker, db_path=db_path)
        deps._config = billing_config
        deps._logger = logger
        application = create_app()
        client = TestClient(application)

        email = f"delete-stripe-{uuid.uuid4().hex[:8]}@test.com"
        password = "deletepass123"

        # Register user
        resp = client.post("/api/auth/register", json={
            "email": email,
            "password": password,
            "tos_accepted": True,
        })
        assert resp.status_code == 200
        token = resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Set up Stripe subscription in DB
        from sentinelai.logger.database import init_database
        _, Session = init_database(db_path)
        session = Session()
        try:
            db_user = session.query(User).filter(User.email == email).first()
            db_user.stripe_subscription_id = "sub_to_cancel_123"
            db_user.stripe_customer_id = "cus_test_123"
            session.commit()
        finally:
            session.close()

        with patch("sentinelai.billing.stripe_stub.StripeClient.cancel_subscription") as mock_cancel:
            mock_cancel.return_value = {"id": "sub_to_cancel_123", "status": "canceled"}

            # Delete account
            resp = client.request("DELETE", "/api/settings/account", json={
                "password": password,
            }, headers=headers)
            assert resp.status_code == 200

            # Verify cancel_subscription was called
            mock_cancel.assert_called_once_with("sub_to_cancel_123")

        deps.reset_singletons()

    def test_delete_without_stripe(self, client):
        """Deleting an account without Stripe subscription should work fine."""
        email = f"delete-nostripe-{uuid.uuid4().hex[:8]}@test.com"
        password = "deletepass123"

        resp = client.post("/api/auth/register", json={
            "email": email,
            "password": password,
            "tos_accepted": True,
        })
        assert resp.status_code == 200
        token = resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        resp = client.request("DELETE", "/api/settings/account", json={
            "password": password,
        }, headers=headers)
        assert resp.status_code == 200


# ── Stripe Health Tests ──────────────────────────────────────────


class TestStripeHealth:
    """Test Stripe health check endpoint."""

    def test_stripe_health_requires_admin(self, client, user_headers):
        """Non-admin users cannot access Stripe health."""
        resp = client.get("/api/admin/stripe-health", headers=user_headers)
        assert resp.status_code == 403

    def test_stripe_health_admin(self, client, admin_headers):
        """Admin can access Stripe health (returns not_configured in test)."""
        resp = client.get("/api/admin/stripe-health", headers=admin_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] in ("not_configured", "ok", "error")


# ── Config Default Tests ───────────────────────────────────────


class TestConfigDefault:
    """Test that config defaults give free tier to new users."""

    def test_config_default_tier_is_free(self):
        """load_config() should return tier='free'."""
        config = load_config()
        assert config.billing.tier == "free"

    def test_new_user_gets_free_tier_limits(self, client, user_headers, billing_config, db_path):
        """A new registered user without explicit DB tier gets free limits (50 cmd/10 scan)."""
        from sentinelai.api.deps import get_user_tier_limits, get_logger
        from sentinelai.api.auth import TokenData as TD

        logger = get_logger()
        # The user_headers fixture creates a user with no explicit tier set
        email = user_headers["_email"]
        user = TD(username=email, email=email, role="user", email_verified=True)

        tier, limits = get_user_tier_limits(user, billing_config, logger)
        assert tier == "free"
        assert limits.commands_per_day == 50
        assert limits.scans_per_day == 10

    def test_super_admin_gets_unlimited(self, billing_config):
        """Super-admin always gets unlimited tier regardless of config."""
        from sentinelai.api.deps import get_user_tier_limits, get_logger, is_super_admin

        logger = get_logger()
        admin = TokenData(
            username="MaxtheCreator",
            email="admin@shieldpilot.dev",
            role="admin",
            is_super_admin=True,
            email_verified=True,
        )

        assert is_super_admin(admin, billing_config)
        tier, limits = get_user_tier_limits(admin, billing_config, logger)
        assert tier == "unlimited"
        assert limits.commands_per_day == -1
        assert limits.scans_per_day == -1

    def test_pro_user_from_db_gets_pro_limits(self, client, user_headers, db_path, billing_config):
        """User with tier='pro' and subscription_status='active' in DB gets pro limits."""
        from sentinelai.logger.database import User
        from sentinelai.api.deps import get_user_tier_limits, get_logger

        session = _get_session(db_path)
        try:
            email = user_headers["_email"]
            db_user = session.query(User).filter(User.email == email).first()
            db_user.tier = "pro"
            db_user.subscription_status = "active"
            session.commit()
        finally:
            session.close()

        logger = get_logger()
        user = TokenData(username=email, email=email, role="user", email_verified=True)
        tier, limits = get_user_tier_limits(user, billing_config, logger)
        assert tier == "pro"
        assert limits.commands_per_day == 1000
        assert limits.scans_per_day == 100


# ── Per-User Usage Tests ───────────────────────────────────────


class TestPerUserUsage:
    """Test per-user usage tracking isolation."""

    def test_increment_command_creates_per_user_record(self, client, billing_config, db_path):
        """increment_command_usage with user_email creates a per-user record."""
        from sentinelai.api.deps import increment_command_usage, get_logger
        from sentinelai.logger.database import UsageRecord, init_database
        from datetime import date

        logger = get_logger()
        increment_command_usage(logger, user_email="a@test.com")

        _, Session = init_database(db_path)
        session = Session()
        try:
            record = session.query(UsageRecord).filter(
                UsageRecord.user_email == "a@test.com",
                UsageRecord.date == date.today().isoformat(),
            ).first()
            assert record is not None
            assert record.commands_evaluated == 1
            assert record.user_email == "a@test.com"
        finally:
            session.close()

    def test_per_user_usage_isolated(self, client, billing_config, db_path):
        """User A's increments don't affect User B's count."""
        from sentinelai.api.deps import increment_command_usage, get_logger
        from sentinelai.logger.database import UsageRecord, init_database
        from datetime import date

        logger = get_logger()
        # Increment user A 3 times
        for _ in range(3):
            increment_command_usage(logger, user_email="usera@test.com")

        _, Session = init_database(db_path)
        session = Session()
        try:
            # User B should have no records
            record_b = session.query(UsageRecord).filter(
                UsageRecord.user_email == "userb@test.com",
                UsageRecord.date == date.today().isoformat(),
            ).first()
            assert record_b is None

            # User A should have 3
            record_a = session.query(UsageRecord).filter(
                UsageRecord.user_email == "usera@test.com",
                UsageRecord.date == date.today().isoformat(),
            ).first()
            assert record_a is not None
            assert record_a.commands_evaluated == 3
        finally:
            session.close()

    def test_global_usage_independent(self, client, billing_config, db_path):
        """increment_command_usage without user_email creates a separate global record."""
        from sentinelai.api.deps import increment_command_usage, get_logger
        from sentinelai.logger.database import UsageRecord, init_database
        from datetime import date

        logger = get_logger()
        increment_command_usage(logger, user_email="per-user@test.com")
        increment_command_usage(logger)  # global (user_email=None)

        _, Session = init_database(db_path)
        session = Session()
        try:
            today = date.today().isoformat()
            per_user = session.query(UsageRecord).filter(
                UsageRecord.user_email == "per-user@test.com",
                UsageRecord.date == today,
            ).first()
            assert per_user is not None
            assert per_user.commands_evaluated == 1

            global_rec = session.query(UsageRecord).filter(
                UsageRecord.user_email == None,
                UsageRecord.date == today,
            ).first()
            assert global_rec is not None
            assert global_rec.commands_evaluated == 1
        finally:
            session.close()

    def test_get_daily_usage_per_user(self, client, billing_config, db_path):
        """_get_daily_usage_internal with user_email shows only that user's usage."""
        from sentinelai.api.deps import increment_command_usage, _get_daily_usage_internal, get_logger

        logger = get_logger()
        # Give user-x 5 commands
        for _ in range(5):
            increment_command_usage(logger, user_email="user-x@test.com")
        # Give user-y 2 commands
        for _ in range(2):
            increment_command_usage(logger, user_email="user-y@test.com")

        usage_x = _get_daily_usage_internal(logger, billing_config, user_email="user-x@test.com")
        assert usage_x.commands_used == 5

        usage_y = _get_daily_usage_internal(logger, billing_config, user_email="user-y@test.com")
        assert usage_y.commands_used == 2

    def test_increment_scan_per_user(self, client, billing_config, db_path):
        """increment_scan_usage with user_email creates a per-user scan record."""
        from sentinelai.api.deps import increment_scan_usage, get_logger
        from sentinelai.logger.database import UsageRecord, init_database
        from datetime import date

        logger = get_logger()
        increment_scan_usage(logger, user_email="scanner@test.com")
        increment_scan_usage(logger, user_email="scanner@test.com")

        _, Session = init_database(db_path)
        session = Session()
        try:
            record = session.query(UsageRecord).filter(
                UsageRecord.user_email == "scanner@test.com",
                UsageRecord.date == date.today().isoformat(),
            ).first()
            assert record is not None
            assert record.scans_performed == 2
        finally:
            session.close()


# ── Per-User Limit Enforcement Tests ──────────────────────────


class TestPerUserLimitEnforcement:
    """Test that per-user limits are properly enforced."""

    def test_free_user_blocked_at_50_commands(self, client, user_headers, db_path, billing_config):
        """Free user gets 429 after 50 commands."""
        from sentinelai.logger.database import UsageRecord, init_database
        from datetime import date

        email = user_headers["_email"]
        # Seed 50 commands directly in the DB
        _, Session = init_database(db_path)
        session = Session()
        try:
            session.add(UsageRecord(
                user_email=email,
                date=date.today().isoformat(),
                commands_evaluated=50,
                scans_performed=0,
                llm_calls=0,
                api_requests=0,
            ))
            session.commit()
        finally:
            session.close()

        # The /api/evaluate endpoint has check_user_command_limit dependency
        resp = client.post("/api/evaluate", json={
            "command": "ls -la",
        }, headers=user_headers)
        assert resp.status_code == 429

    def test_pro_user_not_blocked_at_50_commands(self, client, user_headers, db_path, billing_config):
        """Pro user is NOT blocked at 50 commands (limit is 1000)."""
        from sentinelai.logger.database import UsageRecord, User, init_database
        from sentinelai.api.deps import _check_command_limit_internal, get_logger
        from datetime import date

        email = user_headers["_email"]
        _, Session = init_database(db_path)
        session = Session()
        try:
            # Set user to pro tier with active subscription
            db_user = session.query(User).filter(User.email == email).first()
            db_user.tier = "pro"
            db_user.subscription_status = "active"

            # Seed 50 commands
            session.add(UsageRecord(
                user_email=email,
                date=date.today().isoformat(),
                commands_evaluated=50,
                scans_performed=0,
                llm_calls=0,
                api_requests=0,
            ))
            session.commit()
        finally:
            session.close()

        # Pro user at 50 commands should NOT be blocked (limit is 1000)
        logger = get_logger()
        _check_command_limit_internal(
            billing_config, logger,
            user_tier="pro", user_limits=TIER_LIMITS["pro"],
            user_email=email,
        )  # Should not raise

    def test_super_admin_never_blocked(self, client, admin_headers, db_path, billing_config):
        """Super-admin is never blocked regardless of usage count."""
        from sentinelai.logger.database import UsageRecord, init_database
        from sentinelai.api.deps import check_command_limit_for_user, get_logger
        from datetime import date

        # Seed massive usage for the super-admin email
        _, Session = init_database(db_path)
        session = Session()
        try:
            session.add(UsageRecord(
                user_email="admin@shieldpilot.dev",
                date=date.today().isoformat(),
                commands_evaluated=99999,
                scans_performed=99999,
                llm_calls=0,
                api_requests=0,
            ))
            session.commit()
        finally:
            session.close()

        # Super-admin should never be blocked
        logger = get_logger()
        admin = TokenData(
            username="MaxtheCreator",
            email="admin@shieldpilot.dev",
            role="admin",
            is_super_admin=True,
            email_verified=True,
        )
        check_command_limit_for_user(admin, billing_config, logger)  # Should not raise

    def test_free_user_blocked_at_10_scans(self, client, user_headers, db_path, billing_config):
        """Free user gets 429 after 10 scans."""
        from sentinelai.logger.database import UsageRecord, init_database
        from datetime import date

        email = user_headers["_email"]
        _, Session = init_database(db_path)
        session = Session()
        try:
            session.add(UsageRecord(
                user_email=email,
                date=date.today().isoformat(),
                commands_evaluated=0,
                scans_performed=10,
                llm_calls=0,
                api_requests=0,
            ))
            session.commit()
        finally:
            session.close()

        # The /api/scan/prompt endpoint has check_user_scan_limit dependency
        resp = client.post("/api/scan/prompt", json={"content": "test prompt"}, headers=user_headers)
        assert resp.status_code == 429

    def test_user_a_limit_doesnt_affect_user_b(self, client, billing_config, db_path):
        """User A at their limit doesn't block User B."""
        from sentinelai.api.deps import _check_command_limit_internal, get_logger
        from sentinelai.logger.database import UsageRecord, init_database
        from datetime import date
        from fastapi import HTTPException

        logger = get_logger()

        # Fill user A to limit
        _, Session = init_database(db_path)
        session = Session()
        try:
            session.add(UsageRecord(
                user_email="limit-a@test.com",
                date=date.today().isoformat(),
                commands_evaluated=50,
                scans_performed=0,
                llm_calls=0,
                api_requests=0,
            ))
            session.commit()
        finally:
            session.close()

        # User A should be blocked
        with pytest.raises(HTTPException) as exc_info:
            _check_command_limit_internal(
                billing_config, logger,
                user_tier="free", user_limits=TIER_LIMITS["free"],
                user_email="limit-a@test.com",
            )
        assert exc_info.value.status_code == 429

        # User B should NOT be blocked
        _check_command_limit_internal(
            billing_config, logger,
            user_tier="free", user_limits=TIER_LIMITS["free"],
            user_email="limit-b@test.com",
        )  # Should not raise


# ── Feature Gating Tests ──────────────────────────────────────


class TestFeatureGating:
    """Test feature gating based on billing tier."""

    def test_free_user_no_export(self, client, user_headers):
        """Free user gets 403 on export endpoint (export_enabled=False for free tier)."""
        resp = client.get("/api/export/commands", headers=user_headers)
        assert resp.status_code == 403
        data = resp.json()
        assert "export_enabled" in data["detail"]["error"]
        assert data["detail"]["tier"] == "free"

