"""Tests for AuthService to raise coverage from ~35% to 70%+.

Covers: authenticate, register, request_password_reset, confirm_password_reset,
verify_email, resend_verification_email, get_google_auth_url, handle_google_callback.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sentinelai.api.auth import TokenData, hash_password
from sentinelai.core.config import AuthConfig, BillingConfig, SentinelConfig
from sentinelai.logger.database import (
    Base,
    EmailVerificationToken,
    OAuthState,
    PasswordResetToken,
    User,
)
from sentinelai.services.auth_service import AuthService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(
    *,
    super_admin_email: str = "admin@test.com",
    super_admin_password: str = "SuperSecret123!",
    super_admin_username: str = "superadmin",
    default_admin_user: str = "admin",
    default_admin_password: str = "adminpass",
    secret_key: str = "test-jwt-secret-key-for-tests-only",
    google_client_id: str = "",
    google_client_secret: str = "",
    google_redirect_uri: str = "http://localhost:8420/api/auth/google/callback",
    smtp_user: str = "",
    smtp_host: str = "",
    stripe_secret_key: str = "",
) -> SentinelConfig:
    """Build a minimal SentinelConfig for testing."""
    return SentinelConfig(
        auth=AuthConfig(
            secret_key=secret_key,
            super_admin_email=super_admin_email,
            super_admin_password=super_admin_password,
            super_admin_username=super_admin_username,
            default_admin_user=default_admin_user,
            default_admin_password=default_admin_password,
            google_client_id=google_client_id,
            google_client_secret=google_client_secret,
            google_redirect_uri=google_redirect_uri,
            smtp_host=smtp_host,
            smtp_user=smtp_user,
        ),
        billing=BillingConfig(
            stripe_secret_key=stripe_secret_key,
        ),
    )


def _stub_shared(
    tos_version: str = "2026-02-01",
    oauth_state_expiry: int = 600,
):
    """Return a tuple matching _get_shared() but with no-op limiters."""
    cleanup = MagicMock()
    login_limiter = MagicMock()
    registration_limiter = MagicMock()
    return (tos_version, oauth_state_expiry, cleanup, login_limiter, registration_limiter)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def db_session():
    """Create an in-memory SQLite database with all tables and return a session."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture(autouse=True)
def _patch_shared():
    """Patch _get_shared so tests never hit the real DB-backed rate limiters."""
    with patch(
        "sentinelai.services.auth_service._get_shared",
        return_value=_stub_shared(),
    ) as mock:
        yield mock


# ===================================================================
# 1. authenticate()
# ===================================================================

class TestAuthenticate:
    """Tests for AuthService.authenticate()."""

    def test_super_admin_correct_password(self, db_session):
        """Super-admin with correct password returns a valid token."""
        config = _make_config()
        svc = AuthService(db_session, config)

        token = svc.authenticate("admin@test.com", "SuperSecret123!", "127.0.0.1")

        assert token.access_token
        assert token.token_type == "bearer"
        assert token.expires_in > 0

    def test_super_admin_creates_db_row_if_missing(self, db_session):
        """First super-admin login creates a User row in the database."""
        config = _make_config()
        svc = AuthService(db_session, config)

        svc.authenticate("admin@test.com", "SuperSecret123!", "127.0.0.1")

        user = db_session.query(User).filter(User.email == "admin@test.com").first()
        assert user is not None
        assert user.is_super_admin is True
        assert user.tier == "unlimited"
        assert user.role == "admin"

    def test_super_admin_wrong_password(self, db_session):
        """Wrong password for super-admin email falls through and raises 401."""
        config = _make_config()
        svc = AuthService(db_session, config)

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            svc.authenticate("admin@test.com", "WrongPassword!", "127.0.0.1")
        assert exc_info.value.status_code == 401

    def test_default_admin_login(self, db_session):
        """Default admin login with matching credentials returns a token."""
        config = _make_config(
            super_admin_email="",
            super_admin_password="",
            default_admin_user="admin",
            default_admin_password="adminpass",
        )
        svc = AuthService(db_session, config)

        token = svc.authenticate("admin", "adminpass", "127.0.0.1")

        assert token.access_token
        assert token.token_type == "bearer"

    def test_db_user_login_by_username(self, db_session):
        """DB user can authenticate by username."""
        config = _make_config(super_admin_email="", super_admin_password="")
        user = User(
            username="testuser",
            email="testuser@example.com",
            password_hash=hash_password("MyPassword8!"),
            role="viewer",
            tier="free",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()

        svc = AuthService(db_session, config)
        token = svc.authenticate("testuser", "MyPassword8!", "10.0.0.1")

        assert token.access_token
        assert token.token_type == "bearer"

    def test_db_user_login_by_email(self, db_session):
        """DB user can authenticate by email address."""
        config = _make_config(super_admin_email="", super_admin_password="")
        user = User(
            username="alice",
            email="alice@example.com",
            password_hash=hash_password("AlicePass8!"),
            role="viewer",
            tier="pro",
            is_active=True,
        )
        db_session.add(user)
        db_session.commit()

        svc = AuthService(db_session, config)
        token = svc.authenticate("alice@example.com", "AlicePass8!", "10.0.0.1")

        assert token.access_token

    def test_invalid_credentials_records_failed_attempt(self, db_session, _patch_shared):
        """Invalid credentials raise 401 and record a failed login attempt."""
        config = _make_config(super_admin_email="", super_admin_password="")
        svc = AuthService(db_session, config)

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            svc.authenticate("nobody", "badpass", "192.168.1.1")
        assert exc_info.value.status_code == 401

        # Verify the login limiter recorded the attempt
        shared = _patch_shared.return_value
        login_limiter = shared[3]
        login_limiter.record_attempt.assert_called_once_with("192.168.1.1")

    def test_stripe_reconciliation_active_subscription(self, db_session):
        """Login with an active Stripe subscription updates user tier."""
        config = _make_config(
            super_admin_email="",
            super_admin_password="",
            stripe_secret_key="sk_test_fake",
        )
        user = User(
            username="stripe_user",
            email="stripe@example.com",
            password_hash=hash_password("StripePass8!"),
            role="viewer",
            tier="free",
            is_active=True,
            stripe_subscription_id="sub_123",
        )
        db_session.add(user)
        db_session.commit()

        mock_client = MagicMock()
        mock_client.get_subscription.return_value = {
            "status": "active",
            "price_id": "price_pro",
            "current_period_end": 1700000000,
            "cancel_at_period_end": False,
        }

        # Patch the stripe_client module that gets imported lazily inside authenticate()
        with patch(
            "sentinelai.billing.stripe_client.StripeClient",
            return_value=mock_client,
        ), patch(
            "sentinelai.billing.stripe_client.PRICE_TO_TIER",
            {"price_pro": "pro"},
        ):
            svc = AuthService(db_session, config)
            token = svc.authenticate("stripe@example.com", "StripePass8!", "10.0.0.1")

        assert token.access_token
        # User tier should be updated in DB
        db_session.refresh(user)
        assert user.tier == "pro"
        assert user.subscription_status == "active"

    def test_stripe_reconciliation_canceled_subscription(self, db_session):
        """Login with a canceled Stripe subscription downgrades user to free."""
        config = _make_config(
            super_admin_email="",
            super_admin_password="",
            stripe_secret_key="sk_test_fake",
        )
        user = User(
            username="canceled_user",
            email="canceled@example.com",
            password_hash=hash_password("CancelPass8!"),
            role="viewer",
            tier="pro",
            is_active=True,
            stripe_subscription_id="sub_456",
            subscription_status="active",
        )
        db_session.add(user)
        db_session.commit()

        mock_client = MagicMock()
        mock_client.get_subscription.return_value = {
            "status": "canceled",
            "price_id": "price_pro",
        }

        with patch(
            "sentinelai.billing.stripe_client.StripeClient",
            return_value=mock_client,
        ), patch(
            "sentinelai.billing.stripe_client.PRICE_TO_TIER",
            {"price_pro": "pro"},
        ):
            svc = AuthService(db_session, config)
            token = svc.authenticate("canceled@example.com", "CancelPass8!", "10.0.0.1")

        assert token.access_token
        db_session.refresh(user)
        assert user.tier == "free"
        assert user.subscription_status == "canceled"
        assert user.stripe_subscription_id is None


# ===================================================================
# 2. register()
# ===================================================================

class TestRegister:
    """Tests for AuthService.register()."""

    def test_short_password_raises_400(self, db_session):
        """Password shorter than 8 characters raises 400."""
        config = _make_config()
        svc = AuthService(db_session, config)

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            svc.register("new@example.com", "short", None, True, "127.0.0.1", "TestAgent")
        assert exc_info.value.status_code == 400
        assert "8 characters" in str(exc_info.value.detail)

    def test_tos_not_accepted_raises_400(self, db_session):
        """Registration without accepting ToS raises 400."""
        config = _make_config()
        svc = AuthService(db_session, config)

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            svc.register("new@example.com", "ValidPass8!", None, False, "127.0.0.1", "TestAgent")
        assert exc_info.value.status_code == 400
        assert "Terms of Service" in str(exc_info.value.detail)

    def test_email_already_exists_raises_400(self, db_session):
        """Registering with an existing email raises 400."""
        config = _make_config()
        user = User(
            username="existing",
            email="taken@example.com",
            password_hash=hash_password("SomePassword8!"),
            role="viewer",
            tier="free",
        )
        db_session.add(user)
        db_session.commit()

        svc = AuthService(db_session, config)

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            svc.register("taken@example.com", "ValidPass8!", None, True, "127.0.0.1", "TestAgent")
        assert exc_info.value.status_code == 400
        assert "already registered" in str(exc_info.value.detail)

    def test_username_collision_auto_increments(self, db_session):
        """When username already exists, it auto-increments with a numeric suffix."""
        config = _make_config(super_admin_email="", smtp_host="", smtp_user="")
        # Create a user that will collide on "newuser"
        existing = User(
            username="newuser",
            email="other@example.com",
            password_hash=hash_password("SomePassword8!"),
            role="viewer",
            tier="free",
        )
        db_session.add(existing)
        db_session.commit()

        svc = AuthService(db_session, config)
        token = svc.register(
            "newuser@example.com", "ValidPass8!", "newuser", True, "10.0.0.1", "TestAgent"
        )

        assert token.access_token
        # The new user should have an incremented username
        new_user = db_session.query(User).filter(User.email == "newuser@example.com").first()
        assert new_user is not None
        assert new_user.username == "newuser1"

    def test_super_admin_email_detection(self, db_session):
        """Registering with the super-admin email gives admin role and unlimited tier."""
        config = _make_config(super_admin_email="boss@example.com", smtp_host="", smtp_user="")
        svc = AuthService(db_session, config)

        token = svc.register(
            "boss@example.com", "BossPass8!!", None, True, "10.0.0.1", "TestAgent"
        )

        assert token.access_token
        user = db_session.query(User).filter(User.email == "boss@example.com").first()
        assert user is not None
        assert user.is_super_admin is True
        assert user.tier == "unlimited"
        assert user.role == "admin"
        assert user.email_verified is True  # Super-admin is auto-verified

    def test_email_verification_smtp_not_configured(self, db_session):
        """Without SMTP configured, user is auto-verified (dev mode)."""
        config = _make_config(super_admin_email="", smtp_host="", smtp_user="")
        svc = AuthService(db_session, config)

        token = svc.register(
            "dev@example.com", "DevPass88!", None, True, "10.0.0.1", "TestAgent"
        )

        assert token.access_token
        user = db_session.query(User).filter(User.email == "dev@example.com").first()
        assert user is not None
        assert user.email_verified is True

    def test_email_verification_smtp_configured(self, db_session):
        """With SMTP configured, user stays unverified and a verification email is sent."""
        config = _make_config(
            super_admin_email="",
            smtp_host="smtp.test.com",
            smtp_user="test@test.com",
        )
        svc = AuthService(db_session, config)

        with patch("sentinelai.api.email.EmailService") as MockEmailSvc:
            mock_instance = MagicMock()
            mock_instance.is_configured.return_value = True
            mock_instance.send_email_verification.return_value = True
            MockEmailSvc.return_value = mock_instance

            token = svc.register(
                "smtp_user@example.com", "SmtpPass8!", None, True, "10.0.0.1", "TestAgent"
            )

        assert token.access_token
        user = db_session.query(User).filter(User.email == "smtp_user@example.com").first()
        assert user is not None
        # User should NOT be auto-verified when SMTP is configured
        assert user.email_verified is False
        # Verification token should exist
        verif_token = db_session.query(EmailVerificationToken).filter(
            EmailVerificationToken.user_id == user.id
        ).first()
        assert verif_token is not None
        mock_instance.send_email_verification.assert_called_once()

    def test_ip_anonymization_ipv4(self, db_session):
        """IPv4 address is anonymized to /24 subnet."""
        config = _make_config(super_admin_email="", smtp_host="", smtp_user="")
        svc = AuthService(db_session, config)

        svc.register("ipv4test@example.com", "Ipv4Pass8!", None, True, "192.168.1.42", "TestAgent")

        user = db_session.query(User).filter(User.email == "ipv4test@example.com").first()
        assert user is not None
        assert user.tos_ip_address == "192.168.1.0"

    def test_ip_anonymization_ipv6(self, db_session):
        """IPv6 address is anonymized to /32 prefix."""
        config = _make_config(super_admin_email="", smtp_host="", smtp_user="")
        svc = AuthService(db_session, config)

        svc.register(
            "ipv6test@example.com", "Ipv6Pass8!", None, True,
            "2001:db8:abcd:1234:5678:9abc:def0:1234", "TestAgent",
        )

        user = db_session.query(User).filter(User.email == "ipv6test@example.com").first()
        assert user is not None
        # /32 masks the last 96 bits
        assert user.tos_ip_address == "2001:db8::"

    def test_ip_anonymization_invalid_ip(self, db_session):
        """Invalid IP address is stored as 'unknown'."""
        config = _make_config(super_admin_email="", smtp_host="", smtp_user="")
        svc = AuthService(db_session, config)

        svc.register("badip@example.com", "BadIpPass8!", None, True, "not-an-ip", "TestAgent")

        user = db_session.query(User).filter(User.email == "badip@example.com").first()
        assert user is not None
        assert user.tos_ip_address == "unknown"

    def test_register_records_registration_attempt(self, db_session, _patch_shared):
        """Successful registration records a rate limit attempt."""
        config = _make_config(super_admin_email="", smtp_host="", smtp_user="")
        svc = AuthService(db_session, config)

        svc.register("ratelimit@example.com", "RatePass8!", None, True, "10.0.0.1", "TestAgent")

        shared = _patch_shared.return_value
        registration_limiter = shared[4]
        registration_limiter.record_attempt.assert_called_once_with("10.0.0.1")

    def test_register_default_username_from_email(self, db_session):
        """When no username is provided, it defaults to email prefix."""
        config = _make_config(super_admin_email="", smtp_host="", smtp_user="")
        svc = AuthService(db_session, config)

        svc.register("john.doe@example.com", "JohnPass8!", None, True, "10.0.0.1", "TestAgent")

        user = db_session.query(User).filter(User.email == "john.doe@example.com").first()
        assert user is not None
        assert user.username == "john.doe"


# ===================================================================
# 3. request_password_reset()
# ===================================================================

class TestRequestPasswordReset:
    """Tests for AuthService.request_password_reset()."""

    def test_user_exists_creates_token_and_sends_email(self, db_session):
        """When user exists, a reset token is created and an email is sent."""
        config = _make_config()
        user = User(
            username="resetme",
            email="reset@example.com",
            password_hash=hash_password("OldPass88!"),
            role="viewer",
            tier="free",
        )
        db_session.add(user)
        db_session.commit()

        svc = AuthService(db_session, config)

        with patch("sentinelai.api.email.EmailService") as MockEmailSvc:
            mock_instance = MagicMock()
            MockEmailSvc.return_value = mock_instance

            result = svc.request_password_reset("reset@example.com")

        assert result["message"] == "If the email exists, a reset link has been sent"
        # Token should be in DB
        token_record = db_session.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id
        ).first()
        assert token_record is not None
        assert token_record.used is False
        mock_instance.send_password_reset.assert_called_once()

    def test_user_not_found_still_returns_success(self, db_session):
        """Anti-enumeration: non-existent email still returns success."""
        config = _make_config()
        svc = AuthService(db_session, config)

        result = svc.request_password_reset("nobody@example.com")

        assert result["message"] == "If the email exists, a reset link has been sent"
        # No token in DB
        assert db_session.query(PasswordResetToken).count() == 0


# ===================================================================
# 4. confirm_password_reset()
# ===================================================================

class TestConfirmPasswordReset:
    """Tests for AuthService.confirm_password_reset()."""

    def test_valid_token_resets_password(self, db_session):
        """Valid token updates the user password and marks token as used."""
        config = _make_config()
        user = User(
            username="pwreset",
            email="pwreset@example.com",
            password_hash=hash_password("OldPassword8!"),
            role="viewer",
            tier="free",
        )
        db_session.add(user)
        db_session.commit()

        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        reset_token = PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=datetime.utcnow() + timedelta(hours=1),
            used=False,
        )
        db_session.add(reset_token)
        db_session.commit()

        svc = AuthService(db_session, config)
        result = svc.confirm_password_reset(raw_token, "NewPassword8!")

        assert result["message"] == "Password reset successfully"
        db_session.refresh(reset_token)
        assert reset_token.used is True
        # Verify new password works
        from sentinelai.api.auth import verify_password
        db_session.refresh(user)
        assert verify_password("NewPassword8!", user.password_hash)

    def test_invalid_token_raises_400(self, db_session):
        """Non-existent token raises 400."""
        config = _make_config()
        svc = AuthService(db_session, config)

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            svc.confirm_password_reset("bogus_token_value", "NewPassword8!")
        assert exc_info.value.status_code == 400
        assert "Invalid or expired" in str(exc_info.value.detail)

    def test_expired_token_raises_400(self, db_session):
        """Expired token raises 400."""
        config = _make_config()
        user = User(
            username="expired",
            email="expired@example.com",
            password_hash=hash_password("OldPassword8!"),
            role="viewer",
            tier="free",
        )
        db_session.add(user)
        db_session.commit()

        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        reset_token = PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=datetime.utcnow() - timedelta(hours=1),  # Already expired
            used=False,
        )
        db_session.add(reset_token)
        db_session.commit()

        svc = AuthService(db_session, config)

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            svc.confirm_password_reset(raw_token, "NewPassword8!")
        assert exc_info.value.status_code == 400

    def test_short_new_password_raises_400(self, db_session):
        """New password shorter than 8 characters raises 400."""
        config = _make_config()
        svc = AuthService(db_session, config)

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            svc.confirm_password_reset("any_token", "short")
        assert exc_info.value.status_code == 400
        assert "8 characters" in str(exc_info.value.detail)

    def test_used_token_raises_400(self, db_session):
        """Already-used token raises 400."""
        config = _make_config()
        user = User(
            username="usedtoken",
            email="usedtoken@example.com",
            password_hash=hash_password("OldPassword8!"),
            role="viewer",
            tier="free",
        )
        db_session.add(user)
        db_session.commit()

        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        reset_token = PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=datetime.utcnow() + timedelta(hours=1),
            used=True,  # Already used
        )
        db_session.add(reset_token)
        db_session.commit()

        svc = AuthService(db_session, config)

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            svc.confirm_password_reset(raw_token, "NewPassword8!")
        assert exc_info.value.status_code == 400


# ===================================================================
# 5. verify_email()
# ===================================================================

class TestVerifyEmail:
    """Tests for AuthService.verify_email()."""

    def test_valid_token_verifies_user(self, db_session):
        """Valid verification token marks user as verified and returns success URL."""
        config = _make_config()
        user = User(
            username="unverified",
            email="unverified@example.com",
            password_hash=hash_password("UnverPass8!"),
            role="viewer",
            tier="free",
            email_verified=False,
        )
        db_session.add(user)
        db_session.commit()

        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        verif = EmailVerificationToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=datetime.utcnow() + timedelta(hours=24),
            used=False,
        )
        db_session.add(verif)
        db_session.commit()

        svc = AuthService(db_session, config)
        redirect_url = svc.verify_email(raw_token)

        assert redirect_url == "/login?verified=true"
        db_session.refresh(user)
        assert user.email_verified is True
        db_session.refresh(verif)
        assert verif.used is True

    def test_invalid_token_returns_error_url(self, db_session):
        """Invalid token returns the error redirect URL."""
        config = _make_config()
        svc = AuthService(db_session, config)

        redirect_url = svc.verify_email("totally_bogus_token")

        assert redirect_url == "/login?verify_error=true"

    def test_expired_token_returns_error_url(self, db_session):
        """Expired verification token returns the error redirect URL."""
        config = _make_config()
        user = User(
            username="expverify",
            email="expverify@example.com",
            password_hash=hash_password("ExpVerPass8!"),
            role="viewer",
            tier="free",
            email_verified=False,
        )
        db_session.add(user)
        db_session.commit()

        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        verif = EmailVerificationToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=datetime.utcnow() - timedelta(hours=1),  # Expired
            used=False,
        )
        db_session.add(verif)
        db_session.commit()

        svc = AuthService(db_session, config)
        redirect_url = svc.verify_email(raw_token)

        assert redirect_url == "/login?verify_error=true"

    def test_used_token_returns_error_url(self, db_session):
        """Already-used verification token returns the error redirect URL."""
        config = _make_config()
        user = User(
            username="usedverify",
            email="usedverify@example.com",
            password_hash=hash_password("UsedVerPass8!"),
            role="viewer",
            tier="free",
            email_verified=False,
        )
        db_session.add(user)
        db_session.commit()

        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        verif = EmailVerificationToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=datetime.utcnow() + timedelta(hours=24),
            used=True,  # Already used
        )
        db_session.add(verif)
        db_session.commit()

        svc = AuthService(db_session, config)
        redirect_url = svc.verify_email(raw_token)

        assert redirect_url == "/login?verify_error=true"


# ===================================================================
# 6. resend_verification_email()
# ===================================================================

class TestResendVerificationEmail:
    """Tests for AuthService.resend_verification_email()."""

    def test_already_verified_returns_early(self, db_session):
        """If email is already verified, returns early with a message."""
        config = _make_config()
        svc = AuthService(db_session, config)

        user_data = TokenData(
            username="verified",
            email="verified@example.com",
            role="viewer",
            email_verified=True,
        )
        result = svc.resend_verification_email(user_data)

        assert result["message"] == "Email already verified"

    def test_user_not_found_raises_404(self, db_session):
        """If the user does not exist in the DB, raises 404."""
        config = _make_config()
        svc = AuthService(db_session, config)

        user_data = TokenData(
            username="ghost",
            email="ghost@example.com",
            role="viewer",
            email_verified=False,
        )

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            svc.resend_verification_email(user_data)
        assert exc_info.value.status_code == 404

    def test_success_creates_token_and_sends_email(self, db_session):
        """Successfully resends verification email with a new token."""
        config = _make_config()
        user = User(
            username="needsverify",
            email="needsverify@example.com",
            password_hash=hash_password("NeedVerPass8!"),
            role="viewer",
            tier="free",
            email_verified=False,
        )
        db_session.add(user)
        db_session.commit()

        svc = AuthService(db_session, config)

        user_data = TokenData(
            username="needsverify",
            email="needsverify@example.com",
            role="viewer",
            email_verified=False,
        )

        with patch("sentinelai.api.email.EmailService") as MockEmailSvc:
            mock_instance = MagicMock()
            MockEmailSvc.return_value = mock_instance

            result = svc.resend_verification_email(user_data)

        assert result["message"] == "Verification email sent"
        # New token should be in DB
        verif = db_session.query(EmailVerificationToken).filter(
            EmailVerificationToken.user_id == user.id
        ).first()
        assert verif is not None
        assert verif.used is False
        mock_instance.send_email_verification.assert_called_once()


# ===================================================================
# 7. get_google_auth_url()
# ===================================================================

class TestGetGoogleAuthUrl:
    """Tests for AuthService.get_google_auth_url()."""

    def test_google_not_configured_raises_503(self, db_session):
        """When Google client ID is empty, raises 503."""
        config = _make_config(google_client_id="")
        svc = AuthService(db_session, config)

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            svc.get_google_auth_url()
        assert exc_info.value.status_code == 503
        assert "not configured" in str(exc_info.value.detail)

    def test_success_returns_auth_url_and_state(self, db_session, _patch_shared):
        """When Google is configured, returns auth_url and state."""
        config = _make_config(
            google_client_id="test-client-id",
            google_client_secret="test-secret",
        )
        svc = AuthService(db_session, config)

        # Patch at the source module where get_google_auth_url is defined.
        # auth_service.py imports it locally as:
        #   from sentinelai.api.oauth import get_google_auth_url as _get_google_auth_url
        with patch("sentinelai.api.oauth.get_google_auth_url", return_value="https://accounts.google.com/o/oauth2/auth?fake=1"):
            result = svc.get_google_auth_url()

        assert "auth_url" in result
        assert "state" in result
        assert result["auth_url"] == "https://accounts.google.com/o/oauth2/auth?fake=1"
        # State should be persisted in DB
        oauth_state = db_session.query(OAuthState).filter(
            OAuthState.state == result["state"]
        ).first()
        assert oauth_state is not None


# ===================================================================
# 8. handle_google_callback()
# ===================================================================

class TestHandleGoogleCallback:
    """Tests for AuthService.handle_google_callback()."""

    def test_invalid_state_raises_400(self, db_session):
        """State not found in DB raises 400."""
        config = _make_config(
            google_client_id="test-client-id",
            google_client_secret="test-secret",
        )
        svc = AuthService(db_session, config)

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            svc.handle_google_callback("code123", "invalid_state", "10.0.0.1", "TestAgent")
        assert exc_info.value.status_code == 400
        assert "Invalid" in str(exc_info.value.detail)

    def test_expired_state_raises_400(self, db_session, _patch_shared):
        """Expired state token raises 400."""
        config = _make_config(
            google_client_id="test-client-id",
            google_client_secret="test-secret",
        )
        # Override _get_shared to return a very short expiry so the state is expired
        _patch_shared.return_value = _stub_shared(oauth_state_expiry=0)

        # Create a state that was created 2 seconds ago (will be expired with expiry=0)
        state_val = "expired_state_token"
        oauth_state = OAuthState(
            state=state_val,
            created_at=datetime.utcnow() - timedelta(seconds=2),
        )
        db_session.add(oauth_state)
        db_session.commit()

        svc = AuthService(db_session, config)

        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc_info:
            svc.handle_google_callback("code123", state_val, "10.0.0.1", "TestAgent")
        assert exc_info.value.status_code == 400
        assert "expired" in str(exc_info.value.detail)

    def test_new_user_created(self, db_session, _patch_shared):
        """Valid callback for a new user creates a User row and returns a token."""
        config = _make_config(
            google_client_id="test-client-id",
            google_client_secret="test-secret",
            super_admin_email="",
        )
        # Use a long expiry so the state is not expired
        _patch_shared.return_value = _stub_shared(oauth_state_expiry=600)

        state_val = secrets.token_urlsafe(32)
        oauth_state = OAuthState(state=state_val)
        db_session.add(oauth_state)
        db_session.commit()

        svc = AuthService(db_session, config)

        with patch(
            "sentinelai.api.oauth.exchange_code_for_token_sync",
            return_value={"access_token": "fake_access_token"},
        ), patch(
            "sentinelai.api.oauth.get_google_user_info_sync",
            return_value={
                "id": "google_id_123",
                "email": "googleuser@example.com",
                "name": "Google User",
            },
        ):
            token = svc.handle_google_callback("authcode", state_val, "10.0.0.1", "TestAgent")

        assert token.access_token
        # User should exist in DB
        user = db_session.query(User).filter(User.email == "googleuser@example.com").first()
        assert user is not None
        assert user.google_id == "google_id_123"
        assert user.email_verified is True
        assert user.role == "viewer"
        assert user.tier == "free"

    def test_existing_user_linked_to_google(self, db_session, _patch_shared):
        """Existing email user gets linked to Google when they OAuth for the first time."""
        config = _make_config(
            google_client_id="test-client-id",
            google_client_secret="test-secret",
            super_admin_email="",
        )
        _patch_shared.return_value = _stub_shared(oauth_state_expiry=600)

        # Pre-existing user without google_id
        user = User(
            username="existinguser",
            email="existinguser@example.com",
            password_hash=hash_password("ExistPass8!"),
            role="viewer",
            tier="free",
            google_id=None,
            email_verified=False,
        )
        db_session.add(user)
        db_session.commit()

        state_val = secrets.token_urlsafe(32)
        oauth_state = OAuthState(state=state_val)
        db_session.add(oauth_state)
        db_session.commit()

        svc = AuthService(db_session, config)

        with patch(
            "sentinelai.api.oauth.exchange_code_for_token_sync",
            return_value={"access_token": "fake_access_token"},
        ), patch(
            "sentinelai.api.oauth.get_google_user_info_sync",
            return_value={
                "id": "google_link_456",
                "email": "existinguser@example.com",
                "name": "Existing User",
            },
        ):
            token = svc.handle_google_callback("authcode", state_val, "10.0.0.1", "TestAgent")

        assert token.access_token
        db_session.refresh(user)
        assert user.google_id == "google_link_456"
        assert user.email_verified is True

    def test_google_api_failure_raises_400(self, db_session, _patch_shared):
        """If Google token exchange fails, raises 400."""
        config = _make_config(
            google_client_id="test-client-id",
            google_client_secret="test-secret",
            super_admin_email="",
        )
        _patch_shared.return_value = _stub_shared(oauth_state_expiry=600)

        state_val = secrets.token_urlsafe(32)
        oauth_state = OAuthState(state=state_val)
        db_session.add(oauth_state)
        db_session.commit()

        svc = AuthService(db_session, config)

        with patch(
            "sentinelai.api.oauth.exchange_code_for_token_sync",
            side_effect=Exception("Google API down"),
        ):
            from fastapi import HTTPException
            with pytest.raises(HTTPException) as exc_info:
                svc.handle_google_callback("authcode", state_val, "10.0.0.1", "TestAgent")
            assert exc_info.value.status_code == 400
            assert "Failed to authenticate" in str(exc_info.value.detail)

    def test_new_user_username_collision(self, db_session, _patch_shared):
        """When a Google user's email prefix collides with an existing username, a suffix is appended."""
        config = _make_config(
            google_client_id="test-client-id",
            google_client_secret="test-secret",
            super_admin_email="",
        )
        _patch_shared.return_value = _stub_shared(oauth_state_expiry=600)

        # Create a user that will collide on "googlecollide"
        existing = User(
            username="googlecollide",
            email="other_collide@example.com",
            password_hash=hash_password("CollidePass8!"),
            role="viewer",
            tier="free",
        )
        db_session.add(existing)
        db_session.commit()

        state_val = secrets.token_urlsafe(32)
        oauth_state = OAuthState(state=state_val)
        db_session.add(oauth_state)
        db_session.commit()

        svc = AuthService(db_session, config)

        with patch(
            "sentinelai.api.oauth.exchange_code_for_token_sync",
            return_value={"access_token": "fake_access_token"},
        ), patch(
            "sentinelai.api.oauth.get_google_user_info_sync",
            return_value={
                "id": "google_collide_789",
                "email": "googlecollide@example.com",
                "name": "Collide User",
            },
        ):
            token = svc.handle_google_callback("authcode", state_val, "10.0.0.1", "TestAgent")

        assert token.access_token
        new_user = db_session.query(User).filter(User.email == "googlecollide@example.com").first()
        assert new_user is not None
        # Username should have google_id prefix appended
        assert new_user.username == "googlecollide_google_c"

    def test_oauth_state_consumed_after_use(self, db_session, _patch_shared):
        """OAuth state is deleted from DB after successful callback (one-time use)."""
        config = _make_config(
            google_client_id="test-client-id",
            google_client_secret="test-secret",
            super_admin_email="",
        )
        _patch_shared.return_value = _stub_shared(oauth_state_expiry=600)

        state_val = secrets.token_urlsafe(32)
        oauth_state = OAuthState(state=state_val)
        db_session.add(oauth_state)
        db_session.commit()

        svc = AuthService(db_session, config)

        with patch(
            "sentinelai.api.oauth.exchange_code_for_token_sync",
            return_value={"access_token": "fake_token"},
        ), patch(
            "sentinelai.api.oauth.get_google_user_info_sync",
            return_value={
                "id": "google_consume_111",
                "email": "consume@example.com",
                "name": "Consume User",
            },
        ):
            svc.handle_google_callback("code", state_val, "10.0.0.1", "TestAgent")

        # State should be gone
        remaining = db_session.query(OAuthState).filter(OAuthState.state == state_val).first()
        assert remaining is None

    def test_super_admin_via_google_oauth(self, db_session, _patch_shared):
        """Linking super-admin email via Google OAuth grants unlimited tier."""
        config = _make_config(
            google_client_id="test-client-id",
            google_client_secret="test-secret",
            super_admin_email="superadmin@example.com",
        )
        _patch_shared.return_value = _stub_shared(oauth_state_expiry=600)

        # Existing user with super-admin email but no google link
        user = User(
            username="superadmin",
            email="superadmin@example.com",
            password_hash=hash_password("SuperPass8!"),
            role="viewer",
            tier="free",
            google_id=None,
            is_super_admin=False,
        )
        db_session.add(user)
        db_session.commit()

        state_val = secrets.token_urlsafe(32)
        oauth_state = OAuthState(state=state_val)
        db_session.add(oauth_state)
        db_session.commit()

        svc = AuthService(db_session, config)

        with patch(
            "sentinelai.api.oauth.exchange_code_for_token_sync",
            return_value={"access_token": "fake_token"},
        ), patch(
            "sentinelai.api.oauth.get_google_user_info_sync",
            return_value={
                "id": "google_super_999",
                "email": "superadmin@example.com",
                "name": "Super Admin",
            },
        ):
            token = svc.handle_google_callback("code", state_val, "10.0.0.1", "TestAgent")

        assert token.access_token
        db_session.refresh(user)
        assert user.is_super_admin is True
        assert user.tier == "unlimited"
        assert user.role == "admin"
        assert user.google_id == "google_super_999"
