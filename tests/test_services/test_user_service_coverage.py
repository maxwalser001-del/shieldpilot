"""Coverage-hardening tests for sentinelai/services/user_service.py.

Tests: get_settings, change_password, change_username, delete_account,
generate_api_key, revoke_api_key.

Uses in-memory SQLite via BlackboxLogger to get a real DB session,
and creates UserService(session, config) directly.
"""

from __future__ import annotations

import os
import tempfile
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from sentinelai.api.auth import TokenData, hash_password
from sentinelai.core.config import (
    AuthConfig,
    BillingConfig,
    LoggingConfig,
    SentinelConfig,
)
from sentinelai.core.secrets import SecretsMasker
from sentinelai.logger import BlackboxLogger
from sentinelai.logger.database import User
from sentinelai.services.user_service import UserService


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
def config():
    return SentinelConfig(
        logging=LoggingConfig(database=":memory:", chain_hashing=True),
        auth=AuthConfig(
            secret_key="test-user-service-key",
            super_admin_email="superadmin@test.com",
        ),
        billing=BillingConfig(enabled=False),
    )


@pytest.fixture
def logger(config, db_path):
    masker = SecretsMasker(config.secrets_patterns)
    return BlackboxLogger(config=config.logging, masker=masker, db_path=db_path)


@pytest.fixture
def session(logger):
    """Yield a DB session, close it after the test."""
    s = logger._get_session()
    yield s
    s.close()


@pytest.fixture
def service(session, config):
    return UserService(session, config)


def _make_user(session, **kwargs) -> User:
    """Insert a User into DB and return the ORM object."""
    user = User(
        username=kwargs.get("username", "testuser"),
        email=kwargs.get("email", "test@example.com"),
        password_hash=kwargs.get("password_hash", hash_password("OldPass123!")),
        role=kwargs.get("role", "viewer"),
        tier=kwargs.get("tier", "free"),
        is_super_admin=kwargs.get("is_super_admin", False),
        email_verified=kwargs.get("email_verified", True),
        api_key_hash=kwargs.get("api_key_hash"),
        stripe_customer_id=kwargs.get("stripe_customer_id"),
        stripe_subscription_id=kwargs.get("stripe_subscription_id"),
        google_id=kwargs.get("google_id"),
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def _token(username="testuser", email="test@example.com", **kw) -> TokenData:
    """Quick helper to build a TokenData."""
    return TokenData(
        username=username,
        email=email,
        role=kw.get("role", "viewer"),
        tier=kw.get("tier", "free"),
        is_super_admin=kw.get("is_super_admin", False),
        email_verified=kw.get("email_verified", True),
    )


# ===================================================================
# 1. get_settings
# ===================================================================

class TestGetSettings:
    """UserService.get_settings()"""

    def test_returns_correct_fields(self, service, session):
        db_user = _make_user(session, username="alice", email="alice@test.com",
                             google_id="gid123", tier="pro")
        user = _token(username="alice", email="alice@test.com", tier="pro")

        result = service.get_settings(user)
        assert result["username"] == "alice"
        assert result["email"] == "alice@test.com"
        assert result["tier"] == "pro"
        assert result["has_google"] is True
        assert result["has_password"] is True
        assert result["has_api_key"] is False
        assert result["created_at"] is not None

    def test_handles_missing_db_user(self, service):
        """When user is not in DB, falls back to TokenData values."""
        user = _token(username="ghost", email="ghost@test.com")
        result = service.get_settings(user)
        assert result["username"] == "ghost"
        assert result["email"] == "ghost@test.com"
        assert result["has_google"] is False
        assert result["has_password"] is False
        assert result["created_at"] is None


# ===================================================================
# 2. change_password
# ===================================================================

class TestChangePassword:
    """UserService.change_password()"""

    def test_wrong_current_password_returns_400(self, service, session):
        _make_user(session, email="pw@test.com")
        user = _token(email="pw@test.com")

        with pytest.raises(HTTPException) as exc_info:
            service.change_password(user, "WrongPassword", "NewPass123!")
        assert exc_info.value.status_code == 400
        assert "incorrect" in exc_info.value.detail["error"].lower()

    def test_short_new_password_returns_400(self, service, session):
        _make_user(session, email="pw2@test.com")
        user = _token(email="pw2@test.com")

        with pytest.raises(HTTPException) as exc_info:
            service.change_password(user, "OldPass123!", "short")
        assert exc_info.value.status_code == 400
        assert "8 characters" in exc_info.value.detail["error"]

    def test_success(self, service, session):
        _make_user(session, email="pw3@test.com")
        user = _token(email="pw3@test.com")

        result = service.change_password(user, "OldPass123!", "NewSecurePass!")
        assert "successfully" in result["message"].lower()

        # Verify the new password works
        from sentinelai.api.auth import verify_password
        db_user = session.query(User).filter(User.email == "pw3@test.com").first()
        assert verify_password("NewSecurePass!", db_user.password_hash)

    def test_user_not_found_returns_404(self, service):
        user = _token(email="nonexistent@test.com")
        with pytest.raises(HTTPException) as exc_info:
            service.change_password(user, "any", "anything123")
        assert exc_info.value.status_code == 404


# ===================================================================
# 3. change_username
# ===================================================================

class TestChangeUsername:
    """UserService.change_username()"""

    def test_too_short_returns_400(self, service, session):
        _make_user(session, email="un@test.com")
        user = _token(email="un@test.com")

        with pytest.raises(HTTPException) as exc_info:
            service.change_username(user, "x")
        assert exc_info.value.status_code == 400
        assert "2 characters" in exc_info.value.detail["error"]

    def test_too_long_returns_400(self, service, session):
        _make_user(session, email="un2@test.com")
        user = _token(email="un2@test.com")

        with pytest.raises(HTTPException) as exc_info:
            service.change_username(user, "a" * 65)
        assert exc_info.value.status_code == 400
        assert "64" in exc_info.value.detail["error"]

    def test_collision_returns_400(self, service, session):
        _make_user(session, username="taken_name", email="taken@test.com")
        _make_user(session, username="other_user", email="other@test.com")
        user = _token(username="other_user", email="other@test.com")

        with pytest.raises(HTTPException) as exc_info:
            service.change_username(user, "taken_name")
        assert exc_info.value.status_code == 400
        assert "already taken" in exc_info.value.detail["error"].lower()

    def test_user_not_found_returns_404(self, service):
        user = _token(email="gone@test.com")
        with pytest.raises(HTTPException) as exc_info:
            service.change_username(user, "newname")
        assert exc_info.value.status_code == 404

    def test_success(self, service, session):
        _make_user(session, username="oldname", email="rename@test.com")
        user = _token(username="oldname", email="rename@test.com")

        result = service.change_username(user, "newname")
        assert result["username"] == "newname"
        assert "successfully" in result["message"].lower()

        db_user = session.query(User).filter(User.email == "rename@test.com").first()
        assert db_user.username == "newname"


# ===================================================================
# 4. delete_account
# ===================================================================

class TestDeleteAccount:
    """UserService.delete_account()"""

    def test_super_admin_cannot_delete(self, service, session, config):
        _make_user(session, email="superadmin@test.com", is_super_admin=True)
        user = _token(
            email="superadmin@test.com",
            is_super_admin=True,
        )

        with pytest.raises(HTTPException) as exc_info:
            service.delete_account(user, "anypass")
        assert exc_info.value.status_code == 403
        assert "super-admin" in exc_info.value.detail["error"].lower()

    def test_wrong_password_returns_400(self, service, session):
        _make_user(session, email="del@test.com")
        user = _token(email="del@test.com")

        with pytest.raises(HTTPException) as exc_info:
            service.delete_account(user, "WrongPassword!")
        assert exc_info.value.status_code == 400
        assert "incorrect" in exc_info.value.detail["error"].lower()

    def test_user_not_found_returns_404(self, service):
        user = _token(email="notfound@test.com")
        with pytest.raises(HTTPException) as exc_info:
            service.delete_account(user, "anypass")
        assert exc_info.value.status_code == 404

    @patch("sentinelai.api.email.EmailService")
    def test_success_deletes_user_and_anonymizes_logs(self, mock_email_cls, service, session):
        """Successful deletion removes user and anonymizes related records."""
        _make_user(session, username="todelete", email="del2@test.com")
        user = _token(username="todelete", email="del2@test.com")

        # Mock email service to avoid SMTP calls
        mock_instance = mock_email_cls.return_value
        mock_instance.is_configured.return_value = False

        result = service.delete_account(user, "OldPass123!")
        assert "successfully" in result["message"].lower()

        # Verify user is gone
        db_user = session.query(User).filter(User.email == "del2@test.com").first()
        assert db_user is None

    @patch("sentinelai.api.email.EmailService")
    def test_cancels_stripe_subscription(self, mock_email_cls, session, config):
        """When user has Stripe sub, it gets canceled on delete."""
        config_with_stripe = SentinelConfig(
            logging=config.logging,
            auth=config.auth,
            billing=BillingConfig(enabled=True, stripe_secret_key="sk_test_fake"),
        )
        svc = UserService(session, config_with_stripe)

        _make_user(
            session, username="stripey", email="stripe@test.com",
            stripe_customer_id="cus_test123",
            stripe_subscription_id="sub_test123",
        )
        user = _token(username="stripey", email="stripe@test.com")

        mock_email_cls.return_value.is_configured.return_value = False

        with patch("sentinelai.billing.stripe_client.StripeClient") as mock_stripe:
            mock_client = mock_stripe.return_value
            mock_client.cancel_subscription.return_value = None

            result = svc.delete_account(user, "OldPass123!")
            assert "successfully" in result["message"].lower()
            mock_client.cancel_subscription.assert_called_once_with("sub_test123")


# ===================================================================
# 5. generate_api_key
# ===================================================================

class TestGenerateApiKey:
    """UserService.generate_api_key()"""

    def test_returns_sk_prefixed_key(self, service, session):
        _make_user(session, email="keygen@test.com")
        user = _token(email="keygen@test.com")

        result = service.generate_api_key(user)
        assert result["api_key"].startswith("sk-")
        assert len(result["api_key"]) > 10
        assert "message" in result

        # Verify hash is stored in DB
        import hashlib
        db_user = session.query(User).filter(User.email == "keygen@test.com").first()
        expected_hash = hashlib.sha256(result["api_key"].encode()).hexdigest()
        assert db_user.api_key_hash == expected_hash

    def test_user_not_found_returns_404(self, service):
        user = _token(email="nope@test.com")
        with pytest.raises(HTTPException) as exc_info:
            service.generate_api_key(user)
        assert exc_info.value.status_code == 404


# ===================================================================
# 6. revoke_api_key
# ===================================================================

class TestRevokeApiKey:
    """UserService.revoke_api_key()"""

    def test_no_key_to_revoke_returns_400(self, service, session):
        _make_user(session, email="nokey@test.com", api_key_hash=None)
        user = _token(email="nokey@test.com")

        with pytest.raises(HTTPException) as exc_info:
            service.revoke_api_key(user)
        assert exc_info.value.status_code == 400
        assert "no api key" in exc_info.value.detail["error"].lower()

    def test_success(self, service, session):
        _make_user(session, email="revoke@test.com", api_key_hash="somehash")
        user = _token(email="revoke@test.com")

        result = service.revoke_api_key(user)
        assert "successfully" in result["message"].lower()

        db_user = session.query(User).filter(User.email == "revoke@test.com").first()
        assert db_user.api_key_hash is None

    def test_user_not_found_returns_404(self, service):
        user = _token(email="missing@test.com")
        with pytest.raises(HTTPException) as exc_info:
            service.revoke_api_key(user)
        assert exc_info.value.status_code == 404
