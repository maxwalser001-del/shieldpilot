"""Coverage tests for sentinelai/api/email.py and sentinelai/api/oauth.py.

Targets:
- email.py: 22% -> 60%+
- oauth.py: 0% -> 60%+
"""

from __future__ import annotations

import asyncio
import email as email_lib

import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from sentinelai.api.email import EmailService
from sentinelai.core.config import AuthConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _configured_auth() -> AuthConfig:
    """Return an AuthConfig with SMTP fully configured."""
    return AuthConfig(
        smtp_host="smtp.test.com",
        smtp_port=587,
        smtp_user="test@test.com",
        smtp_password="smtp-pass-123",
        smtp_from_email="noreply@test.com",
        password_reset_url="https://app.test.com/reset?token=",
    )


def _decode_mime_body(raw_mime: str) -> str:
    """Parse a raw MIME message and return the concatenated decoded text of all parts."""
    msg = email_lib.message_from_string(raw_mime)
    parts = []
    if msg.is_multipart():
        for part in msg.walk():
            payload = part.get_payload(decode=True)
            if payload:
                parts.append(payload.decode("utf-8", errors="replace"))
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            parts.append(payload.decode("utf-8", errors="replace"))
    return "\n".join(parts)


def _unconfigured_auth(**overrides) -> AuthConfig:
    """Return an AuthConfig with SMTP NOT configured (missing host/user)."""
    defaults = dict(smtp_host="", smtp_user="", smtp_password="", smtp_from_email="")
    defaults.update(overrides)
    return AuthConfig(**defaults)


# ===================================================================
# EmailService.is_configured()
# ===================================================================


class TestEmailServiceIsConfigured:
    """EmailService.is_configured() returns True only when smtp_host AND smtp_user are set."""

    def test_returns_true_when_both_set(self):
        service = EmailService(_configured_auth())
        assert service.is_configured() is True

    def test_returns_false_when_host_empty(self):
        service = EmailService(_unconfigured_auth(smtp_host="", smtp_user="user@test.com"))
        assert service.is_configured() is False

    def test_returns_false_when_user_empty(self):
        service = EmailService(_unconfigured_auth(smtp_host="smtp.test.com", smtp_user=""))
        assert service.is_configured() is False

    def test_returns_false_when_both_empty(self):
        service = EmailService(_unconfigured_auth())
        assert service.is_configured() is False


# ===================================================================
# send_password_reset()
# ===================================================================


class TestSendPasswordReset:
    """EmailService.send_password_reset()."""

    def test_not_configured_returns_false_with_log(self):
        service = EmailService(_unconfigured_auth())
        with patch("sentinelai.api.email._logger") as mock_logger:
            result = service.send_password_reset("user@example.com", "tok-123", username="Alice")
            assert result is False
            mock_logger.warning.assert_called_once()
            assert "SMTP not configured" in mock_logger.warning.call_args[0][0]

    @patch("sentinelai.api.email.smtplib.SMTP")
    def test_configured_sends_email(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        service = EmailService(_configured_auth())
        result = service.send_password_reset("user@example.com", "reset-tok-456", username="Bob")

        assert result is True
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("test@test.com", "smtp-pass-123")
        mock_server.sendmail.assert_called_once()
        # Verify recipient
        call_args = mock_server.sendmail.call_args
        assert call_args[0][1] == "user@example.com"

    @patch("sentinelai.api.email.smtplib.SMTP")
    def test_uses_email_prefix_when_no_username(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        service = EmailService(_configured_auth())
        result = service.send_password_reset("alice@example.com", "tok-789")

        assert result is True
        # The email body should contain "alice" (the prefix) not a custom username
        sent_body = mock_server.sendmail.call_args[0][2]
        assert "alice" in sent_body


# ===================================================================
# send_email_verification()
# ===================================================================


class TestSendEmailVerification:
    """EmailService.send_email_verification()."""

    def test_not_configured_returns_false(self):
        service = EmailService(_unconfigured_auth())
        with patch("sentinelai.api.email._logger") as mock_logger:
            result = service.send_email_verification("user@test.com", "verify-tok")
            assert result is False
            mock_logger.warning.assert_called_once()
            assert "SMTP not configured" in mock_logger.warning.call_args[0][0]

    @patch("sentinelai.api.email.smtplib.SMTP")
    def test_configured_sends_verification(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        service = EmailService(_configured_auth())
        result = service.send_email_verification(
            "user@test.com", "verify-tok-123", username="Charlie", base_url="https://app.test.com"
        )

        assert result is True
        mock_server.starttls.assert_called_once()
        mock_server.sendmail.assert_called_once()
        sent_body = mock_server.sendmail.call_args[0][2]
        assert "verify-tok-123" in sent_body
        assert "Charlie" in sent_body


# ===================================================================
# send_account_deletion_confirmation()
# ===================================================================


class TestSendAccountDeletionConfirmation:
    """EmailService.send_account_deletion_confirmation()."""

    def test_not_configured_returns_false(self):
        service = EmailService(_unconfigured_auth())
        result = service.send_account_deletion_confirmation("user@test.com", username="DeletedUser")
        assert result is False

    @patch("sentinelai.api.email.smtplib.SMTP")
    def test_configured_sends_deletion_email(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        service = EmailService(_configured_auth())
        result = service.send_account_deletion_confirmation("user@test.com", username="DeletedUser")

        assert result is True
        mock_server.sendmail.assert_called_once()
        sent_body = mock_server.sendmail.call_args[0][2]
        assert "DeletedUser" in sent_body
        assert "Account Deleted" in sent_body


# ===================================================================
# send_tier_upgrade_notification()
# ===================================================================


class TestSendTierUpgradeNotification:
    """EmailService.send_tier_upgrade_notification()."""

    def test_not_configured_returns_false(self):
        service = EmailService(_unconfigured_auth())
        assert service.send_tier_upgrade_notification("u@t.com", "pro") is False

    @patch("sentinelai.api.email.smtplib.SMTP")
    def test_pro_tier_upgrade(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        service = EmailService(_configured_auth())
        result = service.send_tier_upgrade_notification("user@test.com", "pro", username="ProUser")

        assert result is True
        sent_body = mock_server.sendmail.call_args[0][2]
        assert "Pro" in sent_body
        assert "1,000" in sent_body

    @patch("sentinelai.api.email.smtplib.SMTP")
    def test_enterprise_tier_upgrade(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        service = EmailService(_configured_auth())
        result = service.send_tier_upgrade_notification("user@test.com", "enterprise", username="EntUser")

        assert result is True
        sent_body = mock_server.sendmail.call_args[0][2]
        assert "Enterprise" in sent_body
        assert "Unlimited" in sent_body
        assert "Multi-user" in sent_body or "multi-user" in sent_body.lower()


# ===================================================================
# send_tier_downgrade_notification()
# ===================================================================


class TestSendTierDowngradeNotification:
    """EmailService.send_tier_downgrade_notification()."""

    def test_not_configured_returns_false(self):
        service = EmailService(_unconfigured_auth())
        assert service.send_tier_downgrade_notification("u@t.com", "pro") is False

    @patch("sentinelai.api.email.smtplib.SMTP")
    def test_reason_canceled(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        service = EmailService(_configured_auth())
        result = service.send_tier_downgrade_notification("u@t.com", "pro", reason="canceled")

        assert result is True
        sent_body = mock_server.sendmail.call_args[0][2]
        assert "canceled" in sent_body

    @patch("sentinelai.api.email.smtplib.SMTP")
    def test_reason_payment_failed(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        service = EmailService(_configured_auth())
        result = service.send_tier_downgrade_notification("u@t.com", "pro", reason="payment_failed")

        assert result is True
        sent_body = mock_server.sendmail.call_args[0][2]
        assert "payment issue" in sent_body

    @patch("sentinelai.api.email.smtplib.SMTP")
    def test_reason_other(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        service = EmailService(_configured_auth())
        result = service.send_tier_downgrade_notification("u@t.com", "pro", reason="admin_action")

        assert result is True
        sent_body = mock_server.sendmail.call_args[0][2]
        assert "status has changed" in sent_body


# ===================================================================
# send_payment_failed_notification()
# ===================================================================


class TestSendPaymentFailedNotification:
    """EmailService.send_payment_failed_notification()."""

    def test_not_configured_returns_false(self):
        service = EmailService(_unconfigured_auth())
        assert service.send_payment_failed_notification("u@t.com", "pro") is False

    @patch("sentinelai.api.email.smtplib.SMTP")
    def test_sends_payment_warning(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        service = EmailService(_configured_auth())
        result = service.send_payment_failed_notification("user@test.com", "pro", username="PayUser")

        assert result is True
        mock_server.sendmail.assert_called_once()
        raw_mime = mock_server.sendmail.call_args[0][2]
        decoded = _decode_mime_body(raw_mime)
        assert "unable to process" in decoded
        assert "PayUser" in decoded
        assert "Pro" in decoded


# ===================================================================
# _send_email() internals
# ===================================================================


class TestSendEmailInternal:
    """EmailService._send_email() low-level behavior."""

    @patch("sentinelai.api.email.smtplib.SMTP")
    def test_starttls_login_sendmail_called(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        service = EmailService(_configured_auth())
        result = service._send_email("to@test.com", "Subject", "text body", "<p>html body</p>")

        assert result is True
        mock_smtp_cls.assert_called_once_with("smtp.test.com", 587)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("test@test.com", "smtp-pass-123")
        mock_server.sendmail.assert_called_once()

        # Verify from/to addresses in sendmail call
        args = mock_server.sendmail.call_args[0]
        assert args[0] == "noreply@test.com"  # from
        assert args[1] == "to@test.com"  # to

    @patch("sentinelai.api.email.smtplib.SMTP")
    def test_smtp_exception_returns_false(self, mock_smtp_cls):
        mock_smtp_cls.side_effect = ConnectionRefusedError("Connection refused")

        service = EmailService(_configured_auth())
        result = service._send_email("to@test.com", "Subject", "text", "<p>html</p>")

        assert result is False

    @patch("sentinelai.api.email.smtplib.SMTP")
    def test_sendmail_exception_returns_false(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_server.sendmail.side_effect = Exception("SMTP error during send")
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        service = EmailService(_configured_auth())
        result = service._send_email("to@test.com", "Subject", "text", "<p>html</p>")

        assert result is False

    @patch("sentinelai.api.email.smtplib.SMTP")
    def test_skips_login_when_no_credentials(self, mock_smtp_cls):
        mock_server = MagicMock()
        mock_smtp_cls.return_value.__enter__ = MagicMock(return_value=mock_server)
        mock_smtp_cls.return_value.__exit__ = MagicMock(return_value=False)

        config = AuthConfig(
            smtp_host="smtp.test.com",
            smtp_user="",
            smtp_password="",
            smtp_from_email="noreply@test.com",
        )
        service = EmailService(config)
        # Call _send_email directly (bypasses is_configured check)
        result = service._send_email("to@test.com", "Subject", "text", "<p>html</p>")

        assert result is True
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_not_called()


# ===================================================================
# OAuth: get_google_auth_url()
# ===================================================================


class TestGetGoogleAuthUrl:
    """get_google_auth_url() generates correct authorization URL."""

    def test_returns_url_with_all_params(self):
        from sentinelai.api.oauth import get_google_auth_url

        url = get_google_auth_url(
            client_id="test-client-id",
            redirect_uri="https://app.test.com/callback",
            state="csrf-state-token",
        )

        assert url.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
        assert "client_id=test-client-id" in url
        assert "redirect_uri=" in url
        assert "response_type=code" in url
        assert "scope=" in url
        assert "state=csrf-state-token" in url
        assert "access_type=offline" in url
        assert "prompt=select_account" in url

    def test_url_encodes_special_characters(self):
        from sentinelai.api.oauth import get_google_auth_url

        url = get_google_auth_url(
            client_id="id with spaces",
            redirect_uri="https://app.test.com/call back",
            state="state&special=chars",
        )

        # URL should be properly encoded (no raw spaces or ampersands in values)
        assert "id+with+spaces" in url or "id%20with%20spaces" in url


# ===================================================================
# OAuth: exchange_code_for_token_sync()
# ===================================================================


class TestExchangeCodeForTokenSync:
    """exchange_code_for_token_sync() makes correct POST to Google token endpoint."""

    def test_posts_with_correct_data(self):
        from sentinelai.api.oauth import exchange_code_for_token_sync

        mock_response = MagicMock()
        mock_response.json.return_value = {"access_token": "test-access-token", "token_type": "Bearer"}
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.post.return_value = mock_response

        with patch("sentinelai.api.oauth.httpx.Client") as MockClient:
            MockClient.return_value.__enter__ = MagicMock(return_value=mock_client)
            MockClient.return_value.__exit__ = MagicMock(return_value=False)

            result = exchange_code_for_token_sync(
                code="auth-code-123",
                client_id="client-id",
                client_secret="client-secret",
                redirect_uri="https://app.test.com/callback",
            )

        assert result == {"access_token": "test-access-token", "token_type": "Bearer"}
        mock_client.post.assert_called_once()
        call_kwargs = mock_client.post.call_args
        assert call_kwargs[1]["data"]["code"] == "auth-code-123"
        assert call_kwargs[1]["data"]["client_id"] == "client-id"
        assert call_kwargs[1]["data"]["client_secret"] == "client-secret"
        assert call_kwargs[1]["data"]["grant_type"] == "authorization_code"
        mock_response.raise_for_status.assert_called_once()


# ===================================================================
# OAuth: get_google_user_info_sync()
# ===================================================================


class TestGetGoogleUserInfoSync:
    """get_google_user_info_sync() makes correct GET with Bearer token."""

    def test_gets_with_bearer_token(self):
        from sentinelai.api.oauth import get_google_user_info_sync

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "id": "123",
            "email": "user@gmail.com",
            "name": "Test User",
            "picture": "https://photo.url/pic.jpg",
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.get.return_value = mock_response

        with patch("sentinelai.api.oauth.httpx.Client") as MockClient:
            MockClient.return_value.__enter__ = MagicMock(return_value=mock_client)
            MockClient.return_value.__exit__ = MagicMock(return_value=False)

            result = get_google_user_info_sync("my-access-token")

        assert result["email"] == "user@gmail.com"
        assert result["id"] == "123"
        mock_client.get.assert_called_once()
        call_kwargs = mock_client.get.call_args
        assert call_kwargs[1]["headers"]["Authorization"] == "Bearer my-access-token"
        mock_response.raise_for_status.assert_called_once()


# ===================================================================
# OAuth: exchange_code_for_token() (async)
# ===================================================================


class TestExchangeCodeForTokenAsync:
    """exchange_code_for_token() async version."""

    def test_async_posts_with_correct_data(self):
        from sentinelai.api.oauth import exchange_code_for_token

        mock_response = MagicMock()
        mock_response.json.return_value = {"access_token": "async-token", "token_type": "Bearer"}
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response

        with patch("sentinelai.api.oauth.httpx.AsyncClient") as MockAsyncClient:
            MockAsyncClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockAsyncClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = asyncio.get_event_loop().run_until_complete(
                exchange_code_for_token(
                    code="async-code",
                    client_id="async-client-id",
                    client_secret="async-secret",
                    redirect_uri="https://app.test.com/callback",
                )
            )

        assert result == {"access_token": "async-token", "token_type": "Bearer"}
        mock_client.post.assert_called_once()
        call_kwargs = mock_client.post.call_args
        assert call_kwargs[1]["data"]["code"] == "async-code"
        assert call_kwargs[1]["data"]["grant_type"] == "authorization_code"


# ===================================================================
# OAuth: get_google_user_info() (async)
# ===================================================================


class TestGetGoogleUserInfoAsync:
    """get_google_user_info() async version."""

    def test_async_gets_with_bearer_token(self):
        from sentinelai.api.oauth import get_google_user_info

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "id": "456",
            "email": "async@gmail.com",
            "name": "Async User",
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_response

        with patch("sentinelai.api.oauth.httpx.AsyncClient") as MockAsyncClient:
            MockAsyncClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockAsyncClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = asyncio.get_event_loop().run_until_complete(
                get_google_user_info("async-access-token")
            )

        assert result["email"] == "async@gmail.com"
        mock_client.get.assert_called_once()
        call_kwargs = mock_client.get.call_args
        assert call_kwargs[1]["headers"]["Authorization"] == "Bearer async-access-token"
