"""Authentication service: business logic extracted from auth route handlers."""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from sentinelai.api.auth import (
    Token,
    TokenData,
    create_access_token,
    hash_password,
    verify_password,
)
from sentinelai.core.config import SentinelConfig

_logger = logging.getLogger(__name__)


def _get_shared():
    """Lazy import to avoid circular dependency with routers package."""
    from sentinelai.api.routers._shared import (
        TOS_VERSION,
        _OAUTH_STATE_EXPIRY_SECONDS,
        _cleanup_expired_oauth_states,
        _login_limiter,
        _registration_limiter,
    )
    return TOS_VERSION, _OAUTH_STATE_EXPIRY_SECONDS, _cleanup_expired_oauth_states, _login_limiter, _registration_limiter


class AuthService:
    """Business logic for authentication operations.

    Accepts a SQLAlchemy session and config as constructor params.
    Raises HTTPException directly for pragmatic compatibility with existing tests.
    """

    def __init__(self, session: Session, config: SentinelConfig):
        self.session = session
        self.config = config

    def authenticate(self, username: str, password: str, client_ip: str) -> Token:
        """Authenticate user and return JWT token.

        Handles super-admin, default admin, and DB users.
        Records failed login attempts for rate limiting.
        Performs lightweight Stripe reconciliation at login.
        """
        from sentinelai.logger.database import User

        # Check for super-admin login (highest priority)
        # Use constant-time comparison to prevent timing attacks on email check
        _is_sa_email = hmac.compare_digest(
            username.encode(), self.config.auth.super_admin_email.encode()
        ) if self.config.auth.super_admin_email else False

        if _is_sa_email and self.config.auth.super_admin_password:
            # Ensure super-admin has a DB row (needed for API key, settings, etc.)
            sa_user = self.session.query(User).filter(User.email == self.config.auth.super_admin_email).first()
            if not sa_user:
                sa_user = User(
                    username=self.config.auth.super_admin_username,
                    email=self.config.auth.super_admin_email,
                    password_hash=hash_password(self.config.auth.super_admin_password),
                    role="admin",
                    tier="unlimited",
                    is_super_admin=True,
                    email_verified=True,
                )
                self.session.add(sa_user)
                self.session.commit()

            # Verify password: prefer bcrypt hash in DB, then check config value
            if sa_user and sa_user.password_hash:
                _pw_ok = verify_password(password, sa_user.password_hash)
            else:
                # No DB row yet — verify against config value
                config_pw = self.config.auth.super_admin_password
                if config_pw.startswith("$2b$") or config_pw.startswith("$2a$"):
                    # Config contains a bcrypt hash — use bcrypt.verify
                    _pw_ok = verify_password(password, config_pw)
                else:
                    # Plaintext fallback — constant-time compare, log warning
                    _pw_ok = hmac.compare_digest(
                        password.encode(),
                        config_pw.encode(),
                    )
                    if _pw_ok:
                        _logger.warning(
                            "Super-admin authenticated via plaintext password comparison. "
                            "Set SHIELDPILOT_SUPER_ADMIN_PASSWORD to a bcrypt hash for production security."
                        )

            if _pw_ok:
                token_data = TokenData(
                    username=self.config.auth.super_admin_username,
                    email=self.config.auth.super_admin_email,
                    role="admin",
                    tier="unlimited",
                    is_super_admin=True,
                    email_verified=True,
                )
                return create_access_token(token_data, self.config.auth)
            # Wrong password for super-admin email: fall through to normal login path

        # Check against default admin credentials (only if password is configured and non-empty)
        # Use constant-time comparison to prevent timing-based username/password enumeration.
        _default_pw = self.config.auth.default_admin_password or ""
        _default_user = self.config.auth.default_admin_user or ""
        _user_match = hmac.compare_digest(username.encode(), _default_user.encode())
        _pw_match = hmac.compare_digest(password.encode(), _default_pw.encode())
        if _default_pw and _user_match and _pw_match:
            token_data = TokenData(username=username, role="admin", email_verified=True)
            return create_access_token(token_data, self.config.auth)

        # Check database users (by username OR email)
        from sqlalchemy import or_

        user = (
            self.session.query(User)
            .filter(
                or_(User.username == username, User.email == username),
                User.is_active == True,
            )
            .first()
        )
        if user and user.password_hash and verify_password(password, user.password_hash):
            # Check if this user is super-admin by email
            user_is_super = user.is_super_admin or (user.email == self.config.auth.super_admin_email)
            token_data = TokenData(
                username=user.username or user.email,
                email=user.email,
                role=user.role,
                tenant_id=user.tenant_id,
                tier="unlimited" if user_is_super else getattr(user, "tier", "free"),
                is_super_admin=user_is_super,
                email_verified=getattr(user, "email_verified", False) or user_is_super,
            )
            # Lightweight Stripe reconciliation at login
            if user.stripe_subscription_id and self.config.billing.stripe_secret_key:
                try:
                    from sentinelai.billing.stripe_client import StripeClient, PRICE_TO_TIER
                    client = StripeClient(self.config.billing.stripe_secret_key)
                    sub_info = client.get_subscription(user.stripe_subscription_id)
                    real_status = sub_info.get("status")
                    real_tier = PRICE_TO_TIER.get(sub_info.get("price_id", ""), user.tier)

                    if real_status in ("active", "trialing", "past_due"):
                        if user.tier != real_tier or user.subscription_status != real_status:
                            user.tier = real_tier
                            user.subscription_status = real_status
                            user.current_period_end = sub_info.get("current_period_end")
                            user.cancel_at_period_end = sub_info.get("cancel_at_period_end", False)
                            self.session.commit()
                            token_data.tier = real_tier
                    elif real_status == "canceled":
                        if user.tier != "free":
                            user.tier = "free"
                            user.subscription_status = "canceled"
                            user.stripe_subscription_id = None
                            self.session.commit()
                            token_data.tier = "free"
                except Exception as exc:
                    _logger.warning("Stripe tier sync failed for user %s: %s (using cached tier)", user.username, exc)

            return create_access_token(token_data, self.config.auth)

        _, _, _, _login_limiter, _ = _get_shared()
        _login_limiter.record_attempt(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Invalid username or password"},
        )

    def register(
        self,
        email: str,
        password: str,
        username: str | None,
        tos_accepted: bool,
        client_ip: str,
        user_agent: str,
    ) -> Token:
        """Register a new user with email and password.

        Handles password validation, ToS acceptance, email uniqueness,
        username collision resolution, email verification, and super-admin detection.
        """
        from sentinelai.api.email import EmailService
        from sentinelai.logger.database import EmailVerificationToken, User

        # Password validation
        if len(password) < 8:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "Password must be at least 8 characters long"},
            )

        # ToS acceptance required
        if not tos_accepted:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "You must accept the Terms of Service to create an account"},
            )

        # Check if email already exists
        existing = self.session.query(User).filter(User.email == email).first()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "Email already registered"},
            )

        # Check if username already exists
        resolved_username = username or email.split("@")[0]
        existing_username = self.session.query(User).filter(User.username == resolved_username).first()
        if existing_username:
            # Append numbers to make unique
            base_username = resolved_username
            counter = 1
            while existing_username:
                resolved_username = f"{base_username}{counter}"
                existing_username = self.session.query(User).filter(User.username == resolved_username).first()
                counter += 1

        # Check if this is the super-admin email
        user_is_super = email == self.config.auth.super_admin_email

        # Anonymize IP for GDPR consent logging
        import ipaddress as _ipaddress
        try:
            addr = _ipaddress.ip_address(client_ip)
            if isinstance(addr, _ipaddress.IPv4Address):
                anon_ip = str(_ipaddress.IPv4Network(f"{client_ip}/24", strict=False).network_address)
            else:
                anon_ip = str(_ipaddress.IPv6Network(f"{client_ip}/32", strict=False).network_address)
        except ValueError:
            anon_ip = "unknown"

        # Create user (email_verified=False by default, super-admin is auto-verified)
        user = User(
            username=resolved_username,
            email=email,
            password_hash=hash_password(password),
            role="admin" if user_is_super else "viewer",
            tier="unlimited" if user_is_super else "free",
            is_super_admin=user_is_super,
            email_verified=user_is_super,  # Super-admin is auto-verified
            tos_accepted_at=datetime.now(timezone.utc),
            tos_version=_get_shared()[0],  # TOS_VERSION
            tos_ip_address=anon_ip,
            tos_user_agent=user_agent[:512],
        )
        self.session.add(user)
        self.session.commit()

        # Record successful registration for rate limiting
        _get_shared()[4].record_attempt(client_ip)  # _registration_limiter

        # Email verification: auto-verify if SMTP not configured, otherwise send email
        if not user_is_super:
            email_service = EmailService(self.config.auth)
            if not email_service.is_configured():
                # No SMTP = dev mode: auto-verify email
                user.email_verified = True
                self.session.commit()
            else:
                # SMTP configured -- create verification token and send email
                token = secrets.token_urlsafe(32)
                token_hash = hashlib.sha256(token.encode()).hexdigest()
                verification = EmailVerificationToken(
                    user_id=user.id,
                    token_hash=token_hash,
                    expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
                )
                self.session.add(verification)
                self.session.commit()
                try:
                    email_service.send_email_verification(user.email, token, user.username)
                except Exception as e:
                    _logger.error("Failed to send verification email to %s: %s", user.email, e)
                    # User stays unverified -- they can use "Resend" to retry

        # Return token
        token_data = TokenData(
            username=user.username,
            email=user.email,
            role=user.role,
            tier=user.tier,
            is_super_admin=user.is_super_admin,
            email_verified=user.email_verified,
        )
        return create_access_token(token_data, self.config.auth)

    def request_password_reset(self, email: str) -> dict:
        """Request a password reset email.

        Always returns success to prevent email enumeration.
        """
        from sentinelai.api.email import EmailService
        from sentinelai.logger.database import PasswordResetToken, User

        user = self.session.query(User).filter(User.email == email).first()

        # Always return success to prevent email enumeration
        if not user:
            return {"message": "If the email exists, a reset link has been sent"}

        # Generate secure token
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        # Create reset token record (expires in 1 hour)
        reset_token = PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        self.session.add(reset_token)
        self.session.commit()

        # Send email
        email_service = EmailService(self.config.auth)
        email_service.send_password_reset(user.email, token, user.username)

        return {"message": "If the email exists, a reset link has been sent"}

    def confirm_password_reset(self, token: str, new_password: str) -> dict:
        """Reset password using token.

        Validates password length, verifies token, and updates the password.
        """
        from sentinelai.logger.database import PasswordResetToken, User

        # Password validation
        if len(new_password) < 8:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "Password must be at least 8 characters long"},
            )

        token_hash = hashlib.sha256(token.encode()).hexdigest()

        # Atomic UPDATE to prevent race conditions: mark token as used in a
        # single statement and check rowcount.  If two concurrent requests use
        # the same token, only one UPDATE will match (used==False).
        from sqlalchemy import update

        result = self.session.execute(
            update(PasswordResetToken)
            .where(
                PasswordResetToken.token_hash == token_hash,
                PasswordResetToken.used == False,
                PasswordResetToken.expires_at > datetime.now(timezone.utc),
            )
            .values(used=True)
        )
        self.session.flush()

        if result.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "Invalid or expired reset token"},
            )

        # Fetch the token to get user_id
        reset_token = (
            self.session.query(PasswordResetToken)
            .filter(PasswordResetToken.token_hash == token_hash)
            .first()
        )

        # Update user password
        user = self.session.get(User, reset_token.user_id)
        user.password_hash = hash_password(new_password)

        self.session.commit()

        return {"message": "Password reset successfully"}

    def verify_email(self, token: str) -> str:
        """Verify email address using token.

        Returns the redirect URL string (not the RedirectResponse itself).
        The router is responsible for creating the RedirectResponse.
        """
        from sentinelai.logger.database import EmailVerificationToken, User

        token_hash = hashlib.sha256(token.encode()).hexdigest()

        verification = (
            self.session.query(EmailVerificationToken)
            .filter(
                EmailVerificationToken.token_hash == token_hash,
                EmailVerificationToken.used == False,
                EmailVerificationToken.expires_at > datetime.now(timezone.utc),
            )
            .first()
        )

        if not verification:
            return "/login?verify_error=true"

        # Update user
        user = self.session.get(User, verification.user_id)
        if user:
            user.email_verified = True

        # Mark token as used
        verification.used = True
        self.session.commit()

        return "/login?verified=true"

    def resend_verification_email(self, user: TokenData) -> dict:
        """Resend email verification link.

        Returns early if email is already verified.
        """
        from sentinelai.api.email import EmailService
        from sentinelai.logger.database import EmailVerificationToken, User

        if user.email_verified:
            return {"message": "Email already verified"}

        db_user = self.session.query(User).filter(User.email == user.email).first()
        if not db_user:
            raise HTTPException(status_code=404, detail={"error": "User not found"})

        # Generate new token
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        verification = EmailVerificationToken(
            user_id=db_user.id,
            token_hash=token_hash,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
        self.session.add(verification)
        self.session.commit()

        email_service = EmailService(self.config.auth)
        email_service.send_email_verification(db_user.email, token, db_user.username)

        return {"message": "Verification email sent"}

    def get_google_auth_url(self) -> dict:
        """Get Google OAuth authorization URL.

        Creates a CSRF state token and stores it in the database.
        Returns the auth URL and state token.
        """
        from sentinelai.api.oauth import get_google_auth_url as _get_google_auth_url
        from sentinelai.logger.database import OAuthState

        if not self.config.auth.google_client_id:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"error": "Google OAuth not configured"},
            )

        _, _, _cleanup_expired_oauth_states, _, _ = _get_shared()
        state = secrets.token_urlsafe(32)
        _cleanup_expired_oauth_states()  # Clean up old states

        # Store state in database (persists across restarts, shared across workers)
        self.session.add(OAuthState(state=state))
        self.session.commit()

        auth_url = _get_google_auth_url(
            self.config.auth.google_client_id,
            self.config.auth.google_redirect_uri,
            state,
        )
        return {"auth_url": auth_url, "state": state}

    def handle_google_callback(
        self,
        code: str,
        state: str,
        client_ip: str,
        user_agent: str,
    ) -> Token:
        """Handle Google OAuth callback.

        Verifies CSRF state, exchanges code for token, gets user info from Google,
        finds or creates user, and returns a JWT token.
        """
        from sqlalchemy import or_

        from sentinelai.api.oauth import (
            exchange_code_for_token_sync,
            get_google_user_info_sync,
        )
        from sentinelai.logger.database import OAuthState, User

        # Verify state for CSRF protection (check existence and expiration in DB)
        TOS_VERSION, _OAUTH_STATE_EXPIRY_SECONDS, _cleanup_expired_oauth_states, _, _ = _get_shared()
        _cleanup_expired_oauth_states()

        oauth_state = self.session.query(OAuthState).filter(OAuthState.state == state).first()
        if not oauth_state:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "Invalid or expired state parameter"},
            )
        # Check expiration
        created = oauth_state.created_at.replace(tzinfo=timezone.utc) if oauth_state.created_at.tzinfo is None else oauth_state.created_at
        if datetime.now(timezone.utc) - created > timedelta(seconds=_OAUTH_STATE_EXPIRY_SECONDS):
            self.session.delete(oauth_state)
            self.session.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "OAuth state expired, please try again"},
            )
        # Consume the state (one-time use)
        self.session.delete(oauth_state)
        self.session.commit()

        try:
            # Exchange code for token
            token_response = exchange_code_for_token_sync(
                code,
                self.config.auth.google_client_id,
                self.config.auth.google_client_secret,
                self.config.auth.google_redirect_uri,
            )

            # Get user info from Google
            user_info = get_google_user_info_sync(token_response["access_token"])

        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": f"Failed to authenticate with Google: {str(e)}"},
            )

        # Find or create user
        user = (
            self.session.query(User)
            .filter(
                or_(
                    User.google_id == user_info["id"],
                    User.email == user_info["email"],
                )
            )
            .first()
        )

        google_email = user_info.get("email", "")
        is_super = google_email == self.config.auth.super_admin_email

        if not user:
            # Create new user
            username = google_email.split("@")[0] if google_email else user_info["id"]

            # Check for username collision
            existing = self.session.query(User).filter(User.username == username).first()
            if existing:
                username = f"{username}_{user_info['id'][:8]}"

            # Anonymize IP for consent logging
            import ipaddress as _ipaddress
            try:
                _addr = _ipaddress.ip_address(client_ip)
                if isinstance(_addr, _ipaddress.IPv4Address):
                    _anon_ip = str(_ipaddress.IPv4Network(f"{client_ip}/24", strict=False).network_address)
                else:
                    _anon_ip = str(_ipaddress.IPv6Network(f"{client_ip}/32", strict=False).network_address)
            except ValueError:
                _anon_ip = "unknown"

            user = User(
                username=username,
                email=google_email,
                google_id=user_info["id"],
                role="admin" if is_super else "viewer",
                tier="unlimited" if is_super else "free",
                is_super_admin=is_super,
                email_verified=True,  # Google verified email
                tos_accepted_at=datetime.now(timezone.utc),
                tos_version=TOS_VERSION,
                tos_ip_address=_anon_ip,
                tos_user_agent=user_agent[:512],
            )
            self.session.add(user)
            self.session.commit()

        elif not user.google_id:
            # Link existing email account to Google
            user.google_id = user_info["id"]
            user.email_verified = True  # Google verified email
            if is_super and not user.is_super_admin:
                user.is_super_admin = True
                user.tier = "unlimited"
                user.role = "admin"
            self.session.commit()

        # Create JWT token
        token_data = TokenData(
            username=user.email or user.username,
            email=user.email,
            role=user.role,
            tier=getattr(user, "tier", "free"),
            is_super_admin=getattr(user, "is_super_admin", False),
            email_verified=True,  # Google verifies email
        )
        return create_access_token(token_data, self.config.auth)
