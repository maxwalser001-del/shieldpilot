"""User service: business logic for user settings, password, API keys, account deletion."""

from __future__ import annotations

import hashlib
import logging
import secrets

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from sentinelai.api.auth import TokenData, hash_password, verify_password
from sentinelai.api.deps import is_super_admin
from sentinelai.core.config import SentinelConfig
from sentinelai.logger.database import (
    CommandLog,
    EmailVerificationToken,
    FileChangeLog,
    IncidentLog,
    NetworkAccessLog,
    PasswordResetToken,
    PromptScanLog,
    UsageRecord,
    User,
)

logger_module = logging.getLogger(__name__)


class UserService:
    """Encapsulates all user/settings business logic.

    Accepts a SQLAlchemy session and config as constructor params.
    Route handlers create the service, call methods, and handle session lifecycle.
    """

    def __init__(self, session: Session, config: SentinelConfig):
        self.session = session
        self.config = config

    def get_settings(self, user: TokenData) -> dict:
        """Get user profile and settings."""
        db_user = self.session.query(User).filter(User.email == user.email).first()

        return {
            "username": db_user.username if db_user else user.username,
            "email": user.email,
            "tier": db_user.tier if db_user else user.tier,
            "role": user.role,
            "is_super_admin": user.is_super_admin,
            "email_verified": user.email_verified,
            "has_google": bool(db_user and db_user.google_id),
            "has_password": bool(db_user and db_user.password_hash),
            "has_api_key": bool(db_user and db_user.api_key_hash),
            "created_at": db_user.created_at.isoformat() if db_user and db_user.created_at else None,
            "subscription_status": getattr(db_user, "subscription_status", None) if db_user else None,
            "cancel_at_period_end": getattr(db_user, "cancel_at_period_end", False) if db_user else False,
            "current_period_end": getattr(db_user, "current_period_end", None) if db_user else None,
            "has_subscription": bool(db_user and db_user.stripe_customer_id),
        }

    def change_password(self, user: TokenData, current_password: str, new_password: str) -> dict:
        """Change user password."""
        db_user = self.session.query(User).filter(User.email == user.email).first()
        if not db_user:
            raise HTTPException(status_code=404, detail={"error": "User not found"})

        # Verify current password
        if db_user.password_hash and not verify_password(current_password, db_user.password_hash):
            raise HTTPException(status_code=400, detail={"error": "Current password is incorrect"})

        if len(new_password) < 8:
            raise HTTPException(status_code=400, detail={"error": "New password must be at least 8 characters"})

        db_user.password_hash = hash_password(new_password)
        self.session.commit()

        return {"message": "Password updated successfully"}

    def change_username(self, user: TokenData, username: str) -> dict:
        """Change display username."""
        if not username or len(username) < 2:
            raise HTTPException(status_code=400, detail={"error": "Username must be at least 2 characters"})

        if len(username) > 64:
            raise HTTPException(status_code=400, detail={"error": "Username must be at most 64 characters"})

        db_user = self.session.query(User).filter(User.email == user.email).first()
        if not db_user:
            raise HTTPException(status_code=404, detail={"error": "User not found"})

        # Check for collision
        existing = self.session.query(User).filter(
            User.username == username,
            User.id != db_user.id,
        ).first()
        if existing:
            raise HTTPException(status_code=400, detail={"error": "Username already taken"})

        db_user.username = username
        self.session.commit()

        return {"message": "Username updated successfully", "username": username}

    def delete_account(self, user: TokenData, password: str) -> dict:
        """Permanently delete user account and all associated data (GDPR compliant)."""
        # Super-admin cannot delete their own account
        if is_super_admin(user, self.config):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "Super-admin account cannot be deleted"},
            )

        db_user = self.session.query(User).filter(User.email == user.email).first()
        if not db_user:
            raise HTTPException(status_code=404, detail={"error": "User not found"})

        # Verify password
        if not db_user.password_hash or not verify_password(password, db_user.password_hash):
            raise HTTPException(status_code=400, detail={"error": "Incorrect password"})

        # Cancel Stripe subscription if exists
        if db_user.stripe_subscription_id and self.config.billing.stripe_secret_key:
            try:
                from sentinelai.billing.stripe_client import StripeClient
                client = StripeClient(self.config.billing.stripe_secret_key)
                client.cancel_subscription(db_user.stripe_subscription_id)
            except Exception as e:
                logger_module.error(
                    f"Failed to cancel Stripe subscription for {user.email}: {e}"
                )
                # Don't block account deletion -- log and continue

        # Clean up related records
        self.session.query(EmailVerificationToken).filter(
            EmailVerificationToken.user_id == db_user.id
        ).delete()
        self.session.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == db_user.id
        ).delete()

        # Anonymize audit logs (preserve chain_hash integrity, remove personal data)
        tenant_filter = db_user.tenant_id if db_user.tenant_id else None

        # CommandLog: anonymize personal data fields
        cmd_query = self.session.query(CommandLog)
        if tenant_filter:
            cmd_query = cmd_query.filter(CommandLog.tenant_id == tenant_filter)
        cmd_query.update(
            {
                CommandLog.command: "[DELETED]",
                CommandLog.raw_command_hash: "[DELETED]",
                CommandLog.working_directory: None,
                CommandLog.output_snippet: None,
                CommandLog.llm_reasoning: None,
            },
            synchronize_session="fetch",
        )

        # IncidentLog: anonymize
        inc_query = self.session.query(IncidentLog)
        if tenant_filter:
            inc_query = inc_query.filter(IncidentLog.tenant_id == tenant_filter)
        inc_query.update(
            {
                IncidentLog.title: "[DELETED]",
                IncidentLog.description: "[DELETED]",
                IncidentLog.evidence: "[DELETED]",
                IncidentLog.resolution_notes: None,
            },
            synchronize_session="fetch",
        )

        # FileChangeLog: anonymize
        fc_query = self.session.query(FileChangeLog)
        if tenant_filter:
            fc_query = fc_query.filter(FileChangeLog.tenant_id == tenant_filter)
        fc_query.update(
            {FileChangeLog.file_path: "[DELETED]"},
            synchronize_session="fetch",
        )

        # NetworkAccessLog: anonymize
        na_query = self.session.query(NetworkAccessLog)
        if tenant_filter:
            na_query = na_query.filter(NetworkAccessLog.tenant_id == tenant_filter)
        na_query.update(
            {NetworkAccessLog.destination: "[DELETED]"},
            synchronize_session="fetch",
        )

        # PromptScanLog: anonymize
        ps_query = self.session.query(PromptScanLog)
        if tenant_filter:
            ps_query = ps_query.filter(PromptScanLog.tenant_id == tenant_filter)
        ps_query.update(
            {
                PromptScanLog.source: "[DELETED]",
                PromptScanLog.recommendation: None,
            },
            synchronize_session="fetch",
        )

        # UsageRecord: delete (no chain hash)
        usage_query = self.session.query(UsageRecord)
        if tenant_filter:
            usage_query = usage_query.filter(UsageRecord.tenant_id == tenant_filter)
        usage_query.delete(synchronize_session="fetch")

        # Store email before deletion for confirmation
        user_email = db_user.email
        user_name = db_user.username

        # Delete the user
        self.session.delete(db_user)
        self.session.commit()

        # Send deletion confirmation email (best-effort)
        try:
            from sentinelai.api.email import EmailService
            email_service = EmailService(self.config.auth)
            if email_service.is_configured():
                email_service.send_account_deletion_confirmation(user_email, user_name)
        except Exception:
            pass  # Non-critical -- account is already deleted

        return {"message": "Account deleted successfully"}

    def generate_api_key(self, user: TokenData) -> dict:
        """Generate a new API key. Returns the plaintext key once."""
        db_user = self.session.query(User).filter(User.email == user.email).first()
        if not db_user:
            raise HTTPException(status_code=404, detail={"error": "User not found"})

        # Generate a secure random key
        raw_key = "sk-" + secrets.token_hex(24)  # sk- prefix + 48 hex chars
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

        db_user.api_key_hash = key_hash
        self.session.commit()

        return {"api_key": raw_key, "message": "API key generated. Save it now — it won't be shown again."}

    def revoke_api_key(self, user: TokenData) -> dict:
        """Revoke the current API key."""
        db_user = self.session.query(User).filter(User.email == user.email).first()
        if not db_user:
            raise HTTPException(status_code=404, detail={"error": "User not found"})

        if not db_user.api_key_hash:
            raise HTTPException(status_code=400, detail={"error": "No API key to revoke"})

        db_user.api_key_hash = None
        self.session.commit()

        return {"message": "API key revoked successfully"}
