"""FastAPI dependency injection for ShieldPilot API."""

from __future__ import annotations

import hashlib
import logging
import threading
from datetime import date, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from sqlalchemy.orm import Session

from sentinelai.api.auth import TokenData, decode_token
from sentinelai.core.config import TIER_LIMITS, SentinelConfig, TierLimits, load_config
from sentinelai.core.secrets import SecretsMasker
from sentinelai.logger import BlackboxLogger

# Shared singletons (initialized on first use, protected by lock)
_config: Optional[SentinelConfig] = None
_logger: Optional[BlackboxLogger] = None
_init_lock = threading.RLock()  # RLock: reentrant — get_logger() calls get_config() inside the lock

security = HTTPBearer(auto_error=False)


class UsageInfo(BaseModel):
    """Current usage statistics for the billing period."""
    tier: str
    commands_used: int
    commands_limit: int
    scans_used: int
    scans_limit: int
    commands_remaining: int
    scans_remaining: int
    limit_reached: bool
    approaching_limit: bool = False
    upgrade_url: str
    is_admin: bool = False
    booster_credits_remaining: int = 0


def get_config() -> SentinelConfig:
    """Get the application configuration (cached singleton, thread-safe)."""
    global _config
    if _config is None:
        with _init_lock:
            if _config is None:  # Double-checked locking
                _config = load_config()
    return _config


def get_logger() -> BlackboxLogger:
    """Get the blackbox logger (cached singleton, thread-safe)."""
    global _logger
    if _logger is None:
        with _init_lock:
            if _logger is None:  # Double-checked locking
                config = get_config()
                masker = SecretsMasker(config.secrets_patterns)
                _logger = BlackboxLogger(config=config.logging, masker=masker)
    return _logger


def get_db_session(logger: BlackboxLogger = Depends(get_logger)):
    """Yield a SQLAlchemy session, closing it when the request finishes.

    Usage in endpoints:
        session: Session = Depends(get_db_session)

    The session is automatically closed after the response is sent.
    For write operations, call session.commit() / session.rollback() explicitly.
    """
    session = logger._get_session()
    try:
        yield session
    finally:
        session.close()


_LOCAL_ADDRS = {"127.0.0.1", "::1"}

_deps_logger = logging.getLogger(__name__)


def _is_local_request(request: Request) -> bool:
    """Check if request originates from localhost (127.0.0.1 or ::1)."""
    client = request.client
    return client is not None and client.host in _LOCAL_ADDRS


def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    config: SentinelConfig = Depends(get_config),
    session: Session = Depends(get_db_session),
) -> TokenData:
    """Validate JWT token or API key and return current user data.

    Checks in order:
    1. API key (X-API-Key header)
    2. Bearer token (Authorization header)
    3. Local-first bypass (localhost + no credentials + config.auth.local_first)
    Raises HTTPException 401 if none are valid.
    """
    # Check API key first
    api_key = request.headers.get("X-API-Key")
    if api_key:
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        from sentinelai.logger.database import User
        db_user = session.query(User).filter(
            User.api_key_hash == key_hash,
            User.is_active == True,
        ).first()
        if db_user:
            return TokenData(
                username=db_user.username,
                email=db_user.email,
                role=db_user.role,
                tenant_id=db_user.tenant_id,
                tier=db_user.tier,
                is_super_admin=db_user.is_super_admin,
                email_verified=db_user.email_verified,
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Invalid API key"},
        )

    # Fall back to Bearer token
    if credentials is not None:
        token_data = decode_token(credentials.credentials, config.auth)
        if token_data is not None:
            return token_data
        # Token invalid/expired — in local-first mode on localhost, fall through
        # to the local-admin bypass instead of returning 401
        if not (config.auth.local_first and _is_local_request(request)):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"error": "Invalid or expired token"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        _deps_logger.info("Expired token on localhost — falling through to local-first bypass")

    # Local-first mode: localhost connections bypass auth (local = trusted)
    if config.auth.local_first and _is_local_request(request):
        return TokenData(
            username="local-admin",
            email="local@localhost",
            role="admin",
            tier="unlimited",
            is_super_admin=False,
            email_verified=True,
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={"error": "Authentication required"},
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_verified_email(
    user: TokenData = Depends(get_current_user),
    config: SentinelConfig = Depends(get_config),
) -> TokenData:
    """Require verified email for certain actions. Super-admin bypasses."""
    if is_super_admin(user, config):
        return user
    if not user.email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Email verification required", "message": "Please check your inbox."},
        )
    return user


def require_admin(
    user: TokenData = Depends(require_verified_email),
) -> TokenData:
    """Require admin role and verified email for the current user."""
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"error": "Admin access required"},
        )
    return user


def is_super_admin(user: TokenData, config: SentinelConfig) -> bool:
    """Check if user is the super-admin (bypasses all limits).

    Super-admin is determined by:
    1. is_super_admin flag in token (set during login)
    2. Or matching super_admin_email in config
    """
    if getattr(user, "is_super_admin", False):
        return True
    if user.username == config.auth.super_admin_email:
        return True
    if getattr(user, "email", None) == config.auth.super_admin_email:
        return True
    return False


def reset_singletons():
    """Reset cached singletons (used in testing)."""
    global _config, _logger
    with _init_lock:
        _config = None
        _logger = None


def get_user_tier_limits(
    user: TokenData,
    config: SentinelConfig,
    logger: BlackboxLogger,
    session: Optional[Session] = None,
) -> tuple[str, TierLimits]:
    """Resolve effective tier and limits for a user.

    Priority: super-admin > user.tier from DB > config.billing.tier (fallback)
    """
    if is_super_admin(user, config):
        return "unlimited", TIER_LIMITS["unlimited"]
    if not config.billing.enabled:
        user_tier = user.tier or "free"
        return user_tier, TIER_LIMITS.get(user_tier, TIER_LIMITS["free"])

    owns_session = session is None
    if owns_session:
        session = logger._get_session()
    try:
        from sentinelai.logger.database import User as DBUser
        db_user = session.query(DBUser).filter(DBUser.email == user.email).first()
        if db_user and db_user.tier and db_user.tier != "free":
            user_tier = db_user.tier
            # Legacy tier migration: enterprise → pro_plus
            if user_tier == "enterprise":
                user_tier = "pro_plus"
            # Non-admin unlimited users → pro_plus
            if user_tier == "unlimited" and not is_super_admin(user, config):
                user_tier = "pro_plus"
            if user_tier in ("pro", "pro_plus"):
                active_statuses = ("active", "trialing", "past_due")
                if getattr(db_user, "subscription_status", None) not in active_statuses:
                    user_tier = "free"
        else:
            user_tier = "free"
        return user_tier, TIER_LIMITS.get(user_tier, TIER_LIMITS["free"])
    finally:
        if owns_session:
            session.close()


def get_daily_usage_for_user(
    user: TokenData,
    logger: BlackboxLogger,
    config: SentinelConfig,
) -> UsageInfo:
    """Get daily usage for a specific user (per-user tier from DB)."""
    user_is_admin = user.role == "admin" or is_super_admin(user, config)

    if is_super_admin(user, config):
        return UsageInfo(
            tier="unlimited",
            commands_used=0,
            commands_limit=-1,
            scans_used=0,
            scans_limit=-1,
            commands_remaining=-1,
            scans_remaining=-1,
            limit_reached=False,
            upgrade_url="",
            is_admin=True,
        )
    # Resolve per-user tier from DB
    user_tier, user_limits = get_user_tier_limits(user, config, logger)
    return _get_daily_usage_internal(
        logger, config, user_tier=user_tier, user_limits=user_limits,
        is_admin=user_is_admin, user_email=user.email,
    )


def get_daily_usage(
    logger: BlackboxLogger = Depends(get_logger),
    config: SentinelConfig = Depends(get_config),
) -> UsageInfo:
    """Get current daily usage statistics (no user context)."""
    return _get_daily_usage_internal(logger, config)


def _get_daily_usage_internal(
    logger: BlackboxLogger,
    config: SentinelConfig,
    user_tier: Optional[str] = None,
    user_limits: Optional[TierLimits] = None,
    is_admin: bool = False,
    session: Optional[Session] = None,
    user_email: Optional[str] = None,
) -> UsageInfo:
    """Internal function for daily usage stats.

    Args:
        user_tier: Per-user tier from DB (overrides config.billing.tier)
        user_limits: Per-user limits from TIER_LIMITS (overrides config.billing.limits)
        session: Optional pre-existing DB session (avoids creating a new one)
        user_email: Per-user email for usage tracking (None = global counter)
    """
    tier = user_tier or config.billing.tier
    limits = user_limits or TIER_LIMITS.get(tier, TIER_LIMITS["free"])
    today = date.today().isoformat()

    owns_session = session is None
    if owns_session:
        session = logger._get_session()

    try:
        from datetime import datetime as dt

        from sentinelai.logger.database import BoosterCredit, PromptScanLog, UsageRecord

        usage = (
            session.query(UsageRecord)
            .filter(UsageRecord.date == today, UsageRecord.user_email == user_email)
            .first()
        )

        commands_used = usage.commands_evaluated if usage else 0

        # Per-user: use UsageRecord counter; global: count PromptScanLog rows
        if user_email:
            scans_used = usage.scans_performed if usage else 0
        else:
            today_start = dt.strptime(today, "%Y-%m-%d")
            scans_used = session.query(PromptScanLog).filter(
                PromptScanLog.timestamp >= today_start
            ).count()

        # Sum active booster credits for user
        booster_credits = 0
        if user_email:
            try:
                from sqlalchemy import func as sqlfunc
                result = (
                    session.query(sqlfunc.coalesce(sqlfunc.sum(BoosterCredit.credits_remaining), 0))
                    .filter(
                        BoosterCredit.user_email == user_email,
                        BoosterCredit.credits_remaining > 0,
                        BoosterCredit.expires_at >= today,
                    )
                    .scalar()
                )
                booster_credits = int(result)
            except Exception:
                booster_credits = 0
    finally:
        if owns_session:
            session.close()

    commands_limit = limits.commands_per_day
    scans_limit = limits.scans_per_day

    # Cap displayed usage at the limit (show 10/10, not 16/10)
    commands_display = commands_used if commands_limit < 0 else min(commands_used, commands_limit)
    scans_display = scans_used if scans_limit < 0 else min(scans_used, scans_limit)

    # -1 means unlimited
    commands_remaining = -1 if commands_limit < 0 else max(0, commands_limit - commands_used)
    scans_remaining = -1 if scans_limit < 0 else max(0, scans_limit - scans_used)

    if not config.billing.enabled:
        # Billing disabled: show real usage but never enforce limits
        return UsageInfo(
            tier=tier,
            commands_used=commands_display,
            commands_limit=commands_limit,
            scans_used=scans_display,
            scans_limit=scans_limit,
            commands_remaining=commands_remaining,
            scans_remaining=scans_remaining,
            limit_reached=False,
            upgrade_url="",
            is_admin=is_admin,
            booster_credits_remaining=booster_credits,
        )

    # Billing enabled: enforce limits (booster credits extend command limit)
    cmd_limit_hit = commands_limit >= 0 and commands_used >= commands_limit and booster_credits <= 0
    scan_limit_hit = scans_limit >= 0 and scans_used >= scans_limit
    limit_reached = cmd_limit_hit or scan_limit_hit

    # 80% warning threshold
    approaching_limit = (
        (commands_limit > 0 and commands_used >= commands_limit * 0.8) or
        (scans_limit > 0 and scans_used >= scans_limit * 0.8)
    )

    return UsageInfo(
        tier=tier,
        commands_used=commands_display,
        commands_limit=commands_limit,
        scans_used=scans_display,
        scans_limit=scans_limit,
        commands_remaining=commands_remaining,
        scans_remaining=scans_remaining,
        limit_reached=limit_reached,
        approaching_limit=approaching_limit,
        upgrade_url=config.billing.upgrade_url,
        is_admin=is_admin,
        booster_credits_remaining=booster_credits,
    )


def increment_command_usage(
    logger: BlackboxLogger,
    session: Optional[Session] = None,
    user_email: Optional[str] = None,
) -> None:
    """Increment today's command usage counter.

    Args:
        user_email: Per-user tracking key. None = global counter (hook compatibility).
    """
    today = date.today().isoformat()
    owns_session = session is None
    if owns_session:
        session = logger._get_session()

    try:
        from sentinelai.logger.database import UsageRecord

        usage = (
            session.query(UsageRecord)
            .filter(UsageRecord.date == today, UsageRecord.user_email == user_email)
            .first()
        )

        if usage:
            usage.commands_evaluated += 1
        else:
            usage = UsageRecord(
                user_email=user_email,
                date=today,
                commands_evaluated=1,
                scans_performed=0,
                llm_calls=0,
                api_requests=0,
            )
            session.add(usage)

        session.commit()
    except Exception:
        session.rollback()
    finally:
        if owns_session:
            session.close()


def increment_scan_usage(
    logger: BlackboxLogger,
    session: Optional[Session] = None,
    user_email: Optional[str] = None,
) -> None:
    """Increment today's scan usage counter.

    Args:
        user_email: Per-user tracking key. None = global counter (hook compatibility).
    """
    today = date.today().isoformat()
    owns_session = session is None
    if owns_session:
        session = logger._get_session()

    try:
        from sentinelai.logger.database import UsageRecord

        usage = (
            session.query(UsageRecord)
            .filter(UsageRecord.date == today, UsageRecord.user_email == user_email)
            .first()
        )

        if usage:
            usage.scans_performed += 1
        else:
            usage = UsageRecord(
                user_email=user_email,
                date=today,
                commands_evaluated=0,
                scans_performed=1,
                llm_calls=0,
                api_requests=0,
            )
            session.add(usage)

        session.commit()
    except Exception:
        session.rollback()
    finally:
        if owns_session:
            session.close()


def check_command_limit_for_user(
    user: TokenData,
    config: SentinelConfig,
    logger: BlackboxLogger,
) -> None:
    """Check command limit for a specific user (per-user tier from DB)."""
    if is_super_admin(user, config):
        return  # Super-admin has no limits
    user_tier, user_limits = get_user_tier_limits(user, config, logger)
    _check_command_limit_internal(
        config, logger, user_tier=user_tier, user_limits=user_limits,
        user_email=user.email,
    )


def check_command_limit(
    config: SentinelConfig = Depends(get_config),
    logger: BlackboxLogger = Depends(get_logger),
) -> None:
    """Check if command limit has been reached. Raises 429 if limit exceeded."""
    _check_command_limit_internal(config, logger)


def _check_command_limit_internal(
    config: SentinelConfig,
    logger: BlackboxLogger,
    user_tier: Optional[str] = None,
    user_limits: Optional[TierLimits] = None,
    session: Optional[Session] = None,
    user_email: Optional[str] = None,
) -> None:
    """Internal command limit check.

    Args:
        user_email: Per-user tracking key. None = global counter.
    """
    if not config.billing.enabled:
        return

    tier = user_tier or config.billing.tier
    limits = user_limits or config.billing.limits
    if limits.commands_per_day < 0:
        return

    today = date.today().isoformat()
    owns_session = session is None
    if owns_session:
        session = logger._get_session()

    try:
        from sentinelai.logger.database import UsageRecord

        usage = (
            session.query(UsageRecord)
            .filter(UsageRecord.date == today, UsageRecord.user_email == user_email)
            .first()
        )

        commands_used = usage.commands_evaluated if usage else 0

        if commands_used >= limits.commands_per_day:
            # Check for active booster credits before blocking
            if user_email:
                try:
                    from sentinelai.logger.database import BoosterCredit
                    today_str = date.today().isoformat()
                    booster = (
                        session.query(BoosterCredit)
                        .filter(
                            BoosterCredit.user_email == user_email,
                            BoosterCredit.credits_remaining > 0,
                            BoosterCredit.expires_at >= today_str,
                        )
                        .first()
                    )
                    if booster:
                        booster.credits_remaining -= 1
                        session.commit()
                        return  # Booster credit consumed — allow command
                except Exception:
                    pass  # Table may not exist yet

            from sentinelai.core.models import format_limit_exceeded
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=format_limit_exceeded(
                    limit=limits.commands_per_day,
                    used=commands_used,
                    tier=tier,
                    upgrade_url=config.billing.upgrade_url,
                ),
            )
    finally:
        if owns_session:
            session.close()


def check_scan_limit_for_user(
    user: TokenData,
    config: SentinelConfig,
    logger: BlackboxLogger,
) -> None:
    """Check scan limit for a specific user (per-user tier from DB)."""
    if is_super_admin(user, config):
        return  # Super-admin has no limits
    user_tier, user_limits = get_user_tier_limits(user, config, logger)
    _check_scan_limit_internal(
        config, logger, user_tier=user_tier, user_limits=user_limits,
        user_email=user.email,
    )


def check_scan_limit(
    config: SentinelConfig = Depends(get_config),
    logger: BlackboxLogger = Depends(get_logger),
) -> None:
    """Check if scan limit has been reached. Raises 429 if limit exceeded."""
    _check_scan_limit_internal(config, logger)


def _check_scan_limit_internal(
    config: SentinelConfig,
    logger: BlackboxLogger,
    user_tier: Optional[str] = None,
    user_limits: Optional[TierLimits] = None,
    session: Optional[Session] = None,
    user_email: Optional[str] = None,
) -> None:
    """Internal scan limit check.

    Args:
        user_email: Per-user tracking key. None = global counter.
    """
    if not config.billing.enabled:
        return

    tier = user_tier or config.billing.tier
    limits = user_limits or config.billing.limits
    if limits.scans_per_day < 0:
        return

    today = date.today().isoformat()
    owns_session = session is None
    if owns_session:
        session = logger._get_session()

    try:
        from sentinelai.logger.database import UsageRecord

        # Per-user: use UsageRecord counter; global: count PromptScanLog rows
        if user_email:
            usage = (
                session.query(UsageRecord)
                .filter(UsageRecord.date == today, UsageRecord.user_email == user_email)
                .first()
            )
            scans_used = usage.scans_performed if usage else 0
        else:
            from datetime import datetime as dt

            from sentinelai.logger.database import PromptScanLog

            today_start = dt.strptime(today, "%Y-%m-%d")
            scans_used = session.query(PromptScanLog).filter(
                PromptScanLog.timestamp >= today_start
            ).count()

        if scans_used >= limits.scans_per_day:
            from sentinelai.core.models import format_limit_exceeded
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=format_limit_exceeded(
                    limit=limits.scans_per_day,
                    used=scans_used,
                    tier=tier,
                    upgrade_url=config.billing.upgrade_url,
                    resource="scan",
                ),
            )
    finally:
        if owns_session:
            session.close()


def check_user_command_limit(
    user: TokenData = Depends(get_current_user),
    config: SentinelConfig = Depends(get_config),
    logger: BlackboxLogger = Depends(get_logger),
) -> None:
    """Per-user command limit check (FastAPI dependency).

    Uses the user's actual billing tier from DB to enforce limits.
    Super-admin is never blocked.
    """
    check_command_limit_for_user(user, config, logger)


def check_user_scan_limit(
    user: TokenData = Depends(get_current_user),
    config: SentinelConfig = Depends(get_config),
    logger: BlackboxLogger = Depends(get_logger),
) -> None:
    """Per-user scan limit check (FastAPI dependency).

    Uses the user's actual billing tier from DB to enforce limits.
    Super-admin is never blocked.
    """
    check_scan_limit_for_user(user, config, logger)


def get_tenant_filter(
    user: TokenData = Depends(get_current_user),
    session: Session = Depends(get_db_session),
) -> "TenantFilter":
    """Get a tenant-scoped query filter for the current user.

    Super-admins and local-first users get unfiltered access.
    Regular users are scoped to their tenant_id.
    """
    from sentinelai.services.tenant_service import TenantFilter

    # Super-admins see all data
    if user.is_super_admin:
        return TenantFilter(session, tenant_id=None)
    return TenantFilter(session, tenant_id=user.tenant_id)


def require_feature(feature: str):
    """Dependency factory to require a specific feature based on per-user tier."""
    def check_feature(
        config: SentinelConfig = Depends(get_config),
        user: TokenData = Depends(get_current_user),
        logger: BlackboxLogger = Depends(get_logger),
    ) -> None:
        # Super-admin has all features
        if is_super_admin(user, config):
            return

        if not config.billing.enabled:
            return  # Billing disabled = all features available

        user_tier, user_limits = get_user_tier_limits(user, config, logger)
        feature_enabled = getattr(user_limits, feature, True)

        if not feature_enabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": f"Feature '{feature}' not available on {user_tier} tier",
                    "tier": user_tier,
                    "upgrade_url": config.billing.upgrade_url,
                },
            )

    return check_feature


def cleanup_old_usage_records(logger: BlackboxLogger, retention_days: int = 30) -> int:
    """Delete UsageRecords older than retention_days. Returns count deleted."""
    from sentinelai.logger.database import UsageRecord

    cutoff = (date.today() - timedelta(days=retention_days)).isoformat()
    session = logger._get_session()
    try:
        count = session.query(UsageRecord).filter(UsageRecord.date < cutoff).delete()
        session.commit()
        return count
    except Exception:
        session.rollback()
        return 0
    finally:
        session.close()


def check_tenant_rate_limit(
    user: TokenData = Depends(get_current_user),
) -> None:
    """Check per-tenant API rate limit based on billing tier.

    Raises HTTP 429 if the tenant has exceeded their rate limit.
    Super-admin / unlimited tier bypass all checks.
    """
    from sentinelai.services.rate_limit_service import get_tenant_limiter

    limiter = get_tenant_limiter()
    allowed, info = limiter.check_and_record(
        tenant_id=user.tenant_id,
        tier=user.tier or "free",
    )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=info,
            headers={"Retry-After": str(info.get("retry_after", 60))},
        )
