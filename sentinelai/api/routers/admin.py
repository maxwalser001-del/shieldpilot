"""Admin-only endpoints: set tier, reconcile subscriptions, Stripe health, usage reset."""

from __future__ import annotations

from datetime import date
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from sentinelai.api.auth import TokenData
from sentinelai.api.deps import (
    get_config,
    get_db_session,
    require_admin,
)
from sentinelai.core.config import SentinelConfig
from sentinelai.services.billing_service import BillingService

router = APIRouter()


# ── Request models ────────────────────────────────────────────


class AdminTierOverride(BaseModel):
    email: EmailStr
    tier: str  # "free", "pro", "pro_plus"
    reason: str = ""


# ── Admin: Billing Management ─────────────────────────────────


@router.post(
    "/api/admin/users/tier",
    tags=["Admin"],
    summary="Override user billing tier",
    response_description="Confirmation with old and new tier values",
)
def admin_set_user_tier(
    request: AdminTierOverride,
    user: TokenData = Depends(require_admin),
    config: SentinelConfig = Depends(get_config),
    session: Session = Depends(get_db_session),
):
    """Admin: manually set a user's tier (for support cases)."""
    service = BillingService(session, config)
    return service.admin_set_user_tier(request.email, request.tier, request.reason, user.email)


@router.post(
    "/api/admin/reconcile-subscriptions",
    tags=["Admin"],
    summary="Reconcile Stripe subscriptions",
    response_description="Sync results with counts and tier changes",
)
def reconcile_subscriptions(
    user: TokenData = Depends(require_admin),
    config: SentinelConfig = Depends(get_config),
    session: Session = Depends(get_db_session),
):
    """Reconcile all users with active Stripe subscriptions against Stripe API."""
    service = BillingService(session, config)
    return service.reconcile_subscriptions()


@router.get(
    "/api/admin/stripe-health",
    tags=["Admin"],
    summary="Check Stripe connectivity",
    response_description="Stripe API health status and configuration check",
)
def stripe_health(
    user: TokenData = Depends(require_admin),
    config: SentinelConfig = Depends(get_config),
):
    """Check Stripe connectivity and configuration."""
    from sentinelai.billing.stripe_client import StripeClient

    if not config.billing.stripe_secret_key:
        return {"status": "not_configured", "message": "Stripe secret key not set"}

    client = StripeClient(config.billing.stripe_secret_key, config.billing.stripe_webhook_secret)
    return client.health_check()


# ── Admin: Usage Management ──────────────────────────────────


@router.post(
    "/api/admin/usage/reset",
    tags=["Admin"],
    summary="Reset daily usage counter",
    response_description="Confirmation with previous usage values",
)
def admin_reset_usage(
    target_date: Optional[str] = Query(
        default=None,
        description="Date to reset in YYYY-MM-DD format (default: today)",
        alias="date",
    ),
    user: TokenData = Depends(require_admin),
    session: Session = Depends(get_db_session),
):
    """Admin: reset usage counters (commands_evaluated, scans_performed) for a given date."""
    from sentinelai.logger.database import UsageRecord

    # Default to today if no date provided
    reset_date = target_date or date.today().isoformat()

    # Validate date format (YYYY-MM-DD)
    try:
        date.fromisoformat(reset_date)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_date", "message": f"Invalid date format: {reset_date}. Use YYYY-MM-DD."},
        )

    usage = (
        session.query(UsageRecord)
        .filter(UsageRecord.date == reset_date, UsageRecord.tenant_id == None)
        .first()
    )

    if not usage:
        return {
            "message": f"Usage reset for {reset_date}",
            "previous_commands": 0,
            "previous_scans": 0,
        }

    previous_commands = usage.commands_evaluated
    previous_scans = usage.scans_performed

    usage.commands_evaluated = 0
    usage.scans_performed = 0
    session.commit()

    return {
        "message": f"Usage reset for {reset_date}",
        "previous_commands": previous_commands,
        "previous_scans": previous_scans,
    }
