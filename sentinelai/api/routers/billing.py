"""Billing endpoints: usage, tier info, pricing, checkout, portal, webhook handlers."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from sentinelai.api.auth import TokenData
from sentinelai.api.deps import (
    UsageInfo,
    get_config,
    get_current_user,
    get_daily_usage_for_user,
    get_db_session,
    get_logger,
    require_verified_email,
)
from sentinelai.core.config import SentinelConfig
from sentinelai.logger import BlackboxLogger
from sentinelai.services.billing_service import BillingService

router = APIRouter()


# ── Request models ────────────────────────────────────────────


class CheckoutRequest(BaseModel):
    price_key: str  # e.g. "pro_monthly", "pro_annual", "enterprise_monthly"


# ── Usage & Billing ───────────────────────────────────────────


@router.get(
    "/api/usage",
    response_model=UsageInfo,
    tags=["Billing"],
    summary="Get current usage",
    description="Return the authenticated user's daily usage counters (commands and scans) along with tier limits, admin status, and whether limits have been reached.",
    response_description="Daily usage counts and tier limits",
)
def get_usage(
    user: TokenData = Depends(get_current_user),
    config: SentinelConfig = Depends(get_config),
    logger: BlackboxLogger = Depends(get_logger),
):
    """Get current usage statistics and tier limits."""
    # Super-admin gets unlimited usage
    return get_daily_usage_for_user(user, logger, config)


@router.get(
    "/api/billing/tier",
    tags=["Billing"],
    summary="Get billing tier info",
    description="Return the user's current billing tier, available feature flags, and an upgrade URL if applicable.",
    response_description="Current tier, feature flags, and upgrade URL",
)
def get_tier_info(
    user: TokenData = Depends(get_current_user),
    config: SentinelConfig = Depends(get_config),
    session: Session = Depends(get_db_session),
):
    """Get current billing tier and available features."""
    service = BillingService(session, config)
    return service.get_tier_info(user)


# ── Billing / Stripe ──────────────────────────────────────────


@router.get(
    "/api/billing/pricing",
    tags=["Billing"],
    summary="Get pricing tiers",
    description="Return all available pricing plans with monthly/annual prices, feature lists, and the Stripe publishable key for the checkout flow.",
    response_description="All available plans with prices, features, and Stripe publishable key",
)
def get_pricing(
    user: TokenData = Depends(get_current_user),
    config: SentinelConfig = Depends(get_config),
    session: Session = Depends(get_db_session),
):
    """Get pricing tiers and Stripe publishable key for the checkout flow."""
    service = BillingService(session, config)
    return service.get_pricing(user)


@router.post(
    "/api/billing/checkout",
    tags=["Billing"],
    summary="Create Stripe checkout session",
    description="Create a Stripe Checkout session for the specified price key (e.g. pro_monthly). Requires a verified email. Returns a URL to redirect the user to.",
    response_description="Stripe Checkout session URL for redirect",
)
def create_checkout(
    request: CheckoutRequest,
    user: TokenData = Depends(require_verified_email),
    config: SentinelConfig = Depends(get_config),
    session: Session = Depends(get_db_session),
):
    """Create a Stripe Checkout session and return the redirect URL."""
    service = BillingService(session, config)
    return service.create_checkout(request.price_key, user)


@router.post(
    "/api/billing/portal",
    tags=["Billing"],
    summary="Create Stripe customer portal session",
    description="Create a Stripe Customer Portal session where the user can manage their subscription, update payment methods, or cancel.",
    response_description="Stripe Customer Portal URL for subscription management",
)
def create_portal_session(
    user: TokenData = Depends(require_verified_email),
    config: SentinelConfig = Depends(get_config),
    session: Session = Depends(get_db_session),
):
    """Create a Stripe Customer Portal session for subscription management."""
    service = BillingService(session, config)
    return service.create_portal_session(user)


@router.post(
    "/api/billing/booster",
    tags=["Billing"],
    summary="Purchase command booster",
    description="Create a Stripe one-time payment session for a Command Booster (+500 commands, expires midnight UTC). Returns a checkout URL.",
    response_description="Stripe Checkout URL for the booster purchase",
)
def purchase_booster(
    user: TokenData = Depends(require_verified_email),
    config: SentinelConfig = Depends(get_config),
    session: Session = Depends(get_db_session),
):
    """Purchase a command booster (+500 commands for today)."""
    service = BillingService(session, config)
    return service.create_booster_checkout(user)


@router.post(
    "/api/billing/webhook",
    tags=["Billing"],
    summary="Handle Stripe webhook",
    description="Receive and process Stripe webhook events (e.g. checkout.session.completed, invoice.paid). Authenticated via Stripe signature, not JWT.",
    response_description="Processing status of the webhook event",
)
async def stripe_webhook(
    request: Request,
    session: Session = Depends(get_db_session),
):
    """Handle Stripe webhook events. No JWT auth -- verified via Stripe signature."""
    config = get_config()

    # Read raw body for signature verification
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    service = BillingService(session, config)
    return service.process_webhook(payload, sig_header)
