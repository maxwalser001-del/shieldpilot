"""Stripe integration for ShieldPilot billing.

Handles Checkout Session creation, webhook processing, and Customer Portal.
"""

from __future__ import annotations

import logging
import os
from typing import Optional

import stripe

logger = logging.getLogger(__name__)

# Map internal tier names to Stripe Price IDs (loaded from env vars)
PRICE_IDS = {
    "pro_monthly": os.environ.get("STRIPE_PRICE_PRO_MONTHLY", ""),
    "pro_annual": os.environ.get("STRIPE_PRICE_PRO_ANNUAL", ""),
    "pro_plus_monthly": os.environ.get("STRIPE_PRICE_PRO_PLUS_MONTHLY", ""),
    "pro_plus_annual": os.environ.get("STRIPE_PRICE_PRO_PLUS_ANNUAL", ""),
}

# Reverse lookup: Stripe Price ID -> tier name (built at runtime)
PRICE_TO_TIER: dict[str, str] = {}


def _build_price_to_tier():
    """Build reverse lookup from price IDs to tier names."""
    global PRICE_TO_TIER
    PRICE_TO_TIER = {}
    for key, price_id in PRICE_IDS.items():
        if not price_id:
            continue
        if key.startswith("pro_plus"):
            PRICE_TO_TIER[price_id] = "pro_plus"
        elif key.startswith("pro"):
            PRICE_TO_TIER[price_id] = "pro"
    # Backwards compat: old "unlimited" price IDs → pro_plus
    old_unlimited_monthly = os.environ.get("STRIPE_PRICE_UNLIMITED_MONTHLY", "")
    old_unlimited_annual = os.environ.get("STRIPE_PRICE_UNLIMITED_ANNUAL", "")
    if old_unlimited_monthly:
        PRICE_TO_TIER[old_unlimited_monthly] = "pro_plus"
    if old_unlimited_annual:
        PRICE_TO_TIER[old_unlimited_annual] = "pro_plus"


class StripeClient:
    """Real Stripe payment integration."""

    def __init__(self, secret_key: str, webhook_secret: str = ""):
        self.secret_key = secret_key
        self.webhook_secret = webhook_secret
        if secret_key:
            stripe.api_key = secret_key
            _build_price_to_tier()
        else:
            logger.warning("Stripe secret key not configured")

    def is_configured(self) -> bool:
        """Check if Stripe is properly configured."""
        return bool(self.secret_key)

    def get_or_create_customer(self, email: str, user_id: int) -> str:
        """Get or create a Stripe Customer for the given user email.

        Returns the Stripe customer ID (cus_xxx).
        """
        # Search for existing customer by email
        customers = stripe.Customer.list(email=email, limit=1)
        if customers.data:
            return customers.data[0].id

        # Create new customer
        customer = stripe.Customer.create(
            email=email,
            metadata={"shieldpilot_user_id": str(user_id)},
        )
        return customer.id

    def create_checkout_session(
        self,
        customer_id: str,
        price_id: str,
        success_url: str,
        cancel_url: str,
    ) -> dict:
        """Create a Stripe Checkout Session for subscription."""
        params = {
            "customer": customer_id,
            "payment_method_types": ["card"],
            "line_items": [{"price": price_id, "quantity": 1}],
            "mode": "subscription",
            "success_url": success_url,
            "cancel_url": cancel_url,
            "allow_promotion_codes": True,
        }

        # 7-day free trial for Pro+ plans only
        tier = PRICE_TO_TIER.get(price_id, "")
        if tier == "pro_plus":
            params["subscription_data"] = {"trial_period_days": 7}

        session = stripe.checkout.Session.create(**params)
        return {"session_id": session.id, "url": session.url}

    def create_portal_session(self, customer_id: str, return_url: str) -> dict:
        """Create a Stripe Customer Portal session for managing subscriptions."""
        session = stripe.billing_portal.Session.create(
            customer=customer_id,
            return_url=return_url,
        )
        return {"url": session.url}

    def verify_webhook(self, payload: bytes, sig_header: str) -> dict:
        """Verify and parse a Stripe webhook event.

        Returns the parsed event dict. Raises ValueError on invalid signature.
        """
        event = stripe.Webhook.construct_event(
            payload, sig_header, self.webhook_secret
        )
        return event

    def get_subscription(self, subscription_id: str) -> dict:
        """Get subscription details."""
        sub = stripe.Subscription.retrieve(subscription_id)
        price_id = None
        if sub.get("items") and sub["items"].get("data"):
            price_id = sub["items"]["data"][0].get("price", {}).get("id")
        return {
            "id": sub.id,
            "status": sub.status,
            "current_period_end": sub.current_period_end,
            "cancel_at_period_end": sub.cancel_at_period_end,
            "price_id": price_id,
        }

    def cancel_subscription(self, subscription_id: str) -> dict:
        """Immediately cancel a Stripe subscription."""
        sub = stripe.Subscription.cancel(subscription_id)
        return {"id": sub.id, "status": sub.status}

    def health_check(self) -> dict:
        """Check Stripe connectivity and configuration."""
        try:
            if not self.secret_key:
                return {"status": "not_configured", "message": "Stripe secret key not set"}
            stripe.Account.retrieve()
            prices_configured = any(bool(v) for v in PRICE_IDS.values())
            return {
                "status": "ok",
                "prices_configured": prices_configured,
                "webhook_secret_set": bool(self.webhook_secret),
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}
