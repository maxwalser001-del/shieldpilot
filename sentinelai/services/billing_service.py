"""Billing service: business logic extracted from billing and admin route handlers."""

from __future__ import annotations

import logging

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from sentinelai.api.auth import TokenData
from sentinelai.api.deps import (
    get_config,
    get_logger,
    get_user_tier_limits,
    is_super_admin,
)
from sentinelai.core.config import SentinelConfig

_logger = logging.getLogger(__name__)


class BillingService:
    """Business logic for billing operations.

    Accepts a SQLAlchemy session and config as constructor params.
    Raises HTTPException directly for pragmatic compatibility with existing tests.
    """

    def __init__(self, session: Session, config: SentinelConfig):
        self.session = session
        self.config = config

    def get_tier_info(self, user: TokenData) -> dict:
        """Get current billing tier and available features."""
        unlimited_features = {
            "commands_per_day": -1,
            "scans_per_day": -1,
            "history_retention_days": -1,
            "llm_analysis": True,
            "export_enabled": True,
            "multi_user": True,
            "api_access": True,
            "priority_support": True,
        }
        if is_super_admin(user, self.config):
            return {"tier": "unlimited", "features": unlimited_features, "upgrade_url": None}
        if not self.config.billing.enabled:
            # Billing disabled: show real tier for display, but unlock all features
            user_tier = user.tier or "free"
            return {"tier": user_tier, "features": unlimited_features, "upgrade_url": None}

        logger = get_logger()
        user_tier, user_limits = get_user_tier_limits(user, self.config, logger)
        return {
            "tier": user_tier,
            "features": {
                "commands_per_day": user_limits.commands_per_day,
                "scans_per_day": user_limits.scans_per_day,
                "history_retention_days": user_limits.history_retention_days,
                "llm_analysis": user_limits.llm_analysis,
                "export_enabled": user_limits.export_enabled,
                "multi_user": user_limits.multi_user,
                "api_access": user_limits.api_access,
                "priority_support": user_limits.priority_support,
            },
            "upgrade_url": self.config.billing.upgrade_url,
        }

    def get_pricing(self, user: TokenData) -> dict:
        """Get pricing tiers and Stripe publishable key for the checkout flow."""
        from sentinelai.core.config import TIER_LIMITS

        if is_super_admin(user, self.config):
            current_tier = "unlimited"
        else:
            from sentinelai.logger.database import User as DBUser
            _db_u = self.session.query(DBUser).filter(DBUser.email == user.email).first()
            current_tier = _db_u.tier if _db_u else user.tier

        # Map legacy DB tiers for display
        display_tier = current_tier
        if display_tier == "enterprise":
            display_tier = "pro_plus"
        if display_tier == "unlimited" and not is_super_admin(user, self.config):
            display_tier = "pro_plus"

        return {
            "current_tier": display_tier,
            "stripe_publishable_key": self.config.billing.stripe_publishable_key,
            "tiers": {
                "free": {
                    "name": "Free",
                    "description": "Get started with essential AI security monitoring.",
                    "price_monthly": 0,
                    "price_annual": 0,
                    "currency": "\u20ac",
                    "features": TIER_LIMITS["free"].model_dump(),
                },
                "pro": {
                    "name": "Pro",
                    "description": "Full protection for professional developers.",
                    "price_monthly": 19.99,
                    "price_annual": 189,
                    "currency": "\u20ac",
                    "features": TIER_LIMITS["pro"].model_dump(),
                },
                "pro_plus": {
                    "name": "Pro+",
                    "description": "Unlimited security with AI analysis & priority support.",
                    "price_monthly": 29.99,
                    "price_annual": 279,
                    "currency": "\u20ac",
                    "features": TIER_LIMITS["pro_plus"].model_dump(),
                },
            },
        }

    def create_checkout(self, price_key: str, user: TokenData) -> dict:
        """Create a Stripe Checkout session and return the redirect URL."""
        from sentinelai.billing.stripe_client import StripeClient, PRICE_IDS
        from sentinelai.logger.database import User

        if not self.config.billing.stripe_secret_key:
            raise HTTPException(status_code=503, detail={"error": "Stripe not configured"})

        price_id = PRICE_IDS.get(price_key)
        if not price_id:
            raise HTTPException(status_code=400, detail={"error": f"Invalid price: {price_key}"})

        client = StripeClient(self.config.billing.stripe_secret_key, self.config.billing.stripe_webhook_secret)

        # Get or create Stripe customer
        db_user = self.session.query(User).filter(User.email == user.email).first()
        if not db_user:
            raise HTTPException(status_code=404, detail={"error": "User not found"})

        if not db_user.stripe_customer_id:
            customer_id = client.get_or_create_customer(user.email, db_user.id)
            db_user.stripe_customer_id = customer_id
            self.session.commit()
        else:
            customer_id = db_user.stripe_customer_id

        # Build URLs using configurable base URL
        base_url = self.config.app_base_url.rstrip("/")
        success_url = f"{base_url}/#/pricing?checkout=success"
        cancel_url = f"{base_url}/#/pricing?checkout=cancel"

        result = client.create_checkout_session(customer_id, price_id, success_url, cancel_url)
        return result

    def create_portal_session(self, user: TokenData) -> dict:
        """Create a Stripe Customer Portal session for subscription management."""
        from sentinelai.billing.stripe_client import StripeClient
        from sentinelai.logger.database import User

        if not self.config.billing.stripe_secret_key:
            raise HTTPException(status_code=503, detail={"error": "Stripe not configured"})

        db_user = self.session.query(User).filter(User.email == user.email).first()
        if not db_user or not db_user.stripe_customer_id:
            raise HTTPException(status_code=400, detail={"error": "No active subscription found"})

        client = StripeClient(self.config.billing.stripe_secret_key)
        base_url = self.config.app_base_url.rstrip("/")
        result = client.create_portal_session(db_user.stripe_customer_id, f"{base_url}/#/settings")
        return result

    def process_webhook(self, payload: bytes, sig_header: str) -> dict:
        """Process a Stripe webhook event.

        Verifies signature, checks idempotency, and dispatches to appropriate handler.
        """
        from sentinelai.billing.stripe_client import StripeClient
        from sentinelai.logger.database import WebhookEvent

        if not self.config.billing.stripe_webhook_secret:
            raise HTTPException(status_code=503, detail={"error": "Webhook not configured"})

        client = StripeClient(self.config.billing.stripe_secret_key, self.config.billing.stripe_webhook_secret)

        try:
            event = client.verify_webhook(payload, sig_header)
        except Exception as e:
            raise HTTPException(status_code=400, detail={"error": f"Invalid webhook signature: {str(e)}"})

        event_id = event.get("id", "")
        event_type = event.get("type", "")

        # Idempotency check: skip if already processed
        existing = self.session.query(WebhookEvent).filter(
            WebhookEvent.stripe_event_id == event_id
        ).first()
        if existing:
            return {"status": "already_processed"}

        try:
            # Dispatch to handlers
            if event_type == "checkout.session.completed":
                obj = event["data"]["object"]
                if obj.get("metadata", {}).get("type") == "booster":
                    self.handle_booster_payment(obj)
                else:
                    self._handle_checkout_completed(obj)
            elif event_type == "customer.subscription.updated":
                self._handle_subscription_updated(event["data"]["object"])
            elif event_type == "customer.subscription.deleted":
                self._handle_subscription_deleted(event["data"]["object"])
            elif event_type == "invoice.paid":
                self._handle_invoice_paid(event["data"]["object"])
            elif event_type == "invoice.payment_failed":
                self._handle_invoice_failed(event["data"]["object"])

            # Record successful processing
            self.session.add(WebhookEvent(
                stripe_event_id=event_id,
                event_type=event_type,
                status="processed",
            ))
            self.session.commit()
        except Exception:
            self.session.rollback()
            # Record failed processing for audit
            try:
                self.session.add(WebhookEvent(
                    stripe_event_id=event_id,
                    event_type=event_type,
                    status="error",
                ))
                self.session.commit()
            except Exception:
                self.session.rollback()
            raise

        return {"status": "ok"}

    def _handle_checkout_completed(self, checkout_obj: dict) -> None:
        """Process successful checkout -- upgrade user tier."""
        customer_id = checkout_obj.get("customer")
        subscription_id = checkout_obj.get("subscription")
        if not customer_id:
            return

        from sentinelai.logger.database import User
        from sentinelai.billing.stripe_client import StripeClient, PRICE_TO_TIER

        user = self.session.query(User).filter(User.stripe_customer_id == customer_id).first()
        if not user:
            return

        # Determine tier from subscription price
        client = StripeClient(self.config.billing.stripe_secret_key)
        sub_info = client.get_subscription(subscription_id)
        price_id = sub_info.get("price_id", "")
        new_tier = PRICE_TO_TIER.get(price_id, "pro")

        user.tier = new_tier
        user.stripe_subscription_id = subscription_id
        user.subscription_status = sub_info.get("status", "active")
        user.current_period_end = sub_info.get("current_period_end")
        user.cancel_at_period_end = False
        self.session.commit()

        # Send upgrade notification (best-effort)
        try:
            from sentinelai.api.email import EmailService
            email_svc = EmailService(self.config.auth)
            email_svc.send_tier_upgrade_notification(user.email, new_tier, user.username)
        except Exception:
            pass

    def _handle_subscription_updated(self, subscription_obj: dict) -> None:
        """Handle subscription changes (plan change, renewal, etc.)."""
        customer_id = subscription_obj.get("customer")
        sub_status = subscription_obj.get("status")
        if not customer_id:
            return

        from sentinelai.logger.database import User
        from sentinelai.billing.stripe_client import PRICE_TO_TIER

        user = self.session.query(User).filter(User.stripe_customer_id == customer_id).first()
        if not user:
            return

        # Stale-event protection: skip if event is older than current state
        event_period_end = subscription_obj.get("current_period_end")
        if (user.current_period_end
                and event_period_end
                and event_period_end < user.current_period_end):
            return  # Stale event -- skip

        user.subscription_status = sub_status
        user.current_period_end = event_period_end
        user.cancel_at_period_end = subscription_obj.get("cancel_at_period_end", False)

        old_tier = user.tier

        if sub_status == "active":
            items = subscription_obj.get("items", {}).get("data", [])
            if items:
                price_id = items[0].get("price", {}).get("id", "")
                new_tier = PRICE_TO_TIER.get(price_id, user.tier)
                user.tier = new_tier
        elif sub_status == "past_due":
            # GRACE PERIOD: Keep current tier while Stripe retries payment (dunning)
            # Tier stays unchanged -- downgrade only on subscription.deleted or unpaid
            pass
        elif sub_status in ("unpaid", "incomplete_expired"):
            user.tier = "free"  # Hard downgrade only on final payment failure

        self.session.commit()

        # Send notifications for tier changes (best-effort)
        try:
            from sentinelai.api.email import EmailService
            email_svc = EmailService(self.config.auth)
            if sub_status in ("unpaid", "incomplete_expired") and old_tier != "free":
                email_svc.send_tier_downgrade_notification(user.email, old_tier, "payment_failed", user.username)
            elif sub_status == "past_due":
                email_svc.send_payment_failed_notification(user.email, user.tier, user.username)
        except Exception:
            pass

    def _handle_subscription_deleted(self, subscription_obj: dict) -> None:
        """Handle subscription cancellation -- downgrade to free."""
        customer_id = subscription_obj.get("customer")
        if not customer_id:
            return

        from sentinelai.logger.database import User

        user = self.session.query(User).filter(User.stripe_customer_id == customer_id).first()
        if not user:
            return
        old_tier = user.tier
        user.tier = "free"
        user.subscription_status = "canceled"
        user.stripe_subscription_id = None
        user.current_period_end = None
        user.cancel_at_period_end = False
        self.session.commit()

        # Send downgrade notification (best-effort)
        try:
            from sentinelai.api.email import EmailService
            email_svc = EmailService(self.config.auth)
            email_svc.send_tier_downgrade_notification(user.email, old_tier, "canceled", user.username)
        except Exception:
            pass

    def _handle_invoice_paid(self, invoice_obj: dict) -> None:
        """Handle successful invoice payment -- confirm active status."""
        customer_id = invoice_obj.get("customer")
        if not customer_id:
            return

        from sentinelai.logger.database import User
        from sentinelai.billing.stripe_client import StripeClient, PRICE_TO_TIER

        user = self.session.query(User).filter(User.stripe_customer_id == customer_id).first()
        if not user or not user.stripe_subscription_id:
            return

        user.subscription_status = "active"

        # Restore tier if it was downgraded due to past_due
        if user.tier == "free" and user.stripe_subscription_id:
            client = StripeClient(self.config.billing.stripe_secret_key)
            sub_info = client.get_subscription(user.stripe_subscription_id)
            price_id = sub_info.get("price_id", "")
            user.tier = PRICE_TO_TIER.get(price_id, "pro")

            # Send restoration notification (best-effort)
            try:
                from sentinelai.api.email import EmailService
                email_svc = EmailService(self.config.auth)
                email_svc.send_tier_upgrade_notification(user.email, user.tier, user.username)
            except Exception:
                pass

        self.session.commit()

    def _handle_invoice_failed(self, invoice_obj: dict) -> None:
        """Handle failed invoice payment -- set past_due status."""
        customer_id = invoice_obj.get("customer")
        if not customer_id:
            return

        from sentinelai.logger.database import User

        user = self.session.query(User).filter(User.stripe_customer_id == customer_id).first()
        if not user:
            return
        user.subscription_status = "past_due"
        self.session.commit()

        # Send payment failure notification (best-effort)
        try:
            from sentinelai.api.email import EmailService
            email_svc = EmailService(self.config.auth)
            email_svc.send_payment_failed_notification(user.email, user.tier, user.username)
        except Exception:
            pass

    def create_booster_checkout(self, user: TokenData) -> dict:
        """Create a Stripe one-time payment session for a Command Booster."""
        import os
        from sentinelai.billing.stripe_client import StripeClient
        from sentinelai.logger.database import User
        import stripe

        if not self.config.billing.stripe_secret_key:
            raise HTTPException(status_code=503, detail={"error": "Stripe not configured"})

        booster_price_id = os.environ.get("STRIPE_PRICE_BOOSTER", "")
        if not booster_price_id:
            raise HTTPException(status_code=503, detail={"error": "Booster price not configured"})

        client = StripeClient(self.config.billing.stripe_secret_key, self.config.billing.stripe_webhook_secret)

        db_user = self.session.query(User).filter(User.email == user.email).first()
        if not db_user:
            raise HTTPException(status_code=404, detail={"error": "User not found"})

        if not db_user.stripe_customer_id:
            customer_id = client.get_or_create_customer(user.email, db_user.id)
            db_user.stripe_customer_id = customer_id
            self.session.commit()
        else:
            customer_id = db_user.stripe_customer_id

        base_url = self.config.app_base_url.rstrip("/")
        session = stripe.checkout.Session.create(
            customer=customer_id,
            payment_method_types=["card"],
            line_items=[{"price": booster_price_id, "quantity": 1}],
            mode="payment",
            success_url=f"{base_url}/#/dashboard?booster=success",
            cancel_url=f"{base_url}/#/pricing?booster=cancel",
            metadata={"type": "booster", "user_email": user.email},
        )
        return {"checkout_url": session.url}

    def handle_booster_payment(self, checkout_obj: dict) -> None:
        """Process a booster payment — create BoosterCredit."""
        from datetime import date, datetime, timedelta, timezone
        from sentinelai.logger.database import BoosterCredit

        user_email = checkout_obj.get("metadata", {}).get("user_email")
        payment_id = checkout_obj.get("payment_intent")
        if not user_email:
            return

        # Expires at end of tomorrow (UTC) — guarantees at least 24h
        tomorrow = (date.today() + timedelta(days=1)).isoformat()
        credit = BoosterCredit(
            user_email=user_email,
            credits_remaining=500,
            purchased_at=datetime.now(tz=timezone.utc),
            expires_at=tomorrow,
            stripe_payment_id=payment_id,
        )
        self.session.add(credit)
        self.session.commit()

    def admin_set_user_tier(self, email: str, tier: str, reason: str, admin_email: str) -> dict:
        """Admin: manually set a user's tier (for support cases)."""
        from sentinelai.logger.database import User

        if tier not in ("free", "pro", "pro_plus"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": f"Invalid tier: {tier}. Must be free, pro, or pro_plus."},
            )

        db_user = self.session.query(User).filter(User.email == email).first()
        if not db_user:
            raise HTTPException(status_code=404, detail={"error": "User not found"})
        if db_user.is_super_admin:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "Cannot modify super-admin tier"},
            )

        old_tier = db_user.tier
        db_user.tier = tier
        if tier != "free" and not db_user.stripe_subscription_id:
            db_user.subscription_status = "active"
        elif tier == "free":
            db_user.subscription_status = None

        self.session.commit()

        _logger.info(
            f"Admin tier override: {email} {old_tier}->{tier} by {admin_email} reason={reason}"
        )

        return {"message": f"User {email} tier changed from {old_tier} to {tier}"}

    def reconcile_subscriptions(self) -> dict:
        """Reconcile all users with active Stripe subscriptions against Stripe API."""
        from sentinelai.billing.stripe_client import StripeClient, PRICE_TO_TIER
        from sentinelai.logger.database import User

        if not self.config.billing.stripe_secret_key:
            raise HTTPException(status_code=503, detail={"error": "Stripe not configured"})

        client = StripeClient(self.config.billing.stripe_secret_key)

        users = self.session.query(User).filter(User.stripe_subscription_id != None).all()
        results = {"synced": 0, "errors": 0, "changes": []}

        for db_user in users:
            try:
                sub_info = client.get_subscription(db_user.stripe_subscription_id)
                old_tier = db_user.tier
                old_status = db_user.subscription_status
                new_status = sub_info.get("status")
                new_tier = PRICE_TO_TIER.get(sub_info.get("price_id", ""), db_user.tier)

                if new_status in ("active", "trialing", "past_due"):
                    db_user.tier = new_tier
                elif new_status == "canceled":
                    db_user.tier = "free"
                    db_user.stripe_subscription_id = None

                db_user.subscription_status = new_status
                db_user.current_period_end = sub_info.get("current_period_end")
                db_user.cancel_at_period_end = sub_info.get("cancel_at_period_end", False)

                if old_tier != db_user.tier or old_status != db_user.subscription_status:
                    results["changes"].append({
                        "email": db_user.email,
                        "old_tier": old_tier,
                        "new_tier": db_user.tier,
                        "old_status": old_status,
                        "new_status": db_user.subscription_status,
                    })
                results["synced"] += 1
            except Exception:
                results["errors"] += 1

        self.session.commit()
        return results
