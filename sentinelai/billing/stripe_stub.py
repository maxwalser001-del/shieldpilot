"""Backwards-compatibility shim -- real implementation lives in stripe_client.py."""

from sentinelai.billing.stripe_client import (  # noqa: F401
    PRICE_IDS,
    PRICE_TO_TIER,
    StripeClient,
)

# Legacy alias
StripeStub = StripeClient
