"""Rate limit status API endpoint.

Provides an endpoint for authenticated users to check their current
per-tenant API rate limit usage (per-minute and per-day windows).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from sentinelai.api.auth import TokenData
from sentinelai.api.deps import get_current_user

router = APIRouter(prefix="/api/ratelimit", tags=["ratelimit"])


@router.get(
    "/status",
    summary="Get rate limit status",
    description="Return the current API rate limit usage for the authenticated user's tenant. "
    "Includes per-minute and per-day counters, remaining quota, and tier-specific limits.",
    response_description="Rate limit usage and quota information",
)
def rate_limit_status(
    user: TokenData = Depends(get_current_user),
):
    """Get current rate limit usage for the authenticated user's tenant.

    Returns per-minute and per-day usage counters along with tier limits.
    """
    from sentinelai.services.rate_limit_service import get_tenant_limiter

    limiter = get_tenant_limiter()
    return limiter.get_usage(tenant_id=user.tenant_id, tier=user.tier or "free")
