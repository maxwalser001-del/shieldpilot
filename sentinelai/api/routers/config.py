"""Config summary endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from sentinelai.api.auth import TokenData
from sentinelai.api.deps import (
    get_config,
    require_admin,
)
from sentinelai.core.config import SentinelConfig

router = APIRouter()


# ── Config ────────────────────────────────────────────────────


@router.get(
    "/api/config/summary",
    tags=["Configuration"],
    summary="Get configuration summary",
    description="Return a non-sensitive summary of the platform configuration including risk thresholds, LLM settings, sandbox config, and billing tier. Admin only.",
    response_description="Non-sensitive platform configuration (admin only)",
)
def config_summary(
    user: TokenData = Depends(require_admin),
    config: SentinelConfig = Depends(get_config),
):
    """Get non-sensitive configuration summary (admin only)."""
    return {
        "mode": config.mode,
        "risk_thresholds": {
            "block": config.risk_thresholds.block,
            "warn": config.risk_thresholds.warn,
        },
        "llm_enabled": config.llm.enabled,
        "llm_model": config.llm.model if config.llm.enabled else None,
        "sandbox_enabled": config.sandbox.enabled,
        "sandbox_timeout": config.sandbox.timeout,
        "chain_hashing": config.logging.chain_hashing,
        "whitelist_count": len(config.whitelist.commands),
        "blacklist_count": len(config.blacklist.commands),
        "protected_paths_count": len(config.protected_paths),
        "secret_patterns_count": len(config.secrets_patterns),
        "billing_tier": config.billing.tier,
    }
