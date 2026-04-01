"""Scans endpoints: list scans, scan prompt."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from sentinelai.api.auth import TokenData
from sentinelai.api.deps import (
    check_user_scan_limit,
    get_config,
    get_logger,
    require_verified_email,
)
from sentinelai.core.config import SentinelConfig
from sentinelai.logger import BlackboxLogger
from sentinelai.services.scan_service import ScanService

router = APIRouter()


# ── Request models ────────────────────────────────────────────


class ScanRequest(BaseModel):
    content: str = Field(..., max_length=50000)
    source: str = "api"


# ── Scans ─────────────────────────────────────────────────────


@router.get(
    "/api/scans",
    tags=["Scans"],
    summary="List prompt scans",
    description="Return a paginated list of prompt injection scan results with threat details and overall risk scores.",
    response_description="Paginated list of prompt injection scan results",
)
def list_scans(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: TokenData = Depends(require_verified_email),
    logger: BlackboxLogger = Depends(get_logger),
):
    """List prompt scan logs via the ScanService."""
    svc = ScanService(logger=logger, config=None)
    return svc.list_scans(limit=limit, offset=offset)


@router.post(
    "/api/scan/prompt",
    tags=["Scans"],
    summary="Scan text for prompt injection",
    description="Analyze text content for prompt injection patterns using the multi-pass scanner. Subject to daily scan limits based on the user's tier.",
    response_description="Scan result with threat details and risk score",
)
def scan_prompt(
    request: ScanRequest,
    user: TokenData = Depends(require_verified_email),
    logger: BlackboxLogger = Depends(get_logger),
    config: SentinelConfig = Depends(get_config),
    _limit: None = Depends(check_user_scan_limit),
):
    """Scan text content for prompt injection patterns."""
    svc = ScanService(logger=logger, config=config)
    return svc.scan_prompt(
        content=request.content,
        source=request.source,
        user=user,
    )
