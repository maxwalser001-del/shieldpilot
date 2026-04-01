"""Incidents endpoints: list incidents, resolve incident."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from sentinelai.api.auth import TokenData
from sentinelai.api.deps import (
    get_config,
    get_logger,
    get_tenant_filter,
    get_user_tier_limits,
    is_super_admin,
    require_admin,
    require_verified_email,
)
from sentinelai.services.tenant_service import TenantFilter
from sentinelai.api.routers._shared import _sanitize_text
from sentinelai.core.config import SentinelConfig
from sentinelai.explainability import generate_explanation
from sentinelai.logger import BlackboxLogger

router = APIRouter()


# ── Request models ────────────────────────────────────────────


class ResolveRequest(BaseModel):
    resolution_notes: str = ""


# ── Incidents ─────────────────────────────────────────────────


@router.get(
    "/api/incidents",
    tags=["Incidents"],
    summary="List security incidents",
    description="Return a list of security incidents with non-technical explanations. Supports filtering by severity and resolved status. History retention depends on the user's tier.",
    response_description="Paginated list of incidents with explainability data",
)
def list_incidents(
    severity: Optional[str] = None,
    resolved: Optional[bool] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    user: TokenData = Depends(require_verified_email),
    logger: BlackboxLogger = Depends(get_logger),
    config: SentinelConfig = Depends(get_config),
    tf: TenantFilter = Depends(get_tenant_filter),
):
    """List incidents with filters."""
    # Enforce history retention based on user tier (skip when billing disabled)
    since = None
    if config.billing.enabled and not is_super_admin(user, config):
        _, user_limits = get_user_tier_limits(user, config, logger)
        retention_days = user_limits.history_retention_days
        if retention_days > 0:  # -1 means unlimited
            since = datetime.utcnow() - timedelta(days=retention_days)

    incidents, total = logger.query_incidents(
        severity=severity,
        resolved=resolved,
        limit=limit,
        offset=offset,
        since=since,
        tenant_id=tf.tenant_id,
    )

    items = []
    for inc in incidents:
        # Generate non-technical explanation from linked command signals
        explanation = None
        if inc.command and inc.command.signals_json:
            explanation = generate_explanation(
                signals_json=inc.command.signals_json,
                risk_score=inc.command.risk_score,
                severity=inc.severity,
                category=inc.category,
                command_preview=(
                    inc.command.command[:80] if inc.command.command else None
                ),
            ).model_dump()
        elif inc.severity and inc.category:
            # Fallback for incidents without linked command
            explanation = generate_explanation(
                signals_json="[]",
                risk_score=0,
                severity=inc.severity,
                category=inc.category,
            ).model_dump()

        items.append({
            "id": inc.id,
            "timestamp": inc.timestamp.isoformat() if inc.timestamp else None,
            "severity": inc.severity,
            "category": inc.category,
            "title": _sanitize_text(inc.title),
            "description": _sanitize_text(inc.description),
            "evidence": _sanitize_text(inc.evidence),
            "command_id": inc.command_id,
            "resolved": inc.resolved,
            "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
            "resolution_notes": inc.resolution_notes,
            "explanation": explanation,
        })

    return {"items": items, "total": total}


@router.patch(
    "/api/incidents/{incident_id}/resolve",
    tags=["Incidents"],
    summary="Resolve an incident",
    description="Mark an incident as resolved with an optional resolution note. Requires admin privileges.",
    response_description="Confirmation with the resolved incident ID",
)
def resolve_incident(
    incident_id: int,
    request: ResolveRequest,
    user: TokenData = Depends(require_admin),
    logger: BlackboxLogger = Depends(get_logger),
):
    """Resolve an incident (admin only)."""
    success = logger.resolve_incident(incident_id, request.resolution_notes)
    if not success:
        raise HTTPException(status_code=404, detail={"error": "Incident not found"})
    return {"status": "resolved", "incident_id": incident_id}
