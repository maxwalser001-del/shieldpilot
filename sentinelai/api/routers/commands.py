"""Commands endpoints: list commands, command detail, evaluate command."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from sentinelai.api.auth import TokenData
from sentinelai.api.deps import (
    check_user_command_limit,
    get_config,
    get_logger,
    get_tenant_filter,
    require_verified_email,
)
from sentinelai.api.routers._shared import _sanitize_text
from sentinelai.core.config import SentinelConfig
from sentinelai.logger import BlackboxLogger
from sentinelai.services.tenant_service import TenantFilter

router = APIRouter()


# ── Request/Response models ──────────────────────────────────


class EvaluateRequest(BaseModel):
    command: str = Field(..., max_length=10000, description="Shell command to evaluate")
    working_directory: str = Field("/tmp", description="Working directory context")


# ── Commands ──────────────────────────────────────────────────


@router.get(
    "/api/commands",
    tags=["Commands"],
    summary="List command logs",
    description="Return a paginated list of command audit logs. Supports filtering by action (allow/warn/block), risk score range, and text search.",
    response_description="Paginated list of command audit logs with filters",
)
def list_commands(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    action: Optional[str] = None,
    risk_min: Optional[int] = None,
    risk_max: Optional[int] = None,
    search: Optional[str] = None,
    since: Optional[str] = None,
    until: Optional[str] = None,
    user: TokenData = Depends(require_verified_email),
    logger: BlackboxLogger = Depends(get_logger),
    tf: TenantFilter = Depends(get_tenant_filter),
):
    """List command logs with filters and pagination."""
    since_dt = datetime.fromisoformat(since) if since else None
    until_dt = datetime.fromisoformat(until) if until else None

    # Enforce 24h limit on blocked commands for non-admin users
    if user.role != "admin" and action == "block":
        cutoff_24h = datetime.utcnow() - timedelta(hours=24)
        if since_dt is None or since_dt < cutoff_24h:
            since_dt = cutoff_24h

    commands, total = logger.query_commands(
        since=since_dt,
        until=until_dt,
        risk_min=risk_min,
        risk_max=risk_max,
        action=action,
        search=search,
        limit=limit,
        offset=offset,
        tenant_id=tf.tenant_id,
    )

    items = []
    for cmd in commands:
        items.append({
            "id": cmd.id,
            "timestamp": cmd.timestamp.isoformat() if cmd.timestamp else None,
            "command": _sanitize_text(cmd.command),
            "risk_score": cmd.risk_score,
            "risk_level": cmd.risk_level,
            "action_taken": cmd.action_taken,
            "executed": cmd.executed,
            "exit_code": cmd.exit_code,
            "output_snippet": _sanitize_text(cmd.output_snippet),
            "signals": json.loads(cmd.signals_json) if cmd.signals_json else [],
            "llm_used": cmd.llm_used,
            "llm_reasoning": cmd.llm_reasoning,
            "execution_time_ms": cmd.execution_time_ms,
            "chain_hash": cmd.chain_hash,
        })

    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "pages": (total + limit - 1) // limit if limit > 0 else 0,
    }


@router.get(
    "/api/commands/{command_id}",
    tags=["Commands"],
    summary="Get command details",
    description="Return the full details of a single command log entry, including all analysis signals, risk score breakdown, and tamper-proof chain hash.",
    response_description="Full command log entry including signals and chain hash",
)
def get_command(
    command_id: int,
    user: TokenData = Depends(require_verified_email),
    logger: BlackboxLogger = Depends(get_logger),
):
    """Get a single command log by ID."""
    cmd = logger.get_command_by_id(command_id)
    if not cmd:
        raise HTTPException(status_code=404, detail={"error": "Command not found"})

    return {
        "id": cmd.id,
        "timestamp": cmd.timestamp.isoformat() if cmd.timestamp else None,
        "command": _sanitize_text(cmd.command),
        "working_directory": cmd.working_directory,
        "risk_score": cmd.risk_score,
        "risk_level": cmd.risk_level,
        "action_taken": cmd.action_taken,
        "executed": cmd.executed,
        "exit_code": cmd.exit_code,
        "output_snippet": _sanitize_text(cmd.output_snippet),
        "signals": json.loads(cmd.signals_json) if cmd.signals_json else [],
        "llm_used": cmd.llm_used,
        "llm_reasoning": cmd.llm_reasoning,
        "execution_time_ms": cmd.execution_time_ms,
        "chain_hash": cmd.chain_hash,
        "previous_hash": cmd.previous_hash,
    }


# ── Evaluate ─────────────────────────────────────────────────


@router.post(
    "/api/evaluate",
    tags=["Commands"],
    summary="Evaluate command risk",
    description=(
        "Run a shell command through the ShieldPilot risk engine and return "
        "the risk assessment (score, signals, action). The command is NOT "
        "executed — only analyzed. Subject to per-user command limits."
    ),
    response_description="Risk assessment with score, signals, and recommended action",
)
def evaluate_command(
    request: EvaluateRequest,
    user: TokenData = Depends(require_verified_email),
    config: SentinelConfig = Depends(get_config),
    logger: BlackboxLogger = Depends(get_logger),
    _limit: None = Depends(check_user_command_limit),
):
    """Evaluate a command's risk without executing it.

    Runs the full risk engine (9 analyzers + injection scanner)
    and returns the assessment. Counts toward daily command limit.
    """
    from sentinelai.api.deps import increment_command_usage
    from sentinelai.engine import RiskEngine
    from sentinelai.engine.base import AnalysisContext

    engine = RiskEngine(config)
    ctx = AnalysisContext(
        working_directory=request.working_directory,
        user=user.username or "api",
    )
    assessment = engine.assess(request.command, context=ctx)

    # Increment usage counter (per-user)
    increment_command_usage(logger, user_email=user.email)

    score = assessment.final_score

    # Log the evaluation
    try:
        logger.log_command(
            assessment=assessment,
            executed=False,
            working_directory=request.working_directory,
        )
    except Exception:
        pass

    return {
        "command": _sanitize_text(request.command),
        "risk_score": score,
        "risk_level": assessment.risk_level.value if hasattr(assessment.risk_level, "value") else str(assessment.risk_level),
        "action": assessment.action.value if hasattr(assessment.action, "value") else str(assessment.action),
        "signals": [
            {
                "category": s.category.value if hasattr(s.category, "value") else str(s.category),
                "score": s.score,
                "weight": s.weight,
                "description": _sanitize_text(s.description),
            }
            for s in assessment.signals
        ],
    }
