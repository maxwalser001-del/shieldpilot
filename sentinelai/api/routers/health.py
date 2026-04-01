"""Health check endpoints: health, chain integrity."""

from __future__ import annotations

import os
import time

from fastapi import APIRouter, Depends

from sqlalchemy import text as sa_text

from sentinelai import __version__
from sentinelai.api.auth import TokenData
from sentinelai.api.deps import (
    get_config,
    get_logger,
    require_admin,
)
from sentinelai.api.routers._shared import _start_time
from sentinelai.logger import BlackboxLogger

router = APIRouter()


# ── Health ────────────────────────────────────────────────────


@router.get(
    "/api/health",
    tags=["Health"],
    summary="Health check",
    response_description="Service status with component-level health breakdown",
)
def health():
    """Health check with component statuses (no auth required).

    Returns structured component health: database connectivity, disk space,
    chain integrity, and optional service configuration (SMTP, Stripe, OAuth).
    """
    uptime = int(time.time() - _start_time)

    components = {}

    # ── 1. Database connectivity ──────────────────────────────
    db_status = "error"
    db_response_ms = None
    try:
        logger = get_logger()
        session = logger._get_session()
        t0 = time.time()
        session.execute(sa_text("SELECT 1"))
        db_response_ms = round((time.time() - t0) * 1000, 1)
        db_status = "ok"
        session.close()
    except Exception as exc:
        db_status = "error"
        db_response_ms = None

    components["database"] = {
        "status": db_status,
        "response_ms": db_response_ms,
    }

    # ── 2. Disk space for SQLite file ─────────────────────────
    disk_status = "ok"
    disk_info = {}
    try:
        config = get_config()
        db_path = getattr(config.logging, "database", "sentinel.db")
        if os.path.exists(db_path):
            db_size_bytes = os.path.getsize(db_path)
            db_size_mb = round(db_size_bytes / (1024 * 1024), 2)

            # Check available disk space on the partition containing the DB
            stat = os.statvfs(db_path)
            free_bytes = stat.f_bavail * stat.f_frsize
            free_mb = round(free_bytes / (1024 * 1024), 1)
            total_bytes = stat.f_blocks * stat.f_frsize
            total_mb = round(total_bytes / (1024 * 1024), 1)
            usage_pct = round((1 - free_bytes / total_bytes) * 100, 1) if total_bytes > 0 else 0

            disk_info = {
                "db_size_mb": db_size_mb,
                "disk_free_mb": free_mb,
                "disk_total_mb": total_mb,
                "disk_usage_pct": usage_pct,
            }

            # Warn if disk is more than 90% full or less than 100MB free
            if usage_pct > 90 or free_mb < 100:
                disk_status = "warning"
        else:
            # DB file not found at expected path (normal for in-memory / test DBs)
            disk_info = {"db_path": db_path, "exists": False}
    except Exception:
        disk_status = "unknown"

    components["disk"] = {
        "status": disk_status,
        **disk_info,
    }

    # ── 3. Chain integrity ────────────────────────────────────
    chain_status = {}
    chains_ok = True
    try:
        logger = get_logger()
        tables = ["commands", "incidents", "prompt_scans", "file_changes", "network_access"]
        for table in tables:
            result = logger.verify_chain(table)
            chain_status[table] = {
                "valid": result.valid,
                "entries": result.total_entries,
            }
            if not result.valid:
                chains_ok = False
    except Exception:
        chain_status = {"error": "unable to verify chains"}
        chains_ok = False

    components["chain_integrity"] = {
        "status": "ok" if chains_ok else "degraded",
        "tables": chain_status,
    }

    # ── 4. Optional services ──────────────────────────────────
    config = get_config()

    # SMTP
    smtp_configured = bool(config.auth.smtp_user and config.auth.smtp_password)
    smtp_host = config.auth.smtp_host if hasattr(config.auth, "smtp_host") else None
    components["smtp"] = {
        "status": "configured" if smtp_configured else "not_configured",
        "host": smtp_host if smtp_configured else None,
    }

    # Stripe
    stripe_configured = bool(config.billing.stripe_secret_key)
    components["stripe"] = {
        "status": "configured" if stripe_configured else "not_configured",
        "webhook_configured": bool(config.billing.stripe_webhook_secret) if stripe_configured else False,
    }

    # Google OAuth
    oauth_configured = bool(config.auth.google_client_id)
    components["google_oauth"] = {
        "status": "configured" if oauth_configured else "not_configured",
    }

    # ── Overall status ────────────────────────────────────────
    if db_status != "ok":
        overall = "error"
    elif disk_status == "warning" or not chains_ok:
        overall = "degraded"
    else:
        overall = "ok"

    return {
        "status": overall,
        "version": __version__,
        "uptime_seconds": uptime,
        "components": components,
    }


@router.get(
    "/api/health/chain",
    tags=["Health"],
    summary="Verify audit chain integrity",
    response_description="Per-table hash-chain verification results",
)
def verify_chain_health(
    user: TokenData = Depends(require_admin),
    logger: BlackboxLogger = Depends(get_logger),
):
    """Verify hash-chain integrity across all log tables (admin only).

    Uses verify_chain (read-only) -- no incident creation on repeated calls.
    """
    tables = ["commands", "incidents", "prompt_scans", "file_changes", "network_access"]
    results = {}
    for table in tables:
        result = logger.verify_chain(table)
        results[table] = {
            "valid": result.valid,
            "total_entries": result.total_entries,
            "verified_entries": result.verified_entries,
            "first_broken_entry": result.first_broken_entry,
            "message": result.message,
        }

    all_valid = all(r["valid"] for r in results.values())
    return {"healthy": all_valid, "chains": results}
