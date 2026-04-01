"""Legal endpoints: Impressum, GDPR data export."""

from __future__ import annotations

import json
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from sentinelai.api.auth import TokenData
from sentinelai.api.deps import (
    get_config,
    get_db_session,
    require_verified_email,
)
from sentinelai.core.config import SentinelConfig
from sentinelai.logger.database import (
    CommandLog,
    FileChangeLog,
    IncidentLog,
    NetworkAccessLog,
    PromptScanLog,
    User,
)

router = APIRouter()


# ── Legal Endpoints ──────────────────────────────────────────


@router.get(
    "/api/legal/impressum",
    tags=["Legal"],
    summary="Get Impressum data",
    description="Return the public legal disclosure (Impressum) as required by German DDG section 5. No authentication required.",
    response_description="Public legal disclosure as required by DDG section 5",
)
def get_impressum(config: SentinelConfig = Depends(get_config)):
    """Public Impressum data (DDG section 5)."""
    legal = config.legal
    return {
        "company_name": legal.company_name,
        "address_line1": legal.address_line1,
        "address_line2": legal.address_line2,
        "country": legal.country,
        "managing_director": legal.managing_director,
        "registration_court": legal.registration_court,
        "registration_number": legal.registration_number,
        "vat_id": legal.vat_id,
        "contact_email": legal.contact_email,
        "contact_phone": legal.contact_phone,
    }


@router.get(
    "/api/account/export",
    tags=["Account"],
    summary="Export personal data (GDPR)",
    description="Download all personal data associated with the authenticated user as a JSON file, including commands, incidents, scans, and network logs. Implements GDPR Articles 15 and 20.",
    response_description="Complete personal data export as downloadable JSON (GDPR Art. 15/20)",
)
def export_personal_data(
    user: TokenData = Depends(require_verified_email),
    session: Session = Depends(get_db_session),
):
    """Export all personal data as JSON (GDPR Art. 15/20)."""
    db_user = session.query(User).filter(User.email == user.email).first()
    if not db_user:
        raise HTTPException(status_code=404, detail={"error": "User not found"})

    # Build tenant filter
    tenant_filter = CommandLog.tenant_id == db_user.tenant_id if db_user.tenant_id else True

    # Account data
    account = {
        "username": db_user.username,
        "email": db_user.email,
        "tier": db_user.tier,
        "role": db_user.role,
        "email_verified": db_user.email_verified,
        "created_at": db_user.created_at.isoformat() if db_user.created_at else None,
        "tos_accepted_at": db_user.tos_accepted_at.isoformat() if db_user.tos_accepted_at else None,
        "tos_version": db_user.tos_version,
    }

    # Commands (limit 10000)
    commands = []
    for cmd in session.query(CommandLog).filter(tenant_filter).order_by(CommandLog.id.desc()).limit(10000).all():
        commands.append({
            "id": cmd.id,
            "timestamp": cmd.timestamp.isoformat() if cmd.timestamp else None,
            "command": cmd.command,
            "risk_score": cmd.risk_score,
            "risk_level": cmd.risk_level,
            "action_taken": cmd.action_taken,
            "executed": cmd.executed,
            "exit_code": cmd.exit_code,
        })

    # Incidents (limit 10000)
    incident_filter = IncidentLog.tenant_id == db_user.tenant_id if db_user.tenant_id else True
    incidents = []
    for inc in session.query(IncidentLog).filter(incident_filter).order_by(IncidentLog.id.desc()).limit(10000).all():
        incidents.append({
            "id": inc.id,
            "timestamp": inc.timestamp.isoformat() if inc.timestamp else None,
            "severity": inc.severity,
            "category": inc.category,
            "title": inc.title,
            "description": inc.description,
            "resolved": inc.resolved,
        })

    # Scans (limit 10000)
    scan_filter = PromptScanLog.tenant_id == db_user.tenant_id if db_user.tenant_id else True
    scans = []
    for scan in session.query(PromptScanLog).filter(scan_filter).order_by(PromptScanLog.id.desc()).limit(10000).all():
        scans.append({
            "id": scan.id,
            "timestamp": scan.timestamp.isoformat() if scan.timestamp else None,
            "source": scan.source,
            "overall_score": scan.overall_score,
            "threat_count": scan.threat_count,
            "recommendation": scan.recommendation,
        })

    # File changes (limit 10000)
    file_filter = FileChangeLog.tenant_id == db_user.tenant_id if db_user.tenant_id else True
    file_changes = []
    for fc in session.query(FileChangeLog).filter(file_filter).order_by(FileChangeLog.id.desc()).limit(10000).all():
        file_changes.append({
            "id": fc.id,
            "timestamp": fc.timestamp.isoformat() if fc.timestamp else None,
            "file_path": fc.file_path,
            "change_type": fc.change_type,
        })

    # Network access (limit 10000)
    net_filter = NetworkAccessLog.tenant_id == db_user.tenant_id if db_user.tenant_id else True
    network_access = []
    for na in session.query(NetworkAccessLog).filter(net_filter).order_by(NetworkAccessLog.id.desc()).limit(10000).all():
        network_access.append({
            "id": na.id,
            "timestamp": na.timestamp.isoformat() if na.timestamp else None,
            "destination": na.destination,
            "port": na.port,
            "protocol": na.protocol,
            "direction": na.direction,
            "blocked": na.blocked,
        })

    export = {
        "export_date": datetime.utcnow().isoformat(),
        "format_version": "1.0",
        "account": account,
        "commands": commands,
        "incidents": incidents,
        "scans": scans,
        "file_changes": file_changes,
        "network_access": network_access,
    }

    return Response(
        content=json.dumps(export, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": "attachment; filename=shieldpilot-data-export.json",
        },
    )
