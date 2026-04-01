"""Compliance report generation API endpoints.

Provides aggregated security compliance reports in JSON and CSV formats,
including executive summary, incident timeline, scan statistics, and
command audit summary.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from sentinelai.api.auth import TokenData
from sentinelai.api.deps import get_current_user, get_db_session, require_admin
from sentinelai.services.report_service import ReportRequest, ReportService

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.post(
    "/compliance",
    summary="Generate compliance report",
    description=(
        "Generate a full security compliance report for a given date range. "
        "Includes executive summary, incident timeline, scan statistics, "
        "and command audit summary. Admin only. "
        "Set format='csv' for CSV export (incident rows only)."
    ),
)
def generate_compliance_report(
    body: ReportRequest,
    user: TokenData = Depends(require_admin),
    session: Session = Depends(get_db_session),
):
    """Generate a compliance report (admin only).

    Returns JSON report by default. Set format="csv" for CSV export.
    """
    if body.format not in ("json", "csv"):
        raise HTTPException(
            status_code=422,
            detail={"error": "invalid_format", "message": "Format must be 'json' or 'csv'"},
        )

    service = ReportService(session)

    try:
        if body.format == "csv":
            csv_content = service.generate_csv(body, tenant_id=user.tenant_id)
            return PlainTextResponse(
                content=csv_content,
                media_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=compliance_report.csv"},
            )

        return service.generate(body, tenant_id=user.tenant_id)
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"error": "report_generation_failed", "message": str(e)},
        )


@router.get(
    "/summary",
    summary="Quick report summary",
    description=(
        "Get a quick summary report for the last 30 days. "
        "Includes scan statistics and command audit summary. "
        "Available to all authenticated users."
    ),
)
def report_summary(
    user: TokenData = Depends(get_current_user),
    session: Session = Depends(get_db_session),
):
    """Get a quick summary report for the last 30 days."""
    service = ReportService(session)
    params = ReportRequest(
        include_incidents=False,
        include_scans=True,
        include_commands=True,
    )
    try:
        report = service.generate(params, tenant_id=user.tenant_id)
        return {
            "summary": report["summary"],
            "scans": report.get("scans"),
            "commands": report.get("commands"),
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"error": "report_generation_failed", "message": str(e)},
        )
