"""Compliance report generation service for ShieldPilot.

Generates security compliance reports in JSON and CSV formats with:
- Executive summary (total incidents, risk distribution, scan coverage)
- Incident timeline (all incidents in date range)
- Scan statistics (detection rates, top categories)
- Command audit summary (blocked/warned/allowed counts)
"""

from __future__ import annotations

import csv
import io
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


# -- Request/Response Models ---------------------------------------------------


class ReportRequest(BaseModel):
    """Parameters for generating a compliance report."""
    start_date: Optional[str] = None  # ISO date YYYY-MM-DD, defaults to 30 days ago
    end_date: Optional[str] = None    # ISO date YYYY-MM-DD, defaults to today
    format: str = "json"              # json or csv
    include_incidents: bool = True
    include_scans: bool = True
    include_commands: bool = True


# -- Service -------------------------------------------------------------------


class ReportService:
    """Generates compliance reports from audit data."""

    def __init__(self, session: Session):
        self.session = session

    def generate(
        self, params: ReportRequest, tenant_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generate a full compliance report.

        Returns a dict with:
        - metadata: report generation info
        - summary: high-level statistics
        - incidents: incident details (if requested)
        - scans: scan statistics (if requested)
        - commands: command audit summary (if requested)
        """
        start, end = self._parse_dates(params.start_date, params.end_date)

        report: Dict[str, Any] = {
            "metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "period_start": start.isoformat(),
                "period_end": end.isoformat(),
                "tenant_id": tenant_id,
                "format": params.format,
            },
        }

        report["summary"] = self._build_summary(start, end, tenant_id)

        if params.include_incidents:
            report["incidents"] = self._build_incidents(start, end, tenant_id)

        if params.include_scans:
            report["scans"] = self._build_scans(start, end, tenant_id)

        if params.include_commands:
            report["commands"] = self._build_commands(start, end, tenant_id)

        return report

    def generate_csv(
        self, params: ReportRequest, tenant_id: Optional[str] = None
    ) -> str:
        """Generate a CSV compliance report.

        Returns CSV string with incident rows including summary header.
        """
        start, end = self._parse_dates(params.start_date, params.end_date)
        from sentinelai.logger.database import IncidentLog

        query = self.session.query(IncidentLog).filter(
            IncidentLog.timestamp >= start,
            IncidentLog.timestamp <= end,
        )
        if tenant_id:
            query = query.filter(IncidentLog.tenant_id == tenant_id)

        incidents = query.order_by(IncidentLog.timestamp.desc()).all()

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "id", "timestamp", "severity", "category", "title",
            "description", "resolved", "resolved_at",
        ])
        for inc in incidents:
            writer.writerow([
                inc.id,
                inc.timestamp.isoformat() if inc.timestamp else "",
                inc.severity,
                inc.category,
                inc.title,
                inc.description,
                inc.resolved,
                inc.resolved_at.isoformat() if inc.resolved_at else "",
            ])

        return output.getvalue()

    def _parse_dates(
        self, start_str: Optional[str], end_str: Optional[str]
    ) -> tuple[datetime, datetime]:
        """Parse date strings or use defaults (last 30 days)."""
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=30)

        if end_str:
            try:
                end = datetime.fromisoformat(end_str)
            except ValueError:
                pass
        if start_str:
            try:
                start = datetime.fromisoformat(start_str)
            except ValueError:
                pass

        return start, end

    def _build_summary(
        self, start: datetime, end: datetime, tenant_id: Optional[str]
    ) -> Dict[str, Any]:
        """Build executive summary statistics."""
        from sentinelai.logger.database import CommandLog, IncidentLog, PromptScanLog

        # Incident counts by severity
        inc_query = self.session.query(
            IncidentLog.severity, func.count(IncidentLog.id)
        ).filter(
            IncidentLog.timestamp >= start, IncidentLog.timestamp <= end,
        )
        if tenant_id:
            inc_query = inc_query.filter(IncidentLog.tenant_id == tenant_id)
        inc_by_severity = dict(inc_query.group_by(IncidentLog.severity).all())

        # Command counts by action
        cmd_query = self.session.query(
            CommandLog.action_taken, func.count(CommandLog.id)
        ).filter(
            CommandLog.timestamp >= start, CommandLog.timestamp <= end,
        )
        if tenant_id:
            cmd_query = cmd_query.filter(CommandLog.tenant_id == tenant_id)
        cmd_by_action = dict(cmd_query.group_by(CommandLog.action_taken).all())

        # Total scans
        scan_query = self.session.query(func.count(PromptScanLog.id)).filter(
            PromptScanLog.timestamp >= start, PromptScanLog.timestamp <= end,
        )
        if tenant_id:
            scan_query = scan_query.filter(PromptScanLog.tenant_id == tenant_id)
        total_scans = scan_query.scalar() or 0

        total_incidents = sum(inc_by_severity.values())
        total_commands = sum(cmd_by_action.values())

        return {
            "total_incidents": total_incidents,
            "incidents_by_severity": inc_by_severity,
            "total_commands": total_commands,
            "commands_by_action": cmd_by_action,
            "total_scans": total_scans,
            "block_rate": round(
                cmd_by_action.get("block", 0) / max(total_commands, 1) * 100, 1
            ),
        }

    def _build_incidents(
        self, start: datetime, end: datetime, tenant_id: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Build incident timeline."""
        from sentinelai.logger.database import IncidentLog

        query = self.session.query(IncidentLog).filter(
            IncidentLog.timestamp >= start, IncidentLog.timestamp <= end,
        )
        if tenant_id:
            query = query.filter(IncidentLog.tenant_id == tenant_id)

        incidents = query.order_by(IncidentLog.timestamp.desc()).limit(500).all()

        return [
            {
                "id": inc.id,
                "timestamp": inc.timestamp.isoformat() if inc.timestamp else None,
                "severity": inc.severity,
                "category": inc.category,
                "title": inc.title,
                "resolved": inc.resolved,
            }
            for inc in incidents
        ]

    def _build_scans(
        self, start: datetime, end: datetime, tenant_id: Optional[str]
    ) -> Dict[str, Any]:
        """Build scan statistics."""
        from sentinelai.logger.database import PromptScanLog

        query = self.session.query(PromptScanLog).filter(
            PromptScanLog.timestamp >= start, PromptScanLog.timestamp <= end,
        )
        if tenant_id:
            query = query.filter(PromptScanLog.tenant_id == tenant_id)

        scans = query.all()
        total = len(scans)
        threats_detected = sum(1 for s in scans if s.threat_count > 0)
        avg_score = round(sum(s.overall_score for s in scans) / max(total, 1), 1)

        return {
            "total_scans": total,
            "threats_detected": threats_detected,
            "clean_scans": total - threats_detected,
            "detection_rate": round(threats_detected / max(total, 1) * 100, 1),
            "average_risk_score": avg_score,
        }

    def _build_commands(
        self, start: datetime, end: datetime, tenant_id: Optional[str]
    ) -> Dict[str, Any]:
        """Build command audit summary."""
        from sentinelai.logger.database import CommandLog

        query = self.session.query(CommandLog).filter(
            CommandLog.timestamp >= start, CommandLog.timestamp <= end,
        )
        if tenant_id:
            query = query.filter(CommandLog.tenant_id == tenant_id)

        commands = query.all()
        total = len(commands)

        # Risk distribution
        risk_buckets: Dict[str, int] = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for cmd in commands:
            if cmd.risk_score < 30:
                risk_buckets["low"] += 1
            elif cmd.risk_score < 60:
                risk_buckets["medium"] += 1
            elif cmd.risk_score < 80:
                risk_buckets["high"] += 1
            else:
                risk_buckets["critical"] += 1

        avg_risk = round(sum(c.risk_score for c in commands) / max(total, 1), 1)

        return {
            "total_commands": total,
            "risk_distribution": risk_buckets,
            "average_risk_score": avg_risk,
        }
