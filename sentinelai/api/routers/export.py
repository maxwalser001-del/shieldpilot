"""CSV/JSON export endpoints for commands, incidents, and scans."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func

from sentinelai.api.auth import TokenData
from sentinelai.api.deps import (
    get_config,
    get_logger,
    require_feature,
    require_verified_email,
)
from sentinelai.core.config import SentinelConfig
from sentinelai.logger import BlackboxLogger
from sentinelai.logger.database import CommandLog, IncidentLog, PromptScanLog

router = APIRouter()


# ── Export ─────────────────────────────────────────────────────


@router.get(
    "/api/export/commands",
    tags=["Export"],
    summary="Export command logs",
    description="Download command audit logs as a CSV or JSON file. Supports the same filters as the list endpoint. Requires the export feature (Pro tier or above).",
    response_description="Command logs as downloadable CSV or JSON file",
)
def export_commands(
    format: str = Query("csv", pattern="^(csv|json)$"),
    action: Optional[str] = None,
    risk_min: Optional[int] = None,
    search: Optional[str] = None,
    user: TokenData = Depends(require_verified_email),
    logger: BlackboxLogger = Depends(get_logger),
    _feature_check: None = Depends(require_feature("export_enabled")),
):
    """Export command logs as CSV or JSON."""
    commands, total = logger.query_commands(
        action=action, risk_min=risk_min, search=search, limit=10000,
    )

    if format == "json":
        data = []
        for cmd in commands:
            data.append({
                "id": cmd.id,
                "timestamp": cmd.timestamp.isoformat() if cmd.timestamp else None,
                "command": cmd.command,
                "risk_score": cmd.risk_score,
                "action": cmd.action_taken,
                "executed": cmd.executed,
            })
        return Response(
            content=json.dumps(data, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=sentinel-commands.json"},
        )
    else:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["id", "timestamp", "command", "risk_score", "action", "executed"])
        for cmd in commands:
            writer.writerow([
                cmd.id,
                cmd.timestamp.isoformat() if cmd.timestamp else "",
                cmd.command,
                cmd.risk_score,
                cmd.action_taken,
                cmd.executed,
            ])
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=sentinel-commands.csv"},
        )


@router.get(
    "/api/export/incidents",
    tags=["Export"],
    summary="Export incidents",
    description="Download incident logs as a CSV or JSON file. Can be filtered by severity. Requires the export feature (Pro tier or above).",
    response_description="Incident logs as downloadable CSV or JSON file",
)
def export_incidents(
    format: str = Query("csv", pattern="^(csv|json)$"),
    severity: Optional[str] = None,
    user: TokenData = Depends(require_verified_email),
    logger: BlackboxLogger = Depends(get_logger),
    _feature_check: None = Depends(require_feature("export_enabled")),
):
    """Export incidents as CSV or JSON."""
    incidents, total = logger.query_incidents(severity=severity, limit=10000)

    if format == "json":
        data = []
        for inc in incidents:
            data.append({
                "id": inc.id,
                "timestamp": inc.timestamp.isoformat() if inc.timestamp else None,
                "severity": inc.severity,
                "category": inc.category,
                "title": inc.title,
                "resolved": inc.resolved,
            })
        return Response(
            content=json.dumps(data, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=sentinel-incidents.json"},
        )
    else:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["id", "timestamp", "severity", "category", "title", "resolved"])
        for inc in incidents:
            writer.writerow([
                inc.id,
                inc.timestamp.isoformat() if inc.timestamp else "",
                inc.severity, inc.category, inc.title, inc.resolved,
            ])
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=sentinel-incidents.csv"},
        )


@router.get(
    "/api/export/scans",
    tags=["Export"],
    summary="Export prompt scans",
    description="Download prompt scan logs as a CSV or JSON file. Can be filtered by minimum overall score. Requires the export feature (Pro tier or above).",
    response_description="Prompt scan logs as downloadable CSV or JSON file",
)
def export_scans(
    format: str = Query("csv", pattern="^(csv|json)$"),
    score_min: Optional[int] = None,
    user: TokenData = Depends(require_verified_email),
    logger: BlackboxLogger = Depends(get_logger),
    _feature_check: None = Depends(require_feature("export_enabled")),
):
    """Export prompt scan logs as CSV or JSON."""
    scans, total = logger.query_scans(limit=10000)

    # Apply optional score_min filter (query_scans doesn't support it natively)
    if score_min is not None:
        scans = [s for s in scans if s.overall_score >= score_min]

    if format == "json":
        data = []
        for scan in scans:
            data.append({
                "id": scan.id,
                "timestamp": scan.timestamp.isoformat() if scan.timestamp else None,
                "source": scan.source,
                "overall_score": scan.overall_score,
                "threat_count": scan.threat_count,
                "recommendation": scan.recommendation,
            })
        return Response(
            content=json.dumps(data, indent=2),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=sentinel-scans.json"},
        )
    else:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["id", "timestamp", "source", "overall_score", "threat_count", "recommendation"])
        for scan in scans:
            writer.writerow([
                scan.id,
                scan.timestamp.isoformat() if scan.timestamp else "",
                scan.source,
                scan.overall_score,
                scan.threat_count,
                scan.recommendation,
            ])
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=sentinel-scans.csv"},
        )


# ── HTML Report ──────────────────────────────────────────────


def _escape_html(text: str) -> str:
    """Escape HTML special characters to prevent XSS in generated reports."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


@router.get(
    "/api/export/report",
    tags=["Export"],
    summary="Generate security summary report",
    description=(
        "Generate a comprehensive Security Summary Report as a downloadable HTML "
        "file. Includes executive summary, risk score distribution, top blocked "
        "commands, and recent incidents for the last 30 days. "
        "Requires the export feature (Pro tier or above)."
    ),
    response_description="Security summary report as downloadable HTML file",
)
def export_report(
    user: TokenData = Depends(require_verified_email),
    config: SentinelConfig = Depends(get_config),
    logger: BlackboxLogger = Depends(get_logger),
    _feature_check: None = Depends(require_feature("export_enabled")),
):
    """Generate a Security Summary Report as downloadable HTML."""
    now = datetime.utcnow()
    cutoff = now - timedelta(days=30)
    session = logger._get_session()

    try:
        # ── Executive Summary data (last 30 days) ────────────────
        total_commands = (
            session.query(func.count())
            .select_from(CommandLog)
            .filter(CommandLog.timestamp >= cutoff)
            .scalar()
        ) or 0

        blocked_commands = (
            session.query(func.count())
            .select_from(CommandLog)
            .filter(CommandLog.timestamp >= cutoff, CommandLog.action_taken == "block")
            .scalar()
        ) or 0

        warned_commands = (
            session.query(func.count())
            .select_from(CommandLog)
            .filter(CommandLog.timestamp >= cutoff, CommandLog.action_taken == "warn")
            .scalar()
        ) or 0

        allowed_commands = (
            session.query(func.count())
            .select_from(CommandLog)
            .filter(CommandLog.timestamp >= cutoff, CommandLog.action_taken == "allow")
            .scalar()
        ) or 0

        total_incidents = (
            session.query(func.count())
            .select_from(IncidentLog)
            .filter(IncidentLog.timestamp >= cutoff)
            .scalar()
        ) or 0

        total_scans = (
            session.query(func.count())
            .select_from(PromptScanLog)
            .filter(PromptScanLog.timestamp >= cutoff)
            .scalar()
        ) or 0

        # ── Risk Score Distribution ──────────────────────────────
        score_buckets = [
            ("0-19", 0, 19),
            ("20-39", 20, 39),
            ("40-59", 40, 59),
            ("60-79", 60, 79),
            ("80-100", 80, 100),
        ]
        score_rows = []
        for label, lo, hi in score_buckets:
            count = (
                session.query(func.count())
                .select_from(CommandLog)
                .filter(
                    CommandLog.timestamp >= cutoff,
                    CommandLog.risk_score >= lo,
                    CommandLog.risk_score <= hi,
                )
                .scalar()
            ) or 0
            score_rows.append((label, count))

        # ── Top 5 Blocked Commands ───────────────────────────────
        top_blocked = (
            session.query(
                func.substr(CommandLog.command, 1, 60).label("cmd"),
                func.count().label("cnt"),
            )
            .filter(
                CommandLog.action_taken == "block",
                CommandLog.timestamp >= cutoff,
            )
            .group_by(func.substr(CommandLog.command, 1, 60))
            .order_by(func.count().desc())
            .limit(5)
            .all()
        )

        # ── Recent Incidents (last 20) ───────────────────────────
        recent_incidents = (
            session.query(IncidentLog)
            .filter(IncidentLog.timestamp >= cutoff)
            .order_by(IncidentLog.timestamp.desc())
            .limit(20)
            .all()
        )

    finally:
        session.close()

    # ── Build HTML report ────────────────────────────────────────
    generated_at = now.strftime("%Y-%m-%d %H:%M UTC")
    period_start = cutoff.strftime("%Y-%m-%d")
    period_end = now.strftime("%Y-%m-%d")

    # Score distribution table rows
    score_table_rows = ""
    for label, count in score_rows:
        score_table_rows += (
            f"<tr><td>{_escape_html(label)}</td>"
            f"<td>{count}</td></tr>\n"
        )

    # Top blocked commands rows
    blocked_table_rows = ""
    if top_blocked:
        for row in top_blocked:
            blocked_table_rows += (
                f"<tr><td><code>{_escape_html(row.cmd or '')}</code></td>"
                f"<td>{row.cnt}</td></tr>\n"
            )
    else:
        blocked_table_rows = '<tr><td colspan="2">No blocked commands in this period.</td></tr>'

    # Recent incidents rows
    incidents_table_rows = ""
    if recent_incidents:
        for inc in recent_incidents:
            ts = inc.timestamp.strftime("%Y-%m-%d %H:%M") if inc.timestamp else ""
            resolved_str = "Yes" if inc.resolved else "No"
            incidents_table_rows += (
                f"<tr>"
                f"<td>{inc.id}</td>"
                f"<td>{_escape_html(ts)}</td>"
                f"<td>{_escape_html(inc.severity or '')}</td>"
                f"<td>{_escape_html(inc.category or '')}</td>"
                f"<td>{_escape_html(inc.title or '')}</td>"
                f"<td>{_escape_html(resolved_str)}</td>"
                f"</tr>\n"
            )
    else:
        incidents_table_rows = '<tr><td colspan="6">No incidents in this period.</td></tr>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ShieldPilot Security Report</title>
<style>
  :root {{
    --bg: #0D1117;
    --surface: #161B22;
    --border: #30363D;
    --text: #C9D1D9;
    --text-muted: #8B949E;
    --accent: #39D2C0;
    --danger: #F85149;
    --warning: #D29922;
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    padding: 40px;
    line-height: 1.6;
  }}
  .container {{ max-width: 900px; margin: 0 auto; }}
  .header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 2px solid var(--accent);
    padding-bottom: 16px;
    margin-bottom: 32px;
  }}
  .header h1 {{
    font-size: 24px;
    color: var(--accent);
    letter-spacing: 1px;
  }}
  .header .date {{ color: var(--text-muted); font-size: 14px; }}
  h2 {{
    color: var(--accent);
    font-size: 18px;
    margin: 28px 0 12px 0;
    border-bottom: 1px solid var(--border);
    padding-bottom: 6px;
  }}
  .summary-grid {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 16px;
    margin-bottom: 24px;
  }}
  .summary-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
    text-align: center;
  }}
  .summary-card .value {{
    font-size: 28px;
    font-weight: 700;
    color: var(--accent);
  }}
  .summary-card .label {{
    font-size: 12px;
    color: var(--text-muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}
  .summary-card.danger .value {{ color: var(--danger); }}
  .summary-card.warning .value {{ color: var(--warning); }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 24px;
    background: var(--surface);
    border-radius: 8px;
    overflow: hidden;
  }}
  th, td {{
    padding: 10px 14px;
    text-align: left;
    border-bottom: 1px solid var(--border);
    font-size: 13px;
  }}
  th {{
    background: var(--border);
    color: var(--text);
    font-weight: 600;
    text-transform: uppercase;
    font-size: 11px;
    letter-spacing: 0.5px;
  }}
  code {{
    background: var(--bg);
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 12px;
    color: var(--danger);
  }}
  .footer {{
    margin-top: 40px;
    padding-top: 16px;
    border-top: 1px solid var(--border);
    color: var(--text-muted);
    font-size: 12px;
    text-align: center;
  }}
  @media print {{
    body {{ background: #fff; color: #222; padding: 20px; }}
    .summary-card {{ border: 1px solid #ccc; }}
    .summary-card .value {{ color: #333; }}
    .summary-card.danger .value {{ color: #d32f2f; }}
    th {{ background: #eee; }}
    table {{ border: 1px solid #ccc; }}
    td, th {{ border-bottom: 1px solid #ddd; }}
    code {{ background: #f5f5f5; color: #d32f2f; }}
  }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>SHIELDPILOT Security Report</h1>
    <div class="date">
      Generated: {_escape_html(generated_at)}<br>
      Period: {_escape_html(period_start)} to {_escape_html(period_end)}
    </div>
  </div>

  <h2>Executive Summary</h2>
  <div class="summary-grid">
    <div class="summary-card">
      <div class="value">{total_commands}</div>
      <div class="label">Total Commands</div>
    </div>
    <div class="summary-card danger">
      <div class="value">{blocked_commands}</div>
      <div class="label">Blocked</div>
    </div>
    <div class="summary-card warning">
      <div class="value">{warned_commands}</div>
      <div class="label">Warned</div>
    </div>
    <div class="summary-card">
      <div class="value">{allowed_commands}</div>
      <div class="label">Allowed</div>
    </div>
    <div class="summary-card danger">
      <div class="value">{total_incidents}</div>
      <div class="label">Incidents</div>
    </div>
    <div class="summary-card">
      <div class="value">{total_scans}</div>
      <div class="label">Prompt Scans</div>
    </div>
  </div>

  <h2>Risk Score Distribution</h2>
  <table>
    <thead>
      <tr><th>Score Range</th><th>Count</th></tr>
    </thead>
    <tbody>
      {score_table_rows}
    </tbody>
  </table>

  <h2>Top 5 Blocked Commands</h2>
  <table>
    <thead>
      <tr><th>Command</th><th>Times Blocked</th></tr>
    </thead>
    <tbody>
      {blocked_table_rows}
    </tbody>
  </table>

  <h2>Recent Incidents (Last 20)</h2>
  <table>
    <thead>
      <tr>
        <th>ID</th>
        <th>Timestamp</th>
        <th>Severity</th>
        <th>Category</th>
        <th>Title</th>
        <th>Resolved</th>
      </tr>
    </thead>
    <tbody>
      {incidents_table_rows}
    </tbody>
  </table>

  <div class="footer">
    ShieldPilot Security Platform &mdash; Confidential Report &mdash; {_escape_html(generated_at)}
  </div>
</div>
</body>
</html>"""

    filename = f"shieldpilot-report-{now.strftime('%Y%m%d')}.html"
    return Response(
        content=html,
        media_type="text/html",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
