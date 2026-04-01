"""ShieldPilot Local Dashboard Server — read-only monitoring on port 8421.

This is a SEPARATE, lightweight FastAPI application that provides a read-only
view of ShieldPilot's command logs, incidents, and prompt scans.  It is
designed for local use only and intentionally has NO authentication:
localhost is treated as trusted, and every endpoint is read-only.

Start standalone:
    python3 -m sentinelai.dashboard.server

Or import the factory:
    from sentinelai.dashboard.server import create_dashboard_app
    app = create_dashboard_app()
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func
from starlette.requests import Request

from sentinelai.core.config import load_config
from sentinelai.logger.database import (
    CommandLog,
    IncidentLog,
    PromptScanLog,
    init_database,
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PACKAGE_DIR = Path(__file__).resolve().parent            # sentinelai/dashboard/
_TEMPLATE_DIR = _PACKAGE_DIR / "templates"                # sentinelai/dashboard/templates/
_STATIC_DIR = _PACKAGE_DIR.parent / "web" / "static"      # sentinelai/web/static/

# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_dashboard_app() -> FastAPI:
    """Create and return the local dashboard FastAPI application.

    - NO authentication — this server is localhost-only and read-only.
    - Reuses the existing sentinel.css and static assets.
    - Default port 8421 (separate from the main app on 8420).
    """

    config = load_config()
    _engine, Session = init_database(config.logging.database)

    app = FastAPI(
        title="ShieldPilot Local Dashboard",
        description="Read-only local monitoring dashboard for ShieldPilot",
        docs_url="/api/docs",
        redoc_url=None,
    )

    # CORS — allow localhost origins (dashboard is local-only)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:8421",
            "http://127.0.0.1:8421",
            "http://localhost:8420",
            "http://127.0.0.1:8420",
        ],
        allow_credentials=False,
        allow_methods=["GET"],
        allow_headers=["*"],
    )

    # Mount static files (reuses the main app's static assets)
    if _STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    # Jinja2 templates for the dashboard page
    templates = Jinja2Templates(directory=str(_TEMPLATE_DIR))

    # -------------------------------------------------------------------
    # Routes
    # -------------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    async def dashboard_page(request: Request) -> HTMLResponse:
        """Serve the standalone dashboard HTML page."""
        return templates.TemplateResponse("dashboard.html", {"request": request})

    # -- F1: Read-only API endpoints -----------------------------------

    @app.get("/api/stats")
    async def get_stats() -> Dict[str, Any]:
        """Dashboard statistics: totals, averages, and top risk categories."""
        session = Session()
        try:
            today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

            total_commands = session.query(func.count(CommandLog.id)).scalar() or 0
            total_incidents = session.query(func.count(IncidentLog.id)).scalar() or 0
            blocked_count = (
                session.query(func.count(CommandLog.id))
                .filter(CommandLog.action_taken == "block")
                .scalar()
                or 0
            )
            avg_risk = (
                session.query(func.avg(CommandLog.risk_score)).scalar() or 0.0
            )
            commands_today = (
                session.query(func.count(CommandLog.id))
                .filter(CommandLog.timestamp >= today_start)
                .scalar()
                or 0
            )
            incidents_today = (
                session.query(func.count(IncidentLog.id))
                .filter(IncidentLog.timestamp >= today_start)
                .scalar()
                or 0
            )
            scans_today = (
                session.query(func.count(PromptScanLog.id))
                .filter(PromptScanLog.timestamp >= today_start)
                .scalar()
                or 0
            )

            # Top 5 risk categories from incidents
            top_cats_raw = (
                session.query(IncidentLog.category, func.count(IncidentLog.id).label("cnt"))
                .group_by(IncidentLog.category)
                .order_by(desc("cnt"))
                .limit(5)
                .all()
            )
            top_risk_categories = [
                {"category": row[0], "count": row[1]} for row in top_cats_raw
            ]

            return {
                "total_commands": total_commands,
                "total_incidents": total_incidents,
                "blocked_count": blocked_count,
                "avg_risk_score": round(float(avg_risk), 1),
                "commands_today": commands_today,
                "incidents_today": incidents_today,
                "scans_today": scans_today,
                "top_risk_categories": top_risk_categories,
            }
        finally:
            session.close()

    @app.get("/api/commands")
    async def get_commands() -> List[Dict[str, Any]]:
        """Return the last 100 commands ordered by timestamp descending."""
        session = Session()
        try:
            rows = (
                session.query(CommandLog)
                .order_by(desc(CommandLog.timestamp))
                .limit(100)
                .all()
            )
            return [
                {
                    "id": r.id,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                    "command": r.command,
                    "risk_score": r.risk_score,
                    "risk_level": r.risk_level,
                    "action_taken": r.action_taken,
                    "executed": r.executed,
                }
                for r in rows
            ]
        finally:
            session.close()

    @app.get("/api/incidents")
    async def get_incidents() -> List[Dict[str, Any]]:
        """Return the last 50 incidents ordered by timestamp descending."""
        session = Session()
        try:
            rows = (
                session.query(IncidentLog)
                .order_by(desc(IncidentLog.timestamp))
                .limit(50)
                .all()
            )
            return [
                {
                    "id": r.id,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                    "severity": r.severity,
                    "category": r.category,
                    "title": r.title,
                    "description": r.description,
                    "resolved": r.resolved,
                }
                for r in rows
            ]
        finally:
            session.close()

    @app.get("/api/scans")
    async def get_scans() -> List[Dict[str, Any]]:
        """Return the last 50 prompt scans ordered by timestamp descending."""
        session = Session()
        try:
            rows = (
                session.query(PromptScanLog)
                .order_by(desc(PromptScanLog.timestamp))
                .limit(50)
                .all()
            )
            return [
                {
                    "id": r.id,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                    "source": r.source,
                    "overall_score": r.overall_score,
                    "threat_count": r.threat_count,
                    "recommendation": r.recommendation,
                }
                for r in rows
            ]
        finally:
            session.close()

    @app.get("/api/platform")
    async def get_platform() -> Dict[str, Any]:
        """Detect active AI coding tools in the current working directory."""
        cwd = Path.cwd()
        tools: List[str] = []

        # Claude Code
        if (cwd / ".claude").is_dir():
            tools.append("Claude Code")

        # Cursor
        if (cwd / ".cursorrules").exists() or (cwd / ".cursor").is_dir():
            tools.append("Cursor")

        # GitHub Copilot
        if (cwd / ".github" / "copilot").is_dir() or (cwd / ".github" / "copilot-instructions.md").exists():
            tools.append("Copilot")

        # Windsurf / Codeium
        if (cwd / ".windsurfrules").exists() or (cwd / ".codeium").is_dir():
            tools.append("Windsurf")

        # Aider
        if (cwd / ".aider.conf.yml").exists() or (cwd / ".aiderignore").exists():
            tools.append("Aider")

        primary = tools[0] if len(tools) == 1 else ("Multiple" if len(tools) > 1 else None)

        return {
            "tools": tools,
            "primary": primary,
        }

    @app.get("/api/license")
    async def get_license() -> Dict[str, str]:
        """Return the current billing tier from config."""
        return {"tier": config.billing.tier}

    return app


# ---------------------------------------------------------------------------
# Module-level instance for: uvicorn sentinelai.dashboard.server:app
# ---------------------------------------------------------------------------
app = create_dashboard_app()


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("DASHBOARD_PORT", "8421"))
    print(f"ShieldPilot Local Dashboard starting on http://localhost:{port}")
    print("No authentication required — localhost is trusted (read-only).")
    uvicorn.run(app, host="127.0.0.1", port=port)
