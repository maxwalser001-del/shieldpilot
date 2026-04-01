"""API router package -- aggregates all domain-specific sub-routers.

Each module in this package defines its own APIRouter with endpoints
for a specific domain (auth, billing, admin, etc.). This __init__
assembles them into a single `router` that is included by routes.py.
"""

from __future__ import annotations

from fastapi import APIRouter

from sentinelai.api.routers.auth import router as auth_router
from sentinelai.api.routers.settings import router as settings_router
from sentinelai.api.routers.billing import router as billing_router
from sentinelai.api.routers.admin import router as admin_router
from sentinelai.api.routers.dashboard import router as dashboard_router
from sentinelai.api.routers.commands import router as commands_router
from sentinelai.api.routers.incidents import router as incidents_router
from sentinelai.api.routers.scans import router as scans_router
from sentinelai.api.routers.activity import router as activity_router
from sentinelai.api.routers.config import router as config_router
from sentinelai.api.routers.export import router as export_router
from sentinelai.api.routers.legal import router as legal_router
from sentinelai.api.routers.health import router as health_router
from sentinelai.api.routers.reports import router as reports_router
from sentinelai.api.routers.rules import router as rules_router
from sentinelai.api.routers.ratelimit import router as ratelimit_router
from sentinelai.api.routers.teams import router as teams_router

router = APIRouter()

router.include_router(auth_router)
router.include_router(settings_router)
router.include_router(billing_router)
router.include_router(admin_router)
router.include_router(dashboard_router)
router.include_router(commands_router)
router.include_router(incidents_router)
router.include_router(scans_router)
router.include_router(activity_router)
router.include_router(config_router)
router.include_router(export_router)
router.include_router(legal_router)
router.include_router(health_router)
router.include_router(reports_router)
router.include_router(rules_router)
router.include_router(ratelimit_router)
router.include_router(teams_router)
