"""FastAPI application factory for ShieldPilot dashboard.

Creates the app, includes routes, sets up CORS, and mounts static files.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.types import ASGIApp, Receive, Scope, Send


class SecurityHeadersMiddleware:
    """Pure ASGI middleware to add security headers to all responses.

    Uses raw ASGI protocol instead of BaseHTTPMiddleware to avoid the known
    Starlette deadlock when BaseHTTPMiddleware wraps sync endpoints that
    perform blocking I/O (e.g. database queries via SQLAlchemy).
    """

    HEADERS = [
        (b"x-content-type-options", b"nosniff"),
        (b"x-frame-options", b"DENY"),
        (b"x-xss-protection", b"1; mode=block"),
        (b"referrer-policy", b"strict-origin-when-cross-origin"),
        (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
        # CSP: covers landing page (Google OAuth) + SPA (no external scripts)
        (
            b"content-security-policy",
            b"default-src 'self'; "
            b"script-src 'self' 'unsafe-inline' https://accounts.google.com https://apis.google.com; "
            b"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            b"font-src 'self' https://fonts.gstatic.com; "
            b"img-src 'self' data:; "
            b"connect-src 'self' https://accounts.google.com; "
            b"frame-src https://accounts.google.com; "
            b"frame-ancestors 'none'; "
            b"base-uri 'self'; "
            b"form-action 'self'; "
            b"object-src 'none'",
        ),
    ]
    HSTS_HEADER = (b"strict-transport-security", b"max-age=31536000; includeSubDomains")

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        is_https = scope.get("scheme") == "https"

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(self.HEADERS)
                if is_https:
                    headers.append(self.HSTS_HEADER)
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)


def _startup_cleanup() -> None:
    """Best-effort cleanup of old usage records."""
    try:
        from sentinelai.api.deps import cleanup_old_usage_records, get_logger
        bl_logger = get_logger()
        deleted = cleanup_old_usage_records(bl_logger, retention_days=30)
        if deleted > 0:
            import logging
            logging.getLogger("sentinelai.startup").info(
                "Cleaned up %d old usage records", deleted
            )
    except Exception:
        pass  # startup cleanup is best-effort


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown events."""
    # Note: _startup_cleanup skipped in production — init_database already
    # runs Alembic migrations during get_logger() init, and running cleanup
    # concurrently can cause SQLite locking issues in containerized environments.
    yield


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    from sentinelai import __version__

    app = FastAPI(
        title="ShieldPilot",
        description="Security platform for autonomous AI coding agents",
        version=__version__,
        docs_url="/api/docs",
        redoc_url=None,
        lifespan=_lifespan,
    )

    # Security headers (must be added before CORS so it wraps all responses)
    app.add_middleware(SecurityHeadersMiddleware)

    # CSRF Protection Note:
    # This application uses JWT Bearer tokens stored in localStorage and sent
    # via the Authorization header. Since browsers do NOT automatically attach
    # localStorage values to cross-origin requests (unlike cookies), the app is
    # inherently protected against CSRF attacks. No additional CSRF tokens or
    # Double-Submit Cookie patterns are needed.
    # The only cookie-like auth is the Stripe webhook endpoint, which verifies
    # requests via Stripe's own signature header (not browser cookies).

    # CORS — restrict to specific origins for security
    # In production, set SHIELDPILOT_CORS_ORIGINS env var to comma-separated list
    from sentinelai.api.deps import get_config as _get_cfg
    _cfg = _get_cfg()
    _default_cors = "http://localhost:8420,http://127.0.0.1:8420" if _cfg.auth.local_first else ""
    cors_origins = [o for o in os.environ.get("SHIELDPILOT_CORS_ORIGINS", _default_cors).split(",") if o]
    if not cors_origins:
        logging.getLogger(__name__).info("No CORS origins configured — cross-origin requests will be rejected")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key"],
    )

    # Include API routes
    from sentinelai.api.routes import router
    app.include_router(router)

    # Determine paths for static files
    package_dir = Path(__file__).parent.parent
    web_dir = package_dir / "web"
    static_dir = web_dir / "static"
    templates_dir = web_dir / "templates"

    # Mount static files if directory exists
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Public marketing landing page
    @app.get("/", response_class=HTMLResponse)
    async def home():
        home_path = templates_dir / "home.html"
        if home_path.exists():
            return home_path.read_text()
        # Fallback: redirect to /app
        return HTMLResponse('<meta http-equiv="refresh" content="0;url=/app">')

    # Login / signup page
    @app.get("/login", response_class=HTMLResponse)
    async def login_page():
        landing_path = templates_dir / "landing.html"
        if landing_path.exists():
            return landing_path.read_text()
        # Fallback to old login.html
        login_path = templates_dir / "login.html"
        if login_path.exists():
            return login_path.read_text()
        return "<html><body><h1>ShieldPilot Login</h1><p>Dashboard files not found.</p></body></html>"

    # Authenticated dashboard SPA
    @app.get("/app", response_class=HTMLResponse)
    async def app_shell():
        index_path = templates_dir / "index.html"
        if index_path.exists():
            return index_path.read_text()
        return "<html><body><h1>ShieldPilot</h1><p>Dashboard files not found. The API is available at /api/docs</p></body></html>"

    # Catch-all for SPA routes (hash-based routing doesn't need this,
    # but useful if someone navigates directly)
    @app.get("/{path:path}")
    async def spa_catchall(path: str):
        # API routes that don't match any endpoint -> proper JSON 404
        if path.startswith("api/"):
            return JSONResponse(
                status_code=404,
                content={"detail": "Not found"},
            )
        # Static files that don't match -> 404
        if path.startswith("static/"):
            return JSONResponse(
                status_code=404,
                content={"detail": "Not found"},
            )
        # Everything else -> SPA shell (hash-based routing handles it)
        index_path = templates_dir / "index.html"
        if index_path.exists():
            return HTMLResponse(index_path.read_text())
        return HTMLResponse("")

    return app


# Module-level instance for uvicorn CLI: `uvicorn sentinelai.api.app:app`
app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8420)
