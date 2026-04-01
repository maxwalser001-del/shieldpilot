"""API route handlers for ShieldPilot dashboard.

This module aggregates all domain-specific routers from sentinelai.api.routers
into a single `router` instance that is included by app.py.

The individual endpoint modules live in sentinelai/api/routers/:
  auth.py       - Login, register, password reset, OAuth, verify email, /me
  settings.py   - User settings, password change, username, API key, delete account
  billing.py    - Usage, tier info, pricing, checkout, portal, webhook handlers
  admin.py      - Admin-only endpoints (set tier, reconcile, Stripe health)
  dashboard.py  - Stats, streaming (SSE) endpoints
  commands.py   - Command list, command detail
  incidents.py  - Incident list, resolve incident
  scans.py      - Scan list, scan prompt
  activity.py   - Activity feed
  config.py     - Config summary endpoint
  export.py     - CSV/JSON export endpoints
  library.py    - All library endpoints (items, topics, CRUD)
  legal.py      - Impressum, GDPR data export
  health.py     - Health check, chain integrity
"""

from __future__ import annotations

# Import the aggregated router from the routers package
from sentinelai.api.routers import router  # noqa: F401

# Re-export shared utilities for backward compatibility.
# Tests and other modules access these directly via:
#   from sentinelai.api import routes; routes._circuit_breaker.reset()
#   from sentinelai.api.routes import _sanitize_text
from sentinelai.api.routers._shared import (  # noqa: F401
    RateLimiter,
    TOS_VERSION,
    _circuit_breaker,
    _cleanup_expired_oauth_states,
    _display_sanitizer,
    _login_limiter,
    _password_reset_limiter,
    _rate_limit_logger,
    _registration_limiter,
    _sanitize_text,
    _start_time,
)
