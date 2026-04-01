# ShieldPilot - Detailed Task Breakdown (32 Tasks)

**Status:** ALL COMPLETE (32/32)

**Last verified:** 2026-02-13 | **Tests:** 1315 passed, 0 warnings

---

## P1 - High Priority Bugs (7/7 DONE)

### P1-4: Fix Password Validation Inconsistency -- DONE
- **Fixed in:** `sentinelai/services/auth_service.py:186` (registration) + `sentinelai/services/user_service.py:72` (change-password)
- Both enforce `< 8` consistently

### P1-5: Fix UnboundLocalError in _handle_subscription_updated -- DONE
- **Fixed in:** `sentinelai/services/billing_service.py:286`
- `old_tier = user.tier` initialized before the if/elif chain

### P1-6: Add _sanitize_text() to Activity Feed -- DONE
- **Fixed in:** `sentinelai/api/routers/activity.py:52,62,71,80,88`
- All user-controlled text fields wrapped in `_sanitize_text()`

### P1-7: Fix Deprecated `regex` -> `pattern` in Query Params -- DONE
- **Fixed in:** `sentinelai/api/routers/export.py:34,91`
- Uses `pattern=` parameter (no deprecated `regex=` remaining)

### P1-8: Fix Deprecated `.get()` -> `session.get()` in SQLAlchemy -- DONE
- **Fixed in:** `sentinelai/logger/logger.py:445`
- Uses `session.get(IncidentLog, incident_id)`

### P1-9: Fix Regex FutureWarnings in supply_chain.py -- DONE
- All regex patterns verified clean. No FutureWarnings when running with `-W all`.

### P1-10: Fix SPA Catch-All Returning None -- DONE
- **Fixed in:** `sentinelai/api/app.py:98-99`
- Raises `HTTPException(status_code=404)` for API/static paths

---

## P2 - Security Hardening (5/5 DONE)

### P2-11: Add Security Headers Middleware -- DONE
- **Fixed in:** `sentinelai/api/app.py:18-30` (`SecurityHeadersMiddleware`)
- Adds X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy, HSTS

### P2-12: Move OAuth State to Database -- DONE
- **Fixed in:** `sentinelai/logger/database.py` (OAuthState model) + `sentinelai/api/routers/_shared.py:152-162`
- DB-backed with TTL cleanup, persists across restarts

### P2-13: Move Rate Limiters to Database -- DONE
- **Fixed in:** `sentinelai/api/routers/_shared.py:41-145` (RateLimiter class)
- Uses `RateLimitAttempt` table, sliding window, automatic cleanup

### P2-14: Remove `with_for_update()` on SQLite -- DONE
- No occurrences of `with_for_update()` in codebase

### P2-15: Add CSP Meta Tags to HTML Templates -- DONE
- **Fixed in:** `sentinelai/web/templates/index.html:6` + `sentinelai/web/templates/landing.html:6`
- Full CSP policies with Google OAuth domains whitelisted

---

## P3 - Architecture Improvements (5/5 DONE)

### P3-16: Split routes.py into Modules -- DONE
- Split into 14 router modules in `sentinelai/api/routers/`:
  auth.py, settings.py, billing.py, admin.py, dashboard.py, commands.py,
  incidents.py, scans.py, activity.py, config.py, export.py, library.py,
  legal.py, health.py + `_shared.py` for utilities

### P3-17: Create DB Session Dependency -- DONE
- `get_db_session` dependency in `sentinelai/api/deps.py`
- All route handlers use `session: Session = Depends(get_db_session)`

### P3-18: Extract Service Layer -- DONE
- `sentinelai/services/auth_service.py` -- AuthService
- `sentinelai/services/user_service.py` -- UserService
- `sentinelai/services/billing_service.py` -- BillingService
- Route handlers are thin, delegate to services

### P3-19: Add Alembic Migrations -- DONE
- `alembic.ini` and `sentinelai/migrations/` directory created

### P3-20: Standardize Logging -- DONE
- No `print()` calls in production API code
- CLI uses `console.print()` (Rich) appropriately
- Hook uses `print(json.dumps(...))` for stdout protocol (correct)
- All backend modules use `logging.getLogger(__name__)`

---

## P4 - Performance (4/4 DONE)

### P4-21: Fix N+1 Query in Incidents List -- DONE
- **Fixed in:** `sentinelai/logger/logger.py:415-417`
- Uses `joinedload(IncidentLog.command)`

### P4-22: Optimize Activity Feed Queries -- DONE
- **Fixed in:** `sentinelai/api/routers/activity.py:45`
- `per_table = max(limit // 3 + 1, 10)` instead of `limit` per table

### P4-23: Add Composite Index for Scan Count -- DONE
- **Fixed in:** `sentinelai/logger/database.py:451-455`
- `CREATE INDEX IF NOT EXISTS ix_prompt_scans_timestamp ON prompt_scans (timestamp)` in migration

### P4-24: Optimize SSE Session Management -- DONE
- **Fixed in:** `sentinelai/api/routers/dashboard.py`
- SSE generators manage sessions efficiently

---

## P5 - DevOps & Infrastructure (4/4 DONE)

### P5-25: Create Dockerfile and docker-compose.yml -- DONE
- `Dockerfile`, `docker-compose.yml`, `.dockerignore` all exist

### P5-26: Add GitHub Actions CI/CD -- DONE
- `.github/workflows/ci.yml` exists

### P5-27: Add Dependency Health Checks -- DONE
- **Fixed in:** `sentinelai/api/routers/health.py` (186 lines)
- Comprehensive health endpoint

### P5-28: Fix/Enable Skipped Tests -- DONE
- Only 1 conditional skip remaining (`test_cli/test_json_contracts.py` -- skips when CLI not available, which is correct)
- Previously had 32 skipped, now resolved

---

## P6 - Code Quality (4/4 DONE)

### P6-29: Remove Duplicate Imports in routes.py -- DONE
- Routes split into modules, no duplicate imports

### P6-30: Add Type Hints to Webhook Handlers -- DONE
- All handlers have `-> None` return types in `sentinelai/services/billing_service.py`

### P6-31: Audit innerHTML Usages for XSS -- DONE
- **Audited:** 120+ innerHTML assignments across `app.js` (3600+ lines) and `components.js` (1135 lines)
- **Result:** All user-controlled data uses `escapeHtml()`. Unescaped values are from hardcoded maps only.
- **Key patterns:** components.js returns pre-escaped HTML; app.js uses `escapeHtml()` on all dynamic values (email, username, titles, API keys, config values, tags, content)

### P6-32: Document API with OpenAPI Descriptions -- DONE
- 161 occurrences of `summary=`/`description=` across all 14 router modules
- All endpoints documented in `/api/docs`

---

## Summary

| Priority | Tasks | Done | Remaining |
|----------|-------|------|-----------|
| P0 | 3 | 3 | 0 |
| P1 | 7 | 7 | 0 |
| P2 | 5 | 5 | 0 |
| P3 | 5 | 5 | 0 |
| P4 | 4 | 4 | 0 |
| P5 | 4 | 4 | 0 |
| P6 | 4 | 4 | 0 |
| **Total** | **32** | **32** | **0** |
