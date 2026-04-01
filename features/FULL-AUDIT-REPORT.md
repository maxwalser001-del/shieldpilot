# ShieldPilot Full Application Audit Report

**Date:** 2026-02-12
**Audited by:** QA Engineer, Backend Dev, Frontend Dev, DevOps Engineer, Solution Architect
**Test Results:** 917 passed, 32 skipped, 0 failures

---

## CRITICAL SECURITY ISSUES

### SEC-1: Hardcoded Credentials in sentinel.yaml (CRITICAL)
**File:** `sentinel.yaml:84-88`
- Google OAuth `client_secret` is committed to the repo in plaintext
- Super-admin password was previously in plaintext in the config file — **FIXED: moved to env vars**
- Stripe keys moved to env vars — **FIXED**
- All secrets now loaded exclusively from environment variables.

### SEC-2: Empty JWT Secret Key (CRITICAL)
**File:** `sentinel.yaml:79` / `sentinelai/core/config.py`
- `secret_key: ''` - an empty JWT secret means tokens are signed with an empty string
- Anyone who knows the algorithm (HS256) can forge valid JWT tokens
- **Fix:** Generate a strong random secret on first run, or require it via env var

### SEC-3: Super-Admin Plaintext Password Comparison (HIGH)
**File:** `sentinelai/api/routes.py:207-209`
- Super-admin login compares plaintext password directly from config: `credentials.password == config.auth.super_admin_password`
- Not using bcrypt like regular users
- **Fix:** Store hashed super-admin password, or at minimum use constant-time comparison

### SEC-4: JWT Token in URL Query Parameter (MEDIUM)
**File:** `sentinelai/api/routes.py:829`
- Google OAuth callback redirects with `?token=<jwt>` in the URL
- JWT tokens in URLs can leak via Referer headers, browser history, server logs
- **Fix:** Use HTTP-only cookies or a short-lived authorization code pattern

### SEC-5: SSE Endpoints Accept Token via Query Param (MEDIUM)
**File:** `sentinelai/api/routes.py:1869, 1935`
- `/api/stats/stream` and `/api/activity/stream` accept JWT via `?token=` query param
- Tokens in URLs appear in server access logs, proxy logs, browser history
- **Fix:** Use cookie-based auth for SSE, or short-lived stream tokens

### SEC-6: No CSRF Protection on State-Changing Endpoints (MEDIUM)
**File:** `sentinelai/api/routes.py` (multiple POST/DELETE endpoints)
- No CSRF tokens for POST/PATCH/DELETE endpoints
- JWT in Authorization header provides some protection, but cookie-based flows (OAuth) are vulnerable
- **Fix:** Add CSRF token validation for cookie-authenticated requests

### SEC-7: Rate Limiter is In-Memory Only (MEDIUM)
**File:** `sentinelai/api/routes.py:80-135`
- Rate limiters reset on server restart
- With multiple workers/processes, each has its own rate limit state
- **Fix:** Use Redis or database-backed rate limiting for production

### SEC-8: OAuth State Stored In-Memory (MEDIUM)
**File:** `sentinelai/api/routes.py:665`
- `_oauth_states: dict = {}` - lost on restart, not shared across workers
- **Fix:** Store OAuth states in database or Redis

---

## BUGS

### BUG-1: Password Validation Inconsistency
**File:** `sentinelai/api/routes.py:343` vs `routes.py:908`
- Registration requires 8+ character password (line 343)
- Change password requires only 6+ characters (line 908)
- **Fix:** Standardize to 8+ characters everywhere

### BUG-2: Deprecated FastAPI `regex` Parameter
**File:** `sentinelai/api/routes.py:2420, 2471`
- Uses `Query("csv", regex="^(csv|json)$")` which is deprecated
- Produces warning: `FastAPIDeprecationWarning: regex has been deprecated, please use pattern instead`
- **Fix:** Change `regex=` to `pattern=`

### BUG-3: Deprecated SQLAlchemy `.get()` Method
**File:** `sentinelai/logger/logger.py:445`
- Uses `session.query(IncidentLog).get(incident_id)` - deprecated in SQLAlchemy 2.0
- **Fix:** Use `session.get(IncidentLog, incident_id)`

### BUG-4: `with_for_update()` on SQLite
**File:** `sentinelai/api/routes.py:543`
- `with_for_update()` (SELECT ... FOR UPDATE) doesn't work with SQLite
- SQLite doesn't support row-level locking
- **Fix:** Remove `with_for_update()` or use SQLite's transaction isolation

### BUG-5: FutureWarning in Regex Patterns
**File:** `sentinelai/engine/analyzers/supply_chain.py:75, 85, 96`
- Regex patterns producing `FutureWarning: Possible set intersection at position`
- Likely unescaped `[` or `{` in character classes
- **Fix:** Escape special characters in regex patterns

### BUG-6: Potential UnboundLocalError in Webhook Handler
**File:** `sentinelai/api/routes.py:1575-1586`
- `old_tier` is only assigned inside `elif sub_status in ("unpaid", ...)` block
- But referenced in the notification block below for `sub_status == "past_due"` as well
- If status is "past_due", `old_tier` is undefined
- **Fix:** Initialize `old_tier = user.tier` before the if/elif chain

### BUG-7: Activity Feed Missing Sanitization
**File:** `sentinelai/api/routes.py:2338, 2348`
- `activity_feed` endpoint doesn't sanitize `cmd.command` or `inc.title` before returning
- The `/api/commands` endpoint properly uses `_sanitize_text()`, but activity feed doesn't
- **Fix:** Apply `_sanitize_text()` to all user-controlled fields in activity feed

### BUG-8: SPA Catch-All Returns None for API Routes
**File:** `sentinelai/api/app.py:79`
- `spa_catchall` returns `None` for API routes, which FastAPI interprets as 200 with null body
- Should raise 404 instead
- **Fix:** Return proper 404 response for unknown API/static paths

---

## PERFORMANCE ISSUES

### PERF-1: N+1 Query in Incidents List
**File:** `sentinelai/api/routes.py:2160-2206`
- Each incident loads its `command` relationship separately for explanation generation
- With 50 incidents, that's 50 additional queries
- **Fix:** Use `joinedload` or `selectinload` to eager-load command relationships

### PERF-2: Activity Feed Queries All Tables Without Limit Coordination
**File:** `sentinelai/api/routes.py:2334-2381`
- Queries `limit` rows from EACH of 5 tables, then sorts in Python
- With limit=100, it fetches 500 rows total, sorts, then discards 400
- **Fix:** Use a UNION query or at least reduce per-table limits

### PERF-3: SSE Polling Creates New DB Session Every 2-3 Seconds
**File:** `sentinelai/api/routes.py:1889-1919, 1961-2023`
- SSE generators create new DB sessions every poll cycle
- Per connected client, that's a new session every 2-3 seconds
- **Fix:** Reuse session across polls, or use database change notifications

### PERF-4: Scan Count Uses COUNT(*) Without Index
**File:** `sentinelai/api/deps.py:265-267`
- `session.query(PromptScanLog).filter(PromptScanLog.timestamp >= today_start).count()`
- This scans the full table every time usage is checked
- **Fix:** Add composite index on (timestamp) or use the UsageRecord counter

### PERF-5: Global Config and Logger Singletons Not Thread-Safe
**File:** `sentinelai/api/deps.py:19-20, 40-55`
- `_config` and `_logger` global singletons with no locking
- Potential race condition during initialization with multiple workers
- **Fix:** Use `threading.Lock` or FastAPI's lifespan events

---

## ARCHITECTURE ISSUES

### ARCH-1: God File - routes.py is 2500+ Lines (HIGH)
**File:** `sentinelai/api/routes.py`
- Single file contains ALL endpoints: auth, billing, webhooks, CRUD, streaming, export
- **Fix:** Split into route modules: `auth_routes.py`, `billing_routes.py`, `admin_routes.py`, etc.

### ARCH-2: Direct Session Access Pattern (MEDIUM)
**Files:** All route handlers
- Every handler calls `logger._get_session()` directly, manages try/finally manually
- Bypasses FastAPI's dependency injection system for DB sessions
- **Fix:** Create a proper `get_db_session` dependency with yield for automatic cleanup

### ARCH-3: No Alembic Migrations (MEDIUM)
**File:** `sentinelai/logger/database.py:287-400`
- Manual `ALTER TABLE` migrations with silent `except Exception: pass`
- No migration tracking, no rollback capability, no version history
- **Fix:** Adopt Alembic for proper migration management

### ARCH-4: SQLite in Production (LOW for now)
**File:** `sentinel.yaml:75-76`
- SQLite doesn't support concurrent writes well
- No row-level locking (see BUG-4)
- Single-file database with no replication
- **Fix:** Plan migration path to PostgreSQL for production

### ARCH-5: Business Logic in Route Handlers (MEDIUM)
**File:** `sentinelai/api/routes.py`
- Stripe reconciliation logic, user creation, email sending all in route handlers
- No service layer separation
- **Fix:** Extract business logic into service classes

---

## DEVOPS ISSUES

### DEVOPS-1: No Dockerfile or docker-compose.yml
- No containerization for deployment
- **Fix:** Create Dockerfile and docker-compose.yml

### DEVOPS-2: No CI/CD Pipeline
- No `.github/workflows/` directory
- Tests run manually only
- **Fix:** Add GitHub Actions for: lint, test, build, deploy

### DEVOPS-3: No Security Headers Middleware
**File:** `sentinelai/api/app.py`
- No CSP (Content-Security-Policy), HSTS, X-Frame-Options, X-Content-Type-Options
- **Fix:** Add security headers middleware

### DEVOPS-4: Logging Uses print() Instead of Structured Logging
**File:** `sentinelai/api/routes.py:435`
- `print(f"[Registration] Failed to send verification email...")`
- Mix of `print()`, `logging.getLogger()`, and no logging at all
- **Fix:** Standardize on Python's `logging` module with structured output

### DEVOPS-5: No Health Check for Dependencies
**File:** `sentinelai/api/routes.py:1174-1200`
- Health endpoint only checks chain integrity, not DB connectivity, disk space, etc.
- **Fix:** Add dependency health checks (DB, Stripe, SMTP)

---

## FRONTEND ISSUES

### FE-1: Multiple innerHTML Usages Need Audit
**File:** `sentinelai/web/static/js/app.js` + `components.js`
- While `escapeHtml` is imported, need to verify ALL dynamic content is escaped before innerHTML
- **Fix:** Audit every innerHTML usage for proper escaping

### FE-2: No CSP Meta Tag in HTML Templates
**Files:** `sentinelai/web/templates/index.html`, `landing.html`
- No Content-Security-Policy to prevent inline script execution
- **Fix:** Add CSP meta tags or headers

### FE-3: EventSource Cleanup on Navigation
**File:** `sentinelai/web/static/js/app.js:199-200`
- `activeIntervals` array suggests cleanup mechanism exists
- Need to verify SSE EventSource connections are properly closed
- **Fix:** Ensure all EventSource instances are tracked and closed on route change

---

## CODE QUALITY

### QUAL-1: 32 Skipped Tests
- 32 tests are skipped in the test suite
- Need to investigate why and either fix or remove them
- **Fix:** Review and enable or delete skipped tests

### QUAL-2: Duplicate Import Statements
**File:** `sentinelai/api/routes.py`
- `import hashlib` at top (line 9) and again inside functions (line 322, 460, 516, 576)
- `from datetime import datetime, timedelta` at top and again in functions
- **Fix:** Remove duplicate inline imports

### QUAL-3: Missing Type Hints in Several Functions
**File:** `sentinelai/api/routes.py` - webhook handler functions
- `_handle_checkout_completed`, `_handle_subscription_updated`, etc. lack return types
- **Fix:** Add type annotations

---

## PRIORITIZED TASK BREAKDOWN

### P0 - Critical Security (Do Immediately)
1. **Move secrets out of sentinel.yaml** - Use env vars for: JWT secret, Google OAuth secret, super-admin password, Stripe keys
2. **Generate strong JWT secret** - Auto-generate on first run if not set via env var
3. **Hash super-admin password** - Use bcrypt comparison like regular users

### P1 - High Priority Bugs & Security
4. **Fix password validation inconsistency** - Standardize to 8+ chars
5. **Fix UnboundLocalError in webhook handler** - Initialize `old_tier`
6. **Add output sanitization to activity feed** - Apply `_sanitize_text()`
7. **Fix deprecated regex → pattern** in Query parameters
8. **Fix deprecated .get() → session.get()** in SQLAlchemy
9. **Fix regex FutureWarnings** in supply_chain.py
10. **Fix SPA catch-all returning None** - Return 404 for unknown paths

### P2 - Security Hardening
11. **Add security headers middleware** - CSP, HSTS, X-Frame-Options
12. **Move OAuth state to database** - Survive restarts, work across workers
13. **Move rate limiters to database** - Survive restarts, work across workers
14. **Remove `with_for_update()` on SQLite** - Not supported
15. **Add CSP meta tags** to HTML templates

### P3 - Architecture Improvements
16. **Split routes.py** into modules (auth, billing, admin, data, streaming)
17. **Create DB session dependency** - Replace manual `_get_session()`/`close()` pattern
18. **Extract business logic** into service layer
19. **Add Alembic migrations** - Replace manual ALTER TABLE approach
20. **Standardize logging** - Replace print() with structured logging

### P4 - Performance
21. **Fix N+1 query in incidents** - Use joinedload
22. **Optimize activity feed** - Use UNION or coordinated limits
23. **Add index for scan count** - Composite index on timestamp
24. **Optimize SSE session management** - Reuse sessions

### P5 - DevOps & Infrastructure
25. **Create Dockerfile** and docker-compose.yml
26. **Add GitHub Actions CI/CD** - lint, test, build pipeline
27. **Add dependency health checks** to /api/health
28. **Fix/enable 32 skipped tests**

### P6 - Code Quality (Nice to Have)
29. **Remove duplicate imports** in routes.py
30. **Add type hints** to webhook handlers
31. **Audit all innerHTML usages** for XSS safety
32. **Document API with OpenAPI descriptions** on each endpoint
