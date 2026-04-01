# Phase 9 QA Report: Dashboard Paywall Overlay + Real-Time Scans Bar

**Tested:** 2026-02-10
**Tester:** QA Engineer (Code Review + Live Server Testing)
**App URL:** http://localhost:8420
**Server:** FastAPI / SQLite / Vanilla JS SPA
**Billing:** `enabled: false` in sentinel.yaml

---

## 1. Code Review Results

### A. app.js -- Dashboard Paywall Functions

| # | Check | File / Line | Expected | Actual | Status |
|---|---|---|---|---|---|
| CR-1 | `DashboardPaywall(usage)` function exists | app.js:2532 | Function defined | Function defined, returns empty string when `!usage \|\| !usage.limit_reached \|\| usage.is_admin` | PASS |
| CR-2 | `applyDashboardPaywall(usage, wrapper)` function exists | app.js:2560 | Function defined | Function adds/removes paywall dynamically, handles both blocked and unblocked states | PASS |
| CR-3 | `#usage-meter-container` is OUTSIDE `#dashboard-content-wrapper` | app.js:362-363 | Meter above wrapper | `<div id="usage-meter-container">` at line 362, wrapper starts at line 363 | PASS |
| CR-4 | `updateDashboardStats(freshStats, sseUsage)` accepts sseUsage param | app.js:410 | Second parameter | Function signature includes `sseUsage` parameter | PASS |
| CR-5 | SSE `onmessage` extracts `data.usage` and passes to `updateDashboardStats` | app.js:464-467 | Extracts and passes | `const sseUsage = data.usage \|\| null; delete data.usage; updateDashboardStats(data, sseUsage);` | PASS |
| CR-6 | Usage meter update targets `#usage-meter-container` | app.js:435-438 | Uses container ID | `document.getElementById('usage-meter-container')` with `.innerHTML = UsageMeter(freshUsage)` | PASS |
| CR-7 | `applyDashboardPaywall()` called in `updateDashboardStats` | app.js:449 | Called after usage update | Called inside `.then(freshUsage => {...})` promise chain | PASS |
| CR-8 | Global polling interval is 10000ms | app.js:494, 2783 | 10 seconds | `setInterval(..., 10000)` at both locations | PASS |
| CR-9 | No dismiss button on paywall overlay | app.js:2542-2557 | No close/dismiss element | Only "Upgrade Now" link present, no dismiss/close button | PASS |
| CR-10 | Super-admin bypass works | app.js:2533 | Returns '' for admin | `if (!usage \|\| !usage.limit_reached \|\| usage.is_admin) return '';` | PASS |

### B. routes.py -- SSE event_generator() with Usage Data

| # | Check | File / Line | Expected | Actual | Status |
|---|---|---|---|---|---|
| CR-11 | `get_daily_usage_for_user()` called in event_generator | routes.py:1907 | Called inside loop | `usage_info = get_daily_usage_for_user(user, logger, config)` | PASS |
| CR-12 | Usage data added as `stats_dict["usage"]` | routes.py:1908 | Added to dict | `stats_dict["usage"] = usage_info.model_dump()` | PASS |
| CR-13 | `json.dumps` uses `default=str` | routes.py:1912, 1916 | default=str present | Both hash and yield lines use `default=str` | PASS |
| CR-14 | Wrapped in try/except | routes.py:1906-1910 | Exception handled | `try: ... except Exception: stats_dict["usage"] = None` | PASS |
| CR-15 | Hash includes usage data for change detection | routes.py:1912 | Usage affects hash | `current_hash = hash(json.dumps(stats_dict, ...))` computed AFTER usage is added | PASS |

### C. sentinel.css -- Paywall Overlay Styles

| # | Check | File / Line | Expected | Actual | Status |
|---|---|---|---|---|---|
| CR-16 | `.dashboard-content-wrapper` has `position: relative` | sentinel.css:2587-2589 | position: relative | `position: relative;` | PASS |
| CR-17 | `.paywall-active .stat-grid, .paywall-active .dashboard-grid` has blur/opacity/pointer-events | sentinel.css:2591-2598 | All three properties | `filter: blur(4px); pointer-events: none; user-select: none; opacity: 0.3;` + transitions | PASS |
| CR-18 | `.dashboard-paywall-overlay` has `position: absolute; inset: 0; z-index: 50` | sentinel.css:2600-2610 | All three | `position: absolute; inset: 0; z-index: 50;` + flex centering + background overlay | PASS |
| CR-19 | `.dashboard-paywall-content` has card styling | sentinel.css:2612-2620 | Background, border, shadow | `background: var(--bg-secondary); border: 1px solid var(--border-default); border-radius: var(--radius-lg); box-shadow: 0 8px 32px rgba(0,0,0,0.4);` | PASS |
| CR-20 | `.dashboard-paywall-upgrade` has gradient background | sentinel.css:2647-2652 | Gradient | `background: linear-gradient(135deg, #39D2C0, #58A6FF) !important;` | PASS |

**Code Review Summary:** 20/20 checks PASS. All implementations match the Phase 9 specification.

---

## 2. Live Server Integration Tests

| # | Test | Expected | Actual | Status |
|---|---|---|---|---|
| LT-1 | Login as super-admin | 200 + access_token | 200 + JWT token with `is_super_admin: true`, `tier: "unlimited"`, `role: "admin"` | PASS |
| LT-2 | `/api/usage` returns correct structure | All required fields present | `tier`, `commands_used`, `commands_limit`, `scans_used`, `scans_limit`, `commands_remaining`, `scans_remaining`, `limit_reached`, `is_admin` all present | PASS |
| LT-3 | `/api/usage` returns `is_admin: true` for super-admin | is_admin: true | `"is_admin": true` | PASS |
| LT-4 | `/api/usage` returns `limit_reached: false` (billing disabled) | limit_reached: false | `"limit_reached": false` | PASS |
| LT-5 | `/api/usage` returns unlimited tier for super-admin | tier: unlimited, limits: -1 | `"tier": "unlimited", "commands_limit": -1, "scans_limit": -1` | PASS |
| LT-6 | SSE stream `/api/stats/stream` responds | SSE data with stats + usage key | SSE data received with stats BUT **no `"usage"` key** | **FAIL** |

### LT-6 Failure Details

**SSE Response Received:**
```json
{"total_commands": 136, "blocked_commands": 2, "warned_commands": 2, "allowed_commands": 132, "average_risk_score": 13.9, "total_incidents": 24, "unresolved_incidents": 24, "total_scans": 57, "top_risk_categories": [], "timeline": [], "all_time_total": 877, "all_time_blocked": 15, "all_time_warned": 22, "all_time_allowed": 840, "all_time_incidents": 48, "all_time_scans": 252, "all_time_blocked_available": true}
```

**Missing:** The `"usage"` key with usage data is absent from the SSE payload.

**Root Cause:** The running server has not been restarted since the Phase 9 changes were made. `git diff --stat` shows 531 uncommitted lines in `routes.py`. The running Python process is using the previously committed version of `routes.py` which lacks the usage-in-SSE logic. Static files (JS, CSS) are served from disk and reflect the latest changes, but Python code requires a server restart.

**Resolution:** Restart the server process to load the updated `routes.py`.

---

## 3. Security Analysis

### 3.1 Paywall Bypass Resistance

| # | Vector | Assessment | Status |
|---|---|---|---|
| SEC-1 | Client-side JS manipulation (DevTools remove paywall) | Paywall re-applies on every SSE update (every 3s) and polling fallback (every 10s) via `applyDashboardPaywall()` at app.js:449. Even if manually removed, it reappears within seconds. | PASS |
| SEC-2 | Client-side: modify `usage.limit_reached` in memory | The `usageCache` is overwritten from server response on every SSE event (app.js:433) and every poll. Local tampering is overwritten within seconds. | PASS |
| SEC-3 | Server-side enforcement exists (not purely client-side) | Backend hook (`sentinel_hook.py:358-362`) independently checks `_check_usage_limit()` and blocks commands when limits are reached. Paywall is defense-in-depth on top of server enforcement. | PASS |
| SEC-4 | API endpoints still enforce limits regardless of UI | `/api/usage` is read-only (GET). Billing enforcement happens at the hook level and in `_get_daily_usage_internal()`. No user-modifiable parameters affect limit calculation. | PASS |
| SEC-5 | Super-admin bypass is server-authoritative | `is_super_admin()` check uses JWT claims verified by server-side `decode_token()`. Cannot be faked without the JWT secret. | PASS |

### 3.2 SSE Data Leakage

| # | Check | Assessment | Status |
|---|---|---|---|
| SEC-6 | Usage data fields are safe | `UsageInfo` model (deps.py:25-37) only exposes: tier, counts, limits, booleans, upgrade_url. No passwords, tokens, emails, or PII. | PASS |
| SEC-7 | All-time blocked data redacted for non-admins | routes.py:1899-1901 sets `all_time_blocked: None` for non-admin users. | PASS |
| SEC-8 | SSE token in query parameter | JWT is passed as `?token=` query parameter because EventSource does not support custom headers. This is a known pattern. **Medium risk:** Token may appear in server access logs, browser history, and proxy logs. | ADVISORY |
| SEC-9 | SSE authentication is properly enforced | Token is validated via `decode_token()` before streaming begins (routes.py:1881-1885). Missing/invalid token returns 401. | PASS |

### 3.3 Additional Security Observations

| # | Finding | Severity | Notes |
|---|---|---|---|
| SEC-10 | No CSRF protection on SSE endpoint | Low | GET-only endpoint, read-only data, requires valid JWT. CSRF risk is minimal. |
| SEC-11 | SSE connection does not re-validate token after initial auth | Low | If a JWT expires during a long SSE session, the stream continues until client disconnect. The 3-second loop checks `request.is_disconnected()` but not token expiry. |
| SEC-12 | Paywall overlay uses `pointer-events: none` + blur | Info | This is a UX deterrent, not a security boundary. Actual enforcement is server-side (hook). Correct architecture. |

---

## 4. Bugs Found

### BUG-1: SSE Stream Missing Usage Data (Server Restart Required)

- **Severity:** High
- **Component:** Backend (routes.py / server process)
- **Steps to Reproduce:**
  1. Connect to SSE endpoint: `GET /api/stats/stream?hours=24&token=<JWT>`
  2. Observe the JSON payload in the `data:` field
  3. Expected: JSON contains `"usage": {...}` with tier, limits, counts
  4. Actual: No `"usage"` key in the JSON payload
- **Root Cause:** Server process has not been restarted after Phase 9 code changes were applied to `routes.py`. The Python process is running the old committed version (531 lines of diff in working tree).
- **Impact:** Frontend SSE handler extracts `data.usage` as `null`, falls back to `fetchUsage()` on every update cycle. This means:
  - Usage meter still works (via fallback fetch)
  - Paywall still works (via fallback fetch)
  - But there is an unnecessary extra HTTP request per SSE cycle (every 3 seconds triggers a `/api/usage` fetch)
  - The "real-time" benefit of SSE-embedded usage is lost
- **Fix:** Restart the server: `python3 -m sentinelai.api.app` or equivalent
- **Priority:** High (defeats the purpose of the Phase 9 SSE optimization)

### BUG-2: Stale Comment -- "15 seconds" but Interval is 10 seconds

- **Severity:** Low
- **Component:** Frontend (app.js)
- **Location:** app.js line 2782
- **Details:** Comment reads `// Refresh usage every 15 seconds` but the actual interval is `setInterval(fetchUsage, 10000)` (10 seconds).
- **Impact:** No functional impact; documentation inconsistency only.
- **Fix:** Update comment to `// Refresh usage every 10 seconds`
- **Priority:** Low

### BUG-3: SSE Token Expiry Not Re-Validated During Long Sessions

- **Severity:** Low
- **Component:** Backend (routes.py)
- **Location:** routes.py:1887-1919 (event_generator loop)
- **Details:** The JWT token is validated once at connection time (line 1883). The event_generator loop runs indefinitely (checking every 3 seconds) but never re-validates the token. If the JWT expires (default 24h), the SSE stream continues until the client disconnects.
- **Impact:** A user whose session should have expired continues receiving real-time stats. Low risk because:
  - JWT expiry is 24 hours (same as typical session length)
  - Data is read-only stats, not sensitive operations
  - EventSource reconnects reset the auth check
- **Priority:** Low (defense-in-depth improvement for future)

---

## 5. Edge Cases Tested (Code Review)

| # | Edge Case | Handling | Status |
|---|---|---|---|
| EC-1 | Usage data is null/undefined | `DashboardPaywall()` returns '' for falsy usage. `applyDashboardPaywall()` treats null usage as not-blocked. | PASS |
| EC-2 | Both commands AND scans at limit | `whichLimit` logic (app.js:2539) correctly shows "commands and scans" when both >= 100% | PASS |
| EC-3 | Only commands at limit | Shows "commands" in paywall message | PASS |
| EC-4 | Only scans at limit | Shows "scans" in paywall message | PASS |
| EC-5 | Paywall applied then removed (e.g., midnight reset) | `applyDashboardPaywall()` handles removal: `else if (!isBlocked && existingPaywall)` removes overlay and class | PASS |
| EC-6 | Duplicate paywall prevention | Checks `document.getElementById('dashboard-paywall')` before inserting; only adds if not already present | PASS |
| EC-7 | SSE disconnects, falls back to polling | `eventSource.onerror` closes SSE and calls `startPolling()` if SSE never connected | PASS |
| EC-8 | SSE parse error | Wrapped in try/catch (app.js:463-470), logs error, does not crash | PASS |
| EC-9 | Usage fetch failure in SSE event_generator | Wrapped in try/except (routes.py:1906-1910), sets `stats_dict["usage"] = None`, SSE continues | PASS |
| EC-10 | Billing disabled | `_get_daily_usage_internal()` returns `limit_reached: False` when `config.billing.enabled` is false | PASS |

---

## 6. Regression Risk Assessment

| Area | Risk | Assessment |
|---|---|---|
| Dashboard rendering | Low | `renderDashboard()` structure preserved; new elements (`usage-meter-container`, `dashboard-content-wrapper`) added around existing content |
| SSE stream | Medium | Adding `usage` to `stats_dict` changes the hash, which could cause more frequent SSE pushes (usage counts change more often than stats). Mitigated by the 3-second sleep interval. |
| Polling fallback | Low | `startPolling()` unchanged in structure; interval updated from 15s to 10s which is a minor increase in server load |
| Other pages | None | Paywall code only activates on `#/dashboard` page; no impact on other routes |
| Global usage fetch | Low | `setInterval(fetchUsage, 10000)` at app.js:2783 runs on ALL pages (not just dashboard). When SSE is active on dashboard, this creates redundant fetches. Consider guarding with a flag. |

---

## 7. Summary

| Category | Count |
|---|---|
| Code Review Checks | 20/20 PASS |
| Live Server Tests | 5/6 PASS, 1 FAIL |
| Security Checks | 9 PASS, 3 Advisory/Low |
| Edge Cases | 10/10 PASS |
| Bugs Found | 3 (1 High, 2 Low) |

---

## 8. Recommendations

### Immediate (before deployment)

1. **Restart the server** to activate the SSE usage data feature (BUG-1). Without this, the entire "Real-Time Scans Bar via SSE" feature is non-functional on the live server.

### Short-term

2. **Fix the stale comment** at app.js:2782 ("15 seconds" -> "10 seconds") (BUG-2).
3. **Guard global usage polling** when SSE is active on the dashboard to avoid redundant `/api/usage` fetches. A simple boolean flag (`sseActive`) could skip the global `fetchUsage` interval when the dashboard SSE handler is providing usage data.

### Long-term

4. **Re-validate JWT in SSE loop** periodically (BUG-3). Add a token expiry check every N iterations of the event_generator loop.
5. **Consider token rotation for SSE** -- since the JWT is in a query parameter, it may appear in server logs. Evaluate using a short-lived SSE-specific token.

---

## 9. Production-Ready Decision

**NOT READY** -- BUG-1 (SSE stream missing usage data) is High severity because it defeats the core purpose of Phase 9's real-time usage streaming. The fix is trivial (server restart), but must be verified after restart.

After server restart and BUG-1 verification: **READY** for deployment. No critical security issues. The paywall architecture is sound (server-side enforcement + client-side UX overlay). Low-severity items can be addressed in a follow-up.
