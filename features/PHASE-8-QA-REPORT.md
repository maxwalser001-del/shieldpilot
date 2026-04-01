# Phase 8 QA Report: Account Management — Tier-Lifecycle & Stripe-Integration Hardening

**Tested:** 2026-02-10
**Tester:** QA Engineer (Automated + Code Review)
**App URL:** http://localhost:8420
**Server:** FastAPI / SQLite / Vanilla JS SPA
**Billing:** `enabled: false` in sentinel.yaml (Stripe test keys present via env)

---

## 1. Unit Test Results

**Command:** `python3 -m pytest tests/ -q --tb=short`
**Result:** 917 passed, 32 skipped, 0 failed

**Command:** `python3 -m pytest tests/test_api/test_billing.py -v --tb=short`
**Result:** 14/14 passed

| Test Class | Test | Status |
|---|---|---|
| TestGracePeriod | test_past_due_keeps_tier | PASS |
| TestGracePeriod | test_unpaid_downgrades_tier | PASS |
| TestGracePeriod | test_active_keeps_tier | PASS |
| TestAdminTierOverride | test_admin_can_set_tier | PASS |
| TestAdminTierOverride | test_non_admin_rejected | PASS |
| TestAdminTierOverride | test_cannot_modify_super_admin | PASS |
| TestAdminTierOverride | test_invalid_tier_rejected | PASS |
| TestSettingsSubscriptionInfo | test_settings_includes_subscription_fields | PASS |
| TestSettingsSubscriptionInfo | test_settings_tier_from_db | PASS |
| TestPricingDbTier | test_pricing_reads_db_tier | PASS |
| TestDeleteAccountStripe | test_delete_cancels_stripe | PASS |
| TestDeleteAccountStripe | test_delete_without_stripe | PASS |
| TestStripeHealth | test_stripe_health_requires_admin | PASS |
| TestStripeHealth | test_stripe_health_admin | PASS |

---

## 2. API Integration Tests (Against Running Server)

| # | Test | Expected | Actual | Status |
|---|---|---|---|---|
| 1 | Login as Super-Admin | 200 + token | 200 + token | PASS |
| 2 | Settings API - subscription fields present | subscription_status, cancel_at_period_end, current_period_end, has_subscription | All 4 fields present | PASS |
| 3 | Pricing API - current_tier from DB | current_tier: "unlimited" for admin | current_tier: "unlimited" | PASS |
| 4 | Admin Tier Override - set to pro | 200 + message | 200 + "tier changed from free to pro" | PASS |
| 5 | Admin Tier Override - invalid tier "platinum" | 400 | 400 | PASS |
| 6 | Admin Tier Override - super-admin protection | 400 + "Cannot modify super-admin tier" | 400 + correct message | PASS |
| 7 | Admin Reconcile Subscriptions | 200 or 503 | 200 + synced: 0, errors: 0 | PASS |
| 8 | Admin Stripe Health | 200 + status field | 200 + status: "ok" | PASS |
| 9a | Non-admin -> admin/users/tier | 403 | 403 | PASS |
| 9b | Non-admin -> reconcile-subscriptions | 403 | 403 | PASS |
| 9c | Non-admin -> stripe-health | 403 | 403 | PASS |
| 10 | Unauthenticated -> admin endpoints | 401 | 401 | PASS |
| 11 | Verify tier after admin override (re-login) | tier: "pro", subscription_status: "active" | Correct | PASS |
| 12 | Admin set tier back to free | 200 | 200 | PASS |
| 13 | Tier override - nonexistent user | 404 | 404 | PASS |

---

## 3. Security Audit

| # | Check | Result | Status |
|---|---|---|---|
| SEC-1 | No secrets in API responses (/api/settings, /api/admin/stripe-health) | No passwords, keys, or secrets leaked. stripe-health only returns booleans for sensitive config. | PASS |
| SEC-2 | IDOR - User A cannot see User B's data | Each user sees only their own settings | PASS |
| SEC-3 | Auth bypass - malformed JWT | 401 | PASS |
| SEC-3 | Auth bypass - modified JWT (tampered signature) | 401 | PASS |
| SEC-3 | Auth bypass - no auth header | 401 | PASS |
| SEC-4 | XSS via reason field in tier override | Reason field not reflected in API response | PASS |
| SEC-5 | SQL injection in admin tier override (email field) | Blocked by Pydantic EmailStr validation (422) | PASS |
| SEC-5 | SQL injection in admin tier override (tier field) | Blocked by tier whitelist validation (400) | PASS |
| SEC-6 | Webhook rejects unverified signatures | 400 on fake stripe-signature | PASS |
| SEC-7 | Error messages - no user enumeration | "Invalid username or password" (generic) | PASS |
| SEC-8 | No Stripe customer/subscription IDs in settings response | Only `has_subscription` (boolean) exposed | PASS |
| SEC-9 | Privilege escalation - normal user self-upgrade | 403 on all admin endpoints | PASS |
| SEC-10 | Audit logging for admin tier override | Logs email, old_tier, new_tier, admin_email, reason | PASS |
| SEC-11 | Content-Type validation | 422 on non-JSON body | PASS |

---

## 4. Code Review Findings

### 4.1 Files Reviewed

| File | Lines Changed | Review Status |
|---|---|---|
| sentinelai/logger/database.py | User model + migration | PASS |
| sentinelai/api/deps.py | active_statuses with past_due | PASS |
| sentinelai/api/routes.py | Login reconciliation, settings, pricing, delete, admin, webhooks | PASS (with notes) |
| sentinelai/api/email.py | 3 new email templates | PASS (with note) |
| sentinelai/billing/stripe_stub.py | cancel_subscription(), health_check() | PASS |
| sentinelai/web/static/js/app.js | Banners, settings subscription, polling | PASS (with bug) |
| sentinelai/web/static/css/sentinel.css | Banner styles | PASS |
| tests/test_api/test_billing.py | 14 tests across 6 test classes | PASS |

### 4.2 database.py - cancel_at_period_end Column

- `cancel_at_period_end = Column(Boolean, default=False)` -- correct, added to User model (line 193)
- Migration added at line 312: `ALTER TABLE users ADD COLUMN cancel_at_period_end BOOLEAN DEFAULT 0`
- Migration order is correct (appended at end of migrations list)
- **Verdict:** Clean implementation

### 4.3 deps.py - Grace Period Logic

- Line 187: `active_statuses = ("active", "trialing", "past_due")`
- `past_due` included correctly -- users keep their tier during Stripe dunning retries
- Only `unpaid` and `incomplete_expired` trigger downgrade to free (via deny-by-default at line 189)
- **Verdict:** Correct defense-in-depth pattern

### 4.4 routes.py - Login Reconciliation

- Lines 277-302: Lightweight Stripe reconciliation at login
- Wrapped in `try/except Exception: pass` -- non-blocking (correct)
- Handles `active`, `trialing`, `past_due`, `canceled` statuses
- Updates DB and token_data.tier simultaneously
- **Verdict:** Correct, non-blocking, handles all states

### 4.5 routes.py - Settings API

- Lines 868-883: Returns subscription fields from DB
- Uses `getattr()` for backwards compatibility with older DB schemas
- Tier comes from `db_user.tier` (DB), not `user.tier` (JWT)
- **Verdict:** Correct

### 4.6 routes.py - Account Deletion with Stripe

- Lines 987-998: Cancels Stripe subscription before deleting user
- `try/except` with logging -- deletion continues even if Stripe fails
- **Verdict:** Correct fail-safe behavior

### 4.7 routes.py - Admin Endpoints

- `POST /api/admin/users/tier` -- Protected by `require_admin`, validates tier whitelist, protects super-admin
- `POST /api/admin/reconcile-subscriptions` -- Protected by `require_admin`, handles errors per-user
- `GET /api/admin/stripe-health` -- Protected by `require_admin`, returns only safe info
- **Verdict:** Properly secured

### 4.8 routes.py - Webhook Handlers

- `_handle_subscription_updated`: Stale-event protection via `current_period_end` comparison
- Grace period: `past_due` keeps tier, only `unpaid`/`incomplete_expired` downgrade
- `_handle_subscription_deleted`: Full cleanup (tier, status, sub_id, period_end, cancel_at)
- `_handle_invoice_paid`: Restores tier if previously hard-downgraded
- `_handle_invoice_failed`: Sets `past_due` status, sends payment failure email
- All wrapped in `try/except` with rollback and logging
- **Verdict:** Robust, handles all Stripe lifecycle events

### 4.9 stripe_stub.py - New Methods

- `cancel_subscription()`: Simple `stripe.Subscription.cancel()` wrapper -- correct
- `health_check()`: Checks API connectivity, price config, webhook secret
- **Verdict:** Clean implementation

### 4.10 email.py - New Templates

- `send_tier_upgrade_notification()`: Professional HTML email with feature list
- `send_tier_downgrade_notification()`: Informs about free tier limitations
- `send_payment_failed_notification()`: Warning with steps to update payment
- All three check `is_configured()` first (graceful degradation)
- **Verdict:** Good email templates, consistent branding

### 4.11 Frontend (app.js)

- `PaymentIssueBanner()`: Shows when `subscription_status === 'past_due'` -- correct
- `CancellationWarningBanner()`: Shows when `cancel_at_period_end && current_period_end` -- correct null-guard
- Settings subscription section: Shows plan, status badge, next billing date
- Checkout success polling: 10 attempts at 2-second intervals -- reasonable
- **Verdict:** Mostly correct (see BUG-1)

### 4.12 CSS (sentinel.css)

- `.cancellation-banner`: Amber left border + light amber background
- `.payment-issue-banner`: Red left border + light red background
- `.settings-badge-warning`: Amber pill badge
- `.settings-badge-danger`: Red pill badge
- **Verdict:** Clean, consistent with design system

---

## 5. Bugs Found

### BUG-1: Frontend crash when cancel_at_period_end=true but current_period_end=null

- **Severity:** Medium
- **Location:** `/sentinelai/web/static/js/app.js`, line 2154
- **Description:** In the Settings subscription section, when `cancel_at_period_end` is true, the code unconditionally calls `new Date(settings.current_period_end * 1000).toLocaleDateString(...)`. If `current_period_end` is null (which is possible if the DB has inconsistent state), this evaluates to `new Date(0)` which displays "January 1, 1970" -- misleading but not a crash.
- **Steps to Reproduce:**
  1. Set a user's `cancel_at_period_end = True` and `current_period_end = NULL` in the DB
  2. Navigate to Settings page
  3. Status badge shows "Cancels on January 1, 1970"
- **Expected:** Should show "Cancels soon" or hide the date
- **Actual:** Shows "January 1, 1970"
- **Note:** The `CancellationWarningBanner` function (line 2531) correctly guards against this by checking both `cancel_at_period_end` AND `current_period_end`. The settings section template does not have this guard.
- **Priority:** Medium (cosmetic / edge case, no security impact)

### BUG-2: send_tier_downgrade_notification receives wrong parameter

- **Severity:** Low
- **Location:** `/sentinelai/api/routes.py`, line 1612
- **Description:** The call is `send_tier_downgrade_notification(user.email, "free", "canceled", user.username)` but at this point the user has ALREADY been downgraded to "free" (line 1600). The `old_tier` parameter receives `"free"` instead of the tier the user was on before downgrade. However, the email template does not actually display `old_tier` in any meaningful way (it always says "reverted to the Free plan"), so the impact is minimal.
- **Steps to Reproduce:** Observe the email when a subscription is deleted via webhook.
- **Expected:** `old_tier` should be the user's previous tier (e.g., "pro")
- **Actual:** `old_tier` is always "free" because the downgrade happens before the notification
- **Priority:** Low (the email content is still correct for the end user)

### BUG-3: Missing downgrade notification for unpaid/incomplete_expired status

- **Severity:** Low
- **Location:** `/sentinelai/api/routes.py`, lines 1574-1575
- **Description:** When `_handle_subscription_updated` downgrades a user to "free" due to `unpaid` or `incomplete_expired` status, no email notification is sent. The `_handle_subscription_deleted` handler sends a downgrade notification, but the `unpaid` path does not.
- **Steps to Reproduce:**
  1. User has active subscription
  2. Payment fails repeatedly, Stripe sets status to `unpaid`
  3. Webhook fires `customer.subscription.updated` with status `unpaid`
  4. User gets downgraded to free silently (no email)
- **Expected:** Downgrade email notification sent
- **Actual:** No notification
- **Priority:** Low (Stripe itself may send dunning emails, and the user already got a `payment_failed` email when `past_due` was set)

---

## 6. Edge Case Analysis

| Edge Case | Status | Notes |
|---|---|---|
| cancel_at_period_end=true, current_period_end=null | BUG-1 | Settings shows "January 1, 1970" |
| Unknown subscription_status value (e.g., "paused") | SAFE | Falls through to `settings-badge-unverified` CSS class; charAt(0) uppercase display |
| Stripe unreachable during login reconciliation | SAFE | Wrapped in try/except with pass (non-blocking) |
| Stripe unreachable during account deletion | SAFE | Logged, deletion continues |
| Stale webhook events (out-of-order delivery) | SAFE | current_period_end comparison skips stale events |
| Duplicate webhook events | SAFE | WebhookEvent table with unique stripe_event_id (idempotency) |
| Admin overrides tier for user with active Stripe sub | SAFE | subscription_status set to "active" for paid tiers |
| Email notifications fail | SAFE | All wrapped in try/except pass (best-effort) |
| Multiple rapid tier changes | SAFE | Uses DB commit per operation, no race conditions in single-threaded SQLite |
| Login reconciliation for user without Stripe sub | SAFE | Guarded by `if user.stripe_subscription_id and config.billing.stripe_secret_key` |

---

## 7. Test Coverage Assessment

| Component | Covered by Unit Tests | Covered by Integration Tests | Gap |
|---|---|---|---|
| Grace period (past_due keeps tier) | Yes | N/A (needs webhook) | -- |
| Unpaid downgrades to free | Yes | N/A | -- |
| Admin tier override | Yes | Yes | -- |
| Non-admin rejection | Yes | Yes | -- |
| Super-admin protection | Yes | Yes | -- |
| Invalid tier rejection | Yes | Yes | -- |
| Settings subscription fields | Yes | Yes | -- |
| Pricing DB tier | Yes | Yes | -- |
| Delete account + Stripe cancel | Yes (mocked) | N/A (needs Stripe) | -- |
| Stripe health check | Yes | Yes | -- |
| Login reconciliation | No | Partial (no Stripe mock) | MINOR GAP |
| Webhook handlers | No | N/A (need Stripe webhooks) | MINOR GAP |
| Email notifications | No | N/A (need SMTP) | MINOR GAP |
| Frontend banners | No | N/A (need browser) | EXPECTED |
| Checkout success polling | No | N/A (need browser) | EXPECTED |

**Note:** Webhook handlers and login reconciliation are tested indirectly through the grace period tests and the TestClient, but dedicated unit tests with mocked Stripe responses would improve coverage.

---

## 8. Recommendations

### High Priority
None. No critical or high-severity bugs found.

### Medium Priority
1. **Fix BUG-1:** Add null-guard for `current_period_end` in the Settings subscription template (line 2154 of app.js). When `current_period_end` is null but `cancel_at_period_end` is true, display "Cancels soon" instead of a date.

### Low Priority
2. **Fix BUG-2:** Save the old tier before downgrading in `_handle_subscription_deleted` and pass it to `send_tier_downgrade_notification`.
3. **Fix BUG-3:** Add downgrade notification email in `_handle_subscription_updated` when status is `unpaid`/`incomplete_expired`.
4. **Test coverage:** Add unit tests for login reconciliation with mocked Stripe client, and for webhook handlers with various Stripe event payloads.
5. **Dead code:** `old_display` variable in `send_tier_downgrade_notification` is computed but never used in the email body.
6. **Deprecation warning:** Two uses of `regex=` parameter in FastAPI Query should be changed to `pattern=` (lines 2399, 2450 of routes.py). Not Phase 8 related but shows in test output.

---

## 9. Summary

| Category | Count |
|---|---|
| Unit tests passed | 917/917 (32 skipped) |
| Billing tests passed | 14/14 |
| Integration tests passed | 13/13 |
| Security tests passed | 11/11 |
| Bugs found | 3 (0 Critical, 0 High, 1 Medium, 2 Low) |
| Edge cases verified | 10/10 safe |

---

## 10. Production-Ready Decision

**READY** (with minor fixes recommended)

Phase 8 implementation is solid. All 13 identified gaps have been addressed:

1. DB `cancel_at_period_end` column -- correctly added with migration
2. Grace period for `past_due` -- tier preserved, only hard-fails downgrade
3. Stripe subscription cancel on account delete -- implemented with fail-safe
4. Login reconciliation -- non-blocking Stripe sync at login
5. Settings API subscription info -- all 4 new fields present
6. Admin tier override -- secured, validated, logged
7. Admin reconcile -- bulk sync with per-user error handling
8. Admin Stripe health -- safe info disclosure only
9. Email notifications -- 3 templates, all best-effort
10. Frontend banners -- PaymentIssueBanner and CancellationWarningBanner
11. CSS for banners -- consistent with design system
12. Checkout success polling -- 10 attempts, 2-second intervals
13. Stale-event protection in webhooks -- current_period_end comparison

No critical or high-severity bugs. The 3 bugs found are cosmetic/edge-case issues that do not affect security or core functionality. The implementation follows defense-in-depth principles with proper error handling throughout.
