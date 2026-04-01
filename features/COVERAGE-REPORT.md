# ShieldPilot Coverage Report (I1)

**Date:** 2026-02-17
**Total:** 7137 statements, 2872 missed — **60% overall coverage**
**Test Suite:** 2261 passed (with mode=enforce), 0 failed

## Modules Below 70% Coverage

| Module | Stmts | Miss | Cover | Priority |
|--------|-------|------|-------|----------|
| `services/webhook_service.py` | 104 | 104 | **0%** | Low (unused stub) |
| `services/rate_limit_service.py` | 56 | 56 | **0%** | Low (unused stub) |
| `plugins/interface.py` | 24 | 24 | **0%** | Low (plugin system unused) |
| `plugins/loader.py` | 67 | 67 | **0%** | Low (plugin system unused) |
| `plugins/__init__.py` | 3 | 3 | **0%** | Low (plugin system unused) |
| `billing/metering.py` | 65 | 65 | **0%** | Medium (Stripe metering) |
| `billing/tenant.py` | 49 | 49 | **0%** | Medium (multi-tenant billing) |
| `dashboard/server.py` | 92 | 92 | **0%** | Low (standalone server, unused) |
| `api/oauth.py` | 30 | 30 | **0%** | Medium (Google OAuth flow) |
| `ml/analyze_logs.py` | 129 | 114 | **12%** | Low (offline analysis tool) |
| `services/billing_service.py` | 271 | 219 | **19%** | Medium (Stripe integration) |
| `ml/eval.py` | 122 | 98 | **20%** | Low (offline evaluation tool) |
| `api/email.py` | 90 | 70 | **22%** | Medium (email sending) |
| `services/report_service.py` | 110 | 84 | **24%** | Low (PDF reports) |
| `cli/main.py` | 475 | 346 | **27%** | Low (CLI entry point) |
| `api/routers/dashboard.py` | 182 | 131 | **28%** | High (analytics/SSE) |
| `services/auth_service.py` | 239 | 155 | **35%** | High (auth business logic) |
| `services/team_service.py` | 110 | 72 | **35%** | Medium (team management) |
| `services/rules_service.py` | 137 | 82 | **40%** | Medium (custom rules) |
| `api/routers/activity.py` | 25 | 15 | **40%** | Medium (activity feed) |
| `api/routers/teams.py` | 54 | 32 | **41%** | Medium (team endpoints) |
| `cli/formatters.py` | 179 | 98 | **45%** | Low (CLI output) |
| `api/routers/rules.py` | 35 | 18 | **49%** | Medium (rules endpoints) |
| `billing/stripe_client.py` | 60 | 29 | **52%** | Medium (Stripe API calls) |
| `core/exceptions.py` | 30 | 14 | **53%** | Low (exception classes) |
| `services/user_service.py` | 115 | 53 | **54%** | High (user CRUD) |
| `api/routers/export.py` | 54 | 21 | **61%** | Medium (data export) |
| `migrations/runner.py` | 143 | 54 | **62%** | Medium (migration runner) |
| `engine/llm_evaluator.py` | 63 | 23 | **63%** | Low (LLM disabled in hook) |
| `sandbox/executor.py` | 62 | 23 | **63%** | Medium (command sandbox) |
| `api/app.py` | 63 | 22 | **65%** | Medium (app factory) |
| `hooks/sentinel_hook.py` | 371 | 131 | **65%** | High (core hook logic) |
| `cli/styles.py` | 17 | 6 | **65%** | Low (CLI styling) |
| `api/deps.py` | 261 | 86 | **67%** | High (dependency injection) |
| `ml/ml_train.py` | 43 | 14 | **67%** | Low (offline training) |

## Modules At/Above 70% Coverage (Well-Tested)

| Module | Cover | Notes |
|--------|-------|-------|
| `adapters/*` | **100%** | Full adapter coverage (I2) |
| `engine/analyzers/*` | **96-100%** | Risk engine well-tested |
| `scanner/*` | **89-100%** | Scanner/sanitizer well-tested |
| `explainability/*` | **100%** | Full coverage |
| `core/config.py` | **92%** | Config parsing solid |
| `core/constants.py` | **100%** | |
| `core/path_utils.py` | **100%** | |
| `licensing/*` | **82-95%** | License system tested |
| `api/routers/_shared.py` | **89%** | Rate limiter tested (I4) |
| `api/auth.py` | **97%** | JWT auth solid |
| `logger/*` | **80-95%** | Logging/chain tested |

## Recommendations for Future Coverage Improvement

### Priority 1 — Security-Critical (target: 80%+)
1. **`hooks/sentinel_hook.py`** (65%): Core hook — add tests for usage limit path, active learning, injection rate checking
2. **`api/deps.py`** (67%): Auth dependency — add tests for API key auth, token refresh
3. **`services/auth_service.py`** (35%): Auth business logic — registration, password reset, OAuth flows
4. **`services/user_service.py`** (54%): User CRUD operations

### Priority 2 — Business Logic (target: 70%+)
5. **`api/routers/dashboard.py`** (28%): Analytics endpoints and SSE streaming
6. **`services/billing_service.py`** (19%): Stripe integration (hard to test without Stripe)
7. **`api/email.py`** (22%): Email sending (mock SMTP)
8. **`migrations/runner.py`** (62%): Add Alembic integration tests

### Priority 3 — Nice to Have
9. **`cli/main.py`** (27%): CLI commands (integration tests)
10. **`plugins/*`** (0%): Plugin system (currently unused)
11. **`dashboard/server.py`** (0%): Standalone server (unused)
