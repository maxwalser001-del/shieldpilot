---
name: code-review
description: ShieldPilot-specific code review checklist for agents reviewing each other's work. Use when reviewing a pull request, checking code quality, doing a security review, cross-reviewing implementation, or verifying code before merge. Covers XSS, auth guards, rate limiting, database patterns, error handling, billing, CSS, and tests.
---

# ShieldPilot Code Review Checklist

Structured review for agents reviewing each other's implementations. Produces a report with PASS/FAIL per item and specific line references.

## Severity levels

- **CRITICAL**: Blocks merge. Security vulnerability, data loss risk, broken core functionality.
- **MAJOR**: Should fix. Correctness issue, missing guard, convention violation causing bugs.
- **MINOR**: Nice to fix. Style, optimization, documentation. Can be follow-up.

## Review checklist

Execute every applicable item. Mark N/A if not relevant to changed files.

### 1. XSS Prevention (Frontend)

For every file in sentinelai/web/static/js/:

- [ ] All dynamic content in HTML uses escapeHtml()
- [ ] Template literals with user data use escapeHtml(value)
- [ ] innerHTML only contains escaped or static content
- [ ] No document.write() or eval() with user input
- [ ] Component functions escape all parameters

Severity if violated: **CRITICAL**

### 2. Auth Guards (Backend)

For every endpoint in sentinelai/api/routes.py:

- [ ] Protected endpoints use Depends(get_current_user) or stricter
- [ ] Admin-only endpoints use Depends(require_admin)
- [ ] Email-sensitive endpoints use Depends(require_verified_email)
- [ ] Tier-gated features use Depends(require_feature("name"))
- [ ] Public endpoints only: /api/health, /api/auth/login, /api/auth/register, /api/auth/password-reset/*, /api/auth/verify-email, /api/auth/google/*, /api/billing/webhook, /api/legal/impressum

Severity if violated: **CRITICAL**

### 3. Rate Limiting

- [ ] Auth endpoints use RateLimiter
- [ ] is_blocked() checked BEFORE processing
- [ ] record_attempt() called AFTER failed auth
- [ ] New sensitive endpoints have rate limiting
- [ ] 429 responses include Retry-After header

Severity if violated: **MAJOR**

### 4. Database Patterns

- [ ] All sessions closed in try/finally
- [ ] session.commit() only on success
- [ ] session.rollback() in except block
- [ ] New models define __tablename__
- [ ] Audit tables include chain_hash and previous_hash
- [ ] Indexes defined in __table_args__
- [ ] Migrations use ALTER TABLE ADD COLUMN (no DROP)
- [ ] migrate_database() updated for new columns on existing tables

Severity if violated: **CRITICAL** (session leak) / **MAJOR** (missing migration)

### 5. Error Handling

Backend:
- [ ] HTTPException uses detail dict with "error" key
- [ ] No stack traces or DB details in error messages
- [ ] 401 errors include WWW-Authenticate header
- [ ] 429 errors include Retry-After header

Frontend:
- [ ] api() failures handled (null check on return)
- [ ] EmptyState() for missing data
- [ ] Spinner() during loading
- [ ] showToast() for user-facing errors

Severity if violated: **MAJOR**

### 6. Super-Admin Bypass

- [ ] is_super_admin(user, config) checked before billing limits
- [ ] Super-admin bypass in require_verified_email
- [ ] Super-admin bypass in require_feature checks
- [ ] is_admin: true in UsageInfo responses for super-admin
- [ ] Frontend shows unlimited tier, no paywall for super-admin

Severity if violated: **MAJOR**

### 7. Billing Enforcement

- [ ] New paywall features use Depends(require_feature("name"))
- [ ] Usage counters incremented (increment_scan_usage, increment_command_usage)
- [ ] limit_reached checked before resource-consuming operations
- [ ] Free tier limits enforced (50 commands/day, 10 scans/day)
- [ ] billing.enabled == False returns without enforcement
- [ ] Subscription status verified for paid tiers

Severity if violated: **MAJOR**

### 8. CSS Conventions

- [ ] All colors use CSS variables (--bg-primary, --accent-cyan, etc.)
- [ ] No hardcoded hex colors in new rules
- [ ] Spacing uses CSS variables (--space-sm, --space-md)
- [ ] Border radius uses variables (--radius-sm, --radius-md)
- [ ] Kebab-case class names
- [ ] Dark theme maintained

Severity if violated: **MINOR**

### 9. Test Coverage

- [ ] New API endpoints have tests in tests/test_api/
- [ ] Tests use FastAPI TestClient pattern
- [ ] Test fixtures reset singletons via deps.reset_singletons()
- [ ] Auth tests use auth_headers fixture
- [ ] Edge cases tested (invalid input, unauthorized access)
- [ ] Billing tests cover enabled and disabled states

Severity if violated: **MAJOR** (new endpoints) / **MINOR** (edge cases)

### 10. Naming Conventions

- [ ] Python functions: snake_case
- [ ] Python classes: PascalCase
- [ ] JS utility functions: camelCase
- [ ] JS components: PascalCase returning HTML strings
- [ ] JS render functions: renderPageName
- [ ] CSS classes: kebab-case
- [ ] API paths: /api/ + kebab-case
- [ ] Pydantic models: PascalCase

Severity if violated: **MINOR**

## Review output format

```markdown
# Code Review: [Feature/Change Description]

**Reviewer:** [Agent name]
**Date:** [YYYY-MM-DD]
**Files reviewed:** [list]

## Summary
[1-2 sentence assessment]
**Verdict:** APPROVE / REQUEST CHANGES / BLOCK

## Findings

### CRITICAL
| # | Check | File:Line | Issue | Fix |
|---|-------|-----------|-------|-----|
| 1 | XSS | app.js:1234 | escapeHtml missing on user.name | Wrap in escapeHtml() |

### MAJOR
| # | Check | File:Line | Issue | Fix |
|---|-------|-----------|-------|-----|

### MINOR
| # | Check | File:Line | Issue | Fix |
|---|-------|-----------|-------|-----|

### PASSED
- [x] XSS: All template literals use escapeHtml()
- [x] Rate limiting: Login endpoint uses _login_limiter
- [x] DB sessions: All sessions have try/finally
```

## Rules

1. Every checklist item must have: PASS, FAIL (with severity), or N/A
2. FAIL items must include specific file and line number
3. FAIL items must include a concrete fix suggestion
4. CRITICAL findings block merge, no exceptions
5. Review the actual diff, not assumptions
