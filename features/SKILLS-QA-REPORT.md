# QA Report: Claude Code Skills Validation

**Tested:** 2026-02-11
**Tester:** QA Engineer Agent
**Scope:** 5 skills in `.claude/skills/`
**Method:** Static analysis cross-referenced against actual codebase files

---

## A. Frontmatter Validation (All 5 Skills)

| Check | shieldpilot-conventions | agent-debate | code-review | api-contract | feature-lifecycle |
|-------|------------------------|--------------|-------------|--------------|-------------------|
| Has `---` delimiters | PASS | PASS | PASS | PASS | PASS |
| Has `name:` field | PASS | PASS | PASS | PASS | PASS |
| Name matches folder (kebab-case) | PASS | PASS | PASS | PASS | PASS |
| Has `description:` field | PASS | PASS | PASS | PASS | PASS |
| Description under 1024 chars | PASS (385c) | PASS (381c) | PASS (330c) | PASS (407c) | PASS (407c) |
| No angle brackets in frontmatter | PASS | PASS | PASS | PASS | PASS |
| Only name + description fields | PASS | PASS | PASS | PASS | PASS |

**Result: 35/35 checks PASS. Frontmatter is clean across all 5 skills.**

---

## B. shieldpilot-conventions -- Accuracy Check

### B.1 Imports and Router Pattern (routes.py lines 1-50)

**Skill claims:** Routes use `FastAPI APIRouter`, example shows `@router.post("/api/auth/login", response_model=Token)`.

**Actual code (routes.py:19,187):**
```python
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
...
@router.post("/api/auth/login", response_model=Token)
```

**Result: PASS** -- Exact match.

### B.2 Dependency Injection Functions (deps.py)

| Function claimed | Exists in deps.py | Signature match |
|------------------|--------------------|-----------------|
| `get_config` | PASS (line 40) | Returns `SentinelConfig` |
| `get_current_user` | PASS (line 58) | Returns `TokenData` |
| `require_verified_email` | PASS (line 113) | Returns `TokenData`, super-admin bypasses |
| `require_admin` | PASS (line 128) | Returns `TokenData` |
| `get_logger` | PASS (line 48) | Returns `BlackboxLogger` |
| `get_daily_usage` | PASS (line 223) | Returns `UsageInfo` |
| `require_feature("name")` | PASS (line 510) | Dependency factory |
| `is_super_admin` | PASS (line 140) | Returns `bool` |

**Result: PASS** -- All 8 dependency functions exist with correct signatures.

### B.3 Database Models (database.py)

**Skill claims:** `CommandLog` model with `chain_hash`, `previous_hash`, `__table_args__` with Index.

**Actual code (database.py:24-56):**
```python
class CommandLog(Base):
    __tablename__ = "commands"
    chain_hash = Column(String(64), nullable=False, unique=True)
    previous_hash = Column(String(64), nullable=False)
    __table_args__ = (
        Index("ix_commands_risk_score", "risk_score"),
        Index("ix_commands_action", "action_taken"),
    )
```

**Result: PASS** -- Model structure matches. The skill example is a simplified version but all referenced fields exist.

### B.4 migrate_database() and WAL Mode (database.py)

**Skill claims:** `migrate_database(engine)` uses ALTER TABLE ADD COLUMN, WAL mode with `busy_timeout=5000`.

**Actual code:**
- `migrate_database` at line 287: PASS
- WAL mode at line 418: `PRAGMA journal_mode=WAL` -- PASS
- Busy timeout at line 421: `PRAGMA busy_timeout=5000` -- PASS

**Result: PASS**

### B.5 Config Classes (config.py)

| Class claimed | Exists | Line |
|---------------|--------|------|
| `SentinelConfig` | PASS | 184 |
| `AuthConfig` | PASS | 66 |
| `BillingConfig` | PASS | 155 |
| `TIER_LIMITS` | PASS | 107 |

**Result: PASS**

### B.6 Frontend Components (components.js)

**Skill claims:** `escapeHtml`, `StatCard` as PascalCase pure functions returning HTML strings.

**Actual code:**
- `escapeHtml` at line 15: PASS
- `StatCard` at line 130 with signature `StatCard(number, label, color = null, icon = null, accent = null)`: PASS
- All exported functions use PascalCase (Badge, ScoreBadge, DataTable, etc.): PASS

**Result: PASS**

### B.7 Frontend Router (app.js)

**Skill claims:** Routes object maps hashes to render functions, `renderDashboard` pattern, `getPageContent()`.

**Actual code (app.js:181-197):**
```javascript
const routes = {
    '#/dashboard': renderDashboard,
    '#/commands': renderCommands,
    ...
};
```
- `renderDashboard` at line 263: PASS
- `getPageContent()` at line 220: PASS
- `api()` function at line 109: PASS

**Result: PASS**

### B.8 CSS Variables (sentinel.css :root)

| Variable claimed | Actual value | Match |
|------------------|-------------|-------|
| `--bg-primary: #0D1117` | `#0D1117` (line 7) | PASS |
| `--bg-secondary: #161B22` | `#161B22` (line 8) | PASS |
| `--bg-tertiary: #21262D` | `#21262D` (line 9) | PASS |
| `--text-primary: #E6EDF3` | `#E6EDF3` (line 11) | PASS |
| `--text-secondary: #8B949E` | `#8B949E` (line 12) | PASS |
| `--accent-cyan: #39D2C0` | `#39D2C0` (line 19) | PASS |
| `--color-allow: #3FB950` | `#3FB950` (line 14) | PASS |
| `--color-warn: #D29922` | `#D29922` (line 15) | PASS |
| `--color-block: #F85149` | `#F85149` (line 16) | PASS |
| `--border-default: #30363D` | `#30363D` (line 20) | PASS |
| `--font-mono` | `'JetBrains Mono', 'Fira Code', monospace` | PASS |
| `--font-body` | `'Inter', -apple-system, sans-serif` | PASS |

**MINOR FINDING (B.8a):** The skill's `--font-mono` example truncates the actual value. Actual CSS has `'JetBrains Mono', 'Fira Code', 'SF Mono', 'Cascadia Code', monospace` while the skill shows `'JetBrains Mono', 'Fira Code', monospace`. Similarly `--font-body` actual has `'Inter', -apple-system, BlinkMacSystemFont, sans-serif` while skill omits `BlinkMacSystemFont`.
- **Severity:** Minor (cosmetic truncation, no functional impact)
- **File:** `.claude/skills/shieldpilot-conventions/SKILL.md:230-231`

**MINOR FINDING (B.8b):** The skill omits several CSS variables present in `:root`: `--bg-surface`, `--text-muted`, `--color-info`, `--accent-purple`, `--border-focus`, `--space-xs`, `--space-lg`, `--space-xl`, `--radius-lg`, `--shadow-sm`, `--shadow-md`. These are used throughout the codebase.
- **Severity:** Minor (incomplete reference, but not wrong)
- **File:** `.claude/skills/shieldpilot-conventions/SKILL.md:218-231`

### B.9 Rate Limiting (routes.py)

**Skill claims:** `RateLimiter` class, `_login_limiter: 5 per 60s`, `_registration_limiter: 5 per hour`, `_password_reset_limiter: 3 per hour`.

**Actual code (routes.py:80, 133-135):**
```python
class RateLimiter:
_login_limiter = RateLimiter(max_attempts=5, window_seconds=60)
_password_reset_limiter = RateLimiter(max_attempts=3, window_seconds=3600)
_registration_limiter = RateLimiter(max_attempts=5, window_seconds=3600)
```

**Result: PASS** -- All three limiters exist with matching parameters.

### B.10 HTTPException Pattern (routes.py)

**Skill claims:** `detail={"error": "...", "message": "..."}` pattern.

**Actual code:** Verified across 15+ occurrences. All use `detail={"error": ...}` dict format. Some include `"message"` key, some don't (e.g., line 311: `detail={"error": "Invalid username or password"}`).

**Result: PASS** -- The `"error"` key is always present. The `"message"` key is optional, consistent with the skill saying "optional message".

### B.11 Session try/finally Pattern

**Actual code (deps.py:73-88, 179-194, etc.):** Consistently uses `session = logger._get_session()` with `try/finally: session.close()` throughout deps.py and routes.py.

**Result: PASS**

### B.12 Overall shieldpilot-conventions Score

- **Checks passed:** 10/10 major claims verified
- **Findings:** 2 Minor (CSS variable truncation, incomplete CSS variable list)
- **Verdict: PASS with 2 Minor notes**

---

## C. code-review -- Checklist Accuracy

### C.1 Public Endpoints List

**Skill claims (line 40):** Public endpoints: `/api/health`, `/api/auth/login`, `/api/auth/register`, `/api/auth/password-reset/*`, `/api/auth/verify-email`, `/api/auth/google/*`, `/api/billing/webhook`, `/api/billing/pricing`, `/api/legal/impressum`

**Actual code analysis:**

| Endpoint | Auth required? | Skill says public? | Match |
|----------|---------------|---------------------|-------|
| `/api/health` (line 1174) | No Depends | Public | PASS |
| `/api/auth/login` (line 187) | No Depends (only get_config) | Public | PASS |
| `/api/auth/register` (line 315) | No Depends (only get_config) | Public | PASS |
| `/api/auth/password-reset/request` (line 453) | No Depends | Public | PASS |
| `/api/auth/password-reset/confirm` (line 510) | No Depends | Public | PASS |
| `/api/auth/verify-email` (line 570) | No Depends (only get_config) | Public | PASS |
| `/api/auth/google` (line 677) | No Depends | Public | PASS |
| `/api/auth/google/callback` (line 702) | No Depends | Public | PASS |
| `/api/billing/webhook` (line 1417) | No Depends (Stripe sig) | Public | PASS |
| `/api/legal/impressum` (line 3292) | Only get_config | Public | PASS |

**CRITICAL FINDING (C.1a):** `/api/billing/pricing` is listed as public but actually requires auth.

**Actual code (routes.py:1291-1294):**
```python
@router.get("/api/billing/pricing")
def get_pricing(
    user: TokenData = Depends(get_current_user),  # <-- AUTH REQUIRED
    config: SentinelConfig = Depends(get_config),
):
```

This is NOT a public endpoint. It uses `Depends(get_current_user)`.
- **Severity:** Critical (an agent following this skill would leave this endpoint unguarded in a review, or incorrectly assume it can be called without auth)
- **File:** `.claude/skills/code-review/SKILL.md:40`
- **Fix:** Remove `/api/billing/pricing` from the public endpoints list

**MAJOR FINDING (C.1b):** Missing public endpoint: `/api/auth/verify-email/resend` at line 614 actually requires `Depends(get_current_user)`, so this is correctly NOT listed as public. However, it is entirely absent from the skill's endpoint reference. Not strictly wrong, but worth noting.

### C.2 Billing Tier Limits

**Skill claims (line 98):** "Free tier limits enforced (50 commands/day, 10 scans/day)"

**Actual code (config.py:108-118):**
```python
"free": TierLimits(
    commands_per_day=50,
    scans_per_day=10,
    ...
)
```

**Result: PASS** -- Exact match.

### C.3 CSS Variable Names

Already verified in section B.8 above.

**Result: PASS**

### C.4 Overall code-review Score

- **Checks passed:** 2/3 major claims verified
- **Findings:** 1 Critical (billing/pricing listed as public but requires auth)
- **Verdict: FAIL -- Critical finding must be fixed**

---

## D. api-contract -- Endpoint Reference Accuracy

### D.1 Complete Endpoint Comparison

**Method:** Extracted all `@router.*` decorators from `routes.py` and compared against the skill's "Existing endpoints reference" section (lines 142-210).

#### Endpoints in CODE but MISSING from skill:

| Endpoint | Line | Severity |
|----------|------|----------|
| `POST /api/auth/verify-email/resend` | 614 | Major |
| `GET /api/billing/tier` | 1242 | Major |
| `GET /api/library/categories` | 2754 | Major |

**MAJOR FINDING (D.1a):** 3 endpoints exist in routes.py but are not listed in the api-contract skill's endpoint reference.
- **Severity:** Major (agents planning new features would not know these endpoints exist, potentially causing duplicates or integration mismatches)
- **File:** `.claude/skills/api-contract/SKILL.md:142-210`
- **Fix:** Add the 3 missing endpoints to the reference

#### Endpoints in SKILL but NOT in code:

| Endpoint from skill | Exists in code? | Severity |
|---------------------|-----------------|----------|
| `GET /api/billing/subscription` | NO (grep confirms no match) | Critical |

**CRITICAL FINDING (D.1b):** `/api/billing/subscription` is listed in the skill (line 200: `GET /api/billing/subscription -> current sub`) but does NOT exist in routes.py. There is no `@router` decorator containing "billing/subscription" anywhere in the codebase.
- **Severity:** Critical (an agent would try to call or test a non-existent endpoint, or a frontend dev would wire up a call to a 404)
- **File:** `.claude/skills/api-contract/SKILL.md:200`
- **Fix:** Remove the `/api/billing/subscription` line OR note that this endpoint needs to be implemented

#### Public endpoints mismatch (same as code-review finding):

**CRITICAL FINDING (D.1c):** `/api/billing/pricing` is listed under Authentication section as public (no auth), but it actually uses `Depends(get_current_user)` at routes.py:1293.
- **Severity:** Critical (same issue as C.1a, propagated to this skill too)
- **File:** `.claude/skills/api-contract/SKILL.md:29`
- **Fix:** Remove `/api/billing/pricing` from the public endpoints list

#### All other endpoints: VERIFIED MATCH

The remaining ~40 endpoints all match between skill and code. The endpoint paths, HTTP methods, and groupings are correct.

### D.2 Overall api-contract Score

- **Endpoints matched:** ~40/44 correct
- **Findings:** 2 Critical (ghost endpoint, pricing auth status), 1 Major (3 missing endpoints)
- **Verdict: FAIL -- Critical findings must be fixed**

---

## E. feature-lifecycle -- Agent Reference Accuracy

### E.1 Agent Names vs Files in `.claude/agents/`

**Skill references these 6 agents:**
1. Requirements Engineer
2. Solution Architect
3. Frontend Dev
4. Backend Dev
5. QA Engineer
6. DevOps Engineer

**Files in `.claude/agents/`:**
- `requirements-engineer.md` -- PASS
- `solution-architect.md` -- PASS
- `frontend-dev.md` -- PASS
- `backend-dev.md` -- PASS
- `qa-engineer.md` -- PASS
- `devops-engineer.md` -- PASS
- `README.md` (informational, not an agent) -- N/A
- `debate-checklist.md` (checklist, not an agent) -- N/A

**Result: PASS** -- All 6 agent names correspond to existing agent files.

### E.2 Grep Commands in Phase 2

**Skill suggests (line 61-64):**
```bash
grep @router sentinelai/api/routes.py
grep "class.*Base" sentinelai/logger/database.py
grep "export function" sentinelai/web/static/js/components.js
grep "function render" sentinelai/web/static/js/app.js
```

**Verification:**

| Command | Returns results? | Useful? |
|---------|-----------------|---------|
| `grep @router sentinelai/api/routes.py` | Yes (44 matches) | PASS |
| `grep "class.*Base" sentinelai/logger/database.py` | Yes (matches class definitions) | PASS |
| `grep "export function" sentinelai/web/static/js/components.js` | Yes (20+ matches) | PASS |
| `grep "function render" sentinelai/web/static/js/app.js` | Yes (20+ matches) | PASS |

**Result: PASS** -- All suggested grep commands produce useful output.

### E.3 /features/ Directory

**Skill claims:** Feature specs go to `/features/PROJ-X-feature-name.md`

**Actual directory contents:**
```
features/.gitkeep
features/UNIFIED-ROADMAP.md
features/PHASE-8-QA-REPORT.md
features/PHASE-9-QA-REPORT.md
```

**Result: PASS** -- Directory exists and is already in use for project documentation.

### E.4 Phase 7 Port Reference

**Skill claims (line 223):** `Verify at http://localhost:8420`

**Actual code (config.py:188):** `app_base_url: str = "http://localhost:8420"`

**Result: PASS** -- Port 8420 matches.

### E.5 Overall feature-lifecycle Score

- **Checks passed:** 4/4
- **Findings:** None
- **Verdict: PASS**

---

## F. agent-debate -- Structure Check

### F.1 Trigger Categories

The 6 triggers map well to ShieldPilot's architecture:

| Trigger | Relevant ShieldPilot component | Realistic? |
|---------|-------------------------------|------------|
| Security change | auth.py, RateLimiter, JWT, API keys | PASS |
| Data model change | database.py, migrate_database() | PASS |
| Billing logic | billing/stripe_stub.py, TIER_LIMITS | PASS |
| External integration | pip packages, OAuth providers | PASS |
| Performance-critical | SSE streams, risk engine | PASS |
| UX flow change | SPA routes, login page | PASS |

**Result: PASS** -- All 6 triggers are relevant and realistic.

### F.2 Quick Check File References

**Skill claims (lines 36-41):**
- `sentinelai/api/auth.py` -- Verified: exists (imported at routes.py:23)
- `sentinelai/logger/database.py` -- Verified: exists
- `sentinelai/billing/` -- Verified: `sentinelai/billing/stripe_stub.py` exists (imported at routes.py:1420)
- Hash routes, navigation -- Verified: routes object in app.js:181

**Result: PASS**

### F.3 Example Debate Quality

The SSE usage data example:
- Uses real ShieldPilot concepts (SSE `event_generator`, `get_daily_usage_for_user()`, `UsageMeter()`, `stats_dict`, hash dedup)
- References actual file locations
- All 6 agents provide relevant 3-bullet inputs
- Decision is clear with justification
- Acceptance criteria are testable

**MINOR FINDING (F.3a):** The example references `UsageMeter()` component, but this function does not exist in `components.js` (grep found no `export function UsageMeter`). The component that handles usage display may exist under a different name or be inline.
- **Severity:** Minor (example is illustrative, not prescriptive)
- **File:** `.claude/skills/agent-debate/SKILL.md:169`

### F.4 Output Path

**Skill claims:** Save to `/features/DEBATE-[YYYY-MM-DD]-[topic-slug].md`

**Result: PASS** -- Consistent with `/features/` directory convention used by other skills.

### F.5 Overall agent-debate Score

- **Checks passed:** 4/4 major checks
- **Findings:** 1 Minor (UsageMeter reference)
- **Verdict: PASS with 1 Minor note**

---

## Summary of All Findings

### Critical Findings (2)

| # | Skill | Issue | File:Line | Fix |
|---|-------|-------|-----------|-----|
| 1 | code-review + api-contract | `/api/billing/pricing` listed as public endpoint but requires `Depends(get_current_user)` | code-review/SKILL.md:40, api-contract/SKILL.md:29 | Remove from public endpoints list |
| 2 | api-contract | `/api/billing/subscription` listed but does NOT exist in codebase | api-contract/SKILL.md:200 | Remove phantom endpoint or mark as "not yet implemented" |

### Major Findings (1)

| # | Skill | Issue | File:Line | Fix |
|---|-------|-------|-----------|-----|
| 1 | api-contract | 3 endpoints missing from reference: `POST /api/auth/verify-email/resend`, `GET /api/billing/tier`, `GET /api/library/categories` | api-contract/SKILL.md:142-210 | Add missing endpoints to reference |

### Minor Findings (3)

| # | Skill | Issue | File:Line | Fix |
|---|-------|-------|-----------|-----|
| 1 | shieldpilot-conventions | `--font-mono` and `--font-body` CSS values truncated (missing fallback fonts) | shieldpilot-conventions/SKILL.md:230-231 | Include full font stack |
| 2 | shieldpilot-conventions | CSS variable list incomplete -- missing `--bg-surface`, `--text-muted`, `--color-info`, `--accent-purple`, `--border-focus`, spacing/radius/shadow variants | shieldpilot-conventions/SKILL.md:218-231 | Add missing variables |
| 3 | agent-debate | Example references `UsageMeter()` component that does not exist in components.js | agent-debate/SKILL.md:169 | Rename to actual component or add note that it is hypothetical |

---

## Skill-by-Skill Verdict

| Skill | Verdict | Critical | Major | Minor |
|-------|---------|----------|-------|-------|
| shieldpilot-conventions | **PASS** | 0 | 0 | 2 |
| agent-debate | **PASS** | 0 | 0 | 1 |
| code-review | **FAIL** | 1 | 0 | 0 |
| api-contract | **FAIL** | 2 | 1 | 0 |
| feature-lifecycle | **PASS** | 0 | 0 | 0 |

---

## Production-Ready Decision

**Overall: NOT READY** -- 2 Critical bugs found.

### Required Before Deployment

1. **Fix code-review/SKILL.md line 40:** Remove `/api/billing/pricing` from public endpoints list
2. **Fix api-contract/SKILL.md line 29:** Remove `/api/billing/pricing` from public endpoints list
3. **Fix api-contract/SKILL.md line 200:** Remove `/api/billing/subscription` (does not exist) or replace with `/api/billing/tier` (which does exist)
4. **Fix api-contract/SKILL.md lines 142-210:** Add the 3 missing endpoints

### Recommended (Non-Blocking)

5. Expand CSS variable list in shieldpilot-conventions to include all `:root` variables
6. Fix font-family truncation in shieldpilot-conventions
7. Fix or annotate the `UsageMeter()` reference in agent-debate example

---

## Security Notes

From a Red Team perspective, the **`/api/billing/pricing` misclassification** is the highest-risk finding. If an agent doing a code review trusts this skill and sees `/api/billing/pricing` without auth guards, they would mark it as correct (since the skill says it should be public). In reality, this endpoint exposes the Stripe publishable key and user tier information, which should remain behind authentication. This is the kind of subtle documentation error that leads to real security regressions.

The phantom `/api/billing/subscription` endpoint could cause confusion during feature planning -- a developer might assume subscription management already exists and skip implementing it, or waste time debugging 404 errors.

---

*Report generated by QA Engineer Agent -- 2026-02-11*
