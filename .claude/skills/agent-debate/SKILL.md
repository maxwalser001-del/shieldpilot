---
name: agent-debate
description: Structured multi-agent debate protocol for critical decisions in ShieldPilot. Use when making security changes, data model changes, billing logic changes, adding external integrations, modifying performance-critical paths, or changing UX flows. Trigger phrases include debate, discuss decision, critical change, should we, architecture decision, design review, trade-off analysis.
---

# Agent Debate Protocol (Regel F)

Structured decision-making for ShieldPilot agent teams. Produces an immutable Decision Document before implementation begins.

## When to trigger a debate

A debate is MANDATORY before implementation when ANY of these conditions apply:

### Trigger 1: Security change
Auth, RBAC, JWT tokens, hook policies, audit chain integrity, rate limiting, password hashing, API key handling, XSS prevention.

### Trigger 2: Data model change
New SQLAlchemy models, ALTER TABLE migrations, new columns, new tables, schema changes, new indexes, new relationships.

### Trigger 3: Billing logic change
Tier checks, usage limits, Stripe integration, checkout flow, webhook handling, subscription lifecycle, paywall enforcement.

### Trigger 4: External integration
New Python packages, new OAuth providers, external API calls, third-party services.

### Trigger 5: Performance-critical path
SSE event streams, risk engine evaluation, audit chain write path, database query optimization, bulk operations.

### Trigger 6: UX flow change
Login/registration flow, incident response flow, dashboard core layout, navigation structure, paywall UX, onboarding.

## Quick check

Before implementing, verify:

- Touches sentinelai/api/auth.py or auth code in routes.py? Trigger 1
- Modifies sentinelai/logger/database.py or adds ALTER TABLE? Trigger 2
- Touches billing, tiers, Stripe, or sentinelai/billing/? Trigger 3
- Adds a new import or pip dependency? Trigger 4
- Changes SSE endpoints, risk engine, or audit chain hashing? Trigger 5
- Changes login page, hash routes, or navigation? Trigger 6

If NONE apply, skip the debate and implement directly.

## Debate execution

### Step 1: Problem statement

```
PROBLEM: [One sentence: what specific decision needs to be made]
TRIGGER: [Category: Security / Data Model / Billing / Integration / Performance / UX]
CONTEXT: [1-2 sentences of background]
```

### Step 2: Options

Present exactly 2 or 3 options:

| Option | Description | Effort |
|--------|-------------|--------|
| A | [description] | small/medium/large |
| B | [description] | small/medium/large |
| C | [description] | small/medium/large |

### Step 3: Agent inputs

Each agent contributes EXACTLY 3 bullet points (pros, cons, risks). No more.

**Solution Architect** (architecture, tradeoffs, system impact):
- [bullet]
- [bullet]
- [bullet]

**Requirements Engineer** (acceptance criteria, edge cases, user impact):
- [bullet]
- [bullet]
- [bullet]

**Backend Dev** (API impact, DB impact, security, testability):
- [bullet]
- [bullet]
- [bullet]

**Frontend Dev** (UX flow, accessibility, state handling, error states):
- [bullet]
- [bullet]
- [bullet]

**QA Engineer** (test strategy, regression risk, coverage gaps):
- [bullet]
- [bullet]
- [bullet]

**DevOps Engineer** (CI gates, deployment risk, secrets, monitoring):
- [bullet]
- [bullet]
- [bullet]

### Step 4: Decision

```
DECISION: Option [A/B/C]
JUSTIFICATION: [2-3 sentences why]
DISSENT: [Any disagreement, or "None"]
```

### Step 5: Assignment

```
OWNER: [Agent who implements]
REVIEWER: [Agent who reviews]
QA: [Agent who tests]
DEVOPS: [Agent who checks deployment]
```

### Step 6: Acceptance criteria

```
- [ ] [Specific testable criterion]
- [ ] [Specific testable criterion]
- [ ] Tests written and passing
- [ ] Security check completed (if security-relevant)
- [ ] Manual verification documented and executed
```

## Rules

1. ALL 6 agents must contribute. No agent skipped.
2. No implementation starts before the Decision Document is written.
3. Decisions are IMMUTABLE once approved. No re-debating during implementation.
4. Maximum time budget: keep debates focused and concise.
5. If a debate produces a user question, STOP and wait for the answer.

## Output format

Save the Decision Document to:
```
/features/DEBATE-[YYYY-MM-DD]-[topic-slug].md
```

## Example debate

```markdown
# DEBATE: SSE Usage Data in Dashboard Stream

PROBLEM: Should usage data be embedded in the SSE stats stream or fetched via separate polling?
TRIGGER: Performance (SSE event_generator modification)
CONTEXT: Dashboard needs real-time usage meter updates. Currently usage only fetched on page load.

| Option | Description | Effort |
|--------|-------------|--------|
| A | Embed usage in SSE stats_dict payload | small |
| B | Separate /api/usage polling every 10s | small |
| C | Dedicated usage SSE stream | medium |

**Solution Architect:**
- A: Single stream reduces connections; hash dedup prevents redundant updates
- B: Two concurrent connections per client increases server load at scale
- A risk: Larger SSE payload, usage query added to hot path

**Backend Dev:**
- A: get_daily_usage_for_user() is lightweight (single DB query), safe for SSE loop
- A: Wrapped in try/except so failure does not break stats stream
- B: Separate endpoint means separate auth validation per poll

**Frontend Dev:**
- A: Single onmessage handler extracts usage, simpler client code
- B: Two polling loops increase timer management complexity
- A: Already have UsageMeter() helper in app.js, just needs data source change

**QA Engineer:**
- A: Test SSE payload includes usage key with correct structure
- A risk: Must verify hash changes when only usage changes
- Regression: Ensure existing dashboard stats still render correctly

**DevOps Engineer:**
- A: No new endpoints, no infrastructure change needed
- A: SSE connection count unchanged
- B: Additional HTTP connections at scale could need rate limit tuning

**Requirements Engineer:**
- A: Users see usage update in real-time without page refresh
- A: Super-admin must see is_admin: true in usage data
- Edge case: What if usage query fails? Must not break stats stream

DECISION: Option A
JUSTIFICATION: Embedding usage in the existing SSE stream is simplest. The usage query is lightweight, failure handled gracefully, and client code is simpler with one data source.
DISSENT: None

OWNER: Backend Dev
REVIEWER: Solution Architect
QA: QA Engineer
DEVOPS: DevOps Engineer

- [ ] SSE event_generator includes usage key in stats_dict
- [ ] Usage query wrapped in try/except with fallback to null
- [ ] Frontend extracts usage from SSE and updates usage meter in dashboard
- [ ] Hash includes usage data for change detection
- [ ] Super-admin sees is_admin: true in usage payload
- [ ] Tests verify SSE payload structure
```
