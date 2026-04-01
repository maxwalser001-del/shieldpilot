# ShieldPilot Agent System

A structured development workflow with 6 specialized AI agents for systematic feature development.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3 / FastAPI / SQLAlchemy ORM |
| **Database** | SQLite (WAL mode) |
| **Frontend** | Vanilla JS SPA (hash routing, no build step) |
| **Styling** | CSS Variables (dark theme) |
| **Auth** | JWT HS256 (localStorage) |
| **Config** | sentinel.yaml + Pydantic |
| **Tests** | pytest (python3 -m pytest) |

## Agent Overview

| Agent | Role | Output |
|-------|------|--------|
| **Requirements Engineer** | Converts feature ideas into structured specs | `/features/PROJ-X.md` |
| **Solution Architect** | Plans high-level architecture (PM-friendly) | Tech-Design section in feature spec |
| **Frontend Developer** | Builds UI with vanilla JS, CSS Variables, hash routing | Components + Pages in app.js |
| **Backend Developer** | APIs, Database, Server-side logic with FastAPI/SQLAlchemy | Routes + Models + Tests |
| **QA Engineer** | Tests against Acceptance Criteria | Test results in feature spec |
| **DevOps Engineer** | Deployment, server management, testing | Production deployment |

---

## Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                    FEATURE DEVELOPMENT WORKFLOW                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. REQUIREMENTS ENGINEER                                        │
│     └─► Gather requirements via AskUserQuestion                  │
│     └─► Create /features/PROJ-X.md with User Stories            │
│     └─► User Review ✅                                           │
│                        ↓                                         │
│  2. SOLUTION ARCHITECT                                           │
│     └─► Read feature spec                                        │
│     └─► Design component structure + data model                  │
│     └─► Add Tech-Design section to feature spec                  │
│     └─► User Review ✅                                           │
│                        ↓                                         │
│  3. FRONTEND DEVELOPER                                           │
│     └─► Read feature spec + design                               │
│     └─► Build UI components (vanilla JS + CSS Variables)         │
│     └─► User Review ✅ → Handoff to Backend (if needed)          │
│                        ↓                                         │
│  4. BACKEND DEVELOPER (if needed)                                │
│     └─► SQLAlchemy models + migrate_database()                   │
│     └─► FastAPI routes with Depends() auth                       │
│     └─► User Review ✅                                           │
│                        ↓                                         │
│  5. QA ENGINEER                                                  │
│     └─► Test against Acceptance Criteria                         │
│     └─► Document bugs in feature spec                            │
│     └─► Security testing (red team mindset)                      │
│     └─► Production-Ready Decision ✅                             │
│                        ↓                                         │
│  6. DEVOPS ENGINEER                                              │
│     └─► Run tests, restart server                                │
│     └─► Verify at localhost:8420                                 │
│     └─► User Review ✅                                           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Usage Commands

### Start a New Feature
```
Lies .claude/agents/requirements-engineer.md und erstelle eine Feature Spec für [FEATURE_IDEA]
```

### Design Architecture
```
Lies .claude/agents/solution-architect.md und plane /features/PROJ-X-feature-name.md
```

### Build UI (Frontend)
```
Lies .claude/agents/frontend-dev.md und implementiere /features/PROJ-X-feature-name.md
```

### Build Backend (if needed)
```
Lies .claude/agents/backend-dev.md und implementiere /features/PROJ-X-feature-name.md
```

### Test Feature
```
Lies .claude/agents/qa-engineer.md und teste /features/PROJ-X-feature-name.md
```

### Deploy
```
Lies .claude/agents/devops-engineer.md und deploye PROJ-X
```

---

## Skills Reference

Agents can invoke these skills for structured collaboration:

| Skill | Trigger | Purpose |
|-------|---------|---------|
| `shieldpilot-conventions` | Coding standards, project patterns | Mandatory knowledge for all agents |
| `agent-debate` | Critical decisions, architecture changes | Structured multi-agent debate protocol |
| `code-review` | Pull requests, code quality checks | 10-point ShieldPilot-specific checklist |
| `api-contract` | New endpoints, frontend-backend agreement | API contract definition protocol |
| `feature-lifecycle` | New features, sprint planning | 7-phase gated delivery pipeline |
| `skill-writer` | Creating new skills | Interactive skill authoring workflow |
| `owasp-security` | Security audit, auth review | OWASP Top 10 security checklist |
| `test-driven-development` | Writing tests first | Red-green-refactor cycle |
| `testing-anti-patterns` | Reviewing test quality | Prevents common testing mistakes |
| `systematic-debugging` | Bug investigation | Root cause before fixes |
| `root-cause-tracing` | Deep/indirect failures | Backward tracing through call chain |
| `varlock` | Secrets management | Secure env variable handling |

---

## Key Principles

1. **Single Responsibility**: Each feature spec = ONE testable, deployable unit
2. **Human-in-the-Loop**: Every agent has checkpoints for user review
3. **Reuse First**: Always check existing components/APIs before creating new ones
4. **AskUserQuestion**: Agents use interactive prompts to gather requirements
5. **Feature Spec as Source of Truth**: All decisions documented in `/features/PROJ-X.md`
6. **Structured Debate**: Bei kritischen Entscheidungen diskutieren Agents strukturiert vor der Umsetzung (Regel F)

---

## Regel F: Structured Agent Debate

### Wann wird eine Debate getriggert?

Eine Debate ist **verpflichtend** vor der Umsetzung wenn mindestens eins zutrifft:

| Trigger | Beispiele |
|---------|-----------|
| Security-relevante Aenderung | Auth, RBAC, Tokens, Hooks, Policy Engine, Audit Chain, Rate Limiting |
| Datenmodell-Aenderung | Neue Tables, ALTER TABLE, Schema-Migration |
| Paywall/Billing-Logik | Tier-Checks, Limits, Stripe |
| Neue externe Integration | Neue Packages, OAuth Provider, externe APIs |
| Performance-kritischer Pfad | SSE, Risk Engine, Audit Write Path |
| UX-Aenderung im Nutzerfluss | Login, Incident Flow, Dashboard Kern |

### Ablauf

```
1. Trigger erkannt
   |
2. Problem Statement (1 Satz)
   |
3. Options (2-3 Optionen)
   |
4. Agent Inputs (je max 3 Bullets: Pros/Cons/Risiken)
   |
   +-- Solution Architect: Architektur, Tradeoffs
   +-- Requirements Engineer: Akzeptanzkriterien, Edge Cases
   +-- Backend Dev: API/DB Auswirkungen, Security
   +-- Frontend Dev: UX Flow, A11y, UI States
   +-- QA Engineer: Teststrategie, Regression
   +-- DevOps Engineer: CI, Deployment, Secrets
   |
5. Decision + Begruendung
   |
6. Handoff: Owner -> Reviewer -> QA -> DevOps
   |
7. Umsetzung (Single Thread, keine Diskussion mehr)
```

### Regeln

- **Vor Umsetzung**, nicht waehrenddessen
- **Max 12 Minuten** mental — kurz und strukturiert
- **Single Thread bleibt** — nach Decision wird sequentiell umgesetzt
- **Definition of Done** bleibt verpflichtend (Tests, Security Checks, Verification)

Siehe auch: `.claude/agents/debate-checklist.md` und `.claude/skills/agent-debate/SKILL.md`

---

## Feature Naming Convention

```
/features/
├── PROJ-1-user-authentication.md
├── PROJ-2-dashboard-overview.md
├── PROJ-3-incident-management.md
└── ...
```

- `PROJ-X`: Sequential feature ID
- `feature-name`: Kebab-case description
- Each file contains: User Stories + Acceptance Criteria + Tech Design + QA Results
