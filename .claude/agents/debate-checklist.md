# Debate Checklist (Regel F)

Quick-Reference fuer strukturierte Agent-Diskussionen vor kritischen Entscheidungen.

## Trigger-Check

Trifft mindestens eins zu?

- [ ] Security-relevante Aenderung (Auth, RBAC, Tokens, Hooks, Policy Engine, Audit Chain, Rate Limiting)
- [ ] Datenmodell-Aenderung oder Migration (neue Tables, ALTER TABLE, Schema)
- [ ] Paywall oder Billing-Logik (Tier-Checks, Limits, Stripe)
- [ ] Neue externe Integration oder Dependency (Packages, APIs, OAuth)
- [ ] Performance-kritischer Pfad (SSE, Risk Engine, Audit Write Path)
- [ ] UX-Aenderung die Nutzerfluss veraendert (Login, Incidents, Dashboard Kern)

**Wenn JA → Debate ist verpflichtend vor Umsetzung**
**Wenn NEIN → Direkt umsetzen**

---

## Debate-Template

### 1. Problem Statement
> [Ein Satz: Was muss entschieden werden?]

### 2. Options

| Option | Beschreibung |
|--------|-------------|
| A | ... |
| B | ... |
| C (optional) | ... |

### 3. Agent Inputs (je max 3 Bullets)

**Solution Architect:**
- ...

**Requirements Engineer:**
- ...

**Backend Dev:**
- ...

**Frontend Dev:**
- ...

**QA Engineer:**
- ...

**DevOps Engineer:**
- ...

### 4. Decision
> [Entscheidung + Begruendung]
> Falls unklar: Eine gezielte Frage an den User.

### 5. Handoff

- **Owner:** [Agent der implementiert]
- **Reviewer:** [Agent(s) die reviewen]
- **QA:** [Agent der testet]
- **DevOps:** [Agent der Gates prueft]

### 6. Acceptance Criteria

- [ ] ...
- [ ] ...

---

## Definition of Done

- [ ] Tests geschrieben/bestanden (wo relevant)
- [ ] Security Check durchgefuehrt (falls Security-relevant)
- [ ] Manual Verification Steps dokumentiert und ausgefuehrt
