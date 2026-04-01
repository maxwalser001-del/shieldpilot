---
name: feature-lifecycle
description: End-to-end feature delivery workflow for ShieldPilot agent teams. Orchestrates Requirements Engineer, Solution Architect, Frontend Dev, Backend Dev, QA Engineer, and DevOps through 7 gated phases. Use when starting a new feature, planning a sprint, coordinating agents, or checking delivery status. Trigger phrases include new feature, feature workflow, delivery pipeline, coordinate agents, start feature.
---

# ShieldPilot Feature Lifecycle

End-to-end workflow coordinating all 6 agents through gated phases to deliver a complete feature.

## Phase overview

```
Phase 1: Requirements -> Phase 2: Architecture -> Phase 3: API Contract
     |                        |                        |
Requirements Engineer    Solution Architect     Frontend + Backend Dev
     |                        |                        |
/features/PROJ-X.md     Tech-Design section    API Contract section
                                                       |
Phase 4: Implementation -> Phase 5: Code Review -> Phase 6: QA -> Phase 7: Deploy
     |                          |                      |              |
Frontend + Backend Dev    Cross-review agents     QA Engineer    DevOps Engineer
(parallel)
```

## Phase 1: Requirements

**Agent:** Requirements Engineer
**Entry:** User has described a feature idea
**Output:** /features/PROJ-X-feature-name.md

### Steps
1. Check features/ for next PROJ-X number
2. Analyze scope: single-responsibility check
3. Gather requirements via interactive questions
4. Write User Stories: "As [user-type] I want [action] so that [goal]"
5. Define testable Acceptance Criteria
6. Identify Edge Cases (minimum 3-5)
7. Document Dependencies
8. Get user approval

### Gate to Phase 2
- [ ] Feature spec exists at /features/PROJ-X-feature-name.md
- [ ] Status: Planned
- [ ] At least 3 User Stories
- [ ] At least 3 testable Acceptance Criteria
- [ ] At least 3 Edge Cases
- [ ] User approved

### Debate check
If feature involves any of the 6 debate triggers (security, data model, billing, integration, performance, UX), flag it now.

## Phase 2: Architecture

**Agent:** Solution Architect
**Entry:** Phase 1 complete and approved
**Output:** Tech-Design section in feature spec

### Steps
1. Read feature spec thoroughly
2. Check existing code for reuse:
   - Routes: grep @router sentinelai/api/routes.py
   - Models: grep "class.*Base" sentinelai/logger/database.py
   - Components: grep "export function" sentinelai/web/static/js/components.js
   - Pages: grep "function render" sentinelai/web/static/js/app.js
3. If debate trigger flagged, execute agent-debate skill NOW
4. Design Component Structure
5. Design Data Model
6. Make Tech Decisions with justifications
7. List Dependencies
8. Get user approval

### Gate to Phase 3
- [ ] Tech-Design section added to feature spec
- [ ] Component Structure documented
- [ ] Data Model described
- [ ] Tech Decisions justified
- [ ] Reuse opportunities identified
- [ ] If debate triggered: Decision Document exists
- [ ] User approved

## Phase 3: API Contract

**Agents:** Frontend Dev + Backend Dev (collaborative)
**Entry:** Phase 2 complete
**Output:** API Contract section in feature spec

### Steps
1. Both agents read spec and design
2. For each new endpoint, fill api-contract template
3. Both agents verify validation checklists
4. Contracts added to feature spec

### Gate to Phase 4
- [ ] API Contract section in feature spec
- [ ] Every endpoint has complete contract
- [ ] Backend validation checklist passed
- [ ] Frontend validation checklist passed
- [ ] Integration checks passed

**Skip:** If frontend-only (no new endpoints), skip to Phase 4.

## Phase 4: Implementation

**Agents:** Frontend Dev + Backend Dev (parallel)
**Entry:** Phase 3 complete (or skipped)
**Output:** Working code

### Backend Dev steps
1. Check existing code for reuse
2. Data model changes: update database.py, add migrate_database() entry
3. Add Pydantic request/response models to routes.py
4. Implement endpoint with proper Depends()
5. Add rate limiting if specified
6. Add super-admin bypass where needed
7. Close all DB sessions in try/finally
8. Write tests in tests/test_api/

### Frontend Dev steps
1. Check existing components for reuse
2. Add components to components.js (PascalCase, return HTML)
3. Add renderPageName() to app.js
4. Register route in routes object if new page
5. Use api() for backend calls
6. Use escapeHtml() for ALL dynamic content
7. Add Spinner() for loading, EmptyState() for errors
8. Use CSS variables only

### Rules
- Follow shieldpilot-conventions skill
- Backend and Frontend work in parallel (API contract is agreed)
- Use python3, use httpx

### Gate to Phase 5
- [ ] All code written
- [ ] Backend endpoints match API contract
- [ ] Frontend api() calls match API contract
- [ ] Tests passing (python3 -m pytest)
- [ ] Server starts without errors

## Phase 5: Code Review

**Agents:** Cross-review (Backend reviews Frontend, Frontend reviews Backend, Architect reviews both)
**Entry:** Phase 4 complete
**Output:** Review report in feature spec

### Steps
1. Each reviewer executes code-review skill checklist
2. Produce review report with PASS/FAIL per item
3. CRITICAL findings: must fix
4. MAJOR findings: should fix
5. MINOR findings: document for follow-up
6. Re-review after fixes

### Gate to Phase 6
- [ ] All CRITICAL resolved
- [ ] All MAJOR resolved or explicitly accepted
- [ ] Review report in feature spec
- [ ] All reviewers approve

## Phase 6: QA Testing

**Agent:** QA Engineer
**Entry:** Phase 5 complete
**Output:** QA report in feature spec

### Steps
1. Read spec: User Stories, Acceptance Criteria, Edge Cases
2. Test each Acceptance Criterion
3. Test each Edge Case
4. Security testing:
   - XSS attempts in all inputs
   - Auth bypass (missing/expired/wrong token)
   - IDOR (access other user's data)
   - Rate limit verification
   - Super-admin bypass verification
5. Run automated tests: python3 -m pytest
6. Document bugs with severity and reproduction steps
7. Make production-ready decision

### QA report format
```markdown
## QA Test Results
**Date:** [YYYY-MM-DD]

### Acceptance Criteria
- [x] AC-1: [description] - PASS
- [ ] AC-2: [description] - FAIL (BUG-1)

### Bugs Found
#### BUG-1: [title]
- Severity: Critical / Major / Minor
- Steps: 1... 2... 3...
- Expected: ...
- Actual: ...

### Summary
- X AC passed, Y bugs found
- Production-Ready: YES / NO
```

### Gate to Phase 7
- [ ] All Acceptance Criteria tested
- [ ] All Edge Cases tested
- [ ] Security testing completed
- [ ] No CRITICAL bugs
- [ ] No MAJOR bugs (or deferred with justification)
- [ ] Production-ready: YES

### Failure path
Bugs found: Return to Phase 4 for fixes, Phase 5 for re-review, Phase 6 for re-test.

## Phase 7: Deploy

**Agent:** DevOps Engineer
**Entry:** Phase 6 production-ready: YES
**Output:** Deployed and verified

### Steps
1. git status - ensure all changes committed
2. python3 -m pytest - full test suite
3. Restart server for Python changes
4. Verify at http://localhost:8420
5. Test new feature in browser
6. Check DevTools for console errors
7. Tag release if milestone

### Gate (feature complete)
- [ ] All code committed
- [ ] Tests passing
- [ ] Server running
- [ ] Feature verified in browser
- [ ] No console errors
- [ ] Feature spec status: Completed

## Debate integration

At ANY phase, if an agent identifies a concern matching the 6 debate triggers:
1. STOP current work
2. Flag the concern with trigger category
3. Execute agent-debate skill
4. Wait for Decision Document
5. Resume work

## Definition of Done

A feature is DONE when ALL are true:
- [ ] Feature spec exists with Status: Completed
- [ ] All Acceptance Criteria met
- [ ] Tech Design followed (deviations documented)
- [ ] API Contract matches implementation
- [ ] Code Review approved (no CRITICAL/MAJOR open)
- [ ] QA Report: production-ready YES
- [ ] Deploy verified
- [ ] All debate decisions followed
- [ ] Tests passing
- [ ] No security vulnerabilities
