---
name: systematic-debugging
description: Systematic debugging skill. Mandatory for any bug, failing test, unexpected behavior, production issue, performance problem, or integration failure. Enforces root cause investigation before fixes. No fixes without root cause analysis first. Phases must be followed in order.
---

# Systematic Debugging Skill

## When to use this skill
This skill is mandatory for:
- Any bug
- Any failing test
- Any unexpected behavior
- Any production issue
- Any performance problem
- Any integration failure

Apply this skill BEFORE proposing fixes.

If unsure: apply it.

---

## Core principle
Fixing symptoms creates new bugs.
Root causes must be identified before fixes.

If Phase 1 is not complete, fixes are not allowed.

---

## The Iron Law
**NO FIXES WITHOUT ROOT CAUSE INVESTIGATION FIRST**

If a fix is proposed before root cause analysis, stop and restart.

---

## Debugging Phases (must be followed in order)

### Phase 1: Root Cause Investigation (MANDATORY)

Before attempting ANY fix:

#### 1. Read errors carefully
- Read full error messages
- Read entire stack traces
- Note line numbers, files, error codes
- Do not skip warnings

#### 2. Reproduce consistently
- Can it be reproduced reliably?
- What exact steps trigger it?
- If not reproducible: gather more data, do not guess

#### 3. Check recent changes
- Recent commits
- Config changes
- Dependency updates
- Environment differences

#### 4. Gather evidence in multi-component systems
If multiple layers exist (frontend → API → DB, CI → build → deploy):

For EACH boundary:
- Log inputs
- Log outputs
- Verify config propagation
- Verify state transitions

Run once to locate WHERE it breaks.
Then investigate that component only.

#### 5. Trace data flow
When error is deep in stack:
- Trace backward from failure
- Identify where bad data originates
- Fix at the source, not at the crash point

---

### Phase 2: Pattern Analysis

Before fixing:
- Find similar working examples in the codebase
- Compare working vs broken behavior
- List ALL differences, even small ones
- Identify required dependencies and assumptions

Do not assume differences "don't matter".

---

### Phase 3: Hypothesis and Testing

Apply scientific method:

- Form ONE hypothesis
  - "I believe X is the root cause because Y"
- Test minimally
  - Change one variable only
- Verify result
  - Works → proceed
  - Fails → form NEW hypothesis

If unsure:
- Say "I don't understand yet"
- Research more
- Ask for clarification

Never stack fixes.

---

### Phase 4: Implementation

#### 1. Create failing test first
- Minimal reproduction
- Automated test if possible
- Script if framework not available

Use **test-driven-development** skill.

#### 2. Implement single fix
- Address root cause
- One change only
- No refactoring, no extras

#### 3. Verify
- Test now passes
- No regressions
- Issue actually resolved

---

### Phase 4.5: Architectural Stop Condition

If:
- 3 fixes attempted
- Each fix reveals new issues elsewhere
- Fixes require massive refactoring

STOP.

This indicates architectural failure, not a bug.
Discuss architecture before continuing.

---

## Red flags (STOP immediately)
- "Quick fix"
- "Just try this"
- Multiple changes at once
- Skipping tests
- Guessing
- Fixing without understanding
- "One more attempt" after 2 failures

All require returning to Phase 1.

---

## Output requirements when this skill is used
Always output:
1. How the issue was reproduced
2. Evidence collected
3. Root cause identified
4. Hypothesis tested
5. Fix implemented
6. Tests added
7. Verification steps

---

## Related skills
- **test-driven-development**: Failing test before fix
- **testing-anti-patterns**: Test quality during fix
- **owasp-security**: If bug is security-related

---

## Final rule
Debugging without root cause analysis is not debugging.
It is guessing.

Never guess.
