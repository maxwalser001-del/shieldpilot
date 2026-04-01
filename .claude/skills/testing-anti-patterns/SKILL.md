---
name: testing-anti-patterns
description: Testing anti-patterns detection and prevention skill. Automatically apply when writing or changing tests, adding mocks, or creating test utilities. Prevents testing mock behavior, test-only production methods, incomplete mocks, and other common testing mistakes. Mandatory alongside test-driven-development.
---

# Testing Anti-Patterns Skill

## When to use this skill
Automatically apply this skill when:
- Writing or changing tests
- Adding or modifying mocks
- Adding test utilities
- Tempted to add methods "just for tests"
- Tests feel fragile, complex, or unclear

This skill is mandatory alongside Test Driven Development.

---

## Core principle
Tests must verify **real behavior**, not mock behavior.

Mocks are tools to isolate dependencies — they are never the subject of the test.

If a test passes only because a mock exists, the test is invalid.

---

## Iron Laws
1. NEVER test mock behavior
2. NEVER add test-only methods to production code
3. NEVER mock dependencies you do not fully understand

Violation of these rules invalidates the test.

---

## Anti-Pattern 1: Testing mock behavior

### Red flag
Assertions that verify a mock exists or was called instead of verifying behavior.

### Gate check (mandatory)
Before asserting anything related to a mock, ask:
- "Am I testing real behavior, or just confirming a mock exists?"

If testing mock existence → STOP and fix the test.

---

## Anti-Pattern 2: Test-only methods in production code

### Red flag
Methods added to production classes that exist only to support tests.

### Rule
Production code must not contain test-only lifecycle or cleanup logic.

If cleanup is needed:
- Implement it in test utilities
- Keep production classes clean and minimal

---

## Anti-Pattern 3: Mocking without understanding dependencies

### Red flag
Mocking a method without knowing:
- Its side effects
- What downstream code depends on

### Mandatory process before mocking
1. Run test with real implementation first
2. Observe required side effects
3. Mock only the slow or external part
4. Never mock the method under test

---

## Anti-Pattern 4: Incomplete mocks

### Red flag
Mocks that only include fields the test currently uses.

### Rule
Mocks must mirror the **complete real data structure**, not partial guesses.

If unsure:
- Inspect real API responses
- Include all documented fields
- Match real schema shape

---

## Anti-Pattern 5: Tests as an afterthought

### Red flag
Implementation completed before tests exist.

### Rule
Testing is part of implementation.
A feature is not "done" without tests.

---

## When mocks become too complex
Warning signs:
- Mock setup longer than test logic
- Mocking everything "to be safe"
- Test breaks when mock changes
- Cannot explain why a mock is needed

Preferred alternative:
- Use integration tests with real components

---

## Relationship to TDD
TDD prevents these anti-patterns because:
- Tests are written first
- Failures are observed
- Dependencies are understood before mocking

If a test verifies mock behavior, TDD was violated.

---

## Paired skill: test-driven-development
This skill is mandatory alongside **test-driven-development**. TDD enforces test-first; this skill enforces test quality.

---

## Output requirements when this skill is used
Whenever this skill applies, output:
1. What behavior is being tested
2. Why mocking is or is not necessary
3. What is mocked and at which level
4. Proof that test verifies real behavior

---

## Final rule
Mocks are helpers, not the subject.

If unsure:
- Remove the mock
- Run the test
- Reintroduce minimal mocking only if required
