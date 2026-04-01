---
name: test-driven-development
description: Test driven development skill. Enforces strict red-green-refactor cycle. Use before writing any production code for new features, bug fixes, refactoring, or behavior changes. No production code without a failing test first. No exceptions without explicit human approval.
---

# Test Driven Development (TDD) Skill

## When to use this skill
Use this skill **before writing any production code** when:
- Implementing a new feature
- Fixing a bug
- Refactoring behavior
- Changing system behavior or edge cases

Exceptions (must be explicitly approved by human):
- Throwaway prototypes
- Generated code
- Configuration-only changes

If unsure: **apply TDD**.

---

## Core principle
Write the test first.
Watch it fail.
Write the minimum code to make it pass.

If you did not observe the test fail, you cannot trust the test.

---

## The Iron Law (absolute)
**NO PRODUCTION CODE WITHOUT A FAILING TEST FIRST**

If code exists before a failing test:
- Delete the code
- Do not keep it as reference
- Do not adapt it
- Re-implement only after tests exist

Violating this rule invalidates the change.

---

## The TDD cycle (mandatory)

1. RED
   Write **one** minimal failing test for **one** behavior.

2. VERIFY RED
   Run the test and confirm:
   - It fails (not errors)
   - It fails for the expected reason
   - It fails because behavior is missing

3. GREEN
   Write the **simplest possible code** to pass the test.

4. VERIFY GREEN
   - The new test passes
   - All existing tests pass
   - No warnings or errors

5. REFACTOR
   - Clean up code
   - Improve naming
   - Remove duplication
   - Do NOT add behavior

Repeat for the next behavior.

---

## Writing good tests

A good test:
- Covers exactly **one behavior**
- Has a clear, descriptive name
- Uses real code (no mocks unless unavoidable)
- Describes *what should happen*, not how

Bad signals:
- Test names like `test1` or `retry works`
- Testing mocks instead of behavior
- Multiple behaviors in one test
- Tests passing immediately

---

## Red flags (STOP immediately)
If any of the following happen:
- Code written before test
- Test passes immediately
- Tests added "later"
- Manual testing used instead of tests
- Rationalizing "just this once"

→ **Delete the code and restart with TDD**

---

## Bug fix rule
Every bug fix must start with:
- A failing test that reproduces the bug
- The test must fail before the fix
- The test must pass after the fix
- The test must remain to prevent regression

Never fix bugs without tests.

---

## Output requirements when this skill is used
When applying TDD, always output:
1. Tests added (with file paths)
2. Proof that tests failed before implementation
3. Production code added
4. Verification steps
5. Any refactoring performed

---

## Design guidance
If tests are hard to write:
- The design is unclear
- The interface is too complex
- Dependencies are too coupled

Simplify the design before proceeding.

---

## Paired skills
**owasp-security**: When code touches security surfaces (auth, access control, billing, input validation, webhooks, agent hooks), also apply owasp-security. Security code requires both a failing test first and OWASP checklist verification after.

**testing-anti-patterns**: Always active alongside this skill. Prevents testing mock behavior, test-only production methods, and incomplete mocks. TDD enforces test-first; testing-anti-patterns enforces test quality.

---

## Final rule
Production code without a failing test first is **not acceptable**.

No exceptions without explicit human approval.
