---
name: root-cause-tracing
description: Root cause tracing skill. Use whenever a bug appears deep in the call stack, data is incorrect but origin unclear, or a fix at the error site feels suspiciously easy. Mandatory before proposing fixes for deep or indirect failures. Enforces backward tracing through the call chain to the original trigger.
---

# Root Cause Tracing Skill

## When to use this skill
Use this skill whenever:
- A bug appears deep in the call stack
- An error occurs far from the entry point
- Data is incorrect but origin is unclear
- Files are created in the wrong location
- State appears "corrupted"
- A fix at the error site feels suspiciously easy

This skill is mandatory before proposing fixes for deep or indirect failures.

---

## Core principle
Errors that appear deep in execution are almost never the real problem.

**Fixing where the error appears is treating a symptom.**

Always trace backward through the call chain to find the original trigger, then fix at the source.

---

## The tracing rule
**NEVER fix just where the error appears.**

If you cannot trace backward:
- Add instrumentation
- Gather evidence
- Or explicitly declare a dead end (rare)

---

## The Root Cause Tracing Process

### Step 1: Observe the symptom
- What exactly failed?
- Where did it fail?
- What is the error message or behavior?

Do not jump to conclusions.

---

### Step 2: Identify the immediate cause
- What line of code directly caused the failure?
- What operation failed?

This is NOT the root cause — it is the starting point.

---

### Step 3: Ask "What called this?"
Trace one level up:
- Which function called this?
- What parameters were passed?
- What assumptions were made?

Repeat this step recursively.

---

### Step 4: Trace values backward
At each level:
- What values were passed?
- Are any values empty, null, default, or unexpected?
- Where were they originally set?

Follow the data, not the code structure.

---

### Step 5: Find the original trigger
The root cause is usually:
- An uninitialized value
- A default used too early
- A lifecycle order violation
- A missing guard at the boundary
- An assumption that "this will never be empty"

Stop when you find:
- The FIRST place the value became invalid
- The FIRST incorrect assumption

---

## Instrumentation (when tracing manually is hard)

When the call chain is unclear, add temporary instrumentation **before the dangerous operation**.

Rules:
- Log BEFORE the failure, not after
- Include:
  - Parameters
  - cwd / environment
  - Stack trace
- In tests, use `console.error()` (not structured logger)

Example:
```ts
console.error('DEBUG git init', {
  directory,
  cwd: process.cwd(),
  env: process.env.NODE_ENV,
  stack: new Error().stack,
});
```

Remove all instrumentation after fixing.

---

## Output requirements when this skill is used
Always output:
1. Symptom observed
2. Immediate cause (where error appeared)
3. Trace path (each level from symptom to root)
4. Root cause identified (the original trigger)
5. Fix applied at the source
6. Verification that trace is complete

---

## Related skills
- **systematic-debugging**: Parent skill — use root-cause-tracing during Phase 1 step 5
- **test-driven-development**: Failing test before fix at the origin
- **testing-anti-patterns**: Test quality during fix
- **owasp-security**: If root cause is security-related

---

## Final rule
The error site is a symptom.
The root cause is upstream.

Never fix downstream. Always trace upstream.
