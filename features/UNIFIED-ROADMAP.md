# ShieldPilot Unified Roadmap
## Internal Specs + OWASP LLM Top 10 (2025) + OWASP Web App Top 10 (2025)

> Last updated: 2025-02-09 | 475 tests passing | 8 of 10 specs complete

---

## Coverage Matrix

| OWASP LLM 2025 | ShieldPilot Coverage | Spec(s) | Status |
|---|---|---|---|
| **LLM01 Prompt Injection** | Scanner (46 patterns), InputSanitizer, FuzzyMatcher, 2-pass pipeline | Spec 1, 8 | Done (Eval Corpus pending) |
| **LLM02 Sensitive Info Disclosure** | OutputValidator (9 leakage patterns), API key/token detection | Spec 2 | Done |
| **LLM03 Supply Chain** | SupplyChainAnalyzer (typosquatting, untrusted registries), CI pip-audit | Spec 1, CI | Done |
| **LLM04 Data Poisoning** | N/A (ShieldPilot guards agents, doesn't train models) | — | Not applicable |
| **LLM05 Improper Output Handling** | OutputValidator (XSS prevention, HTML sanitization, response filtering) | Spec 2 | Done |
| **LLM06 Excessive Agency** | Hook intercepts all tool calls, risk engine (8 analyzers), CircuitBreaker | Spec 1, 3 | Done |
| **LLM07 System Prompt Leakage** | Scanner patterns (fake_system_prompt), OutputValidator leakage detection | Spec 1, 2 | Done |
| **LLM08 Vector/Embedding Weakness** | N/A (ShieldPilot doesn't use RAG) | — | Not applicable |
| **LLM09 Misinformation** | N/A (ShieldPilot is a security tool, not a content generator) | — | Not applicable |
| **LLM10 Unbounded Consumption** | Billing tiers, daily command limits, rate limiting, CircuitBreaker | Spec 9 | Done |

| OWASP Web App 2025 | ShieldPilot Coverage | Status |
|---|---|---|
| **A01 Broken Access Control** | JWT auth, admin checks, ownership verification, API key scoping | Done |
| **A02 Security Misconfiguration** | Config validation (Pydantic), hardened defaults, protected paths | Done |
| **A03 Supply Chain Failures** | pip-audit in CI, SupplyChainAnalyzer, dependency pinning | Done |
| **A04 Cryptographic Failures** | bcrypt passwords, SHA-256 hashing, JWT HS256 | Done |
| **A05 Injection** | InputSanitizer, parameterized SQLAlchemy queries, output escaping | Done |
| **A06 Insecure Design** | Rate limiting, circuit breaker, fail-closed hook, threat modeling | Done |
| **A07 Auth Failures** | Rate-limited login/register, email verification, Google OAuth | Done |
| **A08 Integrity Failures** | Tamper-proof audit chain (SHA-256 hash chain), chain health API | Done |
| **A09 Logging Failures** | Structured audit logging, auto-incident creation, chain verification | Done |
| **A10 Exception Handling** | Unified error format (dict), fail-closed hook, no stack traces to users | Done |

---

## Spec Status Overview

| # | Spec | OWASP Mapping | Status |
|---|---|---|---|
| 1 | Hook Decision & Risk Engine | LLM01, LLM06, LLM03 | Done |
| 2 | Output Validation & Failure Policy | LLM02, LLM05, LLM07 | Done |
| 3 | Protected Paths & Least Privilege | LLM06, A01 | Done |
| 4 | Observability & Contract Consistency | A09, A10 | Done |
| 5 | Latency Benchmarks | — (quality) | Done |
| 6 | Test Coverage (>400 tests) | A06 | Done (475 tests) |
| 7 | Explainability & Audit Chain | A08, A09 | Done |
| 8 | **Eval Corpus** | LLM01 | **Pending** |
| 9 | Billing & Rate Limiting | LLM10, A06 | Done |
| 10 | **OS Compatibility Matrix** | — (quality) | **Pending** |

---

## Detailed Spec Descriptions

### Spec 1 — Hook Decision & Risk Engine [DONE]

**What it covers:**
- PreToolUse hook intercepts Bash, Write, Edit tool calls
- 8 risk analyzers: Privilege Escalation, Persistence, Network Exfiltration, Credential Access, Obfuscation, Malware Pattern, Supply Chain, Destructive Filesystem
- Risk scoring 0-100 with action thresholds (allow/warn/block)
- Read-only tool fast path (Glob, Read, Grep skip engine)
- Blacklist/whitelist with instant exit

**OWASP LLM01 (Prompt Injection):** 46 regex patterns across 6 categories (jailbreak, instruction override, tool hijacking, role manipulation, encoding bypass, data exfiltration) with 2-pass detection pipeline.

**OWASP LLM03 (Supply Chain):** Typosquatting detection (Levenshtein distance against 15 popular packages), untrusted registry flagging, piped install detection.

**OWASP LLM06 (Excessive Agency):** Every tool call passes through the hook before execution. Dangerous commands are blocked, risky commands warn, safe commands pass. Circuit breaker blocks repeat offenders (5 detections in 60s = 5min block).

---

### Spec 2 — Output Validation & Failure Policy [DONE]

**What it covers:**
- OutputValidator with 9 leakage detection patterns
- XSS prevention (12 dangerous HTML tags, event handlers, JS URIs)
- Response length limiting (50K chars)
- Fail-closed policy (hook errors = block, not allow)

**OWASP LLM02 (Sensitive Info Disclosure):** Detects API keys (AWS AKIA, OpenAI sk-, GitHub ghp_), bearer tokens, credential strings, .env leaks before they reach the user.

**OWASP LLM05 (Improper Output Handling):** All agent output is sanitized: HTML escaping, script tag removal, event handler stripping, data: URI blocking.

**OWASP LLM07 (System Prompt Leakage):** Detects "SYSTEM: You are" patterns and instruction list leakage in outputs.

---

### Spec 3 — Protected Paths & Least Privilege [DONE]

**What it covers:**
- Configurable protected paths in sentinel.yaml
- Write/Edit tool path validation before execution
- Critical system paths hardcoded (/etc, /usr, /var, /boot, /bin, /sbin, /lib)
- chmod 000 detection on important paths

**OWASP LLM06 (Excessive Agency):** Filesystem access is scoped. Agents cannot write to system directories or protected project paths.

**OWASP A01 (Broken Access Control):** Path traversal prevented. Write operations validated server-side.

---

### Spec 4 — Observability & Contract Consistency [DONE]

**What it covers:**
- Chain health API endpoint (/api/health/chain) for admin
- Dashboard chain health widget (healthy/tampered indicator)
- Auto-incident creation on chain tampering (verify_chain_with_alert)
- Hook integration tests (11 tests covering full E2E flow)
- Unified error format (all HTTPExceptions return dict payloads)

**OWASP A09 (Logging Failures):** Structured logging across all components. Security events automatically trigger incidents. Chain integrity continuously monitored.

**OWASP A10 (Exception Handling):** Consistent error format. No stack traces leaked. Errors are structured dicts with error/detail keys.

---

### Spec 5 — Latency Benchmarks [DONE]

**What it covers:**
- Engine benchmarks: 5 tests (safe/complex/empty/blacklisted commands, distribution stability)
- Scanner benchmarks: 4 tests (clean/long/injection text, empty input)
- Hook E2E benchmarks: 5 tests (read-only fast path, write tool, bash safe/dangerous, stability)
- Performance targets: ENGINE p95<30ms, HOOK p95<50ms, SCANNER p95<50ms, FAST_PATH<5ms
- CI enforcement: benchmark job runs on PRs

---

### Spec 6 — Test Coverage [DONE]

**What it covers:**
- 475 tests across 31 test files
- Categories: API (7), Scanner (5), Engine (4), Hook (6), CLI (2), Explainability (1), Logger (1), Sandbox (1), Benchmarks (3), Config (2)
- Zero errors, zero failures

---

### Spec 7 — Explainability & Audit Chain [DONE]

**What it covers:**
- Tamper-proof hash chain (SHA-256) across 5 database tables
- Per-signal risk explanations in API responses
- Chain verification with automatic incident creation
- Dashboard visualization of risk signals

**OWASP A08 (Integrity Failures):** Every log entry is chained via SHA-256 hash. Tampering breaks the chain and auto-creates a critical incident.

**OWASP A09 (Logging Failures):** Full audit trail with timestamps, risk scores, signals, and actions. Queryable via API with tier-based retention.

---

### Spec 8 — Eval Corpus [PENDING]

**What it covers:**
- Curated corpus of prompt injection attack samples
- Regression test suite: known attacks must be detected
- False positive corpus: benign inputs must not trigger
- Detection rate metrics per category
- CI integration: eval suite runs on every PR

**OWASP alignment:**
- **LLM01 (Prompt Injection):** Continuous validation that all known attack vectors are caught. Prevents detection regressions.
- Corpus categories should mirror OWASP LLM01 attack taxonomy:
  - Direct injection (user-facing)
  - Indirect injection (data-embedded)
  - Multi-turn injection (conversation-based)
  - Encoding-based evasion
  - Typoglycemia evasion

**Planned structure:**
```
tests/eval/
  corpus/
    attacks/          # Known-bad samples (must detect)
      jailbreak/
      tool_hijacking/
      data_exfiltration/
      encoding_bypass/
      instruction_override/
      role_manipulation/
    benign/           # Known-good samples (must NOT flag)
      code_snippets/
      documentation/
      normal_prompts/
  test_eval_detection.py    # Parametrized tests
  test_eval_false_positives.py
  metrics.py                # Detection rate calculator
```

---

### Spec 9 — Billing & Rate Limiting [DONE]

**What it covers:**
- 4 billing tiers: free (50/day), pro (500/day), enterprise (5000/day), unlimited (super-admin)
- Daily command metering with database tracking
- Rate-limited auth endpoints (login, register)
- Circuit breaker (sliding window, 5 detections/60s = 5min block)
- Paywall UI for non-admin users
- Tier-based history retention

**OWASP LLM10 (Unbounded Consumption):** Hard daily limits per tier prevent resource abuse. Circuit breaker stops automated attacks. Rate limiting on auth endpoints prevents brute force.

---

### Spec 10 — OS Compatibility Matrix [PENDING]

**What it covers:**
- CI matrix: 2 OS (ubuntu, macos) x 4 Python (3.9-3.12) = 8 jobs
- Platform-specific behavior tests (Unix preexec_fn, path separators)
- Windows exclusion documentation (sandbox uses Unix-only features)
- CI already configured but needs platform-specific test annotations

**Planned work:**
- Add `@pytest.mark.skipif(sys.platform == ...)` markers where needed
- Verify sandbox preexec_fn behavior across OS
- Test path handling (Unix `/` vs potential Windows `\`)
- Document Windows limitations in README

---

## OWASP Gap Analysis

### Fully Covered

| OWASP Category | ShieldPilot Feature | Confidence |
|---|---|---|
| LLM01 Prompt Injection | 46 patterns, sanitizer, fuzzy matcher, 2-pass pipeline | High |
| LLM02 Sensitive Info Disclosure | OutputValidator (9 patterns), credential detection | High |
| LLM03 Supply Chain | SupplyChainAnalyzer, CI pip-audit, typosquatting | High |
| LLM05 Improper Output Handling | XSS prevention, HTML sanitization, length limits | High |
| LLM06 Excessive Agency | Hook intercept, risk engine, circuit breaker, protected paths | High |
| LLM07 System Prompt Leakage | Scanner + OutputValidator leakage detection | High |
| LLM10 Unbounded Consumption | Billing tiers, rate limiting, circuit breaker | High |
| A01-A10 (Web App) | All 10 categories covered via auth, crypto, logging, error handling | High |

### Partially Covered (Enhancement Opportunities)

| OWASP Category | Current State | Enhancement |
|---|---|---|
| LLM01 Prompt Injection | Pattern-based detection only | Spec 8: Add eval corpus for regression testing and detection rate measurement |
| LLM03 Supply Chain | Typosquatting for pip/npm only | Could add: Go modules, Rust crates, Ruby gems detection |
| LLM06 Excessive Agency | Tool-level blocking | Could add: per-session permission budgets, human-in-the-loop for high-risk chains |

### Not Applicable

| OWASP Category | Reason |
|---|---|
| LLM04 Data Poisoning | ShieldPilot guards AI agents; it doesn't train models |
| LLM08 Vector/Embedding Weakness | No RAG or vector DB in ShieldPilot |
| LLM09 Misinformation | ShieldPilot is a security tool, not a content generator |

---

## Phase Plan (Remaining Work)

### Phase 6 — Eval Corpus (Spec 8) + OS Matrix (Spec 10)

**Priority: Spec 8 first** (directly strengthens LLM01 compliance)

| Step | Description | Agent | OWASP |
|---|---|---|---|
| 6.1 | Create attack corpus (50+ samples across 6 categories) | QA Engineer | LLM01 |
| 6.2 | Create benign corpus (30+ samples of safe content) | QA Engineer | LLM01 |
| 6.3 | Build parametrized eval test suite | Backend Dev | LLM01 |
| 6.4 | Add detection rate metrics and CI reporting | DevOps | LLM01 |
| 6.5 | Add platform-specific test markers | Backend Dev | — |
| 6.6 | Verify CI matrix passes on all OS/Python combos | DevOps | — |

---

## Summary

```
Total OWASP LLM Top 10 2025 categories:     10
  Fully covered:                               7  (LLM01-03, 05-07, 10)
  Partially covered (pending eval corpus):     1  (LLM01 via Spec 8)
  Not applicable:                              3  (LLM04, 08, 09)

Total OWASP Web App Top 10 2025 categories:  10
  Fully covered:                              10  (A01-A10)

Total internal specs:                         10
  Complete:                                    8  (Specs 1-7, 9)
  Pending:                                     2  (Specs 8, 10)

Test count:                                  475  (0 failures, 0 errors)
```
