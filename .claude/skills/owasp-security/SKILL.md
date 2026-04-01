---
name: owasp-security
description: OWASP Top 10 (2025) security audit and code review skill. Use when implementing or reviewing authentication, authorization, billing, input validation, webhooks, agent hooks, audit logging, or any security-sensitive code. Covers OWASP Top 10:2025, ASVS 5.0, and agentic AI security patterns.
---

# OWASP Security Skill (Top 10 + ASVS + Agentic AI)

## What this skill is for
Use this skill when implementing or reviewing:
- Authentication, sessions, OAuth
- Authorization and role based access control
- Paywalls, billing, entitlements
- Input validation, file handling, uploads
- Webhook endpoints (Stripe)
- Agent hooks, tool execution, prompt injection protection
- Audit logging and incident workflows

## Default security stance
- Deny by default
- Enforce server side checks
- Fail closed on error
- Do not leak internals
- Prefer allowlists over denylists

## Quick reference (OWASP Top 10 2025)
A01 Broken Access Control: deny by default, verify ownership, enforce server side
A02 Security Misconfiguration: harden configs, disable defaults, minimize features
A03 Supply Chain Failures: lock versions, verify integrity, audit dependencies
A04 Cryptographic Failures: TLS 1.2+, modern ciphers, Argon2 or bcrypt for passwords
A05 Injection: parameterized queries, input validation, safe APIs
A06 Insecure Design: threat model, rate limit, security controls by design
A07 Auth Failures: MFA for sensitive, secure sessions, breached password checks
A08 Integrity Failures: verify packages, safe serialization, signature checks
A09 Logging Failures: log security events, structured logs, alerting
A10 Exception Handling: fail closed, hide internals, log with context

## Code review checklist (always apply)
### Input
- Validate all input server side
- Use parameterized queries
- Enforce length limits
- Prefer allowlists

### Auth and sessions
- Argon2 or bcrypt password hashing
- Strong session tokens (128+ bits)
- Invalidate sessions on logout
- Rate limit auth endpoints

### Access control
- Authorization on every request
- Ownership checks for object references
- No client controlled IDs without verification
- Prevent privilege escalation

### Data protection
- HTTPS everywhere
- No secrets in logs or URLs
- Secrets in env or vault

### Error handling
- No stack traces to users
- Consistent errors, prevent enumeration
- Fail closed on errors

## Agentic AI security checklist
- Sanitize agent inputs
- Least privilege tools
- Short lived scoped credentials
- Verify and sandbox plugins and MCP servers
- Isolate code execution
- Authenticate agent communications
- Circuit breakers between agent components
- Human approval for sensitive actions
- Behavior monitoring and kill switch

## Paired skill: test-driven-development
When implementing security fixes or new security features, also apply the **test-driven-development** skill. Every security control must have:
- A failing test before the fix (TDD Iron Law)
- OWASP checklist verification after the fix (this skill)

Security code without tests is untrusted code.

## Required output when used
When this skill is applied, output:
1 Security risks found
2 Fixes implemented
3 Tests added
4 How to verify manually
5 Any follow up hardening tasks
