# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| latest (main) | Yes |
| older releases | No — upgrade to latest |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities via email to: **security@shieldpilot.dev**

Include:
- Description of the vulnerability
- Steps to reproduce
- Affected component (scanner, hook, API, auth, etc.)
- Potential impact
- Your suggested fix (optional)

We will acknowledge receipt within 48 hours and aim to release a fix within 14 days for critical issues.

## Scope

In scope:
- Prompt injection bypass (evading the scanner)
- Hook bypass (executing blocked commands)
- Authentication/authorization flaws in the dashboard API
- Log tampering that bypasses chain integrity verification
- Secrets leakage (credentials appearing in logs or API responses)

Out of scope:
- Vulnerabilities in dependencies (report to upstream)
- Denial of service via resource exhaustion on self-hosted instances
- Issues in `sentinel.example.yaml` demo credentials

## Disclosure Policy

We follow coordinated disclosure. After a fix is released, you are welcome to publish details. Credit will be given in the release notes unless you prefer to remain anonymous.
