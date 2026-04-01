# ShieldPilot

**Security firewall for autonomous AI coding agents.**

ShieldPilot evaluates every command your AI agent tries to execute — before it runs. Zero trust for AI-generated shell commands.

<div class="grid cards" markdown>

-   :material-shield-check:{ .lg .middle } **Risk Engine**

    ---

    9 specialized analyzers score every command 0–100 across categories: destructive filesystem ops, privilege escalation, network exfiltration, credential access, persistence, obfuscation, malware patterns, supply chain attacks, and prompt injection.

-   :material-hook:{ .lg .middle } **Claude Code Hook**

    ---

    One command installs ShieldPilot as a Claude Code pre-tool-use hook. Your agent runs autonomously while ShieldPilot silently blocks dangerous actions.

    [`sentinel hook install`](getting-started/hook.md)

-   :material-magnify-scan:{ .lg .middle } **Prompt Injection Scanner**

    ---

    178+ patterns across 19 categories. Detects jailbreaks, instruction overrides, role manipulation, encoding bypasses, and data exfiltration attempts in 3 passes.

-   :material-chart-line:{ .lg .middle } **Web Dashboard**

    ---

    Real-time monitoring: command logs, incident management, activity feed, and cryptographic hash-chain audit trail verification.

</div>

## How it works

```
AI Agent tries to run a command
         │
         ▼
  ShieldPilot Hook (pre-tool-use)
         │
         ▼
  ┌──────────────────────────────────┐
  │  Risk Engine (9 analyzers)       │
  │  Prompt Injection Scanner        │
  │  LLM Reasoning (optional)        │
  └──────────────────────────────────┘
         │
   ┌─────┴──────┐
   │            │
score < 40   score >= 80
   │            │
 ALLOW        BLOCK ──→ Incident created
   │
score 40–79
   │
 WARN ──→ User confirms
```

## Quickstart

```bash
pip install sentinelai
sentinel init
sentinel hook install
```

That's it. Your Claude Code agent is now protected.

## Scoring

| Score | Action | Behavior |
|-------|--------|----------|
| 0–39  | ALLOW  | Auto-approved, runs silently |
| 40–79 | WARN   | User prompted to confirm |
| 80–100| BLOCK  | Rejected, incident created |

Thresholds are fully configurable in [`sentinel.yaml`](config/sentinel-yaml.md).
