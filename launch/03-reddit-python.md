# Reddit — r/Python
# Posten auf: https://www.reddit.com/r/Python/submit
# Timing: Donnerstag
# Flair: "I Made This"
# WICHTIG: Nicht verkaufen. Technisch sein. Mit Frage enden.

## Title:
I built a security layer for AI coding agents — 9 risk analyzers, pure regex, <1ms per evaluation

## Text:
Been working on this for a while and wanted to share: **ShieldPilot** is an open-source security platform that evaluates shell commands before AI coding agents can execute them.

**Why I built it:**
AI agents like Claude Code have full shell access. After reading about an AI agent being used for autonomous cyber espionage against 30 targets, I wanted something that sits between the agent and my system.

**How it works:**
Every command goes through 9 independent analyzers — each one checks for a different attack category (destructive ops, credential theft, exfiltration, etc.). Scoring is 0-100, max-weighted across analyzers.

```
shield.evaluate("rm -rf /")
# {'score': 100, 'action': 'block', 'signals': [{'category': 'destructive_filesystem', 'score': 100}]}

shield.evaluate("ls -la")
# {'score': 0, 'action': 'allow', 'signals': []}
```

**Tech stack:**
- Python 3.9+ / FastAPI
- Each analyzer is its own module in `engine/analyzers/`
- Prompt injection scanner: 178+ compiled regex patterns in 19 categories
- SQLAlchemy + SQLite with SHA-256 hash chaining for audit trail
- Vanilla JS dashboard (no React, no build step, no node_modules)
- 2,600+ pytest tests

**Things I learned:**
- Regex-based detection gets surprisingly high recall. The bottleneck is precision (false positives), not recall.
- The hardest injection patterns to detect are "narrative policy erosion" — gradual context shifts instead of obvious overrides.
- Max-weighted scoring beats averaging because one critical signal should dominate, not be diluted by many safe ones.

GitHub: https://github.com/maxwalser001-del/shieldpilot

MIT licensed. Feedback welcome — especially on the analyzer architecture. How would you structure something like this differently?
