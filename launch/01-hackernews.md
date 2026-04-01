# Hacker News — Show HN Post
# Posten auf: https://news.ycombinator.com/submit
# Timing: Mittwoch 14:00 CET (= 8am ET)
# WICHTIG: Ersten 3 Stunden ALLE Kommentare beantworten!

## Title:
Show HN: I built a firewall that sits between AI agents and your terminal

## URL:
https://github.com/maxwalser001-del/shieldpilot

## Text:
After reading about a state-sponsored threat actor using an AI coding agent to autonomously run cyber espionage against 30 targets [1], I started wondering — what's stopping my own Claude Code from doing something destructive if it gets a bad prompt?

Nothing, it turns out. So I built ShieldPilot.

It's a PreToolUse hook for Claude Code (and works standalone) that evaluates every command before execution:

  $ sentinel run "rm -rf /"
  → risk_score: 100 | action: BLOCK

  $ sentinel run "ls -la"
  → risk_score: 0 | action: ALLOW

Under the hood: 9 regex-based analyzers (no LLM calls, <1ms) check for destructive filesystem ops, credential access, network exfiltration, privilege escalation, persistence, obfuscation, supply chain attacks, malware patterns, and prompt injection. 178+ injection patterns across 19 categories.

Everything is logged to a SHA-256 hash chain for tamper-proof auditing. There's also a web dashboard for monitoring.

The whole thing is ~80k lines of Python, 2,600+ tests, MIT licensed.

What I'd love feedback on:
- Are there attack vectors I'm missing?
- Is regex-based detection sufficient or do you think an LLM layer is necessary?
- Would you actually use something like this?

[1] https://thehackernews.com/2026/03/the-kill-chain-is-obsolete-when-your-ai.html

Live demo: https://shieldpilot.dev

---

# ERSTER KOMMENTAR (sofort nach dem Post selbst posten):

Hi, maker here. Happy to answer questions about the architecture.

A few things I learned building this:

1. Regex-based detection gets you surprisingly far — 100% recall on our test corpus. The hard part is false positives, not false negatives.

2. The hardest attack category to detect: "narrative policy erosion" — where an injection gradually shifts the agent's behavior instead of a single obvious override.

3. The risk engine uses max-weighted scoring across 9 independent analyzers. A single high-score signal dominates, which prevents dangerous commands from hiding behind many low-score signals.

Source code is straightforward Python/FastAPI. The risk engine is in sentinelai/engine/ and each analyzer is its own module. PRs welcome.
