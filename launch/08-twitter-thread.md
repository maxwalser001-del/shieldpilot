# Twitter/X Thread
# Posten auf: https://twitter.com/compose/tweet
# Timing: Donnerstag 12:30 CET
# Jeden Tweet als Reply auf den vorherigen posten

## Tweet 1 (Hook — muss alleine funktionieren):
I just open-sourced ShieldPilot.

It's a firewall that sits between AI coding agents and your terminal.

Your AI agent can run rm -rf /
Mine can't.

Here's how it works:

## Tweet 2 (Problem):
AI coding agents have full shell access.

One prompt injection and your agent:
• Deletes your files
• Steals your .env and SSH keys
• Installs a reverse shell
• Exfiltrates data to an external server

All autonomously. Without asking.

## Tweet 3 (Solution):
ShieldPilot evaluates every command before execution:

Score 0-39 → runs silently
Score 40-79 → paused for review
Score 80-100 → blocked

9 analyzers. <1ms. No LLM calls.

## Tweet 4 (Credibility):
Some numbers:

• 178+ injection patterns in 19 categories
• 100% detection rate on known attacks
• 2,600+ automated tests
• Pure regex — no LLM dependency
• Works as a Claude Code hook

## Tweet 5 (CTA):
It's free and open-source (MIT).

GitHub: github.com/maxwalser001-del/shieldpilot
Live demo: shieldpilot.dev

If you think AI agents need guardrails, star the repo.

## Tweet 6 (Engagement — separater Reply):
What's the scariest thing your AI coding agent has done?

I'll start: mine tried to run chmod 777 on /etc/passwd during a "routine cleanup."

That's when I started building this.
