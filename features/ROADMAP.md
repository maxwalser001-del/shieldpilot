# ShieldPilot — Roadmap

## Endziel
`pip install shieldpilot` → 3 Zeilen Code → AI Agent wird überwacht → Dashboard zeigt alles → 49€/Monat

---

## Phase 1: SDK (Woche 1)

### 1.1 Projekt-Setup
- Repo erstellen
- Package-Struktur (shieldpilot/)
- pyproject.toml + CI

### 1.2 Core
- `ShieldPilot(api_key, mode)` Klasse
- `shield.guard(fn, *args)` — Risk-Check vor Ausführung
- `shield.log_event()` — manuelles Logging
- `shield.scan(text)` — Prompt Injection Check
- `@shield.monitor` Decorator

### 1.3 Risk Engine
- Engine aus sentinelai extrahieren (standalone)
- 9 Analyzer mitnehmen
- Neuer API-Call Analyzer
- Scoring: 0-100, block >= 80, warn >= 40

### 1.4 Scanner
- Prompt Injection Scanner extrahieren
- 178+ Patterns, 19 Kategorien

### 1.5 Integrationen
- LangChain CallbackHandler
- CrewAI Tool Wrapper
- Claude Agent SDK wrap_tool
- Generic Python (Decorator)

### 1.6 Cloud Client
- HTTP Client für Event-Upload
- Event-Buffer (batch alle 5s)
- Graceful Degradation (offline → lokal loggen)

### 1.7 Tests + README
- Unit Tests für alles
- README mit Quick-Start
- PyPI Test-Upload

---

## Phase 2: Cloud Backend (Woche 2)

### 2.1 API
- FastAPI Server
- `POST /api/v1/events` (Ingestion)
- `GET /api/v1/events` (Query + Filter)
- `GET /api/v1/sessions` (Gruppierung)
- `GET /api/v1/sessions/:id/report`
- `GET /api/v1/agents` (Agent-Liste)
- `GET /api/v1/stats` (Dashboard-Stats)

### 2.2 Auth + Tenancy
- API Key System (sp_live_xxx / sp_test_xxx)
- Key Management Endpoints
- User Registration + Login (JWT)
- Tenant-Isolation (WHERE tenant_id)

### 2.3 Datenbank
- PostgreSQL (Supabase)
- Schema: tenants, api_keys, events, sessions, alerts
- Indexes + Retention (Free=7d, Pro=90d)

### 2.4 Rate-Limiting
- Per Tier (Free=1k/Tag, Pro=50k, Business=Unlimited)
- Rate-Limit Headers
- 429 + Upgrade-Hinweis

### 2.5 Alerts
- Slack Webhook (risk >= 80)
- E-Mail (Resend)
- Alert-Konfiguration per API

### 2.6 Deployment
- Dockerfile
- Railway/Fly.io Deploy
- Domain api.shieldpilot.dev
- SSL + Health + Monitoring

---

## Phase 3: Dashboard (Woche 3)

### 3.1 Auth Views
- Login / Register
- Onboarding ("Installiere SDK → Warte auf Event")

### 3.2 Dashboard Home
- Stat-Cards (Events, Blocked, Agents, Trend)
- Event-Timeline (Live)
- Risk-Verteilung (Chart)

### 3.3 Sessions
- Session-Liste (Agent, Dauer, Events, Risk)
- Session-Detail (Timeline, expandierbare Events)
- Report generieren

### 3.4 Agents
- Agent-Liste (Status, letzte Aktivität)

### 3.5 Settings
- API Key Management
- Alert-Konfiguration
- Billing + Usage

### 3.6 Billing
- Pricing Page
- Stripe Checkout (Free → Pro)
- Webhook (upgrade/downgrade)
- Usage-Meter + Upgrade-CTA

---

## Phase 4: Landing + Docs (Woche 4)

### 4.1 Landing Page (shieldpilot.dev)
- Hero (Headline + Code-Snippet + CTA)
- Problem Section (3 Szenarien)
- Solution Section (Screenshot + Features)
- How It Works (3 Steps)
- Framework-Logos
- Pricing
- Footer
- Deploy auf Vercel

### 4.2 Documentation
- Getting Started
- Core Concepts
- LangChain Integration
- CrewAI Integration
- Claude Agent SDK
- Generic Python
- Cloud Dashboard
- Alerts
- API Reference
- Self-Hosting

### 4.3 Videos
- "ShieldPilot in 60 Seconds"
- "AI Agent goes rogue — Demo"

### 4.4 GitHub Polish
- README (Badges, GIF, Quick-Start)
- CONTRIBUTING.md
- Issue Templates
- Public schalten
- PyPI Release

---

## Phase 5: Launch (Woche 5)

### 5.1 Soft Launch
- 5-10 Dev-Freunde testen lassen
- Feedback sammeln
- Kritische Bugs fixen

### 5.2 Public Launch
- Hacker News "Show HN"
- Product Hunt
- Reddit (r/Python, r/ClaudeAI, r/MachineLearning, r/LocalLLaMA)
- LinkedIn Post #1
- Twitter/X Thread

### 5.3 Post-Launch (48h)
- Alle Kommentare beantworten
- Bugs sofort fixen
- Install-Zahlen + Conversions tracken

---

## Phase 6: Vertrieb + Wachstum (Woche 6+, fortlaufend)

### 6.1 Content (3x/Woche)
- Montag: Problem-Post
- Mittwoch: Insight/Data-Post
- Freitag: Build-in-Public
- 1 Blog-Post/Woche (ab Woche 8)

### 6.2 Outreach (5 Aktionen/Tag)
- LinkedIn/Twitter kommentieren
- GitHub Issues kommentieren
- DMs an Leute mit AI Agent Problemen
- Reddit/Discord helfen

### 6.3 Consulting (parallel)
- Kostenlose 30-Min Audits anbieten
- Erste 3 gratis → Case Studies
- Ab #4: 150-250€/Stunde
- Paket: "AI Agent Security Audit" — 2.000€

### 6.4 Feature-Iteration
- Requests sammeln (GitHub Issues)
- Top 3/Woche priorisieren
- 1-2 Features/Woche shippen

### 6.5 Meilensteine
- 100 GitHub Stars
- 500 PyPI Installs
- 50 Free User
- Erster Pro-Kunde
- 10 Pro-Kunden
- Erster Business-Kunde
- 1.000€ MRR
- 3.000€ MRR
- 5.000€ MRR

---

## Externe Tasks (außerhalb Claude Code)

- Domain shieldpilot.dev registrieren
- Railway Account
- Supabase Account + Projekt
- Resend Account (E-Mail)
- Stripe Account konfigurieren
- LinkedIn Profil optimieren
- Vercel Account
- UptimeRobot Account
- Loom Account
- Mintlify Account (Docs)
- 5-10 Dev-Freunde für Soft Launch
- Product Hunt "Upcoming" Listing

---

## Timeline

```
Woche 1  ████████████████████  SDK
Woche 2  ████████████████████  Cloud Backend
Woche 3  ████████████████████  Dashboard
Woche 4  ████████████████████  Landing + Docs + Polish
Woche 5  ████████████████████  Launch
Woche 6+ ████████████████████  Vertrieb + Iteration
         ─────────────────────────────────────────────→
         0€                    erste €€€        5.000€/mo
```
