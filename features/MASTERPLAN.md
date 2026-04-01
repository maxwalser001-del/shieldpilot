# ShieldPilot AI Agent Firewall — Masterplan

## Das Endziel

**Ein Python SDK + Cloud-Plattform die zwischen AI Agents und deren Tools sitzt, jede Aktion loggt, bewertet und gefährliche Aktionen blockt.**

```
Entwickler installiert:  pip install shieldpilot
Fügt 3 Zeilen Code ein:  shield = ShieldPilot(api_key="sp_...")
Agent läuft:             Jede Aktion wird bewertet + geloggt
Etwas Gefährliches:      Slack Alert + Block + Dashboard zeigt was passiert ist
Monatsende:              49€ Rechnung, Entwickler zahlt gerne
```

**Ziel-Revenue:** 5.000€+/Monat nach 12 Monaten

---

## Die 4 Produkt-Säulen

```
┌─────────────────────────────────────────────────────────┐
│                    SHIELDPILOT                           │
├──────────┬──────────┬──────────────┬───────────────────┤
│  1. SDK  │ 2. Cloud │ 3. Dashboard │ 4. Landing + Docs │
│          │  Backend │              │                   │
│ pip pkg  │ API      │ Web UI       │ Marketing         │
│ guard()  │ Events   │ Timeline     │ Pricing           │
│ Integr.  │ Sessions │ Reports      │ Documentation     │
│ Scanner  │ Alerts   │ Billing      │ Videos            │
└──────────┴──────────┴──────────────┴───────────────────┘
```

---

## Alle Schritte — Vollständig

### PHASE 1: PRODUKT BAUEN (Woche 1-4)

---

#### SÄULE 1: SDK — `pip install shieldpilot` (Woche 1)

##### 1.1 Projekt-Setup
- [ ] **1.1.1** Neues Repo `shieldpilot-sdk` erstellen (GitHub, private bis Launch)
- [ ] **1.1.2** Package-Struktur anlegen:
  ```
  shieldpilot/
    __init__.py          → Version, public API exports
    core.py              → ShieldPilot Hauptklasse
    guard.py             → guard() Wrapper-Logik
    engine/
      __init__.py
      risk_engine.py     → Kopie aus sentinelai/engine/engine.py (standalone)
      analyzers/         → Alle 9 Analyzer aus sentinelai/engine/analyzers/
      models.py          → RiskAssessment, RiskSignal, Action
    scanner/
      __init__.py
      scanner.py         → PromptScanner (aus sentinelai/scanner/)
      patterns.py        → 178+ Patterns
    integrations/
      __init__.py
      langchain.py       → LangChain CallbackHandler
      crewai.py          → CrewAI Tool Wrapper
      claude_sdk.py      → Claude Agent SDK wrap_tool
    cloud/
      __init__.py
      client.py          → HTTP Client für Cloud API
    config.py            → Konfiguration (Thresholds, API Key, Mode)
  tests/
    test_core.py
    test_guard.py
    test_engine.py
    test_scanner.py
    test_integrations.py
  pyproject.toml
  README.md
  LICENSE               → MIT
  ```
- [ ] **1.1.3** `pyproject.toml` mit metadata, dependencies, entry points
- [ ] **1.1.4** `.gitignore`, `.github/workflows/ci.yml` (lint + test)

##### 1.2 Core-Klasse
- [ ] **1.2.1** `ShieldPilot.__init__(api_key=None, mode="local", config=None)`
  - `mode="local"`: Risk Engine läuft lokal, kein Cloud-Upload
  - `mode="cloud"`: Events werden an api.shieldpilot.dev gesendet
  - `mode="monitor"`: Loggt aber blockt nicht (Audit-Only)
- [ ] **1.2.2** `shield.guard(fn, *args, **kwargs) → GuardResult`
  - Führt Risk-Analyse auf fn + args durch BEVOR fn ausgeführt wird
  - Wenn risk >= block_threshold: wirft `ShieldPilotBlocked` Exception
  - Wenn risk >= warn_threshold: loggt Warning, führt aus
  - Returnt `GuardResult(result=fn_return, risk_score=X, action="allow|warn|block", signals=[...])`
- [ ] **1.2.3** `shield.log_event(action, tool, args, result, risk_score=None)`
  - Manuelles Logging für Frameworks die keinen Auto-Guard haben
  - Sendet Event an Cloud API (wenn mode="cloud")
- [ ] **1.2.4** `shield.scan(text) → ScanResult`
  - Prompt Injection Scanner als standalone Funktion
  - Returnt: `ScanResult(score=X, threats=[...], is_injection=bool)`
- [ ] **1.2.5** `@shield.monitor` Decorator
  - Wrapt eine Funktion automatisch mit guard()
  - `@shield.monitor(risk_threshold=80)`

##### 1.3 Risk Engine (Standalone)
- [ ] **1.3.1** Risk Engine aus `sentinelai/engine/engine.py` kopieren
  - Abhängigkeiten zu sentinelai.core.config entfernen
  - Eigene Config-Klasse in `shieldpilot/config.py`
- [ ] **1.3.2** Alle 9 Analyzer mitnehmen:
  - destructive_fs, credential_access, network_exfil
  - obfuscation, persistence, privilege_escalation
  - supply_chain, malware_patterns, injection
- [ ] **1.3.3** Scoring-Algorithmus beibehalten (max-weighted + diminishing tail)
- [ ] **1.3.4** Thresholds konfigurierbar: block=80, warn=40
- [ ] **1.3.5** Neuer Analyzer: `api_call_analyzer`
  - Bewertet API-Calls (nicht nur Shell-Commands)
  - Erkennt: Daten-Exfiltration über API, massenhafte Löschungen, Admin-Operationen
  - Patterns: DELETE auf User/Data Endpoints, POST mit sensitiven Feldern an externe URLs

##### 1.4 Prompt Injection Scanner (Standalone)
- [ ] **1.4.1** Scanner aus `sentinelai/scanner/` kopieren
- [ ] **1.4.2** Alle 178+ Patterns + 19 Kategorien mitnehmen
- [ ] **1.4.3** Dependencies auf sentinelai entfernen
- [ ] **1.4.4** Standalone nutzbar: `from shieldpilot import scan`

##### 1.5 Framework-Integrationen
- [ ] **1.5.1** LangChain Integration
  ```python
  from shieldpilot.integrations.langchain import ShieldPilotCallbackHandler
  handler = ShieldPilotCallbackHandler(api_key="sp_...")
  agent = initialize_agent(..., callbacks=[handler])
  ```
  - Hook in `on_tool_start`: Risk-Check BEVOR Tool ausgeführt wird
  - Hook in `on_tool_end`: Event loggen mit Result
  - Hook in `on_llm_start`: Prompt Injection Check auf Input
- [ ] **1.5.2** CrewAI Integration
  ```python
  from shieldpilot.integrations.crewai import ShieldPilotTool
  safe_tool = ShieldPilotTool(original_tool, api_key="sp_...")
  ```
  - Wrapper der jede Tool-Execution durch guard() schickt
- [ ] **1.5.3** Claude Agent SDK Integration
  ```python
  from shieldpilot.integrations.claude_sdk import shield_wrap
  tools = [shield_wrap(tool, api_key="sp_...") for tool in original_tools]
  ```
  - Wrapped tool.execute() mit guard()
- [ ] **1.5.4** Generic Python Integration
  ```python
  from shieldpilot import ShieldPilot
  shield = ShieldPilot(api_key="sp_...")
  result = shield.guard(my_function, arg1, arg2)
  ```

##### 1.6 Cloud Client
- [ ] **1.6.1** HTTP Client für Cloud API (`shieldpilot/cloud/client.py`)
  - `POST /api/v1/events` — Event senden (async, non-blocking)
  - `POST /api/v1/events/batch` — Batch-Upload (buffered, alle 5s oder 100 Events)
  - Retry-Logik (3 Versuche, exponentieller Backoff)
  - Graceful Degradation: Cloud nicht erreichbar → lokal loggen, später sync
- [ ] **1.6.2** Event-Buffer: Events lokal sammeln, batch senden
- [ ] **1.6.3** API Key Validierung beim Start (einmal `GET /api/v1/me`)

##### 1.7 Tests + Dokumentation
- [ ] **1.7.1** Unit Tests: core.py (init, guard, log_event, scan)
- [ ] **1.7.2** Unit Tests: risk_engine.py (alle 9 Analyzer, Scoring)
- [ ] **1.7.3** Unit Tests: scanner.py (Injection Detection, False Positives)
- [ ] **1.7.4** Unit Tests: jede Integration (LangChain, CrewAI, Claude SDK)
- [ ] **1.7.5** Integration Test: Full Flow (guard → cloud upload → verify)
- [ ] **1.7.6** README.md mit:
  - Badge: PyPI Version, Tests, License
  - "What is ShieldPilot?" (3 Sätze)
  - Quick Start (5 Zeilen Code)
  - Framework-spezifische Beispiele
  - Link zu Docs
- [ ] **1.7.7** PyPI Test-Upload (`pip install -i test.pypi.org shieldpilot`)

---

#### SÄULE 2: Cloud Backend (Woche 2)

##### 2.1 API Server
- [ ] **2.1.1** Neues Verzeichnis `shieldpilot-cloud/` oder separates Repo
- [ ] **2.1.2** FastAPI App mit CORS, Auth Middleware, Error Handling
- [ ] **2.1.3** `POST /api/v1/events`
  - Input: `{agent_id, action, tool, args, result, risk_score, blocked, timestamp}`
  - Batch-fähig: Array von Events akzeptieren
  - Validierung: Pflichtfelder, Max-Size (1MB)
  - Response: `{received: N, session_id: "..."}`
- [ ] **2.1.4** `POST /api/v1/events/batch`
  - Bis zu 1.000 Events pro Request
  - Async Processing (Queue)
- [ ] **2.1.5** `GET /api/v1/events`
  - Query-Parameter: agent_id, action, risk_min, risk_max, from, to, limit, offset
  - Pagination: cursor-based
  - Response: `{events: [...], cursor: "..."}`
- [ ] **2.1.6** `GET /api/v1/sessions`
  - Automatische Gruppierung: Events mit < 5min Gap = gleiche Session
  - Response: `{sessions: [{id, agent_id, start, end, event_count, max_risk, blocked_count}]}`
- [ ] **2.1.7** `GET /api/v1/sessions/:id`
  - Alle Events einer Session als Timeline
  - Summary: total, blocked, warned, allowed, risk distribution
- [ ] **2.1.8** `GET /api/v1/sessions/:id/report`
  - Formatierter Report (JSON)
  - Optional: PDF Download (`?format=pdf`)
- [ ] **2.1.9** `GET /api/v1/agents`
  - Liste aller Agents des Tenants
  - Status: active (Event in letzten 5min), idle, offline
- [ ] **2.1.10** `GET /api/v1/stats`
  - Dashboard-Stats: Events/Tag, Block-Rate, Top Risks, Active Agents
  - Zeitraum: 24h, 7d, 30d

##### 2.2 Auth + Tenancy
- [ ] **2.2.1** API Key System
  - Format: `sp_live_xxxxxxxxxxxx` (Production) / `sp_test_xxxxxxxxxxxx` (Test)
  - SHA-256 Hash in DB speichern
  - API Key → Tenant ID → alle Queries gefiltert
- [ ] **2.2.2** API Key Management Endpoints
  - `POST /api/v1/keys` — neuen Key erstellen (Auth via Dashboard JWT)
  - `DELETE /api/v1/keys/:id` — Key revoken
  - `GET /api/v1/keys` — alle Keys listen (ohne Secret)
- [ ] **2.2.3** User Registration + Login (für Dashboard)
  - `POST /api/v1/auth/register` — Email + Password
  - `POST /api/v1/auth/login` → JWT Token
  - Kein OAuth im MVP (zu aufwändig)
- [ ] **2.2.4** Tenant-Isolation: Jede DB-Query hat `WHERE tenant_id = :tid`

##### 2.3 Datenbank
- [ ] **2.3.1** PostgreSQL auf Supabase (Free Tier: 500MB, reicht für Monate)
- [ ] **2.3.2** Schema:
  ```sql
  tenants (id, name, email, plan, created_at)
  api_keys (id, tenant_id, key_hash, name, created_at, revoked_at)
  events (id, tenant_id, agent_id, session_id, action, tool, args_json,
          result_json, risk_score, blocked, signals_json, timestamp)
  sessions (id, tenant_id, agent_id, start_at, end_at, event_count,
            max_risk, blocked_count)
  alerts (id, tenant_id, event_id, channel, sent_at)
  ```
- [ ] **2.3.3** Indexes: tenant_id+timestamp, tenant_id+agent_id, session_id
- [ ] **2.3.4** Event-Retention: Free=7 Tage, Pro=90 Tage (Cron-Job löscht alte Events)

##### 2.4 Rate-Limiting
- [ ] **2.4.1** Per API Key: Free=1.000 Events/Tag, Pro=50.000, Business=Unlimited
- [ ] **2.4.2** Response Header: `X-RateLimit-Remaining`, `X-RateLimit-Reset`
- [ ] **2.4.3** 429 Response wenn Limit erreicht mit Upgrade-Hinweis

##### 2.5 Alerts
- [ ] **2.5.1** Slack Webhook
  - User konfiguriert Webhook URL im Dashboard
  - Alert bei: risk_score >= 80, blocked Event, neue Injection Detection
  - Message Format: Agent, Action, Risk Score, Link zum Dashboard
- [ ] **2.5.2** E-Mail Alert (Resend)
  - Template: "ShieldPilot Alert: [Agent] tried to [Action]"
  - Max 10 Mails/Stunde (kein Spam)
- [ ] **2.5.3** Alert-Konfiguration
  - `PUT /api/v1/settings/alerts` — Slack URL, E-Mail on/off, Threshold

##### 2.6 Deployment
- [ ] **2.6.1** Dockerfile (Python 3.12, multi-stage)
- [ ] **2.6.2** Railway oder Fly.io Deployment
  - Railway: Einfacher, Free Tier 500h/Monat, $5/Monat danach
  - Fly.io: Mehr Kontrolle, Free Tier 3 shared VMs
- [ ] **2.6.3** Domain: `api.shieldpilot.dev` → Railway/Fly
- [ ] **2.6.4** SSL (automatisch über Railway/Fly)
- [ ] **2.6.5** Environment Variables: DB_URL, RESEND_API_KEY, JWT_SECRET
- [ ] **2.6.6** Health-Endpoint: `GET /health` → DB-Check + Uptime
- [ ] **2.6.7** UptimeRobot Monitoring (kostenlos, 5min Intervall)

---

#### SÄULE 3: Dashboard (Woche 3)

##### 3.1 Tech-Entscheidung
- [ ] **3.1.1** Framework: Next.js (Vercel Deploy) ODER Vanilla JS (wie ShieldPilot jetzt)
  - Empfehlung: Next.js — schneller zu bauen, Vercel Free Tier, SSR für SEO
  - Alternative: Dashboard als Teil der Cloud API (FastAPI + Jinja2 Templates)
  - Entscheidung treffen am Anfang von Woche 3

##### 3.2 Views
- [ ] **3.2.1** Login/Register Page
- [ ] **3.2.2** Onboarding: "Installiere das SDK" → Code-Snippet → "Warte auf erstes Event"
- [ ] **3.2.3** Dashboard Home
  - Stat-Cards: Events heute, Blocked heute, Active Agents, Risk-Trend
  - Event-Timeline (letzte 50 Events, Live-Update via Polling)
  - Risk-Verteilung (Donut Chart: safe/warn/block)
- [ ] **3.2.4** Sessions View
  - Liste aller Sessions mit: Agent, Dauer, Event-Count, Max-Risk, Status
  - Sortierbar nach: Zeit, Risk, Events
  - Filter nach Agent
- [ ] **3.2.5** Session Detail View
  - Timeline: Jedes Event als Zeile mit Timestamp, Tool, Action, Risk-Badge
  - Expandierbar: Klick auf Event zeigt args, result, signals
  - "Generate Report" Button
- [ ] **3.2.6** Agents View
  - Liste aller Agents mit: Name, Status (active/idle/offline), letzte Aktivität
  - Events pro Agent
- [ ] **3.2.7** Settings View
  - API Keys verwalten (erstellen, revoken, kopieren)
  - Alert-Konfiguration (Slack URL, E-Mail on/off)
  - Billing (aktueller Plan, Upgrade, Usage)

##### 3.3 Billing
- [ ] **3.3.1** Pricing Page (public, kein Login nötig)
  - Free / Pro (49€) / Business (299€)
  - Feature-Vergleichstabelle
- [ ] **3.3.2** Stripe Checkout Integration
  - "Upgrade to Pro" Button → Stripe Checkout Session
  - Success/Cancel Redirect
- [ ] **3.3.3** Stripe Webhook
  - `checkout.session.completed` → Plan upgraden
  - `customer.subscription.deleted` → Downgrade zu Free
- [ ] **3.3.4** Billing Portal
  - "Manage Subscription" → Stripe Customer Portal
- [ ] **3.3.5** Usage-Meter im Dashboard
  - "1.234 / 50.000 Events heute" (Pro) oder "987 / 1.000 Events heute" (Free)
  - Warnung bei 80% Verbrauch
  - Upgrade-CTA bei 100%

##### 3.4 Design
- [ ] **3.4.1** Design Guide anwenden (siehe features/DESIGN-GUIDE.md)
  - Dark Theme: Deep Navy #0B0F1A
  - Accent: Shield Cyan #39D2C0
  - Font: Inter + JetBrains Mono
- [ ] **3.4.2** Responsive: Desktop-first, aber Mobile-lesbar
- [ ] **3.4.3** Keine Animationen außer Hover-Transitions und Loading-States

---

#### SÄULE 4: Landing Page + Docs (Woche 4)

##### 4.1 Landing Page (shieldpilot.dev)
- [ ] **4.1.1** Hero Section
  - Headline: "Know what your AI Agents are doing. In real-time."
  - Subline: "Open-source SDK that monitors, evaluates, and controls every action your AI agents take."
  - CTA: "Get Started Free" → Docs / pip install
  - Code-Snippet: 5 Zeilen Python
- [ ] **4.1.2** Problem Section
  - "Your AI agents are a black box"
  - 3 Szenarien mit Icons: Data Leak, Destructive Action, Prompt Injection
- [ ] **4.1.3** Solution Section
  - Dashboard-Screenshot
  - "3 lines of code. Full visibility."
  - Feature-Liste: Real-time monitoring, Risk scoring, Automatic blocking, Audit trail
- [ ] **4.1.4** How It Works
  - 3 Steps: Install → Integrate → Monitor
  - Code-Snippets für jeden Step
- [ ] **4.1.5** Framework-Logos
  - "Works with:" LangChain, CrewAI, Claude Agent SDK, Custom Agents
- [ ] **4.1.6** Pricing Section
  - 3 Tiers: Free, Pro, Business
  - Feature-Vergleich
  - "Start Free" CTA
- [ ] **4.1.7** Footer
  - Links: GitHub, Docs, Blog, Twitter/LinkedIn
  - "Built by Max Walser"
- [ ] **4.1.8** Deploy auf Vercel (oder Netlify)
- [ ] **4.1.9** Domain `shieldpilot.dev` → Vercel

##### 4.2 Documentation
- [ ] **4.2.1** Doc-Tool wählen: Mintlify (schön, kostenlos für Open Source) oder Docusaurus
- [ ] **4.2.2** Seiten:
  1. **Getting Started** — pip install, API Key holen, erstes guard() in 2 Min
  2. **Core Concepts** — guard(), Risk Engine, Scores, Actions
  3. **LangChain Integration** — Setup + Beispiel
  4. **CrewAI Integration** — Setup + Beispiel
  5. **Claude Agent SDK** — Setup + Beispiel
  6. **Generic Python** — Decorator + manuelles Logging
  7. **Cloud Dashboard** — Login, Events, Sessions, Reports
  8. **Alerts** — Slack + E-Mail Setup
  9. **API Reference** — Alle Endpoints
  10. **Self-Hosting** — Docker + Config
- [ ] **4.2.3** Deploy Docs unter `docs.shieldpilot.dev`

##### 4.3 Videos
- [ ] **4.3.1** Video 1: "ShieldPilot in 60 seconds" (Loom)
  - pip install → 3 Zeilen Code → Agent läuft → Alert kommt → Dashboard zeigt was passiert
- [ ] **4.3.2** Video 2: "What happens when your AI agent goes rogue" (Loom)
  - Agent versucht gefährliche Aktion → ShieldPilot blockt → Alert → Session Report

##### 4.4 GitHub Repo Polish
- [ ] **4.4.1** README mit:
  - Badges (PyPI, Tests, License, Stars)
  - Animated GIF oder Video-Link
  - Quick Start (5 Zeilen)
  - "Why ShieldPilot?" (3 Bullets)
  - Framework-Beispiele
  - Link zu Docs + Dashboard
- [ ] **4.4.2** CONTRIBUTING.md (für Community)
- [ ] **4.4.3** Issue Templates (Bug Report, Feature Request)
- [ ] **4.4.4** GitHub Actions: CI (lint + test auf Push)
- [ ] **4.4.5** Repo public schalten
- [ ] **4.4.6** PyPI Release: `pip install shieldpilot`

---

### PHASE 2: LAUNCH (Woche 5)

##### 5.1 Soft Launch
- [ ] **5.1.1** 5-10 Dev-Freunde anschreiben
  - "Hey, ich hab ein Tool gebaut. Kannst du es in 10 Min testen und mir sagen was kaputt ist?"
  - Ihnen einen Pro-Account schenken (Lifetime Free)
- [ ] **5.1.2** Feedback sammeln (Google Form oder einfach Chat)
- [ ] **5.1.3** Kritische Bugs fixen (1-2 Tage)

##### 5.2 Public Launch
- [ ] **5.2.1** Hacker News "Show HN" Post
  - Titel: "Show HN: ShieldPilot — Open-source firewall for AI agents"
  - Text: Problem (2 Sätze), Solution (2 Sätze), Link, "Built by a solo founder"
  - Timing: Mittwoch 14:00 CET (8:00 EST — US Peak)
  - WICHTIG: Erste 2 Stunden alle Kommentare beantworten
- [ ] **5.2.2** Product Hunt
  - Listing mit 5 Screenshots, Video, Tagline
  - "AI Agent Security" + "Developer Tools" + "Open Source" Tags
  - Maker Comment vorbereiten
- [ ] **5.2.3** Reddit Posts
  - r/Python: "I built an open-source security SDK for AI agents"
  - r/ClaudeAI: "How I monitor what Claude Code does on my system"
  - r/MachineLearning: "Runtime security for AI agents — detecting prompt injection + dangerous actions"
  - r/LocalLLaMA: "Open-source agent firewall — works with any LLM"
- [ ] **5.2.4** LinkedIn Post #1
  - Format: Problem-Story → "So I built this" → Screenshot → Link
- [ ] **5.2.5** Twitter/X Post
  - Thread: Problem → Solution → Demo GIF → Link

##### 5.3 Post-Launch (48h)
- [ ] **5.3.1** ALLE Kommentare beantworten (HN, PH, Reddit, LinkedIn)
- [ ] **5.3.2** Bugs tracken und fixen (gleicher Tag wenn möglich)
- [ ] **5.3.3** Install-Zahlen tracken (PyPI Stats, GitHub Stars)
- [ ] **5.3.4** Erste Conversion-Daten: Free Signups, Pro Upgrades

---

### PHASE 3: VERTRIEB + WACHSTUM (Woche 6+, fortlaufend)

##### 6.1 Content-System (3x/Woche)
- [ ] **6.1.1** Montag: Problem-Post (LinkedIn)
  - "AI Agent hat X gemacht, so hätte man es verhindert"
- [ ] **6.1.2** Mittwoch: Insight-Post (LinkedIn)
  - "Ich habe X Agent-Commands analysiert. Y% waren gefährlich."
- [ ] **6.1.3** Freitag: Build-in-Public (LinkedIn)
  - "Woche X: Y Installs, Z zahlende Kunden. Was ich gelernt habe."
- [ ] **6.1.4** 1 Blog-Post/Woche (ab Woche 8)
  - Technische Deep-Dives: "How ShieldPilot detects prompt injection"
  - Case Studies: "How [Company] secured their AI agents"

##### 6.2 Outreach (5 Aktionen/Tag)
- [ ] **6.2.1** 2x relevante Posts auf LinkedIn/Twitter kommentieren
- [ ] **6.2.2** 1x GitHub Issue in LangChain/CrewAI kommentieren (Security-Themen)
- [ ] **6.2.3** 1x DM an jemanden der über AI Agent Probleme postet
- [ ] **6.2.4** 1x Reddit/Discord Kommentar (helfen, nicht pitchen)

##### 6.3 Consulting (parallel)
- [ ] **6.3.1** LinkedIn Post: "Ich mache kostenlose 30-Min AI Agent Security Audits"
- [ ] **6.3.2** Audit-Template erstellen (Checklist, was wird geprüft)
- [ ] **6.3.3** Erste 3 Audits kostenlos → Case Studies
- [ ] **6.3.4** Ab Audit #4: 150-250€/Stunde
- [ ] **6.3.5** Paket schnüren: "AI Agent Security Audit" — 2.000€ einmalig

##### 6.4 Feature-Iteration (nach User-Feedback)
- [ ] **6.4.1** Feature-Requests sammeln (GitHub Issues + Intercom/Crisp)
- [ ] **6.4.2** Top 3 Requests pro Woche priorisieren
- [ ] **6.4.3** Ship 1-2 Features/Woche (Claude Code macht's schnell)

##### 6.5 Meilensteine
- [ ] **6.5.1** 100 GitHub Stars
- [ ] **6.5.2** 500 PyPI Installs
- [ ] **6.5.3** 50 Free User im Dashboard
- [ ] **6.5.4** Erster Pro-Kunde (49€)
- [ ] **6.5.5** 10 Pro-Kunden (490€ MRR)
- [ ] **6.5.6** Erster Business-Kunde (299€)
- [ ] **6.5.7** 1.000€ MRR
- [ ] **6.5.8** 3.000€ MRR
- [ ] **6.5.9** 5.000€ MRR

---

## Externe Tasks (NICHT in Claude Code)

| # | Task | Wann | Geschätzte Zeit |
|---|---|---|---|
| E1 | Domain `shieldpilot.dev` registrieren | Woche 1, Tag 1 | 15 Min |
| E2 | Railway Account erstellen | Woche 1 | 10 Min |
| E3 | Supabase Account + Projekt erstellen | Woche 2, Tag 1 | 20 Min |
| E4 | Resend Account (E-Mail API) | Woche 2 | 10 Min |
| E5 | Stripe Account prüfen/konfigurieren | Woche 3 | 30 Min |
| E6 | LinkedIn Profil optimieren | Woche 1, Abend | 30 Min |
| E7 | Loom Account erstellen | Woche 4 | 5 Min |
| E8 | Vercel Account (Landing Page) | Woche 4 | 10 Min |
| E9 | UptimeRobot Account (Monitoring) | Woche 2 | 10 Min |
| E10 | 5-10 Dev-Freunde für Soft Launch identifizieren | Woche 1-4 | fortlaufend |
| E11 | Product Hunt Account + "Upcoming" Listing | Woche 4 | 20 Min |
| E12 | Mintlify Account (Docs) | Woche 4 | 15 Min |
| E13 | Twitter/X Account optimieren | Woche 4, Abend | 20 Min |

---

## Revenue-Prognose (konservativ, 4h/Tag Kernzeit)

| Monat | Free User | Pro (49€) | Business (299€) | Consulting | **Netto** |
|---|---|---|---|---|---|
| Monat 1-2 | 100 | 0 | 0 | 0€ | **0€** |
| Monat 3 | 300 | 5 | 0 | 1.000€ | **~1.200€** |
| Monat 4 | 600 | 10 | 0 | 1.500€ | **~2.000€** |
| Monat 5 | 900 | 18 | 1 | 2.000€ | **~3.200€** |
| Monat 6 | 1.200 | 25 | 2 | 2.000€ | **~3.800€** |
| Monat 9 | 3.000 | 50 | 3 | 1.500€ | **~5.000€** |
| Monat 12 | 5.000 | 80 | 5 | 1.500€ | **~7.000€** |

**Abzüge:** Stripe 2.9%, Hosting ~50€, Tools ~100€ → ca. 200€/Monat Fixkosten

---

## Gesamtzahl Tasks

| Phase | Tasks |
|---|---|
| SDK | 32 |
| Cloud Backend | 27 |
| Dashboard | 18 |
| Landing + Docs | 17 |
| Launch | 12 |
| Vertrieb | 14 |
| Externe Tasks | 13 |
| **Gesamt** | **133** |

**Bei 4h/Tag, 5 Tage/Woche = 20h/Woche → ca. 3-4 Tasks/Tag → 42 Arbeitstage → 6 Wochen**
