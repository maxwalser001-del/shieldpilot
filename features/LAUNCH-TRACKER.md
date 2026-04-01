# ShieldPilot AI Agent Firewall — Launch Tracker

## Metadata
- **Start:** 2026-03-16
- **Target Launch:** 2026-04-27 (Woche 5)
- **Current Week:** 1/6
- **Status:** Starting
- **Revenue:** 0€

## Schedule
- Mo-Fr: 14:00-18:00 (4h) + optional 20:00-21:30 (1.5h)
- Wochenende: 4-6h flexibel

---

## Woche 1 (16.03 - 22.03): SDK Core
- [ ] Repo shieldpilot-sdk erstellen + Package-Struktur
- [ ] ShieldPilot Core-Klasse (init, guard, log_event)
- [ ] Risk Engine aus sentinelai/engine/ extrahieren
- [ ] Prompt Injection Scanner standalone machen
- [ ] LangChain Integration (CallbackHandler)
- [ ] CrewAI Integration (Tool Wrapper)
- [ ] Claude Agent SDK Integration (wrap_tool)
- [ ] @shield.monitor Decorator
- [ ] Unit Tests für alle Core-Funktionen
- [ ] README mit Quick-Start Guide
- [ ] PyPI Test-Upload

## Woche 2 (23.03 - 29.03): Cloud Backend
- [ ] FastAPI Server aufsetzen (ShieldPilot als Basis)
- [ ] POST /api/v1/events (Event-Ingestion)
- [ ] GET /api/v1/events (Abfrage + Filter)
- [ ] GET /api/v1/sessions (Session-Gruppierung)
- [ ] GET /api/v1/reports/:session_id
- [ ] API Key Auth System
- [ ] PostgreSQL Setup (Supabase/Railway)
- [ ] Multi-Tenant (API Key → tenant_id)
- [ ] Rate-Limiting per Tier
- [ ] Slack Webhook Alerts
- [ ] E-Mail Alerts (Resend)
- [ ] Deploy auf Railway/Fly.io
- [ ] Domain api.shieldpilot.dev
- [ ] Health-Endpoint + Monitoring

## Woche 3 (30.03 - 05.04): Dashboard
- [ ] Event-Timeline (Live-Feed)
- [ ] Session-Detail-View (Timeline pro Session)
- [ ] Risk-Score Verteilung (Chart)
- [ ] Agent-Übersicht (aktive Agents, letzter Heartbeat)
- [ ] CSV/JSON Export
- [ ] Stripe Checkout (Free → Pro Upgrade)
- [ ] Usage-Limits im Backend erzwingen

## Woche 4 (06.04 - 12.04): Landing + Docs + Polish
- [ ] Landing Page: Hero, Problem, Solution, Pricing, CTA
- [ ] Documentation Site (Install, Quick Start, Frameworks, API Ref)
- [ ] 2 Loom-Videos (Setup, Demo)
- [ ] PyPI veröffentlichen (pip install shieldpilot)
- [ ] GitHub Repo public machen
- [ ] README mit GIF/Video, Badges
- [ ] Full-Flow Test: pip install → guard() → Dashboard → Alert
- [ ] Bug-Fixes

## Woche 5 (13.04 - 19.04): Launch
- [ ] Soft Launch an 5-10 Dev-Freunde (Mo)
- [ ] Feedback einarbeiten (Di)
- [ ] Hacker News "Show HN" (Mi, 14:00 CET)
- [ ] Product Hunt Launch (Do)
- [ ] Reddit Posts: r/Python, r/ClaudeAI, r/MachineLearning (Do)
- [ ] LinkedIn Post #1 (Do)
- [ ] Alle Kommentare beantworten (Mi-Fr)
- [ ] Quick-Fixes nach Feedback (Fr)

## Woche 6+ (20.04+): Vertrieb + Iteration
- [ ] 3 LinkedIn Posts/Woche starten
- [ ] 5 Outreach-Aktionen/Tag starten
- [ ] Erster Blog-Post
- [ ] Consulting-Angebot auf LinkedIn posten
- [ ] Community-Engagement (LangChain/CrewAI Discord)
- [ ] Features nach User-Feedback priorisieren

---

## Revenue Tracking
| Monat | Free User | Pro (49€) | Business (299€) | Consulting | MRR Gesamt |
|---|---|---|---|---|---|
| März | - | - | - | - | 0€ |
| April | | | | | |
| Mai | | | | | |
| Juni | | | | | |

## Externe Tasks (nicht in Claude Code)
| Task | Status | Notizen |
|---|---|---|
| Domain shieldpilot.dev registrieren | ❌ | |
| Railway/Fly.io Account | ❌ | |
| Supabase Account | ❌ | |
| Stripe Account konfigurieren | ❌ | Existiert schon in ShieldPilot? |
| Resend Account (E-Mail) | ❌ | |
| LinkedIn Profil optimieren | ❌ | |
| 5-10 Dev-Freunde für Soft Launch | ❌ | |
| Loom Account | ❌ | |
