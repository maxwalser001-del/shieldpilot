# ShieldPilot — Project Board (Updated 22.03.2026)

**Projekt:** AI Agent Firewall SDK + Cloud Platform
**Start:** 16.03.2026
**Target Launch:** 30.03.2026 (2 Wochen ahead of schedule)
**Startup Event Pitch:** 15.05.2026
**Endziel:** 7.000€+/Monat nach 12 Monaten

---

## Gesamtübersicht

```
MAR                APR          MAI          JUN        JUL-DEZ
W1    W2     W3    W4   W5+     W6-W9        W10-13     ...
SDK   CLOUD  DASH  LNCH SELL    PITCH+GROW   REDTEAM    SCALE
████  ████   ████  ░░░  ░░░░    ░░░░░░░░░    ░░░░░░     ░░░░░
DONE  DONE   DONE  NOW  NEXT
```

| Meilenstein | Deadline | Status | Revenue |
|---|---|---|---|
| M1: SDK Core | 27.03 | ✅ 95% Done | 0€ |
| M2: Cloud Backend | 03.04 | ✅ 100% Done | 0€ |
| M3: Dashboard | 10.04 | ✅ 100% Done | 0€ |
| M4: Landing + Deploy + Release | 26.03 | 🔶 80% | 0€ |
| M5: Public Launch | 30.03 | ⬜ 0% | 0€ |
| M6: Pitch Prep + Erste Kunden | Mai | ⬜ | 500-1.500€ |
| M7: Red-Teaming Loop | Juni | ⬜ | 2.000-3.000€ |
| M8: Growth + Team-Features | Jul-Sep | ⬜ | 3.000-5.000€ |
| M9: Scale + Optimize | Okt-Dez | ⬜ | 5.000-7.000€ |

---

## ✅ MEILENSTEIN 1: SDK — DONE (16-22.03)

| Task | Status | Date |
|---|---|---|
| Repo + Package-Struktur + pyproject.toml | Done | 16.03 |
| Apache 2.0 License | Done | 16.03 |
| Core: ShieldPilot, guard(), GuardResult, scan() | Done | 16.03 |
| Risk Engine + 9 Analyzer migriert | Done | 18.03 |
| Scanner + 178 Patterns migriert | Done | 18.03 |
| LangChain CallbackHandler | Done | 19.03 |
| CrewAI ShieldPilotTool + shield_tool() | Done | 19.03 |
| Claude Agent SDK ShieldedTool + shield_wrap() | Done | 19.03 |
| Cloud Client (HTTP, Batch, Retry, Degradation) | Done | 22.03 |
| GitHub Actions CI (Python 3.9-3.12) | Done | 22.03 |
| README (comprehensive) | Done | 22.03 |
| Quality Audit (120 Checks, 0 Fehler) | Done | 22.03 |
| **Offen: PyPI Upload** | ⬜ | M4 |

**Tests:** 43 Test-Suites + 29 Import Checks + 32 Edge Cases + 16 Quality = **120 Checks**

---

## ✅ MEILENSTEIN 2: Cloud Backend — DONE (22.03)

| Task | Status | Date |
|---|---|---|
| FastAPI Server + Event-Ingestion (POST /api/v1/events) | Done | 22.03 |
| Event-Query + Filter + Pagination | Done | 22.03 |
| Sessions (Auto-Gruppierung + Detail) | Done | 22.03 |
| Auth (Register, Login, JWT) | Done | 22.03 |
| API Key System (Create, List, Revoke, SHA-256) | Done | 22.03 |
| Multi-Tenant (tenant_id auf alle Queries) | Done | 22.03 |
| Dashboard Stats (Aggregates, Risk Distribution) | Done | 22.03 |
| Rate-Limiting per Tier (Free=1k, Pro=50k, Business=1M) | Done | 22.03 |
| Slack Alerts (Block Kit Messages) | Done | 22.03 |
| Email Alerts (Resend API) | Done | 22.03 |
| Alert CRUD (Create, List, Delete) | Done | 22.03 |
| Dockerfile + Railway Config | Done | 22.03 |
| **Railway Deploy — LIVE** | Done | 22.03 |

**Tests:** 22 API Integration Tests
**Live URL:** `shieldpilot-cloud-production.up.railway.app`

---

## ✅ MEILENSTEIN 3: Dashboard — DONE (22.03)

| Task | Status | Date |
|---|---|---|
| Login/Register Page (JWT Auth) | Done | 22.03 |
| Dashboard Home (Stats, Risk Bars, Event Timeline) | Done | 22.03 |
| Sessions View (Table + Detail Drill-Down) | Done | 22.03 |
| Settings (API Keys, Alerts, Usage, Logout) | Done | 22.03 |
| Dark Theme (Design Guide applied) | Done | 22.03 |
| Auto-Refresh (10s Polling) | Done | 22.03 |

---

## 🔶 MEILENSTEIN 4: Landing + Release (23-26.03)

| # | Task | Status | Prio |
|---|---|---|---|
| 1 | Landing Page | ✅ Done | P0 |
| 2 | Deploy auf Railway | ✅ Done | P0 |
| 3 | Domain shieldpilot.dev verbunden | ✅ Done (SSL pending) | P0 |
| 4 | **Stripe Account erstellen** | ⬜ To Do | P0 |
| 5 | **Stripe Checkout Integration (Pro = $49/mo)** | ⬜ To Do | P0 |
| 6 | **Stripe Webhook (tier upgrade nach Zahlung)** | ⬜ To Do | P0 |
| 7 | **PyPI Upload (pip install shieldpilot)** | ⬜ To Do | P0 |
| 8 | **GitHub SDK Repo public schalten** | ⬜ To Do | P0 |
| 9 | Full-Flow Test | ⬜ To Do | P0 |
| 10 | Demo GIF für README | ⬜ To Do | P1 |
| 11 | **Design-Optimierung (siehe M4.5 unten)** | ⬜ To Do | P0 |

### M4.5: Design-Optimierung (vor Veröffentlichung)

**Ziel:** Das Produkt muss sich anfühlen wie ein echtes SaaS, nicht wie ein Dev-Prototyp.

#### Landing Page Polish
| # | Task | Status | Prio |
|---|---|---|---|
| D1 | Favicon + Meta-Tags (og:image, og:title, og:description) | ⬜ | P0 |
| D2 | Logo/Shield-Icon als SVG (nicht nur Emoji) | ⬜ | P1 |
| D3 | Hero-Section: Code-Snippet als animiertes Terminal (typing effect) | ⬜ | P2 |
| D4 | Social Proof Section (GitHub Stars Counter, "Trusted by X developers") | ⬜ | P1 |
| D5 | Mobile Responsive Check + Fix (Hamburger Menu, Stack Layout) | ⬜ | P0 |
| D6 | Page Load Speed optimieren (Font-Loading, CSS minifizieren) | ⬜ | P1 |
| D7 | Footer: Social Links (GitHub, LinkedIn, Twitter) | ⬜ | P2 |

#### Dashboard UX
| # | Task | Status | Prio |
|---|---|---|---|
| D8 | Onboarding Flow: Erster Login → "Install SDK" Anleitung mit Code-Snippet | ⬜ | P0 |
| D9 | Empty States: Hilfreiche Texte wenn noch keine Events/Sessions da sind | ⬜ | P0 |
| D10 | Loading States: Skeleton-Loader statt "Loading..." Text | ⬜ | P1 |
| D11 | Toast/Notification System (Erfolg/Fehler Meldungen) | ⬜ | P1 |
| D12 | Session Detail: Risk-Score als visueller Bar statt nur Zahl | ⬜ | P2 |
| D13 | Dashboard: Event-Timeline mit Icon pro Tool (bash=Terminal, python=Snake) | ⬜ | P2 |
| D14 | Settings: Copy-to-Clipboard Button für API Key | ⬜ | P1 |

#### Login/Register UX
| # | Task | Status | Prio |
|---|---|---|---|
| D15 | Password Strength Indicator | ⬜ | P2 |
| D16 | "Forgot Password" Link (erstmal nur UI, Backend später) | ⬜ | P2 |
| D17 | Google OAuth Button (erstmal nur UI, Backend später) | ⬜ | P2 |

#### Branding Konsistenz
| # | Task | Status | Prio |
|---|---|---|---|
| D18 | Alle Seiten: Konsistente Header/Sidebar/Footer | ⬜ | P0 |
| D19 | Error Pages: Custom 404 + 500 Seiten im ShieldPilot Design | ⬜ | P1 |
| D20 | API Docs Seite (/api/docs) mit ShieldPilot Branding statt default Swagger | ⬜ | P2 |

#### Performance + SEO
| # | Task | Status | Prio |
|---|---|---|---|
| D21 | Lighthouse Score Check (Ziel: >90 Performance, >90 SEO) | ⬜ | P1 |
| D22 | Sitemap.xml + robots.txt | ⬜ | P1 |
| D23 | Schema.org Markup für Landing Page (SoftwareApplication) | ⬜ | P2 |

### Tagesplan M4

**Mo 23.03:**
```
14:00-16:00  Stripe Account + Checkout Integration
16:00-18:00  Stripe Webhook + Tier Upgrade
20:00-21:00  LERNEN: OWASP LLM01 + LLM02
```

**Di 24.03:**
```
14:00-15:00  PyPI Upload + GitHub Repo public
15:00-16:00  Full-Flow Test (pip install → guard → Dashboard → Alert)
16:00-17:00  Demo GIF aufnehmen
17:00-18:00  sentinel.yaml Billing zurücksetzen
20:00-21:00  LERNEN: OWASP LLM03 + LLM04
```

**Mi 25.03:**
```
14:00-18:00  Launch-Vorbereitung (HN Post, Reddit Posts, LinkedIn Posts)
20:00-21:00  LERNEN: Simon Willison Blog
```

---

## ⬜ MEILENSTEIN 5: Public Launch (30.03)

| # | Task | Status | Prio |
|---|---|---|---|
| 1 | Soft Launch (5-10 Dev-Freunde) | ⬜ | P0 |
| 2 | Feedback sammeln + kritische Bugs fixen | ⬜ | P0 |
| 3 | Hacker News "Show HN" Post (Mi 14:00 CET) | ⬜ | P0 |
| 4 | Reddit (r/Python, r/ClaudeAI, r/ML, r/LocalLLaMA) | ⬜ | P0 |
| 5 | Product Hunt Launch | ⬜ | P1 |
| 6 | LinkedIn Post #1 | ⬜ | P0 |
| 7 | Twitter/X Thread | ⬜ | P1 |
| 8 | Alle Kommentare beantworten (48h) | ⬜ | P0 |

---

## ⬜ MEILENSTEIN 6: Pitch Prep + Erste Kunden (April-Mai)

| # | Task | Status |
|---|---|---|
| 1 | Content-System: 3 LinkedIn Posts/Woche | ⬜ |
| 2 | Outreach: 5 Aktionen/Tag | ⬜ |
| 3 | Consulting starten (kostenlose Audits → bezahlt) | ⬜ |
| 4 | Event Networking nutzen (Investors, CTOs) | ⬜ |
| 5 | Pitch Deck für 15.05 Event | ⬜ |
| 6 | Mock Pitches üben (08.05, 13.05) | ⬜ |
| 7 | Case Studies von ersten Kunden | ⬜ |
| 8 | Awesome Lists PRs (awesome-langchain, awesome-ai-security) | ⬜ |

**Key Event Dates:**
- 07.04: Career Workshop + LinkedIn WS
- 15.04: TAM/SAM/SOM + Networking Martín Morillo (Investor)
- 22.04: Networking Joanna Pousset (VC Advisor)
- 24.04: Networking Pablo Félez (CaixaBank/Founder)
- 29.04: Networking Martín Morillo P2 (Investor)
- 05.05: Networking Stefan Florea (Investor) + Alexia Palau ($95B Unicorns)
- 08.05: Mock Pitch 1
- 13.05: Mock Pitch 2
- **14.05: FINAL GALA — Shark Tank**
- 15.05: Closing Workshop

---

## ⬜ MEILENSTEIN 7: Red-Teaming Loop (Juni)

| # | Task | Status |
|---|---|---|
| 1 | Attack Generator (Claude generiert 200 Angriffe/Nacht) | ⬜ |
| 2 | Detection Tester (jeden Angriff durch Engine schicken) | ⬜ |
| 3 | Auto-Pattern Generator (neue Patterns aus Bypasses) | ⬜ |
| 4 | Nightly Cron Job (GitHub Action um 02:00) | ⬜ |
| 5 | Morning Report (was wurde gefunden/gefixt) | ⬜ |
| 6 | Blog-Post: "ShieldPilot attacks itself every night" | ⬜ |
| 7 | Stats auf Landing Page (X attacks tested, Y% detection) | ⬜ |

---

## ⬜ MEILENSTEIN 8: Growth + Team-Features (Jul-Sep)

| # | Task | Status |
|---|---|---|
| 1 | Multi-User Dashboard (Team einladen) | ⬜ |
| 2 | Role-Based Access (Admin, Viewer) | ⬜ |
| 3 | Shared Policies (Team-weite Rules) | ⬜ |
| 4 | PDF Compliance Reports | ⬜ |
| 5 | OpenAI Agents SDK Integration | ⬜ |
| 6 | AutoGen Integration | ⬜ |
| 7 | Onboarding E-Mail Sequenz (Tag 1, 3, 7) | ⬜ |
| 8 | Case Studies auf Landing Page | ⬜ |

---

## ⬜ MEILENSTEIN 9: Scale + Optimize (Okt-Dez)

| # | Task | Status |
|---|---|---|
| 1 | PostgreSQL Migration (wenn nötig) | ⬜ |
| 2 | Anthropic/LangChain Partnership explorieren | ⬜ |
| 3 | Enterprise Tier (SSO, SLA, On-Prem) | ⬜ |
| 4 | Jährliche Billing Option (-20%) | ⬜ |
| 5 | Evaluieren: Acquisition vs. Weiterbauen | ⬜ |

---

## Revenue-Prognose

| Monat | Free User | Pro ($49) | Business ($299) | Consulting | **Netto** |
|---|---|---|---|---|---|
| Apr 26 | 100 | 0 | 0 | 0€ | **0€** |
| Mai 26 | 300 | 5 | 0 | 500€ | **745€** |
| Jun 26 | 600 | 12 | 0 | 1.500€ | **2.088€** |
| Jul 26 | 900 | 20 | 1 | 1.500€ | **2.779€** |
| Sep 26 | 1.600 | 40 | 3 | 1.500€ | **4.357€** |
| Dez 26 | 4.000 | 75 | 5 | 1.500€ | **6.670€** |
| **Mär 27** | **8.000** | **100** | **8** | **1.000€** | **~8.292€** |

---

## Extern

| Task | Status |
|---|---|
| Domain shieldpilot.dev | ✅ Gekauft + DNS konfiguriert |
| Railway Account + Deploy | ✅ Live |
| GitHub shieldpilot-sdk (private) | ✅ |
| GitHub shieldpilot-cloud (private) | ✅ |
| LinkedIn Profil | ✅ |
| Stripe Account | ⬜ Mo 23.03 |
| Resend Account (Email) | ⬜ |
| Loom Account (Videos) | ⬜ |
