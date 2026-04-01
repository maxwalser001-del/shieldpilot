# ShieldPilot — Daily Plan

**Letzte Aktualisierung:** 19.03.2026
**Aktuelle Woche:** 1/6 (SDK)
**Letzter Commit:** Risk Engine + Scanner migriert (18.03)
**Revenue:** 0€
**GitHub Stars:** 0 (private)

---

## Heute — Donnerstag 19. März (Tag 4)

### Build (14:00-18:00)
| Zeit | Task | Details |
|---|---|---|
| 14:00-15:30 | Task 23: LangChain Integration | `ShieldPilotCallbackHandler` — hooks in on_tool_start (risk check), on_tool_end (log), on_llm_start (injection scan) |
| 15:30-17:00 | Task 24: CrewAI Integration | `ShieldPilotTool` Wrapper — jede Tool-Execution durch guard() |
| 17:00-18:00 | Task 25: Claude Agent SDK | `shield_wrap()` — wrapped tool.execute() mit guard() |

### Lernen (20:00-21:00)
| Zeit | Thema | Warum |
|---|---|---|
| 20:00-20:30 | OWASP LLM01: Prompt Injection | Du baust Detection dafür — verstehe den offiziellen Standard |
| 20:30-21:00 | OWASP LLM02: Insecure Output Handling | Relevant für deinen Output-Validator (kommt in M7) |

### Aktion
| Was | Dauer |
|---|---|
| 1 LinkedIn Kommentar auf einen AI Security Post | 5 Min |

---

## Morgen — Freitag 20. März (Tag 5) — EVENT 16:00-20:00

### Build (14:00-16:00)
| Zeit | Task | Details |
|---|---|---|
| 14:00-15:00 | Task 27: Cloud Client HTTP | httpx Client für Event-Upload an Cloud API |
| 15:00-16:00 | Task 28-29: Batch Buffer + Retry | Events lokal sammeln, batch senden, 3x Retry |

### Event (16:00-20:00)
| Was | Vorbereitung |
|---|---|
| Ideation + PUGH Matrix | Elevator Pitch üben: "Ich baue ShieldPilot — eine Open-Source Firewall für AI Agents. 9 Analyzer, 178 Patterns, pip install, 3 Zeilen Code." |
| Personality Assessment | Sei ehrlich, zeig Passion für Security + AI |

### Lernen (21:00-21:30)
| Thema | Warum |
|---|---|
| OWASP LLM03: Training Data Poisoning + LLM04: Model DoS | Erweitert dein Wissen über AI Risiken für Event-Gespräche |

---

## Samstag 21. März (Tag 6) — Wochenende

### Build (14:00-17:00, flexibel)
| Zeit | Task | Details |
|---|---|---|
| 14:00-15:00 | Task 35: Integration Tests | Tests für LangChain, CrewAI, Claude SDK |
| 15:00-16:00 | Task 4: GitHub Actions CI | Lint + Test bei jedem Push |
| 16:00-17:00 | Task 37: PyPI Test-Upload | Verifiziere dass `pip install` funktioniert |

### Lernen (Abend, 30 Min)
| Thema | Warum |
|---|---|
| Simon Willison Blog — 2 neueste Posts | Er ist der Prompt Injection Experte, du musst seine Arbeit kennen |

---

## Sonntag 22. März (Tag 7) — Wochenende

### Build (14:00-17:00, flexibel)
| Zeit | Task | Details |
|---|---|---|
| 14:00-16:00 | M1 Abschluss: Alle offenen P1/P2 Tasks | Cloud Client Graceful Degradation, API Key Validation |
| 16:00-17:00 | M1 Final Test | Kompletter Flow: init → guard → scan → log_event → cloud upload |

### Lernen (Abend, 30 Min)
| Thema | Warum |
|---|---|
| OWASP LLM05: Supply Chain + LLM06: Excessive Agency | LLM06 ist EXAKT dein Pitch: "AI Agents die zu viel dürfen" |

### Vorbereitung
| Was | Dauer |
|---|---|
| Woche 2 vorbereiten: Supabase Account erstellen | 15 Min |
| Railway Account prüfen + Projekt anlegen | 10 Min |

---

## Woche 2 — Montag 23. März bis Freitag 28. März

### Montag 23.03 (Tag 8)
**Build (14:00-18:00):** Task 38-41 — FastAPI Server + Events API + Sessions API
**Lernen (20:00-21:00):** Anthropic Research Blog — "Agent Security" Artikel
**Aktion:** 1 LinkedIn Post (Build-in-Public: "Woche 1 fertig, SDK steht")

### Dienstag 24.03 (Tag 9)
**Build (14:00-18:00):** Task 46-50 — Auth + API Keys + Tenant Isolation
**Lernen (20:00-21:00):** OWASP LLM07: System Prompt Leakage + LLM08: Vector Store Risks
**Aktion:** 2 LinkedIn Kommentare auf AI/Security Posts

### Mittwoch 25.03 (Tag 10)
**Build (14:00-18:00):** Task 51-57 — PostgreSQL + Schema + Rate-Limiting
**Lernen (20:00-21:00):** CompTIA Security+ Video #1-3 (Professor Messer, YouTube)
**Aktion:** 1 Reddit Kommentar in r/ClaudeAI oder r/Python (helfen, nicht pitchen)

### Donnerstag 26.03 (Tag 11)
**Build (14:00-18:00):** Task 58-61 — Slack Alerts + Email Alerts
**Lernen (20:00-21:00):** Kai Greshake Paper: "Not what you signed up for" (Indirect Prompt Injection)
**Aktion:** 1 LinkedIn Post (Problem-Story: "Was passiert wenn ein AI Agent...")

### Freitag 27.03 (Tag 12)
**Build (14:00-18:00):** Task 62-67 — Docker + Railway Deploy + Domain + Health
**Lernen (20:00-21:00):** 1 CTF Lab auf PortSwigger (SQL Injection Basics)
**Aktion:** Resend Account erstellen, UptimeRobot aufsetzen

---

## Woche 3 — Montag 30. März bis Freitag 4. April

### Montag 30.03 (Tag 13)
**Build (14:00-18:00):** Task 68-70 — Dashboard Tech-Entscheidung + Login + Onboarding
**Lernen (20:00-21:00):** OWASP LLM09: Misinformation + LLM10: Unbounded Consumption
**Aktion:** 1 LinkedIn Post (Insight: "9 Dimensionen die jeder AI Agent Angriff hat")

### Dienstag 31.03 (Tag 14)
**Build (14:00-18:00):** Task 71-73 — Dashboard Home + Sessions + Session Detail
**Lernen (20:00-21:00):** CompTIA Security+ Video #4-6 (Network Security Basics)
**Aktion:** 2 LinkedIn Kommentare

### Mittwoch 01.04 (Tag 15)
**Build (14:00-18:00):** Task 74-75 — Agents View + Settings View
**Lernen (20:00-21:00):** Johann Rehberger Blog — "Prompt Injection in the Wild"
**Aktion:** 1 GitHub Issue kommentieren in LangChain Repo (Security-Thema)

### Donnerstag 02.04 (Tag 16)
**Build (14:00-18:00):** Task 76-80 — Pricing Page + Stripe Checkout + Webhooks
**Lernen (20:00-21:00):** EU AI Act — Kernpunkte lesen (EUR-Lex Summary)
**Aktion:** 1 LinkedIn Post (Data: "178 Injection Patterns in 19 Kategorien")

### Freitag 03.04 (Tag 17)
**Build (14:00-18:00):** Task 81-83 — Design Guide anwenden + Responsive + Loading States
**Lernen (20:00-21:00):** 1 CTF Lab auf PortSwigger (XSS Basics)
**Aktion:** Stripe Account konfigurieren

---

## Woche 4 — Montag 6. April bis Freitag 11. April

### Montag 06.04 (Tag 18)
**Build (14:00-18:00):** Task 84-89 — Landing Page komplett (Hero, Problem, Solution, Pricing)
**Lernen (20:00-21:00):** Google Cybersecurity Certificate — Modul 1 starten (Coursera)
**Aktion:** 1 LinkedIn Post (Build-in-Public: "3 Wochen, 5.000 Zeilen, Launch in 2 Wochen")

### Dienstag 07.04 (Tag 19) — EVENT 16:00-20:00
**Build (14:00-16:00):** Task 91 — Deploy Landing auf Vercel + Domain shieldpilot.dev
**Event (16:00-20:00):** Career Workshop + Anna Rubio (iLovePDF Head of Marketing)
**Aktion:** Anna Rubio nach Marketing-Feedback für ShieldPilot fragen

### Mittwoch 08.04 (Tag 20) — EVENT 16:00-20:00
**Build (14:00-16:00):** Task 92-95 — Docs aufsetzen (Mintlify) + Getting Started + Core Concepts
**Event (16:00-20:00):** BMC 2.0 + Pitching Best Practices
**Aktion:** Business Model Canvas für ShieldPilot erstellen (Event-Übung)

### Donnerstag 09.04 (Tag 21)
**Build (14:00-18:00):** Task 96-103 — Restliche Docs + Deploy
**Lernen (20:00-21:00):** Google Cybersecurity Certificate — Modul 1 weiter
**Aktion:** 1 LinkedIn Post (Problem: "Euer AI Agent kann eure .env lesen")

### Freitag 10.04 (Tag 22)
**Build (14:00-18:00):** Task 104-113 — Videos + README + GitHub Polish + Full-Flow Test
**Lernen (20:00-21:00):** CompTIA Security+ Video #7-9
**Aktion:** 5 Dev-Freunde für Soft Launch anschreiben

---

## Woche 5 — Launch Week (13.-19. April)

### Montag 13.04 (Tag 23)
**Build (14:00-18:00):** Task 110-111 — Repo public schalten + PyPI Release
**Aktion:** 5 weitere Dev-Freunde für Soft Launch anschreiben
**Vorbereitung:** HN Post + Reddit Posts vorschreiben

### Dienstag 14.04 (Tag 24)
**Build (14:00-18:00):** Task 114-116 — Soft Launch: Freunde testen lassen, Feedback, Bugfixes
**Lernen (20:00-21:00):** Pitch üben (Spiegel oder Handy-Aufnahme)
**Aktion:** Feedback von Testern einarbeiten

### Mittwoch 15.04 (Tag 25) — EVENT 17:30-20:30
**Build (14:00-17:00):** Task 117 — Hacker News "Show HN" Post live (14:00 CET)
**Event (17:30-20:30):** TAM/SAM/SOM + Martín Morillo (Investor)
**KRITISCH:** Erste 3h nach HN Post: Alle Kommentare beantworten (Handy am Event)

### Donnerstag 16.04 (Tag 26)
**Build (14:00-18:00):** Task 118-121 — Product Hunt + Reddit + LinkedIn + Twitter Launch
**Lernen:** Pause (Launch-Stress)
**Aktion:** ALLE Kommentare auf HN/PH/Reddit beantworten

### Freitag 17.04 (Tag 27) — EVENT 17:30-20:30
**Build (14:00-17:00):** Task 122-124 — Post-Launch: Bugs fixen, Zahlen tracken
**Event (17:30-20:30):** Research + Gerard Pérez (Friesland/Deloitte Digital)
**Aktion:** Gerard Pérez fragen: "Nutzt Friesland AI Agents? Wie sichern die die ab?"

---

## Woche 6-9 — Revenue + Pitch Prep (20. April - 15. Mai)

### Tägliche Routine (Mo-Fr)
```
14:00-16:00  Build: Features nach User-Feedback + Bugs
16:00-17:00  Content: 1 LinkedIn Post ODER 1 Blog-Post Absatz
17:00-18:00  Outreach: 5 Aktionen (Kommentare, DMs, GitHub Issues)
20:00-20:30  Lernen: Siehe Wochenplan unten
20:30-21:00  Pitch üben ODER Consulting-Outreach
```

### Woche 6 (20.-26. April)
**Build-Focus:** User-Feedback einarbeiten, kritische Bugs
**Lernen Mo:** NeMo Guardrails README + Architektur-Übersicht
**Lernen Mi:** Google Cybersecurity Certificate Modul 2
**Lernen Fr:** CompTIA Security+ Video #10-12
**Aktionen:** PRs an awesome-langchain, awesome-ai-security einreichen
**Consulting:** Audit-Angebot auf LinkedIn posten, 3 DMs an CTOs

### Woche 7 (27. April - 3. Mai)
**Build-Focus:** Consulting-Tooling (Audit-Template, Report-Generator)
**Lernen Mo:** Paper: "Not what you signed up for" (Greshake et al.)
**Lernen Mi:** Google Cybersecurity Certificate Modul 2 weiter
**Lernen Fr:** 1 CTF Lab (PortSwigger: Authentication Bypass)
**Aktionen:** Security-Disclosure Research starten (LangChain/CrewAI Code lesen)
**Consulting:** Erste kostenlose Audits anbieten, Retainer-Paket finalisieren

### Woche 8 (4.-10. Mai)
**Build-Focus:** Retainer-Kunden Onboarding automatisieren
**Lernen Mo:** EU AI Act — Artikel 6 + Annex III (High-Risk AI Systems)
**Lernen Mi:** CompTIA Security+ Practice Exam (online, kostenlos)
**Lernen Fr:** Research-Blog-Post Entwurf schreiben
**EVENT Di 05.05:** Stefan Florea (Investor London) + Alexia Palau ($95B)
**EVENT Mi 06.05:** Communication Workshop + Oscar Sánchez (CEO)
**Pitch:** Deck finalisieren, Demo polishen

### Woche 9 (11.-15. Mai) — PITCH WEEK
**Mo 12.05:** Feedback Implementation (Event)
**Di 13.05:** Mock Pitch 2 (Event) — letztes Feedback
**Mi 14.05:** **FINAL GALA — SHARK TANK** — Der Pitch
**Do 15.05:** Closing Workshop — Next Steps mit Mentoren besprechen
**Lernen:** Pause (Pitch-Focus)

---

## Woche 10-14 — NeMo + Red-Teaming + Enterprise (Juni)

### Tägliche Routine
```
14:00-16:00  Build: NeMo Plugin ODER Red-Teaming Loop
16:00-17:00  Sales: Enterprise-Outreach (5 kalte Mails/Tag)
17:00-18:00  Content: 1 LinkedIn Post ODER Blog-Post
20:00-21:00  Lernen: NeMo Deep-Dive + CompTIA Prep
```

### Key Tasks
- NeMo Guardrails Plugin bauen + PR einreichen
- Red-Teaming Loop: Attack Generator + Auto-Pattern Fix
- Blog: "ShieldPilot attacks itself every night"
- Enterprise-Outreach: 10 CISOs/CTOs pro Woche anschreiben
- CompTIA Security+ Prüfung buchen (Ende Juni)

---

## Quick Reference: Heute abfragen

Sage in jeder neuen Claude Code Session:
> "Was steht heute an? Schau in features/DAILY-PLAN.md"

Oder nutze den Daily Planner Agent:
> "Daily Planner, was sind meine Tasks für heute?"

Der Plan wird nach jeder Session aktualisiert mit:
- Erledigte Tasks → Done
- Neue Tasks die dazugekommen sind
- Verschobene Tasks mit neuem Datum
