# ShieldPilot — Learning Plan: AI Security Expert in 12 Monaten

**Ziel:** Du wirst der Typ der AI Agent Security versteht, erklären kann, und dafür bezahlt wird.
**Methode:** Jeden Tag 30-60 Min, abends nach dem Sport. Kein Grinden — smartes Lernen.
**Trick:** Alles was du lernst wird sofort zu Content (LinkedIn Post, Pitch-Argument, ShieldPilot Feature).

---

## Wie du am schnellsten lernst

### NotebookLM als dein persönlicher Tutor

Für JEDES Thema unten:
1. Lade die Quelle in **NotebookLM** (Google) hoch (PDF, URL, Text)
2. Lass dir einen **Audio Overview** (Podcast) generieren
3. Hör den Podcast beim Sport oder auf dem Weg zur Uni
4. Wenn du tiefer einsteigen willst: Frag NotebookLM Fragen zum Material

**So machst du aus 1h Lesezeit → 25 Min Podcast beim Joggen.**

### NotebookLM Prompt für Podcast-Generierung:
```
Erstelle einen Podcast zwischen zwei Hosts die dieses Material besprechen.
Fokussiere auf:
1. Die 3 wichtigsten Erkenntnisse für jemanden der ein AI Security Startup baut
2. Konkrete Beispiele und Analogien die man im Pitch nutzen kann
3. Was überraschend oder kontraintuitiv ist
Halte es unter 15 Minuten. Sprich Deutsch.
```

### Lern-Outputs pro Thema

Für jedes Thema erstellst du EINEN der folgenden Outputs (rotierend):
- **LinkedIn Post** (Mo) — Teile eine Erkenntnis
- **ShieldPilot Feature Idea** (Mi) — Was könntest du einbauen?
- **Pitch-Argument** (Fr) — Ein Satz den du beim Event nutzen kannst

---

## PHASE 1: Foundation (März-April) — Parallel zum Build

### Woche 1-2 (22.03 - 04.04): OWASP Top 10 for LLMs

**Das ist dein Fundament. Jeder in AI Security kennt das. Du musst es im Schlaf können.**

**Tag 1 (So 22.03): LLM01 — Prompt Injection**
- Lies: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
- Dauer: 20 Min lesen
- NotebookLM: URL hochladen → Podcast generieren → beim Sport hören
- Output: Schreib dir 3 Stichpunkte auf die du im Pitch nutzen kannst
- Verbindung zu ShieldPilot: Dein Scanner erkennt genau das. 178 Patterns.

**Tag 2 (Mo 23.03): LLM02 — Sensitive Information Disclosure**
- Lies: https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/
- Dauer: 20 Min
- Verbindung: Dein Credential Access Analyzer erkennt wenn Agents Keys/Passwords lesen

**Tag 3 (Di 24.03): LLM03 — Supply Chain**
- Lies: https://genai.owasp.org/llmrisk/llm03-supply-chain/
- Dauer: 20 Min
- Verbindung: Dein Supply Chain Analyzer erkennt malicious package installs

**Tag 4 (Mi 25.03): LLM04 — Data and Model Poisoning**
- Lies: https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/
- Dauer: 20 Min
- LinkedIn Post: "OWASP listet 10 Risiken für LLMs. Nummer 4 ist Data Poisoning — und die meisten Teams haben keinen Schutz dagegen."

**Tag 5 (Do 26.03): LLM05 — Improper Output Handling**
- Lies: https://genai.owasp.org/llmrisk/llm05-improper-output-handling/
- Dauer: 20 Min
- Verbindung: Deshalb scanned ShieldPilot auch Agent-OUTPUT, nicht nur Input

**Tag 6 (Fr 27.03): LLM06 — Excessive Agency**
- Lies: https://genai.owasp.org/llmrisk/llm06-excessive-agency/
- Dauer: 20 Min
- **DAS IST DEIN WICHTIGSTES KAPITEL.** Excessive Agency = Agent hat zu viele Rechte = genau das was ShieldPilot löst
- Pitch-Argument: "OWASP LLM06 Excessive Agency ist das #1 Risiko bei AI Agents. ShieldPilot ist die Lösung."

**Tag 7-8 (Sa-So): LLM07-LLM10 (Batch)**
- LLM07: System Prompt Leakage
- LLM08: Vector and Embedding Weaknesses
- LLM09: Misinformation
- LLM10: Unbounded Consumption
- Lade alle 4 als PDFs in NotebookLM → ein langer Podcast → beim Sport hören
- Dauer: 40 Min Podcast

**Tag 9-10: Wiederholung + Zusammenfassung**
- Erstelle eine 1-Seiten Cheat-Sheet: Alle 10 Risiken, je 1 Satz, welche ShieldPilot abdeckt
- Das ist dein Pitch-Spickzettel für das Event

**Ressourcen zum Download für NotebookLM:**
- OWASP Top 10 for LLMs PDF: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- Lade das komplette PDF in NotebookLM als Quelle hoch

---

### Woche 3-4 (05.04 - 18.04): Prompt Injection Deep-Dive

**Du hast 178 Patterns. Jetzt verstehst du WARUM jedes funktioniert.**

**Tag 1: Simon Willison — Der Papst der Prompt Injection**
- Lies: https://simonwillison.net/2023/Apr/14/worst-that-can-happen/
- "Prompt injection: What's the worst that can happen?"
- Lade in NotebookLM → Podcast
- Folge Simon auf Twitter/Bluesky: @simonw

**Tag 2: Simon Willison — Dual LLM Pattern**
- Lies: https://simonwillison.net/2023/Apr/25/dual-llm-pattern/
- Das ist eine Architektur-Idee wie man Injection verhindern kann
- Verbindung: ShieldPilot ist eine Implementation dieses Patterns (Guard zwischen Agent und System)

**Tag 3: Kai Greshake — Indirect Prompt Injection Paper**
- Paper: "Not what you've signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection"
- Suche auf arxiv.org nach "Greshake indirect prompt injection"
- Lade das PDF in NotebookLM → Podcast
- DAS ist das akademische Fundament für alles was du baust

**Tag 4: Mark Riedl — Hacking Auto-GPT**
- Lies: https://markriedl.substack.com/p/i-hacked-auto-gpt
- Zeigt wie ein AI Agent über Prompt Injection gehackt wird
- LinkedIn Post: "Ein Forscher hat Auto-GPT gehackt — nur durch Text in einer Webseite. So funktioniert Indirect Prompt Injection."

**Tag 5: NVIDIA NeMo Guardrails Docs**
- Lies: https://docs.nvidia.com/nemo/guardrails/
- Getting Started + Architecture Konzepte
- Verbindung: NeMo ist Topical Rails (was sagt der LLM), ShieldPilot ist Action Rails (was TUT der Agent)

**Tag 6-7: Eigenes Red-Teaming**
- Nimm deine 178 Patterns und versuche sie zu umgehen
- Schreib 10 Bypass-Versuche auf
- Für jeden Bypass den du findest: Neues Pattern schreiben
- Das ist aktives Lernen + verbessert dein Produkt

**Ressourcen für NotebookLM:**
```
Lade diese URLs/PDFs in ein NotebookLM Notebook namens "Prompt Injection Deep Dive":
1. Simon Willison Blog Posts (als Text kopieren)
2. Greshake Paper (PDF von arxiv)
3. Mark Riedl Substack (als Text kopieren)
4. Deine eigenen 178 Patterns (patterns.py als Text)
→ Lass dir einen Podcast generieren: "Erkläre Prompt Injection von den Basics bis zu aktueller Forschung"
```

---

### Woche 5-6 (19.04 - 02.05): Anthropic + OpenAI Safety Research

**Verstehe wie die großen Player über AI Safety denken. Das macht dich glaubwürdig im Pitch.**

**Tag 1: Anthropic — Core Views on AI Safety**
- Lies: https://www.anthropic.com/research#702claf79g4z3lxp17vutm
- "Core Views on AI Safety: When, Why, What, and How"
- NotebookLM → Podcast
- Pitch-Argument: "Selbst Anthropic sagt, dass AI Agents das größte Sicherheitsrisiko sind."

**Tag 2: Anthropic — Claude's Character**
- Lies: https://www.anthropic.com/research/claude-character
- Verstehe wie Anthropic Claude's Verhalten steuert
- Verbindung: Das ist die Modell-Ebene. ShieldPilot ist die System-Ebene darüber.

**Tag 3: OpenAI — Safety Best Practices**
- Lies: https://platform.openai.com/docs/guides/safety-best-practices
- Offizielle Empfehlungen von OpenAI
- Verbindung: Die meisten Empfehlungen = "baue Guardrails" = das was ShieldPilot macht

**Tag 4: Anthropic — Tool Use Safety**
- Lies: https://docs.anthropic.com/en/docs/build-with-claude/tool-use/best-practices-and-limitations
- Direkt relevant: Wie schützt man Tool-Use bei Claude?
- LinkedIn Post: "Anthropic empfiehlt 5 Sicherheitsmaßnahmen für Tool-Use. Die meisten Teams implementieren keine davon."

**Tag 5: EU AI Act — Was du wissen musst**
- YouTube: Suche "EU AI Act explained 2026" (es gibt gute 15-Min Zusammenfassungen)
- Oder: https://artificialintelligenceact.eu/high-level-summary/
- NotebookLM → Podcast
- Pitch-Argument: "Der EU AI Act verpflichtet Unternehmen, AI Systeme abzusichern. ShieldPilot macht das compliance-ready."

**Tag 6-7: Zusammenfassung**
- Erstelle ein Dokument: "Was Anthropic, OpenAI und die EU über AI Agent Security sagen"
- 10 Zitate die du im Pitch nutzen kannst
- Lade in NotebookLM → finaler Podcast für diese Phase

**Ressourcen für NotebookLM:**
```
Notebook: "AI Safety Research"
1. Anthropic Core Views PDF
2. OpenAI Safety Best Practices (Text)
3. EU AI Act Summary (Text)
→ Podcast: "Was sagen die großen AI Firmen und Regulierer über AI Agent Sicherheit?"
```

---

## PHASE 2: Spezialisierung (Mai-Juni) — Parallel zum Vertrieb

### Woche 7-10 (03.05 - 30.05): Hands-On Security

**Jetzt wechselst du von Theorie zu Praxis.**

**Woche 7: Google Cybersecurity Certificate starten**
- Coursera: https://www.coursera.org/professional-certificates/google-cybersecurity
- Kosten: ~40€/Monat
- Plan: 2-3 Videos pro Abend (je 10-15 Min)
- Module 1+2 in Woche 7 (Foundations + Manage Security Risks)
- NotebookLM: Kurs-Transkripte hochladen → Podcast pro Modul

**Woche 8: Google Cert Module 3+4**
- Module 3: Networks and Network Security
- Module 4: Linux and SQL
- Du kennst vieles schon — trotzdem durcharbeiten, die Zertifizierung zählt

**Woche 9: CTF Challenge Week**
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- Starte mit diesen Labs (kostenlos, je 30 Min):
  - SQL Injection: https://portswigger.net/web-security/sql-injection
  - XSS: https://portswigger.net/web-security/cross-site-scripting
  - SSRF: https://portswigger.net/web-security/ssrf
- 1 Lab pro Abend
- Verbindung: Jede Technik die du hier lernst wird ein ShieldPilot Detection-Pattern

**Woche 10: AI-spezifische CTFs**
- Gandalf Challenge: https://gandalf.lakera.ai/
- Prompt Injection Playground (verschiedene Levels)
- Versuch alle Level zu schaffen
- Dokumentiere jeden Bypass → wird ein neues Pattern für ShieldPilot
- LinkedIn Post: "Ich habe Lakera's Gandalf Challenge geschafft. Hier sind 5 Prompt Injection Techniken die die meisten Scanner nicht erkennen."

**Ressourcen für NotebookLM:**
```
Notebook: "Security Hands-On"
1. Google Cert Modul-Zusammenfassungen
2. PortSwigger Lab Notizen
3. Gandalf Challenge Bypass-Dokumentation
→ Podcast: "Die wichtigsten Security-Konzepte die jeder AI Engineer kennen muss"
```

---

### Woche 11-14 (Juni): CompTIA Security+ Vorbereitung

**Der Industriestandard. Jeder Recruiter und CISO kennt dieses Zertifikat.**

**Ressourcen (alle kostenlos):**
- Professor Messer YouTube: https://www.youtube.com/@professormesser
  - Kompletter Security+ Kurs, kostenlos, ~30h Video
  - Playlist: "CompTIA Security+ SY0-701"
  - Plan: 2 Videos pro Abend (je 10-15 Min)

**Wochenplan:**
```
Woche 11: Domain 1 — General Security Concepts (Videos 1-15)
Woche 12: Domain 2 — Threats, Vulnerabilities, Mitigations (Videos 16-35)
Woche 13: Domain 3 — Security Architecture + Domain 4 — Security Operations (Videos 36-55)
Woche 14: Domain 5 — Security Program Management + Review (Videos 56-70)
```

**NotebookLM Strategie:**
- Nach jedem Domain: Notizen in NotebookLM laden
- Podcast generieren: "Erkläre [Domain X] so dass ich es einem Investor erklären könnte"
- Beim Sport hören → passive Wiederholung

**Prüfung:**
- Kosten: ~370€
- Online oder im Testcenter
- Ziel: Juli/August ablegen
- Wenn bestanden → sofort auf LinkedIn: "CompTIA Security+ Certified"

---

## PHASE 3: Authority (Juli-September) — Parallel zum Growth

### Monat 5-6 (Juli-August): Eigene Research publizieren

**Jetzt wechselst du von Lernender zu Expert.**

**Woche 1-2: Research-Projekt wählen**

Wähle EINES dieser Projekte:
1. **"The State of AI Agent Security"** — Analysiere 10 populäre Agent-Frameworks auf Sicherheit
2. **"Prompt Injection Bypass Taxonomy"** — Kategorisiere alle bekannten Bypass-Techniken
3. **"Red-Teaming AI Agents: What 10.000 Automated Attacks Revealed"** — Nutze deinen Red-Teaming Loop

**Woche 3-4: Schreiben + Publizieren**
- Blog-Post (2.000-3.000 Wörter, technisch aber lesbar)
- Publiziere auf: Medium, dev.to, oder eigener Blog
- Teile auf: LinkedIn, Twitter, Hacker News
- Wenn es gut ist, wird es von anderen geteilt und zitiert

**NotebookLM:**
```
Notebook: "My Research"
1. Alle deine Findings
2. Vergleichbare Papers/Posts
→ Podcast: "Zusammenfassung meiner Forschung für den Pitch"
```

### Monat 7 (September): Erster Talk

**Woche 1: Talk vorbereiten**
- Titel: "How I Found X Vulnerabilities in AI Agents" (konkreter Case)
- 15 Minuten, 10-15 Slides
- Struktur: Problem → Demo → Findings → Lösung (ShieldPilot)

**Woche 2: Talk halten**
- OWASP Chapter Meetup in deiner Stadt: https://owasp.org/chapters/
- Oder: Python User Group Meetup
- Oder: Online AI/ML Meetup
- Aufnehmen und auf YouTube stellen

---

## Lern-Kalender (Übersicht)

| Monat | Thema | Output | Zertifikat |
|---|---|---|---|
| **Mär** | OWASP Top 10 for LLMs | Cheat-Sheet + 2 LinkedIn Posts | — |
| **Apr** | Prompt Injection + AI Safety Research | 3 LinkedIn Posts + Pitch-Argumente | — |
| **Mai** | Google Cybersecurity Cert + CTFs | 2 LinkedIn Posts + neue Patterns | Google Cert (in Progress) |
| **Jun** | CompTIA Security+ Vorbereitung | Notizen + Podcasts | — |
| **Jul** | Security+ Prüfung + Research-Projekt | Blog-Post publiziert | CompTIA Security+ |
| **Aug** | Research fertig + publizieren | Artikel auf Medium/dev.to | — |
| **Sep** | Erster öffentlicher Talk | YouTube Video + Slides | — |
| **Okt+** | Continuous Learning + CISSP Vorbereitung | Monatlicher Blog-Post | CISSP (langfristig) |

---

## NotebookLM Master-Setup

Erstelle diese 5 Notebooks:

### 1. "OWASP LLM Top 10"
```
Quellen:
- OWASP Top 10 for LLMs PDF
- Alle 10 Risk-Seiten als Text
Prompt für Podcast:
"Erkläre die OWASP Top 10 für LLMs so, dass ein Startup-Gründer versteht
warum er sich darum kümmern muss. Gib für jedes Risiko ein konkretes
Beispiel mit AI Agents. Auf Deutsch."
```

### 2. "Prompt Injection Masterclass"
```
Quellen:
- Simon Willison Blog Posts
- Greshake Paper PDF
- Mark Riedl Substack
- Eigene patterns.py (178 Patterns)
Prompt für Podcast:
"Erkläre Prompt Injection von den Grundlagen bis zu fortgeschrittenen
Techniken. Zeige warum es so schwer zu verhindern ist und welche
Ansätze es gibt. Gib Beispiele die man in einem Startup-Pitch nutzen kann."
```

### 3. "AI Safety — Was die Großen sagen"
```
Quellen:
- Anthropic Research Posts
- OpenAI Safety Guide
- EU AI Act Summary
Prompt für Podcast:
"Was sagen Anthropic, OpenAI und die EU über die Sicherheit von AI Agents?
Welche Aussagen kann ein Startup-Gründer im Pitch zitieren?
Was sind die stärksten Argumente warum Unternehmen AI Agent Security brauchen?"
```

### 4. "Security Fundamentals"
```
Quellen:
- Google Cybersecurity Cert Zusammenfassungen
- CompTIA Security+ Notizen (Professor Messer)
Prompt für Podcast:
"Erkläre die wichtigsten Security-Konzepte (CIA Triad, Threat Modeling,
Authentication, Encryption) so dass ich sie in Gesprächen mit CISOs
und Investoren nutzen kann. Auf Deutsch."
```

### 5. "Mein Pitch — AI Agent Security"
```
Quellen:
- Alle Cheat-Sheets und Zusammenfassungen
- ShieldPilot README
- Deine Pitch-Argumente
Prompt für Podcast:
"Simuliere ein Investoren-Gespräch über AI Agent Security. Ein Host spielt
den Gründer von ShieldPilot, der andere einen skeptischen VC. Geh durch:
Problem, Lösung, Markt, Differenzierung, Traction, Team. Stelle harte
Fragen und beantworte sie überzeugend."
```

---

## Tägliche Routine

```
20:00-20:30  Lesen/Video (aktives Lernen)
20:30-21:00  Notizen machen + in NotebookLM laden
             ODER: NotebookLM Podcast beim Zähneputzen/Vorbereiten

Beim Sport:  NotebookLM Podcast hören (passives Lernen)
             Das verdoppelt deine effektive Lernzeit ohne Extra-Aufwand
```

---

## Quick Wins (sofort umsetzbar)

### Heute Abend (30 Min):
1. Geh auf https://notebooklm.google.com
2. Erstelle Notebook "OWASP LLM Top 10"
3. Lade hoch: https://genai.owasp.org/llmrisk/llm01-prompt-injection/
4. Klick "Audio Overview" → generiere Podcast
5. Hör ihn morgen beim Sport

### Diese Woche:
1. Folge auf LinkedIn: Simon Willison, Kai Greshake, Johann Rehberger
2. Folge auf Twitter: @simonw, @KGreshake, @waboringcyber
3. Abonniere: Anthropic Research Blog

### Bücher (optional, für Tiefe):
- "The Web Application Hacker's Handbook" (Stuttard/Pinto) — der Klassiker
- "AI Security and Privacy" (Comiter, Belfer Center) — akademisch aber gut
- Beide als PDF → NotebookLM → Podcast

---

## ALLE LINKS — Kopierbar für NotebookLM

### NotebookLM öffnen:
```
https://notebooklm.google.com
```

---

### Notebook 1: "OWASP LLM Top 10"

Lade diese Links als Quellen:

```
OWASP Top 10 for LLMs — Komplettes PDF (47 Seiten):
https://owasp.org/www-project-top-10-for-large-language-model-applications/assets/PDF/OWASP-Top-10-for-LLMs-v2025.pdf

LLM01 — Prompt Injection:
https://genai.owasp.org/llmrisk/llm01-prompt-injection/

LLM02 — Sensitive Information Disclosure:
https://genai.owasp.org/llmrisk/llm02-sensitive-information-disclosure/

LLM03 — Supply Chain:
https://genai.owasp.org/llmrisk/llm03-supply-chain/

LLM04 — Data and Model Poisoning:
https://genai.owasp.org/llmrisk/llm04-data-and-model-poisoning/

LLM05 — Improper Output Handling:
https://genai.owasp.org/llmrisk/llm05-improper-output-handling/

LLM06 — Excessive Agency (WICHTIGSTER für ShieldPilot):
https://genai.owasp.org/llmrisk/llm06-excessive-agency/

LLM07 — System Prompt Leakage:
https://genai.owasp.org/llmrisk/llm07-system-prompt-leakage/

LLM08 — Vector and Embedding Weaknesses:
https://genai.owasp.org/llmrisk/llm08-vector-and-embedding-weaknesses/

LLM09 — Misinformation:
https://genai.owasp.org/llmrisk/llm09-misinformation/

LLM10 — Unbounded Consumption:
https://genai.owasp.org/llmrisk/llm10-unbounded-consumption/

Alle Risiken Übersicht:
https://genai.owasp.org/llm-top-10/

OWASP Agentic AI Security (Bonus — direkt relevant):
https://hal.science/hal-04985337v1/file/Agentic-AI-Threats-and-Mitigations_v1.0.1.pdf
```

NotebookLM Podcast-Prompt:
```
Erstelle einen 15-minütigen Podcast auf Deutsch. Erkläre die OWASP Top 10 für
LLM-Anwendungen so, dass ein Startup-Gründer versteht warum AI Agent Security
ein riesiger Markt wird. Für jedes Risiko: 1 konkretes Beispiel mit AI Agents,
und ob/wie ShieldPilot (eine Firewall für AI Agents) dagegen schützen könnte.
Fokus auf LLM01 (Prompt Injection) und LLM06 (Excessive Agency).
```

---

### Notebook 2: "Prompt Injection Masterclass"

Lade diese Links als Quellen:

```
Simon Willison — Prompt Injection Serie (Übersicht aller Posts):
https://simonwillison.net/series/prompt-injection/

Simon Willison — "Prompt injection: What's the worst that can happen?":
https://simonwillison.net/2023/Apr/14/worst-that-can-happen/

Simon Willison — "The lethal trifecta for AI agents":
https://simonw.substack.com/p/the-lethal-trifecta-for-ai-agents

Simon Willison — "Prompt injections as far as the eye can see":
https://simonw.substack.com/p/prompt-injections-as-far-as-the-eye

Simon Willison — "Accidental prompt injection against RAG":
https://simonw.substack.com/p/accidental-prompt-injection-against

Greshake Paper — "Indirect Prompt Injection" (DAS Fundament-Paper):
https://arxiv.org/abs/2302.12173

Greshake Paper — BlackHat Whitepaper PDF:
https://i.blackhat.com/BH-US-23/Presentations/US-23-Greshake-Not-what-youve-signed-up-for-whitepaper.pdf

VentureBeat — "How prompt injection can hijack AI agents like Auto-GPT":
https://venturebeat.com/security/how-prompt-injection-can-hijack-autonomous-ai-agents-like-auto-gpt/

Generationship Podcast — Simon Willison "I Coined Prompt Injection" (Audio!):
https://www.heavybit.com/library/podcasts/generationship/ep-39-simon-willison-i-coined-prompt-injection

OpenAI — "Understanding prompt injections" (offiziell):
https://openai.com/index/prompt-injections/

OpenAI — "Hardening ChatGPT Atlas against prompt injection":
https://openai.com/index/hardening-atlas-against-prompt-injection/

Prompt Injection Blog 2025 (gute Übersicht):
https://blog.premai.io/prompt-injection-attacks-in-2025-vulnerabilities-exploits-and-how-to-defend/
```

NotebookLM Podcast-Prompt:
```
Erstelle einen Podcast auf Deutsch über Prompt Injection — von den Grundlagen
bis zu aktueller Forschung. Erkläre: 1) Was ist Prompt Injection? 2) Warum ist
es bei AI Agents besonders gefährlich? 3) Was ist die "lethal trifecta"?
4) Welche Bypass-Techniken gibt es? 5) Warum sagt OpenAI es wird "nie gelöst"?
Nutze konkrete Beispiele die man in einem Startup-Pitch verwenden kann.
```

---

### Notebook 3: "AI Safety — Was die Großen sagen"

Lade diese Links als Quellen:

```
Anthropic — "Core Views on AI Safety":
https://www.anthropic.com/news/core-views-on-ai-safety

Anthropic — Research Übersicht:
https://www.anthropic.com/research

Anthropic — Claude Character & Safety:
https://www.anthropic.com/research/claude-character

Anthropic — Tool Use Best Practices & Limitations:
https://docs.anthropic.com/en/docs/build-with-claude/tool-use/best-practices-and-limitations

Anthropic — Recommended Safety Research Directions:
https://alignment.anthropic.com/2025/recommended-directions/

OpenAI — Safety Best Practices:
https://platform.openai.com/docs/guides/safety-best-practices

EU AI Act — High-Level Summary:
https://artificialintelligenceact.eu/high-level-summary/

EU AI Act — 2026 Compliance Requirements:
https://www.legalnodes.com/article/eu-ai-act-2026-updates-compliance-requirements-and-business-risks

EU AI Act — Comprehensive Summary (Jan 2026):
https://www.softwareimprovementgroup.com/blog/eu-ai-act-summary/

EU AI Act — Official Regulatory Framework:
https://digital-strategy.ec.europa.eu/en/policies/regulatory-framework-ai
```

NotebookLM Podcast-Prompt:
```
Erstelle einen Podcast auf Deutsch: Was sagen Anthropic, OpenAI und die EU
über AI Agent Security? Extrahiere die 10 stärksten Zitate/Argumente die ein
Startup-Gründer in einem Pitch für ein AI Security Tool nutzen kann. Erkläre
den EU AI Act so, dass klar wird warum Unternehmen AI Agent Security kaufen
MÜSSEN (nicht nur sollten). Gib konkrete Compliance-Deadlines.
```

---

### Notebook 4: "Security Fundamentals"

```
Google Cybersecurity Certificate (Coursera):
https://www.coursera.org/professional-certificates/google-cybersecurity

Professor Messer — CompTIA Security+ SY0-701 (komplett kostenlos):
https://www.professormesser.com/security-plus/sy0-701/sy0-701-video/sy0-701-comptia-security-plus-course/

Professor Messer — YouTube Kanal:
https://www.youtube.com/@professormesser

PortSwigger Web Security Academy (kostenlos, interaktiv):
https://portswigger.net/web-security

PortSwigger — SQL Injection Labs:
https://portswigger.net/web-security/sql-injection

PortSwigger — XSS Labs:
https://portswigger.net/web-security/cross-site-scripting

PortSwigger — SSRF Labs:
https://portswigger.net/web-security/ssrf

Gandalf Challenge (Prompt Injection CTF von Lakera):
https://gandalf.lakera.ai/
```

NotebookLM Podcast-Prompt:
```
Erkläre die wichtigsten Security-Konzepte auf Deutsch: CIA Triad,
Threat Modeling, Authentication vs Authorization, Encryption Basics,
Network Security Fundamentals. Erkläre alles so, dass ich es in
Gesprächen mit CISOs und Investoren nutzen kann — nicht zu technisch,
aber kompetent. Gib für jedes Konzept ein Beispiel aus der AI Agent Welt.
```

---

### Notebook 5: "Mein Pitch — AI Agent Security"

```
Lade diese Dateien als Text in NotebookLM:

1. ShieldPilot SDK README (kopiere aus GitHub)
2. Dein OWASP Cheat-Sheet (nachdem du es erstellt hast)
3. Deine gesammelten Pitch-Argumente
4. Die 10 Fragen die jeder stellt (aus unserem Chat)
5. Marktanalyse: Lakera, AgentOps, Prisma AIRS Vergleich
```

NotebookLM Podcast-Prompt:
```
Simuliere ein 15-minütiges Investoren-Gespräch auf Deutsch. Ein Host spielt
den Gründer von ShieldPilot (AI Agent Firewall), der andere einen skeptischen
VC der folgende Fragen stellt:
1. Was genau macht ShieldPilot?
2. Warum Regex statt ML?
3. Was wenn Anthropic das selbst einbaut?
4. Wie unterscheidet ihr euch von Lakera?
5. Wie skaliert das?
6. Was ist euer Business Model?
7. Warum sollte ich investieren?
Beantworte jede Frage überzeugend mit konkreten Daten und Argumenten.
```

---

### Leute denen du auf Social Media folgen solltest:

```
LinkedIn / Twitter:
- Simon Willison (@simonw) — Prompt Injection Experte #1
- Kai Greshake (@KGreshake) — Indirect Prompt Injection Forscher
- Johann Rehberger (@wunderwuzzi23) — AI Security Researcher
- Daniel Miessler (@DanielMiessler) — Security + AI Newsletter
- Anthropic Research (@AnthropicAI) — Safety Research
- OWASP (@owasp) — Security Standards

YouTube:
- Professor Messer — CompTIA Security+ (kostenlos)
- David Bombal — Cybersecurity allgemein
- John Hammond — CTF + Hacking
- NetworkChuck — Security für Einsteiger
```
