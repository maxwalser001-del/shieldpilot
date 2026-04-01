# Dispatch Setup — Installation

## Ordner-Struktur (fertig erstellt)
```
dispatch-setup/
  CLAUDE.md              ← Haupt-Instruktionen (LEAN — 6 Zeilen)
  change-log.md          ← Claude loggt Aenderungen hier
  context/
    identity.md          ← Wer du bist (kurz)
    projects.md          ← Aktive Projekte (kurz)
    output-rules.md      ← Wie Antworten aussehen sollen
  skills/
    research.md          ← Web-Recherche Regeln
    content.md           ← Content Writing Regeln
    code-review.md       ← Code Review Regeln
    planning.md          ← Planung & Tasks
    communication.md     ← Emails & Nachrichten
  outputs/               ← Claude speichert Ergebnisse hier
  todo/                  ← Dateien zum Verarbeiten ablegen
  references/            ← Read-only Dokumente
  thoughts/              ← Notizen und Ideen
```

## So richtest du es ein

### Schritt 1: Cowork Ordner setzen
- Oeffne Claude Desktop → Cowork Tab
- "Anpassen" → Arbeitsordner setzen auf:
  `~/Desktop/Cyber Security Claude/dispatch-setup/`

### Schritt 2: Context Files laden
- In Cowork → "Anpassen" → "Context Files"
- Fuege hinzu:
  - `CLAUDE.md` (wird automatisch geladen wenn im Root)
  - `context/identity.md`
  - `context/projects.md`
  - `context/output-rules.md`

### Schritt 3: Unnoetige Plugins deaktivieren
- Cowork → Einstellungen → Plugins
- Deaktiviere alles was du nicht nutzt
- Weniger Plugins = weniger Token-Verbrauch = schnellere Antworten

### Schritt 4: Testen
Sende in Dispatch:
"Fasse meine aktiven Projekte zusammen."

Claude sollte eine kurze Zusammenfassung aus projects.md geben.

## Warum diese Struktur funktioniert

1. **CLAUDE.md ist nur 6 Zeilen** — wird bei JEDER Nachricht geladen,
   daher minimal halten
2. **Context Files sind modular** — Claude liest sie bei Bedarf,
   nicht alle auf einmal
3. **Skills sind chunked** — 5 kleine Skills statt 1 grosser,
   bessere Ergebnisse (bestaetigt durch PH Power Users)
4. **outputs/ Ordner** — alle Ergebnisse an einem Ort, leicht zu finden
5. **change-log.md** — Nachvollziehbarkeit was Claude geaendert hat

## Token-Budget Regeln

- Context Files: ~500 Tokens gesamt (identity 80, projects 120, rules 100, CLAUDE.md 50)
- Skills: ~150 Tokens Metadata, Full Instructions nur bei Bedarf geladen
- GESAMT: ~650 Tokens fixer Overhead — das sind <1% der 200K Context Window
- Zum Vergleich: Ein einziger langer Prompt verbraucht oft 500+ Tokens

## Bei Problemen

- Antworten zu generisch? → Pruefe ob context/ Files geladen sind
- Zu langsam? → Plugins deaktivieren die du nicht brauchst
- Dispatch antwortet nicht? → Bekannter macOS Bug (Issue #40283), nutze Cowork direkt
