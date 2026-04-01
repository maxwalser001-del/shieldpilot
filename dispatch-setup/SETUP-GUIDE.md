# Claude Dispatch Setup Guide — Schritt für Schritt

## Schritt 1: Desktop vorbereiten (einmalig)

### Mac Sleep verhindern
Systemeinstellungen → Energie → "Ruhezustand deaktivieren" oder Sleep-Timer auf "Nie"
Sonst stirbt Dispatch wenn dein Mac einschläft.

### Claude Desktop App aktuell halten
Prüfe ob du die neueste Version hast (aktuell Bug in 1.1.9310, warte auf Update).

## Schritt 2: Cowork konfigurieren (einmalig)

Alles was du in Cowork einrichtest, wird automatisch in Dispatch verfügbar.

### Connectors aktivieren (Cowork → Einstellungen)
Aktiviere die Connectors die du brauchst:
- Gmail (für E-Mail Tasks)
- Google Drive (für Dokumente)
- Chrome Browser (für Web-Recherche)
- Slack (falls du es nutzt)

### Context Files laden
Klick in Cowork auf "Anpassen" und lade hoch:
1. Die Datei `DISPATCH-INSTRUCTIONS.md` aus diesem Ordner
2. Deinen CV (`cv-max-walser.md`)

Das gibt Claude Kontext über dich in jeder Session.

### Browser-Aktionen erlauben
Cowork → Einstellungen → "Alle Browser-Aktionen erlauben" → AN

## Schritt 3: Dispatch aktivieren

1. Claude Desktop → Cowork Tab → Dispatch (Sidebar links)
2. "Aktiv halten" → AN
3. "Alle Browser-Aktionen erlauben" → AN
4. "Computernutzung" → Einstellungen öffnen → alles aktivieren

## Schritt 4: Handy verbinden

1. Claude App auf iPhone/Android installieren
2. In der App: Dispatch Tab öffnen
3. QR Code auf dem Desktop scannen
4. Verbindung testen: "Welcher Tag ist heute?" senden

## Schritt 5: Optimale Nutzung

### DO:
- Einen Task pro Nachricht
- Spezifische Dateipfade angeben
- Klaren Output-Format vorgeben
- Kleine iterative Anpassungen statt große Rewrites
- Templates aus TASK-TEMPLATES.md nutzen

### DON'T:
- Mehrere Tasks in einer Nachricht
- Vage Anweisungen ("mach das besser")
- Neue Connectors remote einrichten (mach das am Desktop)
- Erwarten dass Dispatch iMessage oder native Apps steuert
- Tasks die länger als 10 Minuten dauern in einem Schritt

### Beste Task-Typen für Dispatch:
1. Research & Zusammenfassungen
2. Content schreiben (LinkedIn, Emails)
3. Dateien analysieren und zusammenfassen
4. Kleine Code-Änderungen reviewen
5. Kalender/Termine organisieren

### Schlechte Task-Typen für Dispatch:
1. Komplexe Multi-Step Coding Tasks (nutze Claude Code dafür)
2. Native App-Steuerung (iMessage, FaceTime)
3. Aufgaben die Echtzeit-Interaktion brauchen
4. Grosse Refactorings oder Architektur-Entscheidungen
