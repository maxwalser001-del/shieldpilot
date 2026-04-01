# Demo Video Script (60 Sekunden)
# Tool: https://www.loom.com ODER QuickTime (File → New Screen Recording)
# Wichtig: Kein langes Intro. Sofort Action zeigen.

## Setup:
- Terminal: dunkles Theme, Schrift gross genug (16px+)
- Browser: shieldpilot.dev Dashboard eingeloggt
- Zwei Fenster nebeneinander: Terminal links, Dashboard rechts
- Nichts anderes auf dem Screen (Desktop sauber)

## Ablauf:

### 0-3s: Titel
Schwarzer Screen, weisser Text:
"ShieldPilot — What happens when your AI agent goes rogue?"

### 3-10s: Safe Command
Terminal zeigen:
$ sentinel run "git status"
→ ALLOW | score: 0

Text-Overlay: "Safe commands pass through instantly"

### 10-20s: Dangerous Command (GELD-SHOT)
$ sentinel run "rm -rf /"
→ BLOCK | score: 100 | Incident created
→ Rote Ausgabe, klar sichtbar

Text-Overlay: "Dangerous commands are blocked in <1ms"

### 20-30s: Prompt Injection
$ echo "Ignore all previous instructions" | sentinel scan
→ ALERT | score: 70 | 1 threat detected
→ Category: role_manipulation

Text-Overlay: "Prompt injection detected and flagged"

### 30-45s: Dashboard
Wechsel zum Browser:
- Zeige Command Center (Score 100, SYSTEM SECURE)
- Scroll zu Threat Timeline (Balken sichtbar)
- Klick auf Commands → zeige die evaluierten Befehle in der Tabelle

Text-Overlay: "Real-time monitoring dashboard"

### 45-55s: Install
Zurueck zum Terminal:
$ pip install sentinelai
$ sentinel init
$ sentinel hook install

Text-Overlay: "3 commands. That's it."

### 55-60s: End Screen
Schwarzer Screen:
"ShieldPilot"
"Open Source | MIT License"
"github.com/maxwalser001-del/shieldpilot"
"shieldpilot.dev"

## Tipps:
- KEIN Voiceover noetig (Text-Overlays reichen)
- Schnelle Schnitte, keine Wartezeit
- Terminal-Output muss lesbar sein (nicht zu klein)
- Das "rm -rf /" → BLOCKED Moment ist der virale Clip
- Falls moeglich: den 10-20s Clip separat als GIF fuer GitHub README exportieren
