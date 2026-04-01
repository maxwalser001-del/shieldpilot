# ShieldPilot Launch Breakdown — Waves 3-6

## Pricing-Entscheidungen (Basis für alle Tasks)

### Neue Tier-Struktur
| | Free | Pro | Unlimited |
|---|---|---|---|
| Preis | €0 | €29/mo (€279/yr) | €99/mo (€990/yr) |
| Commands/Tag | 50 | 1.000 | Unbegrenzt |
| Scans/Tag | 10 | 100 | Unbegrenzt |
| History | 24h | 30 Tage | 1 Jahr |
| LLM-Analyse | Nein | Ja | Ja |
| API + Export | Nein | Ja | Ja |
| Library | Preview | Voll | Voll |
| Priority Support | Nein | Nein | Ja |

Enterprise = "Contact us" (kein Self-Serve-Tier)

### Command Booster (Add-On)
- €4.99 einmalig → +500 Commands für heute (verfällt Mitternacht UTC)
- Verfügbar für Free + Pro User
- Neues DB-Model: `BoosterCredit`
- Neuer Endpoint: POST /api/billing/booster

---

## Wave 3: Pricing Backend + Dashboard Cleanup (3 parallele Lanes)

### Lane H — Pricing Model Backend (Backend Dev)
**Ziel:** Tier-Struktur + Preise im Backend aktualisieren, Enterprise entfernen, Unlimited public machen.

**Dateien:**
- `sentinelai/core/config.py` — TIER_LIMITS + TierLimits
- `sentinelai/services/billing_service.py` — get_pricing()
- `sentinelai/billing/stripe_client.py` — PRICE_IDS

**Tasks:**
1. **H-1:** `config.py` TIER_LIMITS anpassen:
   - Pro: `commands_per_day=1000, scans_per_day=100` (bleibt gleich)
   - Enterprise **entfernen** aus Self-Serve (bleibt intern für manuell zugewiesene Kunden)
   - Unlimited: bleibt wie es ist (wird jetzt public statt nur super-admin)
2. **H-2:** `billing_service.py` `get_pricing()`:
   - Pro price: `19.99 → 29`, annual: `190 → 279`
   - Enterprise-Tier aus `tiers` dict entfernen
   - Neuen "unlimited" Tier hinzufügen: `price_monthly: 99, price_annual: 990`
   - Enterprise-Hinweis als `enterprise_cta` Feld: `{"text": "Need more?", "link": "mailto:..."}`
3. **H-3:** Tests anpassen in `tests/test_api/test_billing.py`

**Akzeptanzkriterium:** `GET /api/billing/pricing` gibt 3 Tiers zurück (free, pro, unlimited) mit korrekten Preisen. Kein Enterprise-Tier im Response.

---

### Lane I — Dashboard Cleanup (Frontend Dev)
**Ziel:** "Usage Analytics (7 Days)" Widget entfernen, Dashboard aufräumen.

**Dateien:**
- `sentinelai/web/static/js/app.js` — renderDashboard()

**Tasks:**
1. **I-1:** "Usage Analytics (7 Days)" Section entfernen (Zeile ~653-655):
   ```html
   <section class="dashboard-section dashboard-section-full">
       <h2>Usage Analytics (7 Days)</h2>
       <div id="usage-analytics">${Spinner()}</div>
   </section>
   ```
2. **I-2:** Zugehörigen JS-Code entfernen der `#usage-analytics` befüllt (K5 Widget-Loader)
3. **I-3:** CSS für entfernte Elemente aufräumen (falls vorhanden)
4. **I-4:** Sicherstellen dass "Commands Trend (7 Days)" und "Daily Commands Breakdown (7 Days)" bleiben (die sind nützlich)

**Akzeptanzkriterium:** Dashboard zeigt kein "Usage Analytics (7 Days)" Widget mehr. Alle anderen Dashboard-Widgets funktionieren weiterhin. Tests grün.

---

### Lane J — Sidebar Usage Widget (Frontend Dev)
**Ziel:** Immer sichtbare Command/Scan-Verbrauchsanzeige in der Sidebar.

**Dateien:**
- `sentinelai/web/static/js/app.js` — neue Funktion `updateSidebarUsage()`
- `sentinelai/web/static/css/sentinel.css` — neue Styles
- `sentinelai/web/templates/index.html` — Container in Sidebar

**Tasks:**
1. **J-1:** HTML: Neuen `<div class="sidebar-usage" id="sidebar-usage">` Container in `index.html` zwischen `sidebar-nav` und `sidebar-footer` einfügen
2. **J-2:** JS: `updateSidebarUsage(usage)` Funktion:
   - Zwei Progress-Bars: Commands (z.B. "38/50") und Scans ("7/10")
   - Farbe: Grün (<70%), Gelb (70-89%), Rot (>=90%)
   - Bei unlimited: "∞" anzeigen, kein Progressbar
   - Bei `limit_reached`: Roter Text "LIMIT REACHED" + Upgrade-Link
3. **J-3:** CSS: `.sidebar-usage` Styling (kompakt, passt zum Dark Theme)
   - Progress-Bar: 4px hoch, runde Ecken, bg #1c2333, fill #39D2C0/gelb/rot
   - Text: 0.7rem, #8b949e, bold für Zahl
4. **J-4:** `fetchUsage()` aufrufen: `updateSidebarUsage(usage)` nach `updateAdminNav(usage)`
5. **J-5:** Für Admins: "Unlimited" Badge statt Progress-Bars

**Akzeptanzkriterium:** Sidebar zeigt live Command/Scan-Verbrauch. Farbe wechselt bei 70% und 90%. Admin sieht "Unlimited". Tests grün.

---

## Wave 4: Pricing Page + Paywall UX (2 parallele Lanes, abhängig von Lane H)

### Lane K — Pricing Page Redesign (Frontend Dev)
**Ziel:** Pricing Page mit neuen 3 Tiers + Enterprise CTA + Booster-Teaser.

**Dateien:**
- `sentinelai/web/static/js/app.js` — renderPricing()
- `sentinelai/web/static/css/sentinel.css` — Pricing Styles

**Tasks:**
1. **K-1:** `renderPricing()` umbauen:
   - 3 Tier-Cards nebeneinander: Free / Pro (featured, "Most Popular") / Unlimited
   - Pro-Card hervorgehoben (Cyan Border, leicht erhöht)
   - Unlimited-Card mit "Best Value" Badge bei Annual
2. **K-2:** Monthly/Annual Toggle beibehalten, Savings-Badge updaten
3. **K-3:** Enterprise CTA unter den Cards:
   ```
   "Need custom deployment or dedicated support? Contact us →"
   ```
4. **K-4:** Booster-Teaser-Card unter Enterprise CTA:
   ```
   "Just need a little more today? Buy a Command Booster — €4.99 for +500 commands"
   ```
   (Button deaktiviert mit "Coming soon" oder aktiv falls Lane M fertig)
5. **K-5:** Feature-Vergleichstabelle unter den Cards (responsive):
   - Zeilen: Commands, Scans, History, LLM, API, Export, Library, Support
6. **K-6:** Tests

**Akzeptanzkriterium:** Pricing Page zeigt 3 Tiers mit korrekten Preisen. Annual Toggle funktioniert. Enterprise CTA vorhanden. Responsive auf Mobile.

---

### Lane L — Paywall & Conversion UX (Frontend Dev)
**Ziel:** Aggressivere aber hilfreiche Conversion-Trigger für Free-User.

**Dateien:**
- `sentinelai/web/static/js/app.js` — SecurityDisabledBanner, DashboardPaywall, renderCommands, renderScans
- `sentinelai/web/static/css/sentinel.css`

**Tasks:**
1. **L-1:** `SecurityDisabledBanner()` verbessern — konkreter Text:
   - "Your AI agents executed **{n} commands** today without security screening."
   - "Any of these could have contained malicious code, credential theft, or data exfiltration."
   - Zwei CTAs: "Upgrade to Pro — €29/mo" und "Buy Booster — €4.99 today"
2. **L-2:** `DashboardPaywall()` verbessern:
   - Zeige Anzahl blockierter Threats heute: "ShieldPilot blocked **{n} threats** before your limit ran out"
   - Value-Reinforcement statt nur Fear
3. **L-3:** Approaching-Limit inline Hints in Commands + Scans Seiten:
   - Bei 80%+: gelber Banner "You've used {used}/{limit} commands today. [Upgrade](#/pricing)"
   - Bei 100%: roter Banner wie oben
4. **L-4:** Upgrade-Prompt nach jedem 10. blocked Command (Toast):
   - "Another command blocked by your daily limit. Upgrade for uninterrupted protection."
5. **L-5:** Tests

**Akzeptanzkriterium:** Free-User sehen bei 80% approaching-limit Hinweise. Bei 100% aggressive aber hilfreiche Upgrade-CTAs. Texte erwähnen konkrete Zahlen (blocked threats, commands today). Tests grün.

---

## Wave 5: Booster Pack (2 parallele Lanes)

### Lane M — Booster Backend (Backend Dev)
**Ziel:** Neues DB-Model + Endpoint für Command Booster Kauf.

**Dateien:**
- `sentinelai/logger/database.py` — BoosterCredit Model
- `sentinelai/api/routers/billing.py` — POST /api/billing/booster
- `sentinelai/api/deps.py` — Limit-Check mit Booster-Credits
- `sentinelai/services/billing_service.py` — create_booster()

**Tasks:**
1. **M-1:** `database.py` neues Model:
   ```python
   class BoosterCredit(Base):
       __tablename__ = "booster_credits"
       id = Column(Integer, primary_key=True)
       user_email = Column(String(256), nullable=False, index=True)
       credits_remaining = Column(Integer, default=500)
       purchased_at = Column(DateTime, default=func.now())
       expires_at = Column(String(10))  # ISO date, midnight UTC
       stripe_payment_id = Column(String(256), nullable=True)
   ```
2. **M-2:** Migration in `migrate_database()`
3. **M-3:** `deps.py` — `_check_command_limit_internal()` anpassen:
   - Nach dem normalen Limit-Check: prüfe ob aktive (nicht abgelaufene) BoosterCredits existieren
   - Falls ja: dekrementiere `credits_remaining` statt zu blockieren
   - Falls alle Booster aufgebraucht: normales Limit-Verhalten
4. **M-4:** `billing.py` neuer Endpoint:
   ```
   POST /api/billing/booster
   Body: {} (kein Input nötig, Preis ist fix)
   Response: { "credits": 500, "expires_at": "2026-02-19", "checkout_url": "..." }
   ```
   - Erstellt Stripe One-Time Payment Session (€4.99)
   - Nach Webhook-Bestätigung: BoosterCredit anlegen
5. **M-5:** `GET /api/usage` Response erweitern: `booster_credits_remaining: int`
6. **M-6:** Tests

**Akzeptanzkriterium:** POST /api/billing/booster erstellt Stripe Session. Nach Payment: BoosterCredit in DB. Limit-Check berücksichtigt Booster. GET /api/usage zeigt Booster-Credits. Tests grün.

---

### Lane N — Booster Frontend (Frontend Dev)
**Ziel:** UI für Booster-Kauf + Anzeige im Dashboard.

**Dateien:**
- `sentinelai/web/static/js/app.js`
- `sentinelai/web/static/css/sentinel.css`

**Tasks:**
1. **N-1:** "Buy Booster" Button im Sidebar-Usage-Widget (wenn limit_reached oder approaching):
   - "⚡ +500 Commands — €4.99"
   - Klick → POST /api/billing/booster → Redirect zu Stripe
2. **N-2:** Booster-Credits im Sidebar anzeigen:
   - Unter dem normalen Usage: "⚡ 340 booster credits remaining"
   - Progress-Bar in Cyan
3. **N-3:** Pricing Page: Booster-Card aktivieren (nicht mehr "Coming soon")
4. **N-4:** Paywall-Overlay: "Buy Booster" als zweite Option neben "Upgrade to Pro"
5. **N-5:** Tests

**Akzeptanzkriterium:** User kann Booster kaufen. Credits werden angezeigt und abgezählt. Nach Ablauf (Mitternacht) verschwinden sie.

---

## Wave 6: QA & Final Polish (2 parallele Lanes)

### Lane O — End-to-End QA (QA Engineer)
**Ziel:** Alle Flows testen: Free → Limit → Paywall → Upgrade → Pro → Unlimited.

**Tasks:**
1. **O-1:** Free-User Journey testen:
   - Registrieren → 50 Commands → Limit → Paywall → Upgrade-CTA
2. **O-2:** Pro-User Journey testen:
   - 1000 Commands → Approaching Limit (800) → Limit
3. **O-3:** Admin Journey testen:
   - Unlimited → kein Paywall → Config sichtbar
4. **O-4:** Booster Journey testen:
   - Free → Limit → Buy Booster → 500 extra → Expire
5. **O-5:** Pricing Page testen:
   - 3 Tiers korrekt, Toggle funktioniert, Stripe-Redirect
6. **O-6:** Edge Cases:
   - Tab offen lassen → Mitternacht → Limit reset
   - Mehrere Tabs gleichzeitig
   - Abgelaufener JWT → Redirect zu Login

---

### Lane P — Responsiveness + A11y (Frontend Dev)
**Ziel:** Mobile-Optimierung und WCAG 2.1 AA Compliance.

**Tasks:**
1. **P-1:** Sidebar: Mobile Hamburger-Menu testen + fixen
2. **P-2:** Pricing Page responsive (Cards stacken auf Mobile)
3. **P-3:** Dashboard: Cards stacken auf <768px
4. **P-4:** Alle Buttons: min 44px Touch-Target
5. **P-5:** aria-labels, focus-management, skip-links verifizieren
6. **P-6:** Keyboard-Navigation durch alle Pages testen

---

## Reihenfolge & Abhängigkeiten

```
Wave 3 (parallel):  Lane H (Backend) | Lane I (Dashboard) | Lane J (Sidebar Widget)
                           ↓
Wave 4 (parallel):  Lane K (Pricing Page) | Lane L (Paywall UX)
     [K+L brauchen H für korrekte Preise im Backend]
                           ↓
Wave 5 (parallel):  Lane M (Booster Backend) | Lane N (Booster Frontend)
     [N braucht M für API]
                           ↓
Wave 6 (parallel):  Lane O (QA) | Lane P (A11y)
```
