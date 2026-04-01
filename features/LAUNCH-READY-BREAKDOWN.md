# ShieldPilot Launch-Ready Task Breakdown

## Tier-Referenz (Free / Pro / Admin)

| Feature | Free ($0) | Pro ($19.99/mo) | Admin (Super-Admin) |
|---------|-----------|-----------------|---------------------|
| Commands/day | 50 | 1,000 | Unlimited |
| Scans/day | 10 | 100 | Unlimited |
| History retention | 1 day | 30 days | Forever |
| LLM analysis | No | Yes | Yes |
| Export (CSV/JSON) | No | Yes | Yes |
| API key access | No | Yes | Yes |
| Library (full) | No (nur erstes Item) | Yes | Yes |
| Priority support | No | No | Yes |
| Multi-user/tenants | No | No | Yes |
| Sidebar Badge | "FREE" (grau) | "PRO" (blau) | "UNLIMITED" (cyan) |
| Paywall bei Limit | Ja, sofort | Ja, bei 1000/100 | Nie |

---

## Wave 1 — Critical Billing Bug Fixes

### Lane A: Config Default + Tier Fallback Fix
**Agent:** Backend Dev
**Ziel:** Neue User bekommen `free` Tier statt `unlimited`
**DONE wenn:** Ein neuer User ohne DB-Tier wird als `free` behandelt mit 50 cmd/day + 10 scans/day

**Dateien:**
1. `sentinel.yaml` Zeile 101: `tier: unlimited` → `tier: free`
2. `sentinelai/api/deps.py` Zeile 238: Fallback auf `"free"` statt `config.billing.tier`

**Exakte Änderungen:**

```yaml
# sentinel.yaml Zeile 101
# VORHER:
    tier: unlimited
# NACHHER:
    tier: free
```

```python
# sentinelai/api/deps.py — get_user_tier_limits() Zeile 228-238
# VORHER:
        if db_user and db_user.tier and db_user.tier != "free":
            user_tier = db_user.tier
            if user_tier in ("pro", "enterprise"):
                active_statuses = ("active", "trialing", "past_due")
                if getattr(db_user, "subscription_status", None) not in active_statuses:
                    user_tier = "free"
        else:
            user_tier = config.billing.tier  # <-- BUG: falls back to "unlimited"

# NACHHER:
        if db_user and db_user.tier and db_user.tier != "free":
            user_tier = db_user.tier
            if user_tier in ("pro", "enterprise"):
                active_statuses = ("active", "trialing", "past_due")
                if getattr(db_user, "subscription_status", None) not in active_statuses:
                    user_tier = "free"
        else:
            user_tier = "free"  # FIX: always default to free tier
```

**Verifikation:**
```bash
python3 -m pytest tests/test_api/test_routes.py -x -q --tb=short
python3 -c "from sentinelai.core.config import load_config; c = load_config(); assert c.billing.tier == 'free', f'Expected free, got {c.billing.tier}'"
```

---

### Lane B: Per-User Usage Tracking
**Agent:** Backend Dev
**Ziel:** Jeder User hat seinen eigenen Usage-Zähler statt eines globalen Zählers
**DONE wenn:** User A mit 50 Commands erreicht sein Limit, während User B noch 50 übrig hat

**Problem:** In `sentinelai/api/deps.py` filtern 5 Stellen `UsageRecord` mit `tenant_id == None` — das ist ein GLOBALER Zähler. Alle User teilen sich denselben Zähler.

**Dateien:**
1. `sentinelai/api/deps.py` — 5 Funktionen anpassen
2. `sentinelai/logger/database.py` — UsageRecord braucht `user_email` Column (Migration)

**Exakte Änderungen:**

1. **`sentinelai/logger/database.py`** — `UsageRecord` erweitern:
   - Neue Column: `user_email = Column(String(256), nullable=True, index=True)`
   - In `migrate_database()`: `ALTER TABLE usage ADD COLUMN user_email VARCHAR(256)` hinzufügen
   - Neuer Index: `ix_usage_user_date` auf `(user_email, date)`

2. **`sentinelai/api/deps.py`** — Alle 5 Stellen die `tenant_id == None` filtern, auf `user_email` umstellen:

   a) `_get_daily_usage_internal()` (Zeile 307-311): Parameter `user_email: Optional[str] = None` hinzufügen. Query: `UsageRecord.user_email == user_email` statt `tenant_id == None`

   b) `increment_command_usage()` (Zeile 376-410): Parameter `user_email: Optional[str] = None` hinzufügen. Query und Insert: `user_email=user_email` statt `tenant_id=None`

   c) `increment_scan_usage()` (Zeile 413-448): Gleich wie oben

   d) `_check_command_limit_internal()` (Zeile 470-515): Parameter `user_email: Optional[str] = None` hinzufügen. Query: `UsageRecord.user_email == user_email`

   e) `_check_scan_limit_internal()` (Zeile 538-581): Gleich wie oben

3. **Alle Aufrufer** dieser Funktionen müssen jetzt `user_email=user.email` übergeben:
   - `get_daily_usage_for_user()` → `_get_daily_usage_internal(..., user_email=user.email)`
   - `check_command_limit_for_user()` → `_check_command_limit_internal(..., user_email=user.email)`
   - `check_scan_limit_for_user()` → `_check_scan_limit_internal(..., user_email=user.email)`

4. **Hook-Kompatibilität:** `sentinelai/hooks/sentinel_hook.py` ruft `increment_command_usage(logger)` ohne User auf. Das muss weiter funktionieren (globaler Zähler für Hook = OK, der Hook hat keinen User-Context). Die Funktionen müssen also mit `user_email=None` als Fallback weiter den globalen Zähler nutzen.

**Verifikation:**
```bash
python3 -m pytest tests/ -x -q --tb=short
# Manuell: Zwei verschiedene User registrieren, jeder hat eigene 50/10 Limits
```

---

### Lane C: Per-User Limit Enforcement am API
**Agent:** Backend Dev
**Ziel:** Command/Scan Limits werden pro User enforced, nicht nur im Hook
**DONE wenn:** API-Endpoint `/api/evaluate` einen 429 wirft wenn User sein Limit erreicht hat

**Problem:** `check_command_limit()` und `check_scan_limit()` (die FastAPI Dependencies ohne User-Context) nutzen den globalen Zähler. Die per-User Varianten (`check_command_limit_for_user` etc.) existieren schon, werden aber nicht als Dependencies an den Endpoints genutzt.

**Dateien:**
1. `sentinelai/api/routers/evaluate.py` — `check_command_limit` durch per-User Version ersetzen
2. `sentinelai/api/routers/scan.py` — `check_scan_limit` durch per-User Version ersetzen
3. Alle anderen Router prüfen ob sie `check_command_limit` nutzen

**Vorgehen:**
- Suche alle Router die `Depends(check_command_limit)` oder `Depends(check_scan_limit)` nutzen
- Ersetze durch neue Dependency die den User hat:
  ```python
  def check_user_command_limit(
      user: TokenData = Depends(get_current_user),
      config: SentinelConfig = Depends(get_config),
      logger: BlackboxLogger = Depends(get_logger),
  ) -> None:
      check_command_limit_for_user(user, config, logger)
  ```
- Diese neue Dependency in die Router einbauen

**WICHTIG:** Nicht die globalen `check_command_limit`/`check_scan_limit` löschen — der Hook braucht sie noch als Fallback.

**Verifikation:**
```bash
python3 -m pytest tests/ -x -q --tb=short
```

---

### Lane D: Tests für Wave 1
**Agent:** QA Engineer
**Ziel:** Alle 3 Bug-Fixes haben automatisierte Tests
**DONE wenn:** Mindestens 15 neue Tests in `tests/test_api/test_billing.py` die PASS

**Test-Datei:** `tests/test_api/test_billing.py`

**Zu testende Szenarien:**

1. **Config Default (Lane A):**
   - Neuer User ohne expliziten Tier bekommt `free` Limits (50 cmd, 10 scans)
   - Super-Admin bekommt `unlimited` unabhängig von Config
   - User mit `tier="pro"` in DB bekommt Pro-Limits (1000 cmd, 100 scans)

2. **Per-User Usage (Lane B):**
   - User A incrementiert Usage → User B Usage bleibt bei 0
   - Globaler Zähler (user_email=None) ist unabhängig von per-User Zählern
   - Usage reset nach Datum-Wechsel

3. **Per-User Limit Enforcement (Lane C):**
   - Free User bei 50 Commands → 429 bei nächstem `/api/evaluate`
   - Pro User bei 50 Commands → kein 429 (Limit ist 1000)
   - Super-Admin → nie 429
   - Free User bei 10 Scans → 429 bei nächstem `/api/scan/prompt`

4. **Feature Gating:**
   - Free User → 403 bei `/api/export/*` (export_enabled=False)
   - Free User → Library zeigt nur erstes Item (library_access=False)
   - Pro User → Export + Library voll zugänglich
   - Free User → 403 bei API Key Generierung (api_access=False)

**Warte auf Lane A+B+C Completion, dann schreibe Tests.**

---

## Wave 2 — Tier-Differentiated UI

### Lane E: Free-Tier Experience
**Agent:** Frontend Dev
**Ziel:** Free-User sieht klar was gesperrt ist und wie man upgraden kann
**DONE wenn:** Gesperrte Features einen Pro-Lock-Overlay zeigen + Upgrade-CTA sichtbar

**Dateien:**
1. `sentinelai/web/static/js/app.js`
2. `sentinelai/web/static/js/components.js`
3. `sentinelai/web/static/css/sentinel.css`

**Änderungen:**

1. **Sidebar Navigation — Feature Locks:**
   - Neben "Library" und "Config" Sidebar-Items ein Lock-Icon anzeigen wenn `usageCache.tier === 'free'`
   - Lock-Icon: SVG Schloss, grau, klein (12x12px)
   - Klick auf gesperrtes Item → zeigt Inline-Banner "Upgrade to Pro to unlock this feature" mit Button

2. **Export Buttons — Pro-Only Gate:**
   - Alle "Export CSV/JSON" Buttons (auf Commands, Incidents, Activity, Scans):
     - Wenn `tier === 'free'`: Button disabled + Tooltip "Pro feature"
     - Klick zeigt Toast: "Export is a Pro feature. Upgrade at #/pricing"

3. **Dashboard — Upgrade CTA Card:**
   - Neues OpsCard im Dashboard Grid wenn `tier === 'free'`:
     ```
     ┌─────────────────────┐
     │  Upgrade to Pro     │
     │  Unlock unlimited   │
     │  scans, exports,    │
     │  API access & more  │
     │  [Upgrade →]        │
     └─────────────────────┘
     ```
   - Position: letzte Karte im `ops-grid`
   - Styling: Border `var(--accent-cyan)`, leicht hervorgehoben

4. **Scans Page — Limit Info:**
   - Bereits implementiert (Zeile 1536-1552). Prüfen ob es korrekt funktioniert.

5. **Neuer Component in `components.js`:**
   ```javascript
   export function ProFeatureLock(featureName) {
       return `<div class="pro-feature-lock">
           <svg ...lock icon...></svg>
           <p>${escapeHtml(featureName)} is available on the Pro plan</p>
           <a href="#/pricing" class="btn btn-primary btn-sm">Upgrade to Pro</a>
       </div>`;
   }
   ```

6. **CSS für Lock-Overlay:**
   ```css
   .pro-feature-lock { /* centered overlay, semi-transparent bg, blur */ }
   .nav-item-locked .nav-lock-icon { /* small lock next to nav text */ }
   .btn-pro-only:disabled { opacity: 0.5; cursor: not-allowed; }
   ```

**Verifikation:**
- Browser: Als Free-User einloggen → Library zeigt Lock → Export-Buttons disabled → Dashboard zeigt Upgrade-Card
- `python3 -m pytest tests/ -x -q --tb=short` (keine Regression)

---

### Lane F: Pro-Tier Experience
**Agent:** Frontend Dev
**Ziel:** Pro-User sieht alle Features freigeschaltet + Subscription-Status
**DONE wenn:** Pro-Badge in Sidebar, alle Features unlocked, Subscription-Info in Settings

**Dateien:**
1. `sentinelai/web/static/js/app.js` — Settings-Page Subscription-Sektion
2. `sentinelai/web/static/css/sentinel.css` — Pro Badge Styling

**Änderungen:**

1. **Sidebar Badge:**
   - Bereits implementiert (Zeile 3612-3634). Prüfen:
     - `tier-badge tier-free` → grau (#94a3b8)
     - `tier-badge tier-pro` → blau (#3b82f6)
     - `tier-badge tier-unlimited` → cyan (#39D2C0)
   - Falls nicht vorhanden: CSS-Klassen hinzufügen

2. **Settings Page — Subscription Management:**
   - Bereits teilweise implementiert (Zeile 3327). Erweitern:
   - Wenn `tier === 'pro'` und `has_subscription`:
     - Zeige "Current Plan: Pro ($19.99/mo)"
     - Zeige "Next billing: [date]"
     - Zeige "Cancel subscription" Button (führt zu Stripe Portal)
     - Wenn `cancel_at_period_end`: Zeige "Your plan ends on [date]. Reactivate?"
   - Wenn `subscription_status === 'past_due'`:
     - Zeige Banner: "Payment failed. Update your payment method." + Link zu Stripe Portal

3. **All Features Unlocked:**
   - Export-Buttons enabled
   - Library vollständig zugänglich (kein Lock)
   - API Key Generierung erlaubt
   - Keine Upgrade-CTAs anzeigen für Pro-User

4. **Pro Welcome Toast:**
   - Bereits implementiert (Zeile 3033-3034). Prüfen ob es funktioniert.

**Verifikation:**
- Browser: Als Pro-User einloggen → Blauer "PRO" Badge → Alle Features unlocked → Settings zeigt Subscription-Info
- `python3 -m pytest tests/ -x -q --tb=short`

---

### Lane G: Admin Experience
**Agent:** Frontend Dev
**Ziel:** Admin hat Zugang zu Admin-Funktionen und sieht "UNLIMITED" Badge
**DONE wenn:** Admin sieht User-Management, Config-Editor, und Unlimited Badge

**Dateien:**
1. `sentinelai/web/static/js/app.js`
2. `sentinelai/web/static/css/sentinel.css`

**Änderungen:**

1. **Sidebar — Admin-Only Items:**
   - "Config" Nav-Item: Nur sichtbar wenn `usageCache?.is_admin`
   - Wenn nicht Admin: Nav-Item komplett ausblenden (nicht nur Lock)
   - Implementierung: In `handleRoute()` oder `initSidebar()` prüfen

2. **Dashboard — Admin Extras:**
   - Wenn Admin: Zusätzliche KPI-Karte "Active Users" im ops-grid (Wert aus `/api/stats`)
   - Keine Limit-Banner, keine Paywall, kein Upgrade-CTA

3. **Config Page — Nur Admin:**
   - Route Guard: Wenn nicht Admin → Redirect zu `#/dashboard` + Toast "Admin access required"
   - Bereits `require_admin` am API-Level, muss auch im Frontend enforced werden

4. **Unlimited Badge:**
   - Bereits implementiert. Prüfen dass CSS korrekt ist:
   ```css
   .tier-badge.tier-unlimited { background: #39D2C020; color: #39D2C0; border: 1px solid #39D2C040; }
   ```

**Verifikation:**
- Browser: Als Admin einloggen → Cyan "UNLIMITED" Badge → Config sichtbar → Kein Limit-Banner
- Browser: Als Free-User → Config NICHT in Sidebar → Redirect bei direktem Zugriff
- `python3 -m pytest tests/ -x -q --tb=short`

---

## Wave 3 — Page Polish

### Lane H: Library Page Komplett
**Agent:** Frontend Dev
**Ziel:** Library-Page ist fertig mit Item-Detail, Code-Copy, Pro-Lock, Suche
**DONE wenn:** Library zeigt Topics → Items → Detail-View mit Copy-Button, Free-User sieht Lock auf Items

**Dateien:**
1. `sentinelai/web/static/js/app.js` — Library-Funktionen (ab Zeile 1936)
2. `sentinelai/web/static/js/components.js` — Library-Components
3. `sentinelai/web/static/css/sentinel.css` — Library-Styles

**Aktueller Stand:**
- Topics-Sidebar funktioniert (fetchLibraryTopics, wireTopicNav)
- Card-Grid zeigt Items (LibraryCardGrid Component)
- Admin kann Items hinzufügen/bearbeiten/löschen
- `libraryHasProAccess` Flag vorhanden
- API-Endpoints existieren alle (13 Endpoints in `routers/library.py`)

**Was fehlt:**

1. **Item Detail View:**
   - Klick auf Library-Card → Detail-Ansicht (nicht nur Card)
   - Layout: Breites Panel rechts (oder Modal) mit:
     - Item-Titel + Beschreibung
     - Content (Markdown oder Plain-Text), scrollbar
     - "Copy to Clipboard" Button (oben rechts)
     - Tags/Kategorie
     - "Back to list" Button
   - API: `GET /api/library/{item_id}` ist vorhanden

2. **Copy to Clipboard:**
   - Button kopiert den `content` des Library-Items
   - `navigator.clipboard.writeText()` mit Fallback
   - Toast: "Copied to clipboard!"

3. **Pro-Lock auf Items:**
   - Wenn `libraryHasProAccess === false`:
     - Erstes Item: Voll sichtbar + kopierbar (Teaser)
     - Alle weiteren Items: Blur-Overlay + Lock-Icon + "Upgrade to Pro"
   - Implementierung in `LibraryCardGrid` Component

4. **Suche/Filter:**
   - Suchfeld oben in `library-main` Header
   - Client-side Filter über `libraryData` (Name + Description)
   - Input mit Debounce (300ms)

5. **Empty State Verbesserung:**
   - Aktuell: "No items in this topic. Check back soon!"
   - Besser: Icon (Buch/Library SVG) + aussagekräftigerer Text
   - Wenn Admin: "No items yet. Click '+Add Item' to get started."

**Verifikation:**
- Browser: Library → Topic wählen → Item klicken → Detail-View → Copy → Toast
- Browser als Free: Erstes Item sichtbar, Rest geblurrt mit Lock
- `python3 -m pytest tests/ -x -q --tb=short`

---

### Lane I: Config Page Redesign
**Agent:** Frontend Dev
**Ziel:** Config-Page von YAML-Dump zu einem hübschen, lesbaren Dashboard (read-only)
**DONE wenn:** Config zeigt gruppierte Sektionen mit Icons, Status-Badges, und klaren Werten

**Dateien:**
1. `sentinelai/web/static/js/app.js` — `renderConfig()` (Zeile 2481-2509)
2. `sentinelai/web/static/css/sentinel.css`

**Aktueller Stand:**
- `renderConfig()` macht API-Call zu `/api/config/summary`
- Response: `{ mode, risk_thresholds: {block, warn}, llm_enabled, llm_model, sandbox_enabled, sandbox_timeout, chain_hashing, whitelist_count, blacklist_count, protected_paths_count, secret_patterns_count, billing_tier }`
- Aktuell: Einfache Key-Value Liste (config-row / config-key / config-value)

**Neues Design:**

```
┌────────────────────────────────────────────────────────────┐
│  Configuration                                    [Admin]  │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  ┌─ Security Engine ──────────────────────────────────┐    │
│  │  Mode:    [ENFORCE]  (green badge)                  │    │
│  │  Block:   ≥ 80      Warn: ≥ 40                     │    │
│  │  Chain:   Enabled ✓                                 │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                            │
│  ┌─ Sandbox ──────────────────────────────────────────┐    │
│  │  Status:  [ENABLED]  (green badge)                  │    │
│  │  Timeout: 30s       Max Memory: 512 MB              │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                            │
│  ┌─ LLM Analysis ────────────────────────────────────┐     │
│  │  Status:  [DISABLED]  (grey badge)                  │    │
│  │  Model:   —                                         │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                            │
│  ┌─ Rules ────────────────────────────────────────────┐    │
│  │  Whitelist:        12 commands                      │    │
│  │  Blacklist:         6 commands                      │    │
│  │  Protected Paths:   8 paths                         │    │
│  │  Secret Patterns:   5 patterns                      │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                            │
│  ┌─ Billing ──────────────────────────────────────────┐    │
│  │  Tier:    [FREE]  (badge in tier color)              │    │
│  └─────────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────┘
```

**Implementierung:**
- 5 Sektions-Cards mit CSS class `config-section`
- Jede Sektion: Titel mit Icon-SVG, Key-Value Grid
- Status-Badges: `enforce` → grün, `audit` → gelb, `disabled` → grau
- Boolean-Werte: Checkmark ✓ grün oder Cross ✗ grau
- Reuse von `.ops-card` oder `.health-component-card` Styling wo möglich
- KEIN Edit-Formular (read-only). Das kommt in einem späteren Release.

**Verifikation:**
- Browser: Config-Page zeigt 5 gruppierte Sektionen mit Badges
- `python3 -m pytest tests/ -x -q --tb=short`

---

### Lane J: Scans Page Enhancement
**Agent:** Frontend Dev
**Ziel:** Scans-Page bekommt Scan-History-Tabelle und bessere Ergebnis-Darstellung
**DONE wenn:** Scans zeigt History-Tabelle mit vergangenen Scans + Detail-Expand

**Dateien:**
1. `sentinelai/web/static/js/app.js` — `renderScans()` (Zeile 1532)
2. `sentinelai/web/static/css/sentinel.css`

**Aktueller Stand:**
- Scan-Form (Textarea + Submit) funktioniert
- Scan-Result wird inline angezeigt
- `scan-table` Container existiert aber `loadScanTable()` muss geprüft werden
- API: `GET /api/scans` liefert History, `POST /api/scan/prompt` macht den Scan

**Was hinzufügen:**

1. **Scan-History Tabelle:**
   - Unter dem Scan-Formular
   - Columns: Timestamp | Source | Score | Threats | Status
   - Score als Farb-Badge (0-39 grün, 40-79 gelb, 80+ rot)
   - Threats-Count als Zahl
   - Klick auf Row → Expand mit Threat-Details (JSON pretty-printed)
   - Pagination: 20 pro Seite, "Load more" Button
   - Leer-State: "No scans yet. Try scanning some text above."

2. **Scan-Ergebnis Verbesserung:**
   - Aktuelles Ergebnis: Prüfen was angezeigt wird
   - Soll: Großer Score-Circle (wie OpsScoreCard), Threat-Liste mit Kategorie + Severity, Recommendation-Text

3. **Scan-Statistik Mini-Header:**
   - Über der Tabelle: "X scans today | Y threats detected | Z blocked"
   - Daten aus `/api/stats` oder berechnet aus History

**Verifikation:**
- Browser: Scan durchführen → Ergebnis mit Score-Circle → History-Tabelle zeigt Eintrag
- `python3 -m pytest tests/ -x -q --tb=short`

---

### Lane K: Empty States + Loading Skeletons
**Agent:** Frontend Dev
**Ziel:** Alle Seiten haben hübsche Empty States und Loading-Skeletons statt nur Spinner
**DONE wenn:** Jede Seite hat einen SVG-Icon Empty State und Skeleton-Loading

**Dateien:**
1. `sentinelai/web/static/js/components.js` — `EmptyState()` erweitern + `SkeletonCard()` neu
2. `sentinelai/web/static/css/sentinel.css` — Skeleton Animation

**Änderungen:**

1. **EmptyState Component erweitern:**
   - Aktuell: `EmptyState(message, sub)` → Text only
   - Neu: `EmptyState(message, sub, icon)` mit optionalem SVG-Icon
   - Icons pro Kontext:
     - Commands: Terminal-Icon
     - Incidents: Shield-Check-Icon
     - Scans: Magnifying-Glass-Icon
     - Activity: Clock-Icon
     - Library: Book-Icon
   - SVGs inline, 48x48px, `var(--text-muted)` Farbe

2. **SkeletonCard Component (neu):**
   ```javascript
   export function SkeletonCard(count = 3) {
       return Array(count).fill(0).map(() => `
           <div class="skeleton-card">
               <div class="skeleton-line skeleton-title"></div>
               <div class="skeleton-line skeleton-text"></div>
               <div class="skeleton-line skeleton-text short"></div>
           </div>
       `).join('');
   }
   ```

3. **CSS Skeleton Animation:**
   ```css
   .skeleton-card { /* card shape, same as ops-card */ }
   .skeleton-line { background: linear-gradient(90deg, #1a2332 25%, #243447 50%, #1a2332 75%);
                    background-size: 200% 100%; animation: shimmer 1.5s infinite; }
   @keyframes shimmer { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }
   ```

4. **Einsetzen:**
   - `renderDashboard()`: Skeleton statt Spinner beim Laden
   - `renderCommands()`: Skeleton-Tabelle
   - `renderIncidents()`: Skeleton-Cards
   - `renderLibrary()`: Skeleton-Cards
   - `renderActivity()`: Skeleton-Feed-Items

**Verifikation:**
- Browser: Seite laden → kurz Skeleton sichtbar → echte Daten ersetzen Skeleton
- `python3 -m pytest tests/ -x -q --tb=short`

---

## Wave 4 — QA + Final Verification

### Lane L: End-to-End QA
**Agent:** QA Engineer
**Ziel:** Alle User-Flows funktionieren korrekt für Free/Pro/Admin
**DONE wenn:** Alle Flows getestet, Bugs dokumentiert, 0 Critical/High Bugs offen

**Test-Plan:**

1. **Registration Flow:**
   - Registrieren mit Email/Password → Email kommt (oder Skip in Dev) → Login → Tier = Free

2. **Free User Flow:**
   - Dashboard: Sieht Usage (X/50 commands, X/10 scans) + Upgrade CTA
   - Commands: Tabelle sichtbar, Export disabled
   - Scans: Form sichtbar, Limit-Banner bei 10 Scans
   - Library: Erstes Item sichtbar, Rest gelockt
   - Config: Nicht in Sidebar sichtbar
   - Pricing: Sieht 3 Tier-Cards, Upgrade-Button bei Pro

3. **Pro User Flow (simuliert über DB-Tier-Update):**
   - Dashboard: Kein Upgrade CTA, höhere Limits
   - Export: Funktioniert
   - Library: Alle Items sichtbar
   - Settings: Subscription-Info sichtbar

4. **Admin Flow:**
   - Dashboard: Keine Limits, kein Paywall
   - Config: Sichtbar + zeigt gruppierte Konfiguration
   - Library: Admin-Buttons (Add/Edit/Delete)
   - Settings: Unlimited Badge

5. **Paywall Flow:**
   - Free User: 50 Commands ausschöpfen → Dashboard zeigt Paywall-Overlay → "Security Protection Disabled"
   - Pro User: Bei 1000 → gleicher Flow

6. **Edge Cases:**
   - Logout → Login → Usage bleibt erhalten
   - Zwei Browser-Tabs gleichzeitig → kein Race Condition
   - Abgelaufene Subscription → Fallback auf Free

**Output:** QA-Report in `features/WAVE4-QA-REPORT.md`

---

### Lane M: Responsiveness + Accessibility
**Agent:** Frontend Dev
**Ziel:** Plattform ist mobile-tauglich und accessible
**DONE wenn:** Mobile Sidebar collapsed, Touch-Targets ≥ 44px, ARIA Labels vorhanden

**Dateien:**
1. `sentinelai/web/static/css/sentinel.css`
2. `sentinelai/web/templates/index.html`
3. `sentinelai/web/static/js/app.js`

**Änderungen:**

1. **Mobile Sidebar (< 768px):**
   - Sidebar collapsed by default
   - Hamburger-Button (☰) oben links
   - Klick → Sidebar slided rein (overlay)
   - Backdrop: Semi-transparent, klick schließt Sidebar
   - CSS: `@media (max-width: 768px) { .sidebar { transform: translateX(-100%); } .sidebar.open { transform: translateX(0); } }`

2. **Touch Targets:**
   - Alle Buttons/Links mindestens 44x44px (WCAG 2.5.5)
   - Nav-Items: Padding erhöhen auf mobile
   - Tabellen: Horizontal scrollbar auf mobile

3. **ARIA Labels:**
   - Sidebar Nav: `role="navigation"`, `aria-label="Main navigation"`
   - Modals: `role="dialog"`, `aria-modal="true"`, `aria-labelledby`
   - Buttons: Alle SVG-only Buttons brauchen `aria-label`
   - Status-Badges: `aria-label="Risk score: 85, blocked"`
   - Live-Regions: Dashboard-Updates als `aria-live="polite"`

4. **Keyboard Navigation:**
   - Tab-Reihenfolge logisch (Sidebar → Main Content)
   - Escape schließt Modals
   - Enter/Space auf alle clickable Elements

5. **Focus Indicators:**
   - Sichtbarer Focus-Ring (2px solid var(--accent-cyan))
   - `*:focus-visible { outline: 2px solid var(--accent-cyan); outline-offset: 2px; }`

**Verifikation:**
- Browser DevTools: Mobile View (375px) → Sidebar collapsed → Hamburger → Navigation funktioniert
- Tab durch alle Seiten → Focus-Ring sichtbar → logische Reihenfolge
- `python3 -m pytest tests/ -x -q --tb=short`

---

## Execution Order

```
Wave 1 (parallel):  Lane A + B + C gleichzeitig
                    Lane D wartet auf A+B+C

Wave 2 (parallel):  Lane E + F + G gleichzeitig (nach Wave 1)

Wave 3 (parallel):  Lane H + I + J + K gleichzeitig (nach Wave 2)

Wave 4 (parallel):  Lane L + M gleichzeitig (nach Wave 3)
```

## Abhängigkeiten

| Lane | Abhängig von | Grund |
|------|-------------|-------|
| D | A, B, C | Tests brauchen die Fixes |
| E | A | Free-Tier muss korrekt enforced sein |
| F | A | Pro-Tier muss korrekt funktionieren |
| G | A | Admin-Check muss korrekt sein |
| H | E | Pro-Lock braucht Feature-Gate UI |
| L | Alle vorherigen | E2E testet alles zusammen |
| M | Keine (unabhängig) | CSS/HTML only |
