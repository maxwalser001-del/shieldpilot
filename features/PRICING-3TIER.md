# ShieldPilot 3-Tier Pricing

## Ziel
Von 4 Tiers (Free/Pro/Enterprise/Unlimited) auf 3 klare Tiers (Free + Pro €19.99 + Pro+ €29.99).
Enterprise wird gestrichen. Der €10-Jump von Pro zu Pro+ macht das Upgrade zum No-Brainer.

## Neue Tier-Struktur

| | Free (€0) | Pro (€19.99/mo · €189/yr) | Pro+ (€29.99/mo · €279/yr) |
|---|---|---|---|
| Commands/Tag | 50 | 1.000 | Unlimited (-1) |
| Scans/Tag | 10 | 100 | Unlimited (-1) |
| History | 1 Tag | 30 Tage | 90 Tage |
| AI/LLM Analyse | Nein | Nein | Ja |
| Export (CSV/JSON) | Nein | Ja | Ja |
| API Keys | Nein | Unbegrenzt | 5 |
| Library (voll) | Nein (nur 1. Item) | Ja | Ja |
| Priority Support | Nein | Nein | Ja |
| Sidebar Badge | "FREE" grau | "PRO" blau | "PRO+" cyan |
| Paywall bei Limit | Ja, bei 50/10 | Ja, bei 1.000/100 | Nie |

**Interner Tier-Key:** `"pro_plus"` (DB, API, Config)
**Display Name:** `"Pro+"` (UI, Emails, Badge)
**Super-Admin bleibt intern als `"unlimited"` Tier mit role=admin.**
**Annual Pricing:** Pro €189/yr (21% Rabatt), Pro+ €279/yr (22% Rabatt)

---

## Naming Convention

| Kontext | Wert |
|---|---|
| DB `users.tier` | `"pro_plus"` |
| `TIER_LIMITS` Key | `"pro_plus"` |
| Stripe Product | "ShieldPilot Pro+" |
| `PRICE_IDS` Keys | `"pro_plus_monthly"`, `"pro_plus_annual"` |
| `PRICE_TO_TIER` Value | `"pro_plus"` |
| CSS Class | `.tier-badge.tier-pro-plus` |
| Badge Text | "PRO+" |
| Frontend Display | "Pro+" |
| Upgrade CTA | "Upgrade to Pro+" |
| Env Vars | `STRIPE_PRICE_PRO_PLUS_MONTHLY`, `STRIPE_PRICE_PRO_PLUS_ANNUAL` |

**Bestandskunden-Mapping:**
- DB `tier="enterprise"` → behandeln als `"pro_plus"`
- DB `tier="unlimited"` + role≠admin → behandeln als `"pro_plus"`
- DB `tier="unlimited"` + role=admin → bleibt Super-Admin

---

## Delta zum aktuellen Code

### Was sich NICHT ändert
- `TIER_LIMITS["free"]` → bleibt identisch
- `TIER_LIMITS["pro"]` → fast identisch (nur `llm_analysis: False`)
- Pro Stripe-Preise → bleiben, nur Preis anpassen (€29/mo → €19.99/mo)
- Frontend Pro-Badge, Pro-CTA für Free-User → bleiben
- DB Schema → keine Migration nötig

### Was sich ändert

| Datei | Ist | Soll |
|---|---|---|
| `config.py` → `TIER_LIMITS` | `free/pro/enterprise/unlimited` | `free/pro/pro_plus` (+ `unlimited` als Admin-Alias) |
| `config.py` → `TIER_LIMITS["pro"]` | `llm_analysis=True` | `llm_analysis=False` |
| `config.py` → `TIER_LIMITS["enterprise"]` | Existiert | **Entfernen** |
| `config.py` → `TIER_LIMITS["unlimited"]` | Eigener Eintrag | **Alias für pro_plus** (oder Super-Admin-only) |
| `config.py` → `TierLimits` | Kein `max_api_keys` | **Neu: `max_api_keys: int = 0`** |
| `billing_service.py` → `get_pricing()` | 3 Tiers + enterprise CTA | 3 Tiers (free/pro/pro_plus) |
| `billing_service.py` → Preise | Pro €29, Unlimited €99 | Pro €19.99, Pro+ €29.99 |
| `stripe_client.py` → `PRICE_IDS` | `unlimited_monthly/annual` | `pro_plus_monthly/annual` |
| `stripe_client.py` → `PRICE_TO_TIER` | `→ "unlimited"` | `→ "pro_plus"` |
| `deps.py` → `get_user_tier_limits()` | enterprise fallback | enterprise/unlimited (non-admin) → `"pro_plus"` |
| `app.js` → Pricing Page | enterprise Karte | **Pro+ Karte** |
| `app.js` → Badge | `tier-unlimited` | `tier-pro-plus` mit Text "PRO+" |
| `app.js` → CTAs | "Upgrade to Pro" überall | Free→"Upgrade to Pro", Pro→"Upgrade to Pro+" |
| `sentinel.css` | `.tier-unlimited` | `.tier-pro-plus` (cyan) |

---

## Task Breakdown

### Lane 1: Backend — Config + Limits (Backend Dev)
**DONE wenn:** `TIER_LIMITS` hat `free/pro/pro_plus`, enterprise→pro_plus mapping funktioniert, `max_api_keys` enforced

**Exakte Änderungen:**

1. **`sentinelai/core/config.py`** — `TierLimits` Model erweitern:
```python
class TierLimits(BaseModel):
    commands_per_day: int = 50
    scans_per_day: int = 10
    history_retention_days: int = 1
    llm_analysis: bool = False
    export_enabled: bool = False
    multi_user: bool = False
    api_access: bool = False
    priority_support: bool = False
    library_access: bool = False
    max_api_keys: int = 0           # NEW: 0=keine, -1=unbegrenzt
```

2. **`sentinelai/core/config.py`** — `TIER_LIMITS` Zeile 112-157:
```python
TIER_LIMITS = {
    "free": TierLimits(
        commands_per_day=50, scans_per_day=10,
        history_retention_days=1,
        llm_analysis=False, export_enabled=False,
        multi_user=False, api_access=False,
        priority_support=False, library_access=False,
        max_api_keys=0,
    ),
    "pro": TierLimits(
        commands_per_day=1000, scans_per_day=100,
        history_retention_days=30,
        llm_analysis=False, export_enabled=True,
        multi_user=False, api_access=True,
        priority_support=False, library_access=True,
        max_api_keys=-1,           # unbegrenzt
    ),
    "pro_plus": TierLimits(
        commands_per_day=-1, scans_per_day=-1,
        history_retention_days=90,
        llm_analysis=True, export_enabled=True,
        multi_user=True, api_access=True,
        priority_support=True, library_access=True,
        max_api_keys=5,
    ),
    # Super-admin internal alias (not purchasable)
    "unlimited": TierLimits(
        commands_per_day=-1, scans_per_day=-1,
        history_retention_days=-1,
        llm_analysis=True, export_enabled=True,
        multi_user=True, api_access=True,
        priority_support=True, library_access=True,
        max_api_keys=-1,
    ),
}
```

3. **`sentinelai/api/deps.py`** → `get_user_tier_limits()`:
```python
# Bestandskunden-Migration
if user_tier == "enterprise":
    user_tier = "pro_plus"
# Non-admin unlimited users → pro_plus
if user_tier == "unlimited" and not is_super_admin(user, config):
    user_tier = "pro_plus"
```

4. **API Key Limit enforcing** — in der API Key generation Endpoint:
   - Prüfe `user_limits.max_api_keys` vor dem Erstellen
   - 0 = Feature gesperrt (403), -1 = unbegrenzt, N = max N Keys

**Verifikation:**
```bash
python3 -c "from sentinelai.core.config import TIER_LIMITS; assert 'pro_plus' in TIER_LIMITS; assert TIER_LIMITS['pro_plus'].max_api_keys == 5"
python3 -m pytest tests/ -x -q --tb=short
```

---

### Lane 2: Backend — Billing Service + Stripe Client (Backend Dev)
**DONE wenn:** `/api/billing/pricing` gibt 3 Tiers (free/pro/pro_plus) mit neuen Preisen zurück

**Exakte Änderungen:**

1. **`sentinelai/services/billing_service.py`** → `get_pricing()`:
```python
"tiers": {
    "free": {
        "name": "Free",
        "description": "Get started with essential AI security monitoring.",
        "price_monthly": 0, "price_annual": 0,
        "currency": "€",
        "features": TIER_LIMITS["free"].model_dump(),
    },
    "pro": {
        "name": "Pro",
        "description": "Full protection for professional developers.",
        "price_monthly": 19.99, "price_annual": 189,
        "currency": "€",
        "features": TIER_LIMITS["pro"].model_dump(),
    },
    "pro_plus": {
        "name": "Pro+",
        "description": "Unlimited security with AI analysis & priority support.",
        "price_monthly": 29.99, "price_annual": 279,
        "currency": "€",
        "features": TIER_LIMITS["pro_plus"].model_dump(),
    },
},
```

2. **`sentinelai/billing/stripe_client.py`** — `PRICE_IDS`:
```python
PRICE_IDS = {
    "pro_monthly": os.environ.get("STRIPE_PRICE_PRO_MONTHLY", ""),
    "pro_annual": os.environ.get("STRIPE_PRICE_PRO_ANNUAL", ""),
    "pro_plus_monthly": os.environ.get("STRIPE_PRICE_PRO_PLUS_MONTHLY", ""),
    "pro_plus_annual": os.environ.get("STRIPE_PRICE_PRO_PLUS_ANNUAL", ""),
}
```

3. **`sentinelai/billing/stripe_client.py`** — `_build_price_to_tier()`:
```python
def _build_price_to_tier():
    global PRICE_TO_TIER
    PRICE_TO_TIER = {}
    for key, price_id in PRICE_IDS.items():
        if not price_id:
            continue
        if key.startswith("pro_plus"):
            PRICE_TO_TIER[price_id] = "pro_plus"
        elif key.startswith("pro"):
            PRICE_TO_TIER[price_id] = "pro"
    # Backwards compat: old "unlimited" price IDs → pro_plus
    old_unlimited_monthly = os.environ.get("STRIPE_PRICE_UNLIMITED_MONTHLY", "")
    old_unlimited_annual = os.environ.get("STRIPE_PRICE_UNLIMITED_ANNUAL", "")
    if old_unlimited_monthly:
        PRICE_TO_TIER[old_unlimited_monthly] = "pro_plus"
    if old_unlimited_annual:
        PRICE_TO_TIER[old_unlimited_annual] = "pro_plus"
```

4. **Webhook-Handler**: `_handle_checkout_completed` already uses `PRICE_TO_TIER` → works automatically.

**Verifikation:**
```bash
python3 -m pytest tests/test_api/test_billing.py -x -q --tb=short
```

---

### Lane 3: Stripe Dashboard (manuell — Du selbst)
**DONE wenn:** Pro + Pro+ Price IDs in `.env`, Test-Checkout funktioniert

**Schritte:**

#### Pro-Produkt aktualisieren:
1. Stripe Dashboard → Products → "ShieldPilot Pro"
2. Neuer Preis: **€19.99/mo** (recurring monthly)
3. Neuer Preis: **€189/yr** (recurring yearly)
4. Alte Preise archivieren (NICHT löschen)
5. Price IDs kopieren → `.env`:
   - `STRIPE_PRICE_PRO_MONTHLY=price_xxx`
   - `STRIPE_PRICE_PRO_ANNUAL=price_xxx`

#### Pro+ Produkt anlegen:
1. Neues Produkt: **"ShieldPilot Pro+"**
2. Description: "Unlimited commands & scans, AI-powered analysis, priority support"
3. Preis: **€29.99/mo** (recurring monthly)
4. Preis: **€279/yr** (recurring yearly)
5. Price IDs kopieren → `.env`:
   - `STRIPE_PRICE_PRO_PLUS_MONTHLY=price_xxx`
   - `STRIPE_PRICE_PRO_PLUS_ANNUAL=price_xxx`

#### Environment Variables:
```bash
# .env
STRIPE_PRICE_PRO_MONTHLY=price_xxx          # €19.99/mo
STRIPE_PRICE_PRO_ANNUAL=price_xxx            # €189/yr
STRIPE_PRICE_PRO_PLUS_MONTHLY=price_xxx      # €29.99/mo
STRIPE_PRICE_PRO_PLUS_ANNUAL=price_xxx       # €279/yr
# Keep old ones for backwards compat (existing subs)
STRIPE_PRICE_UNLIMITED_MONTHLY=price_xxx     # Old unlimited → maps to pro_plus
STRIPE_PRICE_UNLIMITED_ANNUAL=price_xxx      # Old unlimited → maps to pro_plus
```

---

### Lane 4: Frontend — Pricing Page + Badges (Frontend Dev)
**DONE wenn:** Pricing zeigt 3 Karten (Free/Pro/Pro+), Badge zeigt "PRO+" in cyan

**Exakte Änderungen:**

1. **`app.js`** → `renderPricing()`:
   - `tierOrder`: `['free', 'pro', 'pro_plus']`
   - Featured Card: `key === 'pro_plus'` (cyan border, "Most Popular" oder "Best Value" Badge)

2. **`app.js`** → `tierBenefits`:
```javascript
const tierBenefits = {
    free: [
        'Up to 50 commands per day',
        '10 security scans per day',
        '1 day incident history',
        'Real-time threat detection',
        'Tamper-proof audit trail',
    ],
    pro: [
        'Everything in Free, plus:',
        '1,000 commands per day',
        '100 security scans per day',
        '30 day incident history',
        'Export reports (CSV & JSON)',
        'REST API access',
        'Full prompts & skills library',
    ],
    pro_plus: [
        'Everything in Pro, plus:',
        'Unlimited commands & scans',
        '90 day incident history',
        'AI-powered threat analysis',
        'Up to 5 API keys',
        'Priority support',
    ],
};
```

3. **`app.js`** → Sidebar Badge / `updateTierBadge()`:
   - `tier === 'pro_plus'` → Badge Text "PRO+", CSS class `tier-pro-plus`
   - `tier === 'unlimited'` → Badge Text "ADMIN", CSS class `tier-unlimited` (nur Super-Admin)

4. **`sentinel.css`** — Neue Badge-Klasse:
```css
.tier-badge.tier-pro-plus {
    background: rgba(57, 210, 192, 0.12);
    color: #39D2C0;
    border: 1px solid rgba(57, 210, 192, 0.25);
}
```

**Verifikation:**
- Browser: `#/pricing` zeigt 3 Karten mit korrekten Preisen
- Pro+ Badge ist cyan mit "PRO+" Text
```bash
python3 -m pytest tests/ -x -q --tb=short
```

---

### Lane 5: Frontend — Kontextabhängige CTAs (Frontend Dev)
**DONE wenn:** Free→"Upgrade to Pro", Pro→"Upgrade to Pro+", Pro+→keine CTAs

**Exakte Änderungen:**

1. **CTA-Logik zentral:**
```javascript
function getUpgradeCTA(tier) {
    if (tier === 'free') return { text: 'Upgrade to Pro', link: '#/pricing', sub: 'From €19.99/mo' };
    if (tier === 'pro') return { text: 'Upgrade to Pro+', link: '#/pricing', sub: 'Just €10 more/mo' };
    return null; // pro_plus, unlimited, admin → keine CTA
}
```

2. **Stellen anpassen:**
   - `UpgradeCTACard()` in `components.js` — Tier-Parameter hinzufügen
   - Scan Limit Banner — "Upgrade to Pro" / "Upgrade to Pro+"
   - Security Disabled Banner
   - Dashboard Paywall
   - Sidebar Upgrade Box
   - Feature Lock Overlays
   - Pro-User Limit Banner: "Go Pro+ for unlimited — just €10 more/mo"

3. **Global Replace:**
   - `"Upgrade to Pro"` → nur wo es Free-User-spezifisch ist
   - Neue Texte für Pro-User: `"Upgrade to Pro+"`
   - `"Pro feature"` → `"Paid feature"` (gilt für Pro und Pro+)

**Verifikation:**
- Browser als Free: CTAs → "Upgrade to Pro"
- Browser als Pro: CTAs → "Upgrade to Pro+"
- Browser als Pro+: Keine CTAs
```bash
python3 -m pytest tests/ -x -q --tb=short
```

---

### Lane 6: Tests anpassen (QA Engineer)
**DONE wenn:** Alle Tests pass, enterprise→pro_plus, neue Tier-Logik getestet

**Dateien:**
1. `tests/test_api/test_billing.py`
   - Enterprise Test-Cases → pro_plus
   - Unlimited Test-Cases → pro_plus (außer Super-Admin)
   - Neue Preise in Assertions
   - Test: `max_api_keys` Limit enforcement

2. `tests/test_api/test_deps_coverage.py`
   - Tier-Mapping: enterprise → pro_plus, unlimited (non-admin) → pro_plus
   - Pro `llm_analysis=False`, Pro+ `llm_analysis=True`
   - `max_api_keys`: free=0, pro=-1, pro_plus=5

3. Alle `tier="enterprise"` → `tier="pro_plus"`
4. Alle `tier="unlimited"` (non-admin context) → `tier="pro_plus"`

**Verifikation:**
```bash
python3 -m pytest tests/ -x -q --tb=short
```

---

## Execution Order

```
Lane 1 + 2 (parallel):  Backend Config + Billing
Lane 3 (manuell):        Stripe Dashboard — parallel zu Lane 1+2
Lane 4 + 5 (parallel):   Frontend Pricing + CTAs (nach Lane 1+2)
Lane 6 (danach):          Tests (nach Lane 4+5)
```

## Abhängigkeiten

| Lane | Agent | Abhängig von |
|---|---|---|
| 1 | Backend Dev | — |
| 2 | Backend Dev | — |
| 3 | Du (manuell) | — |
| 4 | Frontend Dev | 1, 2 |
| 5 | Frontend Dev | 1 |
| 6 | QA Engineer | 1-5 |

## Risiken

| Risiko | Mitigation |
|---|---|
| Bestehende Pro-Subscriber (€29) sehen niedrigeren Preis | Alte Subs laufen weiter, Stripe Portal zum Wechseln |
| Enterprise-Bestandskunden | Automatisch auf pro_plus gemappt (mehr Features, nicht weniger) |
| Pro hatte bisher LLM in Config | `llm.enabled=False` in sentinel.yaml — war nie aktiv. Kein realer Verlust |
| Alte Stripe Unlimited Webhooks | `PRICE_TO_TIER` mappt alte Price IDs auf pro_plus |
| Tests mit "enterprise"/"unlimited" | Lane 6 fixt alle |
