---
name: shieldpilot-conventions
description: ShieldPilot project conventions encyclopedia. Mandatory when writing any code, implementing features, reviewing code, or asking about project patterns. Covers Python FastAPI backend, vanilla JS SPA frontend, SQLite database, CSS theming, auth, billing, and naming conventions. Trigger phrases include conventions, project patterns, how does ShieldPilot, coding standards, style guide.
---

# ShieldPilot Conventions Encyclopedia

Every agent working on ShieldPilot MUST follow these conventions. This is the single source of truth for project patterns.

## Tech Stack

- Backend: Python 3 / FastAPI / SQLAlchemy ORM / SQLite (WAL mode)
- Frontend: Vanilla JS SPA (ES modules, no build step, no React) / CSS variables
- Config: sentinel.yaml + Pydantic validation + environment variable overrides
- Testing: pytest + FastAPI TestClient
- Internal package: sentinelai (do not rename)
- User-facing brand: ShieldPilot / SHIELDPILOT
- Use python3 not python on macOS
- Use httpx not requests (requests is not installed)

## Backend Patterns

### Route definitions
All routes live in sentinelai/api/routes.py using FastAPI APIRouter:

```python
@router.post("/api/auth/login", response_model=Token)
def login(
    credentials: LoginRequest,
    http_request: Request,
    config: SentinelConfig = Depends(get_config),
):
```

### Request and response models
Pydantic BaseModel classes defined in routes.py above the endpoint:

```python
class LoginRequest(BaseModel):
    username: str
    password: str

class ScanRequest(BaseModel):
    content: str = Field(..., max_length=50000)
    source: str = "api"
```

### Error responses
Always use HTTPException with a dict containing error and optional message:

```python
raise HTTPException(
    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
    detail={"error": "Too many login attempts", "message": f"Try again in {retry_after} seconds."},
)
```

### Dependency injection
Defined in sentinelai/api/deps.py:
- Depends(get_config) returns SentinelConfig
- Depends(get_current_user) returns TokenData (validates JWT or API key)
- Depends(require_verified_email) returns TokenData (super-admin bypasses)
- Depends(require_admin) returns TokenData (admin role required)
- Depends(get_logger) returns BlackboxLogger
- Depends(get_daily_usage) returns UsageInfo
- Depends(require_feature("feature_name")) for tier-gated features

### Super-admin bypass pattern
Always check before enforcing limits:

```python
from sentinelai.api.deps import is_super_admin
if is_super_admin(user, config):
    return  # bypass all limits
```

### Rate limiting
RateLimiter class in routes.py. Existing limiters:
- _login_limiter: 5 per 60s per IP
- _registration_limiter: 5 per hour per IP
- _password_reset_limiter: 3 per hour per email

### Database session pattern
Always close in try/finally:

```python
session = logger._get_session()
try:
    # query logic
    session.commit()
except Exception:
    session.rollback()
finally:
    session.close()
```

## Frontend Patterns

### Component functions
Pure functions returning HTML strings. PascalCase names. Defined in components.js:

```javascript
export function StatCard(number, label, color = null, icon = null, accent = null) {
    return `<div class="stat-card">${escapeHtml(String(number))}</div>`;
}
```

### Page render pattern
Each page has an async function in app.js:

```javascript
async function renderDashboard() {
    const page = getPageContent();
    page.innerHTML = `<h1>Dashboard</h1>${Spinner()}`;

    const data = await api('/api/stats', { params: { hours: 24 } });
    if (!data) {
        page.innerHTML = `<h1>Dashboard</h1>${EmptyState('Failed to load stats.')}`;
        return;
    }
    page.innerHTML = `...`;
    // Wire event listeners at end
}
```

### Hash routing
Routes object maps hashes to render functions:

```javascript
const routes = {
    '#/dashboard': renderDashboard,
    '#/commands': renderCommands,
    '#/settings': renderSettings,
    // ...
};
```

### XSS prevention
ALWAYS use escapeHtml() for dynamic content. No exceptions:

```javascript
// CORRECT
`<td>${escapeHtml(item.title)}</td>`
// WRONG - XSS vulnerability
`<td>${item.title}</td>`
```

### API client
Use api() for all backend calls. Handles auth headers, 401 auto-logout, error toasts:

```javascript
const data = await api('/api/stats', { params: { hours: 24 } });
const result = await api('/api/scan/prompt', { method: 'POST', body: { content } });
```

### Token storage
localStorage key: sentinel_token. Cleared on 401 with redirect to /login.

## Database Patterns

### Models
SQLAlchemy ORM in sentinelai/logger/database.py:

```python
class CommandLog(Base):
    __tablename__ = "commands"
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    chain_hash = Column(String(64), nullable=False, unique=True)
    previous_hash = Column(String(64), nullable=False)
    __table_args__ = (
        Index("ix_commands_risk_score", "risk_score"),
    )
```

### Tamper-proof audit chain
All audit tables have chain_hash and previous_hash columns forming integrity chain.

### Migrations (SQLite limitations)
SQLite cannot DROP COLUMN. Use ALTER TABLE ADD COLUMN only:

```python
def migrate_database(engine) -> None:
    inspector = inspect(engine)
    if "users" in inspector.get_table_names():
        existing_columns = [col["name"] for col in inspector.get_columns("users")]
        migrations = [
            ("new_col", "ALTER TABLE users ADD COLUMN new_col VARCHAR(256)"),
        ]
        with engine.connect() as conn:
            for col_name, sql in migrations:
                if col_name not in existing_columns:
                    try:
                        conn.execute(text(sql))
                        conn.commit()
                    except Exception:
                        pass
```

### Database init
WAL mode enabled for concurrency, busy_timeout=5000.

## Config Pattern

sentinel.yaml with nested sentinel: key. Pydantic validation in sentinelai/core/config.py. Environment variables override YAML values (SHIELDPILOT_SECRET_KEY, SMTP_PASSWORD, etc.).

## Auth Pattern

- JWT HS256 Bearer tokens (24h expiry)
- Created via create_access_token() in sentinelai/api/auth.py
- Claims: username, email, role, tier, is_super_admin, email_verified
- API key alternative: X-API-Key header, SHA-256 hashed in User.api_key_hash
- Billing tiers: free / pro / enterprise / unlimited

## CSS Conventions

### Variables (from :root in sentinel.css)

```css
/* Backgrounds */
--bg-primary: #0D1117;
--bg-secondary: #161B22;
--bg-tertiary: #21262D;
--bg-surface: #1C2128;

/* Text */
--text-primary: #E6EDF3;
--text-secondary: #8B949E;
--text-muted: #6E7681;

/* Status colors */
--color-allow: #3FB950;
--color-warn: #D29922;
--color-block: #F85149;
--color-info: #58A6FF;

/* Accents */
--accent-cyan: #39D2C0;
--accent-purple: #BC8CFF;

/* Borders */
--border-default: #30363D;
--border-focus: #58A6FF;

/* Typography */
--font-mono: 'JetBrains Mono', 'Fira Code', 'SF Mono', 'Cascadia Code', monospace;
--font-body: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;

/* Spacing */
--space-xs: 4px;
--space-sm: 8px;
--space-md: 16px;
--space-lg: 24px;
--space-xl: 32px;

/* Border radius */
--radius-sm: 4px;
--radius-md: 6px;
--radius-lg: 8px;

/* Shadows */
--shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.3);
--shadow-md: 0 4px 12px rgba(0, 0, 0, 0.4);
```

NEVER hardcode colors. Always use CSS variables. Dark theme only.

## Naming Conventions

| Context | Convention | Example |
|---------|-----------|---------|
| Python functions | snake_case | get_current_user |
| Python classes | PascalCase | CommandLog, SentinelConfig |
| JS utility functions | camelCase | getToken, decodeJwtPayload |
| JS component functions | PascalCase | StatCard, DataTable |
| JS render functions | renderPageName | renderDashboard |
| CSS classes | kebab-case | stat-card, nav-item |
| API paths | /api/ + kebab-case | /api/auth/password-reset/request |
| DB tables | snake_case plural | commands, file_changes |

## Common Pitfalls

1. Never use python, always python3 on macOS
2. Never use requests library, use httpx
3. Always escapeHtml() dynamic content in frontend
4. Always close DB sessions in try/finally
5. Always check is_super_admin before enforcing limits
6. SQLite cannot DROP COLUMN, only ADD COLUMN
7. Server must restart for Python changes; JS/CSS load from disk
8. ShieldPilot hook may block complex curl commands (risk score 93)
9. When billing limit reached (50 free/day), disable billing in sentinel.yaml temporarily
10. JWT secret regenerates on restart if SHIELDPILOT_SECRET_KEY not set
