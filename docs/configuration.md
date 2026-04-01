# Configuration

ShieldPilot is configured via `sentinel.yaml` in your project root, with secrets always injected via environment variables.

## Config File Search Order

1. `--config PATH` flag (CLI)
2. `SENTINEL_CONFIG` environment variable
3. `sentinel.yaml` in current working directory or any parent directory
4. Built-in defaults

---

## Full `sentinel.yaml` Reference

```yaml
sentinel:

  # ── Mode ──────────────────────────────────────────────────────────────────
  # enforce  - block commands at or above the block threshold (default)
  # audit    - log everything, never block (dry-run / observability)
  # disabled - skip all analysis (passthrough)
  mode: enforce

  # Base URL for OAuth callbacks, Stripe checkout, password reset emails
  # app_base_url: https://shield.example.com

  # ── Risk Thresholds (0–100) ───────────────────────────────────────────────
  risk_thresholds:
    block: 80     # Score >= block → DENY execution
    warn:  40     # Score >= warn  → flag for review
    allow: 0      # Score >= allow → permit silently

  # ── LLM Second Opinion ────────────────────────────────────────────────────
  # For commands in the warn zone, ask an LLM for a second risk assessment.
  # Requires ANTHROPIC_API_KEY environment variable.
  llm:
    enabled: false
    model: claude-sonnet-4-20250514
    max_tokens: 512
    score_range: [40, 79]

  # ── Whitelist ──────────────────────────────────────────────────────────────
  whitelist:
    commands:
      - ls
      - cat
      - echo
      - pwd
      - whoami
      - date
    domains: []

  # ── Blacklist ──────────────────────────────────────────────────────────────
  blacklist:
    commands:
      - "rm -rf /"
      - "rm -rf /*"
      - mkfs
      - "dd if=/dev/zero"
      - ":(){:|:&};:"    # fork bomb
    domains:
      - pastebin.com
      - transfer.sh
      - ngrok.io

  # ── Protected Paths ────────────────────────────────────────────────────────
  # Commands accessing these paths are flagged by the filesystem analyzer.
  protected_paths:
    - /etc
    - /var
    - /boot
    - ~/.ssh
    - ~/.aws
    - ~/.gnupg
    - ~/.config

  # ── Credential Patterns ────────────────────────────────────────────────────
  # Regex patterns for credential detection. Matches add to risk score.
  secrets_patterns:
    - '(?i)(api[_-]?key|secret|password|token)\s*[=:]\s*[A-Za-z0-9+/=]{16,}'
    - 'AKIA[0-9A-Z]{16}'
    - 'sk-[a-zA-Z0-9]{20,}'
    - 'ghp_[a-zA-Z0-9]{36}'

  # ── Sandbox ────────────────────────────────────────────────────────────────
  sandbox:
    enabled: true
    timeout: 30               # Max seconds per command
    max_memory_mb: 512
    max_file_size_mb: 100
    restricted_env_vars:
      - AWS_SECRET_ACCESS_KEY
      - AWS_ACCESS_KEY_ID
      - ANTHROPIC_API_KEY
      - OPENAI_API_KEY
      - GITHUB_TOKEN
      - STRIPE_SECRET_KEY

  # ── Logging & Audit ────────────────────────────────────────────────────────
  logging:
    database: sentinel.db     # SQLite path (relative to CWD)
    chain_hashing: true       # SHA-256 hash chain for tamper detection
    retention_days: 90        # Auto-purge logs older than this

  # ── Authentication ─────────────────────────────────────────────────────────
  # NEVER put real secrets here. Use environment variables.
  auth:
    secret_key: ''                   # env: SHIELDPILOT_SECRET_KEY
    algorithm: HS256
    access_token_expire_minutes: 1440
    local_first: true                # Skip auth for 127.0.0.1/::1
    google_client_id: ''             # env: GOOGLE_CLIENT_ID
    google_client_secret: ''         # env: GOOGLE_CLIENT_SECRET
    google_redirect_uri: http://localhost:8420/api/auth/google/callback
    super_admin_email: ''            # env: SHIELDPILOT_SUPER_ADMIN_EMAIL
    super_admin_password: ''         # env: SHIELDPILOT_SUPER_ADMIN_PASSWORD
    super_admin_username: ''         # env: SHIELDPILOT_SUPER_ADMIN_USERNAME
    smtp_user: ''                    # env: SMTP_USER
    smtp_password: ''                # env: SMTP_PASSWORD
    smtp_from_email: ''              # env: SMTP_FROM_EMAIL

  # ── Billing ────────────────────────────────────────────────────────────────
  # Tiers: free (50 cmd/day), pro (1000/day), enterprise (unlimited)
  billing:
    enabled: false
    tier: free
    stripe_publishable_key: ''       # env: STRIPE_PUBLISHABLE_KEY
    stripe_secret_key: ''            # env: STRIPE_SECRET_KEY
    stripe_webhook_secret: ''        # env: STRIPE_WEBHOOK_SECRET
    upgrade_url: '#/pricing'
```

---

## Environment Variables

All secrets must be set via environment variables. ShieldPilot auto-loads `.env` files via `python-dotenv`.

### Required for Production

| Variable | Description |
|----------|-------------|
| `SHIELDPILOT_SECRET_KEY` | JWT signing key (auto-generated if empty, **not safe for prod**) |

### Optional — Auth

| Variable | Description |
|----------|-------------|
| `GOOGLE_CLIENT_ID` | Google OAuth app client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth app client secret |
| `SMTP_USER` | SMTP username for transactional email |
| `SMTP_PASSWORD` | SMTP password |
| `SMTP_FROM_EMAIL` | Sender address for password reset / verification emails |
| `SHIELDPILOT_SUPER_ADMIN_EMAIL` | Super-admin account email (unlimited tier) |
| `SHIELDPILOT_SUPER_ADMIN_PASSWORD` | Super-admin account password |
| `SHIELDPILOT_SUPER_ADMIN_USERNAME` | Super-admin display name |

### Optional — Billing (Stripe)

| Variable | Description |
|----------|-------------|
| `STRIPE_PUBLISHABLE_KEY` | Client-side Stripe key |
| `STRIPE_SECRET_KEY` | Server-side Stripe key |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook signing secret |

### Optional — LLM Second Opinion

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Required when `llm.enabled: true` |

---

## Minimal `.env` for Development

```bash
# .env — never commit this file
SHIELDPILOT_SECRET_KEY=dev-secret-change-in-production
SHIELDPILOT_SUPER_ADMIN_EMAIL=admin@example.com
SHIELDPILOT_SUPER_ADMIN_PASSWORD=change-me
SHIELDPILOT_SUPER_ADMIN_USERNAME=admin
```

---

## Hook Integration

### Claude Code (automatic)

```bash
sentinel hook install
```

This adds to `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 -m sentinelai.hooks.sentinel_hook"
          }
        ]
      }
    ]
  }
}
```

### OpenClaw (manual)

Set the pre-tool-execution hook in your OpenClaw config to:

```
python3 -m sentinelai.hooks.sentinel_hook
```

The hook auto-detects the input format via the Adapter Layer.

### Generic agent

Pass the command JSON to the hook via stdin:

```bash
echo '{"command": "rm -rf /tmp", "tool": "Bash"}' | python3 -m sentinelai.hooks.sentinel_hook
```

Exit code 0 = allow, 1 = block.

---

## Billing Tiers

| Tier | Daily limit | Features |
|------|------------|----------|
| `free` | 50 evaluations/day | All analyzers, dashboard, API |
| `pro` | 1,000 evaluations/day | + priority support, extended log retention |
| `enterprise` | Unlimited | + SSO, audit export, SLA |
| `unlimited` | Unlimited | Super-admin only |

Disable billing enforcement for local development:

```yaml
billing:
  enabled: false
```
