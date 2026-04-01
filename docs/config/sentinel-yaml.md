# sentinel.yaml

ShieldPilot's configuration file. Created by `sentinel init`.

## Full Reference

```yaml
# Operating mode
# protect  — block commands scoring >= threshold (default)
# monitor  — log everything, block nothing
# audit    — log everything, execute everything, warn only
# disabled — passthrough, no evaluation
mode: protect

# Risk thresholds
thresholds:
  block: 80      # Score >= this → BLOCK
  warn: 40       # Score >= this → WARN

# Auth settings
auth:
  local_first: true   # Skip JWT for localhost requests

# Logging
logging:
  db_path: sentinel.db
  retention_days: 30

# LLM evaluation (second pass after rule engine)
llm:
  enabled: false
  model: claude-sonnet-4-6
  # api_key: set via ANTHROPIC_API_KEY env var

# Billing / rate limits
billing:
  enabled: true
  free_tier_daily_limit: 50

# Sandbox settings
sandbox:
  timeout: 30          # Command timeout in seconds
  memory_limit_mb: 512

# Secrets masking patterns (added to defaults)
secrets_patterns: []
```

## Environment Variables

Sensitive values should be set via environment variables, not hardcoded in `sentinel.yaml`:

| Variable | Purpose |
|----------|---------|
| `SHIELDPILOT_SECRET_KEY` | JWT signing secret |
| `SHIELDPILOT_SUPER_ADMIN_EMAIL` | Super-admin email |
| `SHIELDPILOT_SUPER_ADMIN_PASSWORD` | Super-admin password |
| `ANTHROPIC_API_KEY` | Claude API key for LLM evaluation |
| `STRIPE_SECRET_KEY` | Stripe secret key |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OAuth |
