"""Configuration loader for ShieldPilot.

Loads config from sentinel.yaml with environment variable overrides.
Uses Pydantic for validation.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml
from pydantic import BaseModel, Field


class RiskThresholds(BaseModel):
    """Thresholds for risk-based actions."""
    block: int = 80
    warn: int = 40
    allow: int = 0


class LLMConfig(BaseModel):
    """Configuration for optional LLM-based evaluation."""
    enabled: bool = False
    model: str = "claude-sonnet-4-20250514"
    max_tokens: int = 512
    score_range: List[int] = Field(default_factory=lambda: [40, 79])


class WhitelistConfig(BaseModel):
    """Whitelisted commands and domains."""
    commands: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    rate_limit_exempt: List[str] = Field(
        default_factory=list,
        description="Extra command prefixes that bypass the injection rate limiter",
    )


class BlacklistConfig(BaseModel):
    """Blacklisted commands and domains."""
    commands: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)


class SandboxConfig(BaseModel):
    """Sandbox execution constraints."""
    enabled: bool = True
    timeout: int = 30
    max_memory_mb: int = 512
    max_file_size_mb: int = 100
    restricted_env_vars: List[str] = Field(default_factory=list)


class PluginConfig(BaseModel):
    """Plugin system configuration."""
    enabled: bool = True
    directory: str = "plugins"


class LoggingConfig(BaseModel):
    """Logging and database configuration."""
    database: str = "sentinel.db"
    chain_hashing: bool = True
    retention_days: int = 90


class AuthConfig(BaseModel):
    """Authentication configuration."""
    secret_key: str = ""  # Required: set via SHIELDPILOT_SECRET_KEY env var
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 1440
    default_admin_user: str = "admin"
    default_admin_password: str = ""  # Optional: set via SHIELDPILOT_ADMIN_PASSWORD env var
    local_first: bool = False  # Dev only: skip auth for localhost. Set to true in sentinel.yaml for local dev.

    # Super-admin with unlimited access (email required, password via env var)
    super_admin_email: str = ""  # Set via SHIELDPILOT_SUPER_ADMIN_EMAIL env var
    super_admin_password: str = ""  # Set via SHIELDPILOT_SUPER_ADMIN_PASSWORD env var
    super_admin_username: str = ""  # Set via SHIELDPILOT_SUPER_ADMIN_USERNAME env var

    # Google OAuth settings (secrets via env vars)
    google_client_id: str = ""  # Set via GOOGLE_CLIENT_ID env var
    google_client_secret: str = ""  # Set via GOOGLE_CLIENT_SECRET env var
    google_redirect_uri: str = "http://localhost:8420/api/auth/google/callback"

    # SMTP settings for password reset (password via env var)
    smtp_host: str = "smtp.gmail.com"
    smtp_port: int = 587
    smtp_user: str = ""  # Set via SMTP_USER env var
    smtp_password: str = ""  # Set via SMTP_PASSWORD env var
    smtp_from_email: str = ""  # Set via SMTP_FROM_EMAIL env var
    password_reset_url: str = "http://localhost:8420/login?reset_token="


class TierLimits(BaseModel):
    """Usage limits for a specific tier."""
    commands_per_day: int = 50
    scans_per_day: int = 10
    history_retention_days: int = 1
    llm_analysis: bool = False
    export_enabled: bool = False
    multi_user: bool = False
    api_access: bool = False
    priority_support: bool = False
    library_access: bool = False  # Full prompts & skills library access
    max_api_keys: int = 0  # 0=none, -1=unlimited, N=max N keys


# Predefined tier configurations
TIER_LIMITS = {
    "free": TierLimits(
        commands_per_day=50,
        scans_per_day=10,
        history_retention_days=1,
        llm_analysis=False,
        export_enabled=False,
        multi_user=False,
        api_access=False,
        priority_support=False,
        library_access=False,
        max_api_keys=0,
    ),
    "pro": TierLimits(
        commands_per_day=1000,
        scans_per_day=100,
        history_retention_days=30,
        llm_analysis=False,
        export_enabled=True,
        multi_user=False,
        api_access=True,
        priority_support=False,
        library_access=True,
        max_api_keys=-1,  # unlimited
    ),
    "pro_plus": TierLimits(
        commands_per_day=-1,  # unlimited
        scans_per_day=-1,  # unlimited
        history_retention_days=90,
        llm_analysis=True,
        export_enabled=True,
        multi_user=True,
        api_access=True,
        priority_support=True,
        library_access=True,
        max_api_keys=5,
    ),
    # Super-admin internal alias (not purchasable)
    "unlimited": TierLimits(
        commands_per_day=-1,  # unlimited
        scans_per_day=-1,  # unlimited
        history_retention_days=-1,  # forever
        llm_analysis=True,
        export_enabled=True,
        multi_user=True,
        api_access=True,
        priority_support=True,
        library_access=True,
        max_api_keys=-1,  # unlimited
    ),
}


class BillingConfig(BaseModel):
    """Billing and SaaS configuration."""
    enabled: bool = False
    tier: str = "free"
    stripe_publishable_key: str = ""
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    upgrade_url: str = "#/pricing"

    @property
    def limits(self) -> TierLimits:
        """Get limits for the current tier."""
        return TIER_LIMITS.get(self.tier, TIER_LIMITS["free"])


class LegalConfig(BaseModel):
    """Legal/Impressum configuration (§ 5 DDG)."""
    company_name: str = ""
    address_line1: str = ""
    address_line2: str = ""
    country: str = "Germany"
    managing_director: str = ""
    registration_court: str = ""
    registration_number: str = ""
    vat_id: str = ""
    contact_email: str = ""
    contact_phone: str = ""


class SentinelConfig(BaseModel):
    """Root configuration model for ShieldPilot."""

    mode: str = "enforce"  # enforce | audit | disabled
    fail_mode: str = "open"  # open | closed — what to do when hook errors unexpectedly
    # fail_mode=open  → allow command on hook error (availability-first, default)
    # fail_mode=closed → deny command on hook error (security-first, recommended for prod)
    app_base_url: str = "http://localhost:8420"  # Base URL for redirects (Stripe, OAuth, etc.)
    risk_thresholds: RiskThresholds = Field(default_factory=RiskThresholds)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    whitelist: WhitelistConfig = Field(default_factory=WhitelistConfig)
    blacklist: BlacklistConfig = Field(default_factory=BlacklistConfig)
    protected_paths: List[str] = Field(default_factory=list)
    secrets_patterns: List[str] = Field(default_factory=list)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    plugins: PluginConfig = Field(default_factory=PluginConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    billing: BillingConfig = Field(default_factory=BillingConfig)
    legal: LegalConfig = Field(default_factory=LegalConfig)


def _find_config_file() -> Optional[Path]:
    """Search for sentinel.yaml in CWD and parent directories."""
    current = Path.cwd()
    for directory in [current] + list(current.parents):
        candidate = directory / "sentinel.yaml"
        if candidate.exists():
            return candidate
    return None


def load_config(config_path: Optional[str] = None) -> SentinelConfig:
    """Load configuration from YAML file with environment variable overrides.

    Search order:
    1. Explicit config_path argument
    2. SENTINEL_CONFIG environment variable
    3. sentinel.yaml in CWD or parent directories
    4. Fall back to defaults

    Environment variables can be set in a .env file (auto-loaded via python-dotenv).
    """
    # Load .env file if it exists (secrets stay out of git-tracked files)
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass  # python-dotenv not installed, skip

    path = None

    if config_path:
        path = Path(config_path)
    elif os.environ.get("SENTINEL_CONFIG"):
        path = Path(os.environ["SENTINEL_CONFIG"])
    else:
        path = _find_config_file()

    if path and path.exists():
        with open(path, "r") as f:
            raw = yaml.safe_load(f)
        # Config is nested under 'sentinel' key
        data = raw.get("sentinel", raw) if raw else {}
    else:
        data = {}

    # Environment variable overrides
    if os.environ.get("SENTINEL_MODE"):
        data["mode"] = os.environ["SENTINEL_MODE"]
    if os.environ.get("SENTINEL_FAIL_MODE"):
        data["fail_mode"] = os.environ["SENTINEL_FAIL_MODE"]
    if os.environ.get("SENTINEL_LLM_ENABLED"):
        data.setdefault("llm", {})["enabled"] = (
            os.environ["SENTINEL_LLM_ENABLED"].lower() == "true"
        )
    if os.environ.get("SENTINEL_DB"):
        data.setdefault("logging", {})["database"] = os.environ["SENTINEL_DB"]

    # Auth secrets from environment variables (REQUIRED for production)
    auth_data = data.setdefault("auth", {})
    if os.environ.get("SENTINEL_AUTH_SECRET"):
        auth_data["secret_key"] = os.environ["SENTINEL_AUTH_SECRET"]
    if os.environ.get("SHIELDPILOT_SECRET_KEY"):
        auth_data["secret_key"] = os.environ["SHIELDPILOT_SECRET_KEY"]
    if os.environ.get("SHIELDPILOT_ADMIN_PASSWORD"):
        auth_data["default_admin_password"] = os.environ["SHIELDPILOT_ADMIN_PASSWORD"]

    # Super-admin credentials from environment
    if os.environ.get("SHIELDPILOT_SUPER_ADMIN_EMAIL"):
        auth_data["super_admin_email"] = os.environ["SHIELDPILOT_SUPER_ADMIN_EMAIL"]
    if os.environ.get("SHIELDPILOT_SUPER_ADMIN_PASSWORD"):
        auth_data["super_admin_password"] = os.environ["SHIELDPILOT_SUPER_ADMIN_PASSWORD"]
    if os.environ.get("SHIELDPILOT_SUPER_ADMIN_USERNAME"):
        auth_data["super_admin_username"] = os.environ["SHIELDPILOT_SUPER_ADMIN_USERNAME"]

    # Google OAuth from environment
    if os.environ.get("GOOGLE_CLIENT_ID"):
        auth_data["google_client_id"] = os.environ["GOOGLE_CLIENT_ID"]
    if os.environ.get("SHIELDPILOT_GOOGLE_SECRET"):
        auth_data["google_client_secret"] = os.environ["SHIELDPILOT_GOOGLE_SECRET"]
    elif os.environ.get("GOOGLE_CLIENT_SECRET"):
        auth_data["google_client_secret"] = os.environ["GOOGLE_CLIENT_SECRET"]

    # SMTP from environment
    if os.environ.get("SMTP_USER"):
        auth_data["smtp_user"] = os.environ["SMTP_USER"]
    if os.environ.get("SMTP_PASSWORD"):
        auth_data["smtp_password"] = os.environ["SMTP_PASSWORD"]
    if os.environ.get("SMTP_FROM_EMAIL"):
        auth_data["smtp_from_email"] = os.environ["SMTP_FROM_EMAIL"]

    # Stripe from environment
    billing_data = data.setdefault("billing", {})
    if os.environ.get("STRIPE_PUBLISHABLE_KEY"):
        billing_data["stripe_publishable_key"] = os.environ["STRIPE_PUBLISHABLE_KEY"]
    if os.environ.get("STRIPE_SECRET_KEY"):
        billing_data["stripe_secret_key"] = os.environ["STRIPE_SECRET_KEY"]
    if os.environ.get("STRIPE_WEBHOOK_SECRET"):
        billing_data["stripe_webhook_secret"] = os.environ["STRIPE_WEBHOOK_SECRET"]

    # App base URL from environment
    if os.environ.get("APP_BASE_URL"):
        data["app_base_url"] = os.environ["APP_BASE_URL"]

    # Legal/Impressum from environment
    legal_data = data.setdefault("legal", {})
    if os.environ.get("SHIELDPILOT_COMPANY_NAME"):
        legal_data["company_name"] = os.environ["SHIELDPILOT_COMPANY_NAME"]
    if os.environ.get("SHIELDPILOT_CONTACT_EMAIL"):
        legal_data["contact_email"] = os.environ["SHIELDPILOT_CONTACT_EMAIL"]

    config = SentinelConfig(**data)

    # -------------------------------------------------------------------------
    # SEC-1 Warning: Detect secrets stored in sentinel.yaml instead of .env
    # -------------------------------------------------------------------------
    _SECRET_FIELDS = [
        ("auth.secret_key", config.auth.secret_key),
        ("auth.super_admin_password", config.auth.super_admin_password),
        ("auth.google_client_secret", config.auth.google_client_secret),
        ("auth.smtp_password", config.auth.smtp_password),
        ("billing.stripe_secret_key", config.billing.stripe_secret_key),
        ("billing.stripe_webhook_secret", config.billing.stripe_webhook_secret),
    ]

    # Map each field to the env vars that could legitimately provide it.
    # If none of these env vars are set, the value must have come from YAML.
    _ENV_SOURCES: Dict[str, List[str]] = {
        "auth.secret_key": ["SHIELDPILOT_SECRET_KEY", "SENTINEL_AUTH_SECRET"],
        "auth.super_admin_password": ["SHIELDPILOT_SUPER_ADMIN_PASSWORD"],
        "auth.google_client_secret": ["GOOGLE_CLIENT_SECRET", "SHIELDPILOT_GOOGLE_SECRET"],
        "auth.smtp_password": ["SMTP_PASSWORD"],
        "billing.stripe_secret_key": ["STRIPE_SECRET_KEY"],
        "billing.stripe_webhook_secret": ["STRIPE_WEBHOOK_SECRET"],
    }

    import logging as _logging
    _config_logger = _logging.getLogger("sentinelai.config")

    for _field_name, _field_value in _SECRET_FIELDS:
        if _field_value:
            _env_keys = _ENV_SOURCES.get(_field_name, [])
            _from_env = any(os.environ.get(k) for k in _env_keys)
            if not _from_env:
                _config_logger.warning(
                    "SEC-1: Secret '%s' found in sentinel.yaml! "
                    "Move to .env file or set environment variable. "
                    "See .env.example for variable names.",
                    _field_name,
                )

    # Validate required secrets are set -- never start with empty JWT secret
    if not config.auth.secret_key:
        import secrets as sec
        import logging
        logging.warning(
            "No JWT secret key configured! Auto-generating a random 64-byte key. "
            "Tokens will NOT persist across restarts. "
            "Set SHIELDPILOT_SECRET_KEY environment variable for production."
        )
        config.auth.secret_key = sec.token_hex(64)

    return config
