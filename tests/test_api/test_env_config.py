"""Tests for environment variable overrides in load_config().

Verifies that environment variables correctly override YAML values for all
secret fields, following the priority: env > yaml > default.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from sentinelai.core.config import load_config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_yaml(tmp_path: Path, content: str) -> str:
    """Write a sentinel.yaml in a temp directory and return its path."""
    config_file = tmp_path / "sentinel.yaml"
    config_file.write_text(content)
    return str(config_file)


MINIMAL_YAML = """\
sentinel:
  mode: enforce
  auth:
    secret_key: yaml-secret-key
    google_client_id: yaml-google-id
    google_client_secret: yaml-google-secret
    smtp_user: yaml-smtp-user
    smtp_password: yaml-smtp-password
    smtp_from_email: yaml@example.com
    super_admin_email: yaml-admin@example.com
    super_admin_password: yaml-admin-pass
  billing:
    enabled: false
    stripe_secret_key: yaml-stripe-secret
    stripe_publishable_key: yaml-stripe-pub
    stripe_webhook_secret: yaml-stripe-webhook
"""

EMPTY_SECRETS_YAML = """\
sentinel:
  mode: enforce
  auth:
    secret_key: ''
    google_client_id: ''
    google_client_secret: ''
    smtp_user: ''
    smtp_password: ''
    smtp_from_email: ''
    super_admin_email: ''
    super_admin_password: ''
  billing:
    enabled: false
    stripe_secret_key: ''
    stripe_publishable_key: ''
    stripe_webhook_secret: ''
"""


# ---------------------------------------------------------------------------
# Test: Env vars override YAML values
# ---------------------------------------------------------------------------


class TestEnvOverridesYaml:
    """Environment variables must take priority over YAML values."""

    def test_secret_key_override(self, tmp_path):
        path = _write_yaml(tmp_path, MINIMAL_YAML)
        with patch.dict(os.environ, {"SHIELDPILOT_SECRET_KEY": "env-secret"}, clear=False):
            config = load_config(path)
        assert config.auth.secret_key == "env-secret"

    def test_google_client_id_override(self, tmp_path):
        path = _write_yaml(tmp_path, MINIMAL_YAML)
        with patch.dict(os.environ, {"GOOGLE_CLIENT_ID": "env-google-id"}, clear=False):
            config = load_config(path)
        assert config.auth.google_client_id == "env-google-id"

    def test_google_client_secret_override(self, tmp_path):
        path = _write_yaml(tmp_path, MINIMAL_YAML)
        with patch.dict(os.environ, {"GOOGLE_CLIENT_SECRET": "env-google-secret"}, clear=False):
            config = load_config(path)
        assert config.auth.google_client_secret == "env-google-secret"

    def test_google_client_secret_shieldpilot_variant(self, tmp_path):
        """SHIELDPILOT_GOOGLE_SECRET takes precedence over GOOGLE_CLIENT_SECRET."""
        path = _write_yaml(tmp_path, MINIMAL_YAML)
        with patch.dict(os.environ, {
            "GOOGLE_CLIENT_SECRET": "env-google-secret",
            "SHIELDPILOT_GOOGLE_SECRET": "env-shieldpilot-google-secret",
        }, clear=False):
            config = load_config(path)
        assert config.auth.google_client_secret == "env-shieldpilot-google-secret"

    def test_smtp_user_override(self, tmp_path):
        path = _write_yaml(tmp_path, MINIMAL_YAML)
        with patch.dict(os.environ, {"SMTP_USER": "env-smtp-user"}, clear=False):
            config = load_config(path)
        assert config.auth.smtp_user == "env-smtp-user"

    def test_smtp_password_override(self, tmp_path):
        path = _write_yaml(tmp_path, MINIMAL_YAML)
        with patch.dict(os.environ, {"SMTP_PASSWORD": "env-smtp-pass"}, clear=False):
            config = load_config(path)
        assert config.auth.smtp_password == "env-smtp-pass"

    def test_smtp_from_email_override(self, tmp_path):
        path = _write_yaml(tmp_path, MINIMAL_YAML)
        with patch.dict(os.environ, {"SMTP_FROM_EMAIL": "env@example.com"}, clear=False):
            config = load_config(path)
        assert config.auth.smtp_from_email == "env@example.com"

    def test_super_admin_email_override(self, tmp_path):
        path = _write_yaml(tmp_path, MINIMAL_YAML)
        with patch.dict(os.environ, {"SHIELDPILOT_SUPER_ADMIN_EMAIL": "env-admin@example.com"}, clear=False):
            config = load_config(path)
        assert config.auth.super_admin_email == "env-admin@example.com"

    def test_super_admin_password_override(self, tmp_path):
        path = _write_yaml(tmp_path, MINIMAL_YAML)
        with patch.dict(os.environ, {"SHIELDPILOT_SUPER_ADMIN_PASSWORD": "env-admin-pass"}, clear=False):
            config = load_config(path)
        assert config.auth.super_admin_password == "env-admin-pass"

    def test_stripe_secret_key_override(self, tmp_path):
        path = _write_yaml(tmp_path, MINIMAL_YAML)
        with patch.dict(os.environ, {"STRIPE_SECRET_KEY": "env-stripe-secret"}, clear=False):
            config = load_config(path)
        assert config.billing.stripe_secret_key == "env-stripe-secret"

    def test_stripe_publishable_key_override(self, tmp_path):
        path = _write_yaml(tmp_path, MINIMAL_YAML)
        with patch.dict(os.environ, {"STRIPE_PUBLISHABLE_KEY": "env-stripe-pub"}, clear=False):
            config = load_config(path)
        assert config.billing.stripe_publishable_key == "env-stripe-pub"

    def test_stripe_webhook_secret_override(self, tmp_path):
        path = _write_yaml(tmp_path, MINIMAL_YAML)
        with patch.dict(os.environ, {"STRIPE_WEBHOOK_SECRET": "env-stripe-webhook"}, clear=False):
            config = load_config(path)
        assert config.billing.stripe_webhook_secret == "env-stripe-webhook"


# ---------------------------------------------------------------------------
# Test: Env vars populate empty YAML fields
# ---------------------------------------------------------------------------


class TestEnvPopulatesEmptyYaml:
    """Env vars should fill in empty string values from YAML."""

    def test_all_secrets_from_env_when_yaml_empty(self, tmp_path):
        path = _write_yaml(tmp_path, EMPTY_SECRETS_YAML)
        env_vars = {
            "SHIELDPILOT_SECRET_KEY": "env-secret",
            "GOOGLE_CLIENT_ID": "env-gid",
            "GOOGLE_CLIENT_SECRET": "env-gsecret",
            "SMTP_USER": "env-smtp-user",
            "SMTP_PASSWORD": "env-smtp-pass",
            "SMTP_FROM_EMAIL": "env-from@test.com",
            "SHIELDPILOT_SUPER_ADMIN_EMAIL": "env-admin@test.com",
            "SHIELDPILOT_SUPER_ADMIN_PASSWORD": "env-admin-pass",
            "STRIPE_SECRET_KEY": "env-sk",
            "STRIPE_PUBLISHABLE_KEY": "env-pk",
            "STRIPE_WEBHOOK_SECRET": "env-wh",
        }
        with patch.dict(os.environ, env_vars, clear=False):
            config = load_config(path)

        assert config.auth.secret_key == "env-secret"
        assert config.auth.google_client_id == "env-gid"
        assert config.auth.google_client_secret == "env-gsecret"
        assert config.auth.smtp_user == "env-smtp-user"
        assert config.auth.smtp_password == "env-smtp-pass"
        assert config.auth.smtp_from_email == "env-from@test.com"
        assert config.auth.super_admin_email == "env-admin@test.com"
        assert config.auth.super_admin_password == "env-admin-pass"
        assert config.billing.stripe_secret_key == "env-sk"
        assert config.billing.stripe_publishable_key == "env-pk"
        assert config.billing.stripe_webhook_secret == "env-wh"


# ---------------------------------------------------------------------------
# Test: YAML values used when no env vars set
# ---------------------------------------------------------------------------


class TestYamlFallback:
    """When no env vars are set, YAML values should be used."""

    def test_yaml_values_used_without_env(self, tmp_path):
        path = _write_yaml(tmp_path, MINIMAL_YAML)
        # Ensure none of the override env vars are set, and disable dotenv
        # so it doesn't load secrets from .env file
        env_keys = [
            "SHIELDPILOT_SECRET_KEY", "SENTINEL_AUTH_SECRET",
            "SHIELDPILOT_ADMIN_PASSWORD",
            "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "SHIELDPILOT_GOOGLE_SECRET",
            "SMTP_USER", "SMTP_PASSWORD", "SMTP_FROM_EMAIL",
            "SHIELDPILOT_SUPER_ADMIN_EMAIL", "SHIELDPILOT_SUPER_ADMIN_PASSWORD",
            "SHIELDPILOT_SUPER_ADMIN_USERNAME",
            "STRIPE_SECRET_KEY", "STRIPE_PUBLISHABLE_KEY", "STRIPE_WEBHOOK_SECRET",
            "SENTINEL_MODE", "SENTINEL_LLM_ENABLED", "SENTINEL_DB",
            "SHIELDPILOT_COMPANY_NAME", "SHIELDPILOT_CONTACT_EMAIL",
        ]
        clean_env = {k: v for k, v in os.environ.items() if k not in env_keys}
        with patch.dict(os.environ, clean_env, clear=True), \
             patch("dotenv.load_dotenv", return_value=None):
            config = load_config(path)

        assert config.auth.secret_key == "yaml-secret-key"
        assert config.auth.google_client_id == "yaml-google-id"
        assert config.auth.google_client_secret == "yaml-google-secret"
        assert config.auth.smtp_user == "yaml-smtp-user"
        assert config.auth.smtp_password == "yaml-smtp-password"
        assert config.auth.smtp_from_email == "yaml@example.com"
        assert config.auth.super_admin_email == "yaml-admin@example.com"
        assert config.auth.super_admin_password == "yaml-admin-pass"
        assert config.billing.stripe_secret_key == "yaml-stripe-secret"
        assert config.billing.stripe_publishable_key == "yaml-stripe-pub"
        assert config.billing.stripe_webhook_secret == "yaml-stripe-webhook"


# ---------------------------------------------------------------------------
# Test: Auto-generated secret key when nothing is set
# ---------------------------------------------------------------------------


class TestAutoGeneratedSecretKey:
    """When no secret key is configured, one should be auto-generated."""

    def test_auto_generates_secret_key_when_empty(self, tmp_path):
        path = _write_yaml(tmp_path, EMPTY_SECRETS_YAML)
        env_keys = ["SHIELDPILOT_SECRET_KEY", "SENTINEL_AUTH_SECRET"]
        clean_env = {k: v for k, v in os.environ.items() if k not in env_keys}
        with patch.dict(os.environ, clean_env, clear=True), \
             patch("dotenv.load_dotenv", return_value=None):
            config = load_config(path)
        # Should auto-generate a 64-byte hex key (128 hex chars)
        assert len(config.auth.secret_key) == 128
        assert all(c in "0123456789abcdef" for c in config.auth.secret_key)

    def test_no_auto_generate_when_secret_key_set(self, tmp_path):
        path = _write_yaml(tmp_path, MINIMAL_YAML)
        env_keys = ["SHIELDPILOT_SECRET_KEY", "SENTINEL_AUTH_SECRET"]
        clean_env = {k: v for k, v in os.environ.items() if k not in env_keys}
        with patch.dict(os.environ, clean_env, clear=True), \
             patch("dotenv.load_dotenv", return_value=None):
            config = load_config(path)
        assert config.auth.secret_key == "yaml-secret-key"


# ---------------------------------------------------------------------------
# Test: No config file — pure env var configuration
# ---------------------------------------------------------------------------


class TestPureEnvConfig:
    """Config should work with only env vars and no YAML file at all."""

    def test_config_from_env_only(self, tmp_path):
        # Point to a nonexistent file
        fake_path = str(tmp_path / "nonexistent.yaml")
        env_vars = {
            "SHIELDPILOT_SECRET_KEY": "pure-env-secret",
            "GOOGLE_CLIENT_ID": "pure-env-gid",
            "STRIPE_SECRET_KEY": "pure-env-stripe",
        }
        with patch.dict(os.environ, env_vars, clear=False):
            config = load_config(fake_path)
        assert config.auth.secret_key == "pure-env-secret"
        assert config.auth.google_client_id == "pure-env-gid"
        assert config.billing.stripe_secret_key == "pure-env-stripe"


# ---------------------------------------------------------------------------
# Test: SENTINEL_AUTH_SECRET legacy env var
# ---------------------------------------------------------------------------


class TestLegacyEnvVars:
    """Legacy env var SENTINEL_AUTH_SECRET should still work."""

    def test_sentinel_auth_secret_sets_secret_key(self, tmp_path):
        path = _write_yaml(tmp_path, EMPTY_SECRETS_YAML)
        clean_env = {k: v for k, v in os.environ.items()
                     if k not in ("SHIELDPILOT_SECRET_KEY", "SENTINEL_AUTH_SECRET")}
        clean_env["SENTINEL_AUTH_SECRET"] = "legacy-secret"
        with patch.dict(os.environ, clean_env, clear=True), \
             patch("dotenv.load_dotenv", return_value=None):
            config = load_config(path)
        assert config.auth.secret_key == "legacy-secret"

    def test_shieldpilot_secret_key_overrides_legacy(self, tmp_path):
        """SHIELDPILOT_SECRET_KEY takes precedence over SENTINEL_AUTH_SECRET."""
        path = _write_yaml(tmp_path, EMPTY_SECRETS_YAML)
        env_vars = {
            "SENTINEL_AUTH_SECRET": "legacy-secret",
            "SHIELDPILOT_SECRET_KEY": "new-secret",
        }
        with patch.dict(os.environ, env_vars, clear=False):
            config = load_config(path)
        assert config.auth.secret_key == "new-secret"
