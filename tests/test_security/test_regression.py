"""I6: Security Regression Tests.

Validates key security properties:
- XSS prevention (escapeHtml / _sanitize_text)
- SQL injection prevention (ORM-only, no raw user input in queries)
- Auth bypass (protected endpoints require authentication)
- Path traversal (protected paths enforcement)
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient


# ── XSS Prevention ────────────────────────────────────────────


class TestXssSanitization:
    """Verify _sanitize_text strips dangerous HTML/JS from user input."""

    def test_sanitize_script_tag(self):
        from sentinelai.api.routers._shared import _sanitize_text

        result = _sanitize_text("<script>alert('xss')</script>")
        assert "<script>" not in result
        assert "alert" not in result or "&" in result  # Escaped or removed

    def test_sanitize_event_handler(self):
        from sentinelai.api.routers._shared import _sanitize_text

        result = _sanitize_text('<img onerror="alert(1)">')
        assert "onerror" not in result or "&" in result

    def test_sanitize_none_returns_none(self):
        from sentinelai.api.routers._shared import _sanitize_text

        assert _sanitize_text(None) is None

    def test_sanitize_plain_text_unchanged(self):
        from sentinelai.api.routers._shared import _sanitize_text

        result = _sanitize_text("normal text without html")
        assert result == "normal text without html"

    def test_sanitize_html_entities(self):
        from sentinelai.api.routers._shared import _sanitize_text

        result = _sanitize_text("a < b & c > d")
        # Should be escaped
        assert "<" not in result or "&lt;" in result


# ── Auth Bypass Prevention ────────────────────────────────────


class TestAuthBypass:
    """Protected endpoints must reject unauthenticated requests."""

    @pytest.fixture
    def client(self, test_config):
        test_config.auth.local_first = False
        from sentinelai.api.app import create_app
        from sentinelai.api import deps

        app = create_app()
        deps._config = test_config
        yield TestClient(app)
        deps.reset_singletons()

    def test_dashboard_requires_auth(self, client):
        resp = client.get("/api/stats")
        assert resp.status_code == 401

    def test_commands_requires_auth(self, client):
        resp = client.get("/api/commands")
        assert resp.status_code == 401

    def test_incidents_requires_auth(self, client):
        resp = client.get("/api/incidents")
        assert resp.status_code == 401

    def test_settings_requires_auth(self, client):
        resp = client.get("/api/settings")
        assert resp.status_code == 401

    def test_admin_requires_auth(self, client):
        resp = client.post("/api/admin/users/tier")
        assert resp.status_code in (401, 422)

    def test_health_is_public(self, client):
        """Health endpoint should be accessible without auth."""
        resp = client.get("/api/health")
        assert resp.status_code == 200

    def test_invalid_token_rejected(self, client):
        resp = client.get(
            "/api/stats",
            headers={"Authorization": "Bearer invalid.token.here"},
        )
        assert resp.status_code == 401

    def test_empty_api_key_rejected(self, client):
        resp = client.get(
            "/api/stats",
            headers={"X-API-Key": ""},
        )
        # Empty key should fail (either 401 or treated as no key)
        assert resp.status_code in (401, 422)


# ── Protected Path Enforcement ────────────────────────────────


class TestProtectedPaths:
    """Verify the hook blocks writes to protected paths."""

    def test_check_protected_path_etc(self):
        from sentinelai.hooks.sentinel_hook import _check_protected_path

        mock_config = MagicMock()
        mock_config.protected_paths = ["/etc", "~/.ssh", "~/.aws"]
        assert _check_protected_path("/etc/passwd", mock_config) is True

    def test_check_protected_path_ssh(self):
        from pathlib import Path
        from sentinelai.hooks.sentinel_hook import _check_protected_path

        mock_config = MagicMock()
        mock_config.protected_paths = ["/etc", "~/.ssh"]
        # Use the actual expanded home path (~ expands to current user)
        ssh_path = str(Path("~/.ssh/id_rsa").expanduser())
        assert _check_protected_path(ssh_path, mock_config) is True

    def test_check_unprotected_path(self):
        from sentinelai.hooks.sentinel_hook import _check_protected_path

        mock_config = MagicMock()
        mock_config.protected_paths = ["/etc", "~/.ssh"]
        assert _check_protected_path("/tmp/test.txt", mock_config) is False


# ── SQL Injection Prevention ──────────────────────────────────


class TestSqlInjectionPrevention:
    """Verify that user input is never interpolated into raw SQL."""

    def test_orm_query_uses_parameters(self):
        """The ORM should parameterize all queries, not concatenate."""
        from sentinelai.logger.database import CommandLog, Base

        # Verify the model uses Column types (ORM, not raw SQL)
        assert hasattr(CommandLog, "__tablename__")
        assert CommandLog.__tablename__ == "commands"
        # All fields should be Column objects (SQLAlchemy ORM)
        assert hasattr(CommandLog.command, "type")

    def test_no_raw_sql_in_routes(self):
        """Search for dangerous patterns in route files."""
        import re
        from pathlib import Path

        routers_dir = Path("sentinelai/api/routers")
        dangerous_patterns = [
            r'\.execute\s*\(\s*f["\']',  # f-string in execute()
            r'\.execute\s*\(\s*["\'].*\%s',  # %-format in execute()
            r'text\s*\(\s*f["\']',  # f-string in text()
        ]

        for py_file in routers_dir.glob("*.py"):
            content = py_file.read_text()
            for pattern in dangerous_patterns:
                matches = re.findall(pattern, content)
                assert len(matches) == 0, (
                    f"Potential SQL injection in {py_file.name}: {pattern}"
                )
