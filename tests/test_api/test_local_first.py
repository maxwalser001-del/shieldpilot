"""I3: Local-First Mode Tests.

Tests the local-first auth bypass (localhost connections skip JWT auth
when config.auth.local_first=True).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from sentinelai.api.deps import _is_local_request


# ── _is_local_request unit tests ──────────────────────────────


class TestIsLocalRequest:
    def test_ipv4_localhost(self):
        req = MagicMock()
        req.client = MagicMock()
        req.client.host = "127.0.0.1"
        assert _is_local_request(req) is True

    def test_ipv6_localhost(self):
        req = MagicMock()
        req.client = MagicMock()
        req.client.host = "::1"
        assert _is_local_request(req) is True

    def test_remote_ip(self):
        req = MagicMock()
        req.client = MagicMock()
        req.client.host = "192.168.1.100"
        assert _is_local_request(req) is False

    def test_public_ip(self):
        req = MagicMock()
        req.client = MagicMock()
        req.client.host = "8.8.8.8"
        assert _is_local_request(req) is False

    def test_no_client(self):
        req = MagicMock()
        req.client = None
        assert _is_local_request(req) is False


# ── /api/auth/mode endpoint tests ─────────────────────────────


@pytest.fixture
def local_first_app(test_config):
    """Create app with local_first enabled."""
    test_config.auth.local_first = True

    from sentinelai.api.app import create_app
    from sentinelai.api import deps

    app = create_app()
    deps._config = test_config
    yield app
    deps.reset_singletons()


@pytest.fixture
def no_local_first_app(test_config):
    """Create app with local_first disabled."""
    test_config.auth.local_first = False

    from sentinelai.api.app import create_app
    from sentinelai.api import deps

    app = create_app()
    deps._config = test_config
    yield app
    deps.reset_singletons()


class TestAuthModeEndpoint:
    def test_local_first_enabled_from_localhost(self, local_first_app):
        # TestClient uses "testclient" as host, not 127.0.0.1.
        # Patch _is_local_request in the router module where it's imported.
        with patch("sentinelai.api.routers.auth._is_local_request", return_value=True):
            client = TestClient(local_first_app)
            resp = client.get("/api/auth/mode")
            assert resp.status_code == 200
            data = resp.json()
            assert data["local_first"] is True
            assert data["is_local"] is True

    def test_local_first_disabled(self, no_local_first_app):
        with patch("sentinelai.api.routers.auth._is_local_request", return_value=True):
            client = TestClient(no_local_first_app)
            resp = client.get("/api/auth/mode")
            assert resp.status_code == 200
            data = resp.json()
            # local_first is False in config, so even from localhost it should be False
            assert data["local_first"] is False


# ── Auth bypass integration tests ─────────────────────────────


class TestLocalFirstAuthBypass:
    def test_protected_endpoint_accessible_with_local_first(self, local_first_app):
        """Localhost + local_first=True should bypass auth on protected endpoints."""
        client = TestClient(local_first_app)
        resp = client.get("/api/health")
        assert resp.status_code == 200

    def test_protected_endpoint_requires_auth_without_local_first(self, no_local_first_app):
        """Without local_first, protected endpoints should require auth."""
        client = TestClient(no_local_first_app)
        # Stats endpoint requires auth
        resp = client.get("/api/stats")
        assert resp.status_code == 401
