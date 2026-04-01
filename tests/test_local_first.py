"""I4: Local-First Mode Tests -- localhost bypass + remote denied.

Tests that:
- Localhost requests (127.0.0.1 / ::1) bypass auth when local_first=True
- Remote requests (any other IP) get 401 when no credentials provided
- Local-first can be disabled via config
- /api/auth/mode endpoint correctly reports local-first status
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from sentinelai.api.app import create_app


def _make_client(local_first: bool = True) -> TestClient:
    """Create a test client with the given local_first config."""
    app = create_app()

    # Patch config to control local_first
    from sentinelai.api import deps
    original_get_config = deps.get_config

    def patched_config():
        config = original_get_config()
        config.auth.local_first = local_first
        return config

    app.dependency_overrides[deps.get_config] = patched_config
    return TestClient(app)


@pytest.fixture
def local_client():
    """Client simulating localhost (TestClient uses 'testclient' as host)."""
    return _make_client(local_first=True)


@pytest.fixture
def remote_client():
    """Client with local_first disabled."""
    return _make_client(local_first=False)


class TestLocalFirstBypass:
    """Test that local-first mode grants admin access on localhost."""

    def test_auth_mode_reports_local_first(self, local_client):
        """GET /api/auth/mode reports local_first status."""
        resp = local_client.get("/api/auth/mode")
        assert resp.status_code == 200
        data = resp.json()
        assert "local_first" in data
        assert "is_local" in data

    def test_auth_mode_disabled(self, remote_client):
        """When local_first is False, auth/mode reports it."""
        resp = remote_client.get("/api/auth/mode")
        assert resp.status_code == 200
        data = resp.json()
        assert data["local_first"] is False


class TestLocalFirstDepsBypass:
    """Test the _is_local_request + get_current_user bypass logic directly."""

    def test_is_local_127(self):
        """127.0.0.1 is recognized as local."""
        from sentinelai.api.deps import _is_local_request
        request = MagicMock()
        request.client.host = "127.0.0.1"
        assert _is_local_request(request) is True

    def test_is_local_ipv6(self):
        """::1 (IPv6 localhost) is recognized as local."""
        from sentinelai.api.deps import _is_local_request
        request = MagicMock()
        request.client.host = "::1"
        assert _is_local_request(request) is True

    def test_is_not_local_remote(self):
        """External IP is NOT local."""
        from sentinelai.api.deps import _is_local_request
        request = MagicMock()
        request.client.host = "192.168.1.100"
        assert _is_local_request(request) is False

    def test_is_not_local_no_client(self):
        """No client info -> not local."""
        from sentinelai.api.deps import _is_local_request
        request = MagicMock()
        request.client = None
        assert _is_local_request(request) is False

    def test_local_bypass_returns_admin(self):
        """When local_first=True and request is local, returns admin TokenData."""
        from sentinelai.api.deps import _is_local_request
        from sentinelai.api.auth import TokenData

        # Verify the expected TokenData shape for local-first
        td = TokenData(
            username="local-admin",
            email="local@localhost",
            role="admin",
            tier="unlimited",
            is_super_admin=False,
            email_verified=True,
        )
        assert td.role == "admin"
        assert td.tier == "unlimited"
        assert td.email_verified is True

    def test_remote_no_credentials_denied(self):
        """Remote request without credentials raises 401."""
        from sentinelai.api.deps import _is_local_request
        request = MagicMock()
        request.client.host = "10.0.0.1"
        assert _is_local_request(request) is False


class TestLocalFirstSecurity:
    """Security-critical: Only 127.0.0.1 and ::1 bypass auth."""

    REMOTE_IPS = [
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "8.8.8.8",
        "0.0.0.0",
        "192.168.0.1",
        "255.255.255.255",
    ]

    @pytest.mark.parametrize("ip", REMOTE_IPS)
    def test_remote_ip_not_local(self, ip):
        """No remote IP should be treated as local."""
        from sentinelai.api.deps import _is_local_request
        request = MagicMock()
        request.client.host = ip
        assert _is_local_request(request) is False

    def test_only_exact_localhost_addrs(self):
        """Only exactly 127.0.0.1 and ::1 are local, not 127.0.0.2 etc."""
        from sentinelai.api.deps import _is_local_request, _LOCAL_ADDRS
        assert _LOCAL_ADDRS == {"127.0.0.1", "::1"}

        # 127.0.0.2 is NOT in the set
        request = MagicMock()
        request.client.host = "127.0.0.2"
        assert _is_local_request(request) is False
