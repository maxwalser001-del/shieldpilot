"""Tests for SecurityHeadersMiddleware (pure ASGI)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from sentinelai.api.app import SecurityHeadersMiddleware, create_app
from sentinelai.api import deps
from sentinelai.core.secrets import SecretsMasker
from sentinelai.logger import BlackboxLogger


@pytest.fixture
def app(test_config, db_path):
    """Create a test FastAPI app with test config."""
    deps.reset_singletons()
    masker = SecretsMasker(test_config.secrets_patterns)
    logger = BlackboxLogger(config=test_config.logging, masker=masker, db_path=db_path)
    deps._config = test_config
    deps._logger = logger
    application = create_app()
    yield application
    deps.reset_singletons()


@pytest.fixture
def client(app):
    return TestClient(app)


class TestSecurityHeaders:
    """Verify that all security headers are present on every response."""

    EXPECTED_HEADERS = {
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "x-xss-protection": "1; mode=block",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=(), microphone=(), geolocation=()",
    }

    def test_health_endpoint_has_security_headers(self, client):
        """GET /api/health should include all security headers."""
        r = client.get("/api/health")
        for header, value in self.EXPECTED_HEADERS.items():
            assert r.headers.get(header) == value, (
                f"Missing or wrong {header}: got {r.headers.get(header)!r}"
            )

    def test_login_page_has_security_headers(self, client):
        """GET /login (HTML) should include all security headers."""
        r = client.get("/login")
        for header, value in self.EXPECTED_HEADERS.items():
            assert r.headers.get(header) == value

    def test_404_has_security_headers(self, client):
        """Even 404 responses should include security headers."""
        r = client.get("/api/nonexistent-endpoint-xyz")
        for header, value in self.EXPECTED_HEADERS.items():
            assert r.headers.get(header) == value

    def test_no_hsts_on_http(self, client):
        """HSTS header should NOT be present for plain HTTP requests."""
        r = client.get("/api/health")
        assert "strict-transport-security" not in r.headers

    def test_hsts_on_https(self, app):
        """HSTS header should be present for HTTPS requests."""
        client = TestClient(app, base_url="https://testserver")
        r = client.get("/api/health")
        assert r.headers.get("strict-transport-security") == (
            "max-age=31536000; includeSubDomains"
        )

    def test_headers_on_post_request(self, client, test_config):
        """Security headers should be on POST responses too."""
        r = client.post("/api/auth/login", json={
            "username": test_config.auth.default_admin_user,
            "password": test_config.auth.default_admin_password,
        })
        for header, value in self.EXPECTED_HEADERS.items():
            assert r.headers.get(header) == value

    def test_headers_on_error_response(self, client):
        """Security headers should be present even on 422 validation errors."""
        r = client.post("/api/auth/login", json={})
        assert r.status_code in (400, 422)
        for header, value in self.EXPECTED_HEADERS.items():
            assert r.headers.get(header) == value


class TestSecurityHeadersMiddlewareUnit:
    """Unit tests for the middleware class directly."""

    def test_middleware_has_expected_header_count(self):
        """Middleware should define at least 6 standard headers (including CSP)."""
        assert len(SecurityHeadersMiddleware.HEADERS) >= 6

    def test_middleware_hsts_header_value(self):
        """HSTS header should include includeSubDomains."""
        name, value = SecurityHeadersMiddleware.HSTS_HEADER
        assert name == b"strict-transport-security"
        assert b"includeSubDomains" in value
        assert b"max-age=31536000" in value

    def test_non_http_scope_passes_through(self):
        """Non-HTTP scopes (websocket, lifespan) should pass through unchanged."""
        import asyncio

        received_scope = {}

        async def inner_app(scope, receive, send):
            received_scope.update(scope)

        async def _run():
            middleware = SecurityHeadersMiddleware(inner_app)
            await middleware({"type": "lifespan"}, None, None)

        asyncio.get_event_loop().run_until_complete(_run())
        assert received_scope["type"] == "lifespan"

    def test_http_scope_adds_headers(self):
        """HTTP scope should trigger header injection."""
        import asyncio

        captured_messages = []

        async def inner_app(scope, receive, send):
            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            })
            await send({
                "type": "http.response.body",
                "body": b"ok",
            })

        async def _run():
            async def capture_send(message):
                captured_messages.append(message)

            middleware = SecurityHeadersMiddleware(inner_app)
            await middleware(
                {"type": "http", "scheme": "http"},
                None,
                capture_send,
            )

        asyncio.get_event_loop().run_until_complete(_run())

        # First message should be response.start with injected headers
        start = captured_messages[0]
        assert start["type"] == "http.response.start"
        header_names = [h[0] for h in start["headers"]]
        assert b"x-content-type-options" in header_names
        assert b"x-frame-options" in header_names
        assert b"x-xss-protection" in header_names
        assert b"referrer-policy" in header_names
        assert b"permissions-policy" in header_names
        # No HSTS on HTTP
        assert b"strict-transport-security" not in header_names

        # Second message should be body, unchanged
        body = captured_messages[1]
        assert body["type"] == "http.response.body"
        assert body["body"] == b"ok"

    def test_https_scope_adds_hsts(self):
        """HTTPS scope should include HSTS header."""
        import asyncio

        captured_messages = []

        async def inner_app(scope, receive, send):
            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [],
            })

        async def _run():
            async def capture_send(message):
                captured_messages.append(message)

            middleware = SecurityHeadersMiddleware(inner_app)
            await middleware(
                {"type": "http", "scheme": "https"},
                None,
                capture_send,
            )

        asyncio.get_event_loop().run_until_complete(_run())

        start = captured_messages[0]
        header_names = [h[0] for h in start["headers"]]
        assert b"strict-transport-security" in header_names
