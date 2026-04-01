"""Shared fixtures for API tests."""

import pytest


@pytest.fixture(autouse=True)
def reset_circuit_breaker_and_singletons():
    """Reset circuit breaker and singletons between all API tests.

    - Circuit breaker: in-memory, reset to prevent injection 429s leaking
    - Singletons: reset so each test's `app` fixture can set its own logger
    - Rate limiters: no longer cleared here because they are DB-backed (A26)
      and each test gets a fresh database via the `app` fixture
    """
    from sentinelai.api import deps
    from sentinelai.api.routers._shared import _circuit_breaker
    _circuit_breaker.reset()
    deps.reset_singletons()
    yield
    _circuit_breaker.reset()
    deps.reset_singletons()
