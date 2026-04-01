"""Shared test fixtures for ShieldPilot test suite."""

from __future__ import annotations

import os
import platform
import tempfile
from typing import Generator

import pytest

# ---------------------------------------------------------------------------
# Platform skip markers
#
# Usage in tests:
#   from tests.conftest import unix_only, linux_only
#
#   @unix_only
#   def test_sandbox_exec(): ...
#
#   @linux_only
#   def test_cgroups_isolation(): ...
# ---------------------------------------------------------------------------

unix_only = pytest.mark.skipif(
    platform.system() == "Windows",
    reason="Unix-only test (uses bash/subprocess with preexec_fn)",
)

linux_only = pytest.mark.skipif(
    platform.system() != "Linux",
    reason="Linux-only test",
)

from sentinelai.core.config import (
    AuthConfig,
    BillingConfig,
    BlacklistConfig,
    LLMConfig,
    LoggingConfig,
    PluginConfig,
    RiskThresholds,
    SandboxConfig,
    SentinelConfig,
    WhitelistConfig,
)
from sentinelai.core.secrets import SecretsMasker
from sentinelai.engine.base import AnalysisContext
from sentinelai.logger.database import Base, init_database


@pytest.fixture
def test_config() -> SentinelConfig:
    """SentinelConfig with test-appropriate defaults."""
    return SentinelConfig(
        mode="enforce",
        risk_thresholds=RiskThresholds(block=80, warn=40, allow=0),
        llm=LLMConfig(enabled=False),
        whitelist=WhitelistConfig(
            commands=["ls", "cat", "echo", "pwd", "whoami"],
        ),
        blacklist=BlacklistConfig(
            commands=["rm -rf /", "mkfs", ":(){:|:&};:"],
            domains=["evil.com", "malware.net"],
        ),
        protected_paths=["/etc", "~/.ssh", "~/.aws"],
        secrets_patterns=[
            r"AKIA[0-9A-Z]{16}",
            r"sk-[a-zA-Z0-9]{20,}",
        ],
        sandbox=SandboxConfig(enabled=True, timeout=5),
        plugins=PluginConfig(enabled=False),
        logging=LoggingConfig(database=":memory:", chain_hashing=True),
        auth=AuthConfig(
            secret_key="test-secret-key-for-testing-only",
            default_admin_user="admin",
            default_admin_password="testpass",
            local_first=False,  # Disable in tests so auth tests work correctly
        ),
        billing=BillingConfig(enabled=False),
    )


@pytest.fixture
def mock_context(test_config) -> AnalysisContext:
    """Standard analysis context for tests."""
    return AnalysisContext(
        working_directory="/tmp/test",
        environment={"PATH": "/usr/bin", "USER": "testuser"},
        config=test_config,
    )


@pytest.fixture
def masker() -> SecretsMasker:
    """SecretsMasker with test patterns."""
    return SecretsMasker([
        r"AKIA[0-9A-Z]{16}",
        r"sk-[a-zA-Z0-9]{20,}",
        r"ghp_[a-zA-Z0-9]{36}",
    ])


@pytest.fixture
def db_path():
    """Temporary database file path."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    yield path
    try:
        os.unlink(path)
    except OSError:
        pass


@pytest.fixture
def logger(test_config, masker, db_path):
    """BlackboxLogger with in-memory database."""
    from sentinelai.logger import BlackboxLogger
    return BlackboxLogger(config=test_config.logging, masker=masker, db_path=db_path)


@pytest.fixture
def risk_engine(test_config):
    """Fully configured RiskEngine with all analyzers."""
    from sentinelai.engine import RiskEngine
    return RiskEngine(test_config)
