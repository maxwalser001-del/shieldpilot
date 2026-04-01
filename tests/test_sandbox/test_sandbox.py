"""Tests for sandbox execution and path guarding."""

from __future__ import annotations

import os
import pytest

from sentinelai.core.config import SandboxConfig, SentinelConfig
from sentinelai.sandbox.executor import CommandSandbox
from sentinelai.sandbox.path_guard import PathGuard
from tests.conftest import unix_only


@unix_only
class TestCommandSandbox:
    """Test sandboxed command execution."""

    @pytest.fixture
    def sandbox(self):
        config = SandboxConfig(enabled=True, timeout=5, max_memory_mb=256, restricted_env_vars=["SECRET_VAR"])
        return CommandSandbox(config)

    def test_simple_command(self, sandbox):
        result = sandbox.execute("echo hello")
        assert result.exit_code == 0
        assert "hello" in result.stdout
        assert result.timed_out is False

    def test_command_stderr(self, sandbox):
        result = sandbox.execute("echo error >&2")
        assert "error" in result.stderr

    def test_command_exit_code(self, sandbox):
        result = sandbox.execute("exit 42")
        assert result.exit_code == 42

    def test_command_timeout(self):
        config = SandboxConfig(enabled=True, timeout=1, max_memory_mb=256)
        sandbox = CommandSandbox(config)
        result = sandbox.execute("sleep 10")
        assert result.timed_out is True

    def test_env_var_stripped(self, sandbox):
        os.environ["SECRET_VAR"] = "sensitive"
        try:
            result = sandbox.execute("echo $SECRET_VAR")
            assert "sensitive" not in result.stdout
        finally:
            os.environ.pop("SECRET_VAR", None)

    def test_sentinel_sandboxed_flag(self, sandbox):
        result = sandbox.execute("echo $SENTINEL_SANDBOXED")
        assert "1" in result.stdout

    def test_execution_time_tracked(self, sandbox):
        result = sandbox.execute("echo fast")
        assert result.execution_time_ms >= 0

    def test_working_directory(self, sandbox, tmp_path):
        result = sandbox.execute("pwd", working_dir=str(tmp_path))
        assert str(tmp_path) in result.stdout


class TestPathGuard:
    """Test path traversal prevention."""

    @pytest.fixture
    def guard(self, test_config):
        return PathGuard(test_config)

    @pytest.fixture
    def bare_guard(self):
        return PathGuard()

    def test_safe_path(self, bare_guard, tmp_path):
        child = tmp_path / "subdir" / "file.txt"
        child.parent.mkdir(parents=True, exist_ok=True)
        child.touch()
        assert bare_guard.check_path(str(child), str(tmp_path)) is True

    def test_traversal_escape(self, bare_guard, tmp_path):
        escaped = str(tmp_path / ".." / ".." / "etc" / "passwd")
        assert bare_guard.check_path(escaped, str(tmp_path)) is False

    def test_protected_path(self, guard):
        assert guard.is_protected("/etc/shadow") is True

    def test_unprotected_path(self, guard):
        assert guard.is_protected("/tmp/safe.txt") is False

    def test_extract_paths_basic(self, bare_guard):
        paths = bare_guard.extract_paths_from_command("cat /etc/passwd /tmp/file.txt")
        assert "/etc/passwd" in paths
        assert "/tmp/file.txt" in paths

    def test_extract_paths_with_flags(self, bare_guard):
        paths = bare_guard.extract_paths_from_command("cp -o /tmp/output.txt source.py")
        assert "/tmp/output.txt" in paths

    def test_check_command_protected(self, guard):
        violations = guard.check_command("cat /etc/shadow")
        assert len(violations) > 0
        assert any(v["severity"] == "critical" for v in violations)

    def test_check_command_traversal(self, bare_guard):
        violations = bare_guard.check_command("cat ../../etc/passwd")
        assert len(violations) > 0
        assert any(v["reason"].startswith("Path contains") for v in violations)

    def test_check_command_sensitive_dotfile(self, bare_guard):
        violations = bare_guard.check_command("cat ~/.ssh/id_rsa")
        assert len(violations) > 0

    def test_check_command_safe(self, bare_guard):
        violations = bare_guard.check_command("echo hello")
        assert len(violations) == 0
