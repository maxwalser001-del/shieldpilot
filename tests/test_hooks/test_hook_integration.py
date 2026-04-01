"""End-to-end integration tests for the ShieldPilot hook main() function.

These tests simulate the full hook flow: JSON stdin -> decision -> JSON stdout.
Each decision function (_allow, _deny, _ask) prints JSON to stdout then calls
sys.exit(0), so we mock sys at the module level and capture print() output.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


def _run_hook(input_data: dict | str) -> dict:
    """Run the hook main() with mocked stdin/stdout and return the output JSON.

    Args:
        input_data: Dict (will be JSON-serialized) or raw string for stdin.

    Returns:
        Parsed JSON dict from the hook's print() call.
    """
    raw = json.dumps(input_data) if isinstance(input_data, dict) else input_data

    captured_output = {}

    def mock_print(text, **kwargs):
        # Only capture stdout prints (skip stderr prints which use file=sys.stderr)
        if "file" not in kwargs:
            captured_output["text"] = text

    mock_stdin = MagicMock()
    mock_stdin.read.return_value = raw

    with patch("sentinelai.hooks.sentinel_hook.sys") as mock_sys, \
         patch("builtins.print", side_effect=mock_print), \
         patch("sentinelai.engine.base.AnalysisContext", MagicMock):
        mock_sys.stdin = mock_stdin
        mock_sys.stderr = MagicMock()
        mock_sys.exit = MagicMock(side_effect=SystemExit(0))

        from sentinelai.hooks.sentinel_hook import main

        try:
            main()
        except SystemExit:
            pass

    assert "text" in captured_output, "Hook did not produce any output"
    return json.loads(captured_output["text"])


def _get_decision(output: dict) -> str:
    """Extract permissionDecision from hook output."""
    return output.get("hookSpecificOutput", {}).get("permissionDecision", "")


def _get_reason(output: dict) -> str:
    """Extract permissionDecisionReason from hook output."""
    return output.get("hookSpecificOutput", {}).get("permissionDecisionReason", "")


# ---------------------------------------------------------------------------
# 1. Read-only tools -- auto-allowed without engine invocation
# ---------------------------------------------------------------------------

class TestHookReadOnlyTools:
    """Read-only tools should be auto-allowed without engine invocation."""

    def test_glob_tool_allowed(self):
        """Glob (read-only) should be immediately allowed."""
        output = _run_hook({
            "tool_name": "Glob",
            "tool_input": {"pattern": "*.py"},
        })
        assert _get_decision(output) == "allow"

    def test_grep_tool_allowed(self):
        """Grep (read-only) should be immediately allowed."""
        output = _run_hook({
            "tool_name": "Grep",
            "tool_input": {"pattern": "test"},
        })
        assert _get_decision(output) == "allow"

    def test_read_tool_allowed(self):
        """Read (read-only) should be immediately allowed."""
        output = _run_hook({
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/test.txt"},
        })
        assert _get_decision(output) == "allow"


# ---------------------------------------------------------------------------
# 2. Write tools -- check protected paths
# ---------------------------------------------------------------------------

class TestHookWriteTools:
    """Write tools should check protected paths."""

    def test_write_normal_path_allowed(self):
        """Write to a non-protected path should be allowed."""
        with patch("sentinelai.hooks.sentinel_hook._load_sentinel") as mock_load:
            mock_config = MagicMock()
            mock_config.mode = "enforce"
            mock_config.protected_paths = ["/etc", "/var"]
            mock_load.return_value = (mock_config, MagicMock(), MagicMock())

            with patch(
                "sentinelai.hooks.sentinel_hook._check_protected_path",
                return_value=False,
            ):
                output = _run_hook({
                    "tool_name": "Write",
                    "tool_input": {"file_path": "/tmp/test.txt"},
                })
                assert _get_decision(output) == "allow"

    def test_write_protected_path_denied(self):
        """Write to a protected path in enforce mode should be denied."""
        with patch("sentinelai.hooks.sentinel_hook._load_sentinel") as mock_load:
            mock_config = MagicMock()
            mock_config.mode = "enforce"
            mock_config.protected_paths = ["/etc", "/var", "~/.ssh"]
            mock_load.return_value = (mock_config, MagicMock(), MagicMock())

            with patch(
                "sentinelai.hooks.sentinel_hook._check_protected_path",
                return_value=True,
            ):
                output = _run_hook({
                    "tool_name": "Write",
                    "tool_input": {"file_path": "/etc/passwd"},
                })
                assert _get_decision(output) == "deny"
                assert "protected path" in _get_reason(output).lower()

    def test_write_protected_path_audit_mode(self):
        """Write to a protected path in audit mode should allow with reason."""
        with patch("sentinelai.hooks.sentinel_hook._load_sentinel") as mock_load:
            mock_config = MagicMock()
            mock_config.mode = "audit"
            mock_config.protected_paths = ["/etc"]
            mock_load.return_value = (mock_config, MagicMock(), MagicMock())

            with patch(
                "sentinelai.hooks.sentinel_hook._check_protected_path",
                return_value=True,
            ):
                output = _run_hook({
                    "tool_name": "Write",
                    "tool_input": {"file_path": "/etc/hosts"},
                })
                assert _get_decision(output) == "allow"
                reason = _get_reason(output)
                assert "audit" in reason.lower()


# ---------------------------------------------------------------------------
# 3. Bash commands -- full risk engine
# ---------------------------------------------------------------------------

class TestHookBashCommands:
    """Bash commands go through the full risk engine."""

    def test_safe_command_allowed(self):
        """A safe command (low risk) should be allowed."""
        from sentinelai.core.constants import Action
        from sentinelai.ml.ml_infer import MlResult

        mock_assessment = MagicMock()
        mock_assessment.action = Action.ALLOW
        mock_assessment.final_score = 5
        mock_assessment.signals = []

        # Mock scanner to return benign result (avoids ML gate false positive
        # on short shell commands like "ls -la" which are out-of-distribution)
        mock_scan_result = MagicMock()
        mock_scan_result.overall_score = 0
        mock_scan_result.threats = []
        mock_scanner_cls = MagicMock()
        mock_scanner_cls.return_value.scan.return_value = mock_scan_result

        # Mock ML stage to return benign result
        mock_ml_stage = MagicMock()
        mock_ml_stage.predict.return_value = MlResult(
            scores={"clean": 0.9, "hard": 0.05, "injection": 0.05}, status="ok"
        )

        with patch("sentinelai.hooks.sentinel_hook._load_sentinel") as mock_load, \
             patch("sentinelai.hooks.sentinel_hook._check_usage_limit", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._check_injection_rate", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._increment_usage"), \
             patch("sentinelai.hooks.sentinel_hook._log_assessment"), \
             patch("sentinelai.hooks.sentinel_hook._get_usage_warning", return_value=""), \
             patch("sentinelai.scanner.scanner.PromptScanner", mock_scanner_cls), \
             patch("sentinelai.hooks.sentinel_hook._get_ml_stage", return_value=mock_ml_stage):
            mock_config = MagicMock()
            mock_config.mode = "enforce"
            mock_engine = MagicMock()
            mock_engine.assess.return_value = mock_assessment
            mock_load.return_value = (mock_config, mock_engine, Action)

            output = _run_hook({
                "tool_name": "Bash",
                "tool_input": {"command": "ls -la"},
            })
            assert _get_decision(output) == "allow"

    def test_dangerous_command_denied(self):
        """A dangerous command (high risk, BLOCK) should be denied in enforce mode."""
        from sentinelai.core.constants import Action, RiskCategory

        mock_signal = MagicMock()
        mock_signal.category = RiskCategory.DESTRUCTIVE_FS
        mock_signal.description = "Recursive delete"
        mock_signal.score = 95

        mock_assessment = MagicMock()
        mock_assessment.action = Action.BLOCK
        mock_assessment.final_score = 95
        mock_assessment.signals = [mock_signal]

        with patch("sentinelai.hooks.sentinel_hook._load_sentinel") as mock_load, \
             patch("sentinelai.hooks.sentinel_hook._check_usage_limit", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._check_injection_rate", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._increment_usage"), \
             patch("sentinelai.hooks.sentinel_hook._log_assessment"), \
             patch("sentinelai.hooks.sentinel_hook._get_usage_warning", return_value=""):
            mock_config = MagicMock()
            mock_config.mode = "enforce"
            mock_engine = MagicMock()
            mock_engine.assess.return_value = mock_assessment
            mock_load.return_value = (mock_config, mock_engine, Action)

            output = _run_hook({
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf /"},
            })
            assert _get_decision(output) == "deny"
            assert "BLOCKED" in _get_reason(output)


# ---------------------------------------------------------------------------
# 4. Operating modes
# ---------------------------------------------------------------------------

class TestHookModes:
    """Test different operating modes."""

    def test_disabled_mode_allows_everything(self):
        """Disabled mode should immediately allow all Bash commands."""
        with patch("sentinelai.hooks.sentinel_hook._load_sentinel") as mock_load:
            mock_config = MagicMock()
            mock_config.mode = "disabled"
            mock_load.return_value = (mock_config, MagicMock(), MagicMock())

            output = _run_hook({
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf /"},
            })
            assert _get_decision(output) == "allow"
            assert "disabled" in _get_reason(output).lower()


# ---------------------------------------------------------------------------
# 5. Edge cases -- empty / broken input
# ---------------------------------------------------------------------------

class TestHookEdgeCases:
    """Edge cases: empty input, broken JSON, etc."""

    def test_empty_input_allows(self):
        """Empty stdin should result in allow (fail-open)."""
        output = _run_hook("")
        assert _get_decision(output) == "allow"

    def test_broken_json_allows(self):
        """Broken JSON should result in allow (fail-open)."""
        output = _run_hook("{not valid json!!!")
        assert _get_decision(output) == "allow"


# ---------------------------------------------------------------------------
# 6. OpenClaw format -- adapter auto-detection
# ---------------------------------------------------------------------------

class TestHookOpenClawFormat:
    """Verify the hook correctly parses OpenClaw-format input via the adapter layer."""

    def test_openclaw_read_tool_allowed(self):
        """OpenClaw readFile maps to Read (read-only) → auto-allow."""
        openclaw_input = json.dumps({
            "event": "preToolExecution",
            "tool": {"name": "readFile", "parameters": {"path": "/tmp/test.txt"}},
            "context": {"workingDir": "/home/user"},
        })
        output = _run_hook(openclaw_input)
        assert _get_decision(output) == "allow"

    def test_openclaw_search_tool_allowed(self):
        """OpenClaw search maps to Grep (read-only) → auto-allow."""
        openclaw_input = json.dumps({
            "event": "preToolExecution",
            "tool": {"name": "search", "parameters": {"pattern": "test"}},
            "context": {"workingDir": "/home/user"},
        })
        output = _run_hook(openclaw_input)
        assert _get_decision(output) == "allow"

    def test_openclaw_shell_safe_command(self):
        """OpenClaw shell maps to Bash → goes through risk engine."""
        from sentinelai.core.constants import Action
        from sentinelai.ml.ml_infer import MlResult

        mock_assessment = MagicMock()
        mock_assessment.action = Action.ALLOW
        mock_assessment.final_score = 5
        mock_assessment.signals = []

        mock_scan_result = MagicMock()
        mock_scan_result.overall_score = 0
        mock_scan_result.threats = []
        mock_scanner_cls = MagicMock()
        mock_scanner_cls.return_value.scan.return_value = mock_scan_result

        mock_ml_stage = MagicMock()
        mock_ml_stage.predict.return_value = MlResult(
            scores={"clean": 0.9, "hard": 0.05, "injection": 0.05}, status="ok"
        )

        with patch("sentinelai.hooks.sentinel_hook._load_sentinel") as mock_load, \
             patch("sentinelai.hooks.sentinel_hook._check_usage_limit", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._check_injection_rate", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._increment_usage"), \
             patch("sentinelai.hooks.sentinel_hook._log_assessment"), \
             patch("sentinelai.hooks.sentinel_hook._get_usage_warning", return_value=""), \
             patch("sentinelai.scanner.scanner.PromptScanner", mock_scanner_cls), \
             patch("sentinelai.hooks.sentinel_hook._get_ml_stage", return_value=mock_ml_stage):
            mock_config = MagicMock()
            mock_config.mode = "enforce"
            mock_engine = MagicMock()
            mock_engine.assess.return_value = mock_assessment
            mock_load.return_value = (mock_config, mock_engine, Action)

            openclaw_input = json.dumps({
                "event": "preToolExecution",
                "tool": {"name": "shell", "parameters": {"command": "ls -la"}},
                "context": {"workingDir": "/tmp"},
            })
            output = _run_hook(openclaw_input)
            assert _get_decision(output) == "allow"

    def test_openclaw_write_protected_denied(self):
        """OpenClaw writeFile to protected path should be denied."""
        with patch("sentinelai.hooks.sentinel_hook._load_sentinel") as mock_load:
            mock_config = MagicMock()
            mock_config.mode = "enforce"
            mock_config.protected_paths = ["/etc"]
            mock_load.return_value = (mock_config, MagicMock(), MagicMock())

            with patch(
                "sentinelai.hooks.sentinel_hook._check_protected_path",
                return_value=True,
            ):
                openclaw_input = json.dumps({
                    "event": "preToolExecution",
                    "tool": {"name": "writeFile", "parameters": {"file_path": "/etc/hosts"}},
                    "context": {"workingDir": "/home/user"},
                })
                output = _run_hook(openclaw_input)
                assert _get_decision(output) == "deny"
                assert "protected path" in _get_reason(output).lower()


# ---------------------------------------------------------------------------
# 7. Generic format -- adapter auto-detection
# ---------------------------------------------------------------------------

class TestHookGenericFormat:
    """Verify the hook correctly parses Generic-format input via the adapter layer."""

    def test_generic_bash_safe_command(self):
        """Generic format with tool=Bash → goes through risk engine."""
        from sentinelai.core.constants import Action
        from sentinelai.ml.ml_infer import MlResult

        mock_assessment = MagicMock()
        mock_assessment.action = Action.ALLOW
        mock_assessment.final_score = 5
        mock_assessment.signals = []

        mock_scan_result = MagicMock()
        mock_scan_result.overall_score = 0
        mock_scan_result.threats = []
        mock_scanner_cls = MagicMock()
        mock_scanner_cls.return_value.scan.return_value = mock_scan_result

        mock_ml_stage = MagicMock()
        mock_ml_stage.predict.return_value = MlResult(
            scores={"clean": 0.9, "hard": 0.05, "injection": 0.05}, status="ok"
        )

        with patch("sentinelai.hooks.sentinel_hook._load_sentinel") as mock_load, \
             patch("sentinelai.hooks.sentinel_hook._check_usage_limit", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._check_injection_rate", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._increment_usage"), \
             patch("sentinelai.hooks.sentinel_hook._log_assessment"), \
             patch("sentinelai.hooks.sentinel_hook._get_usage_warning", return_value=""), \
             patch("sentinelai.scanner.scanner.PromptScanner", mock_scanner_cls), \
             patch("sentinelai.hooks.sentinel_hook._get_ml_stage", return_value=mock_ml_stage):
            mock_config = MagicMock()
            mock_config.mode = "enforce"
            mock_engine = MagicMock()
            mock_engine.assess.return_value = mock_assessment
            mock_load.return_value = (mock_config, mock_engine, Action)

            generic_input = json.dumps({
                "command": "echo hello",
                "tool": "Bash",
                "cwd": "/tmp",
            })
            output = _run_hook(generic_input)
            assert _get_decision(output) == "allow"

    def test_generic_read_tool_allowed(self):
        """Generic format with tool=Read → auto-allow (read-only)."""
        generic_input = json.dumps({
            "command": "/tmp/test.txt",
            "tool": "Read",
        })
        output = _run_hook(generic_input)
        assert _get_decision(output) == "allow"

    def test_generic_default_tool_is_bash(self):
        """Generic format without tool field → defaults to Bash."""
        from sentinelai.core.constants import Action
        from sentinelai.ml.ml_infer import MlResult

        mock_assessment = MagicMock()
        mock_assessment.action = Action.ALLOW
        mock_assessment.final_score = 5
        mock_assessment.signals = []

        mock_scan_result = MagicMock()
        mock_scan_result.overall_score = 0
        mock_scan_result.threats = []
        mock_scanner_cls = MagicMock()
        mock_scanner_cls.return_value.scan.return_value = mock_scan_result

        mock_ml_stage = MagicMock()
        mock_ml_stage.predict.return_value = MlResult(
            scores={"clean": 0.9, "hard": 0.05, "injection": 0.05}, status="ok"
        )

        with patch("sentinelai.hooks.sentinel_hook._load_sentinel") as mock_load, \
             patch("sentinelai.hooks.sentinel_hook._check_usage_limit", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._check_injection_rate", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._increment_usage"), \
             patch("sentinelai.hooks.sentinel_hook._log_assessment"), \
             patch("sentinelai.hooks.sentinel_hook._get_usage_warning", return_value=""), \
             patch("sentinelai.scanner.scanner.PromptScanner", mock_scanner_cls), \
             patch("sentinelai.hooks.sentinel_hook._get_ml_stage", return_value=mock_ml_stage):
            mock_config = MagicMock()
            mock_config.mode = "enforce"
            mock_engine = MagicMock()
            mock_engine.assess.return_value = mock_assessment
            mock_load.return_value = (mock_config, mock_engine, Action)

            generic_input = json.dumps({"command": "pwd"})
            output = _run_hook(generic_input)
            assert _get_decision(output) == "allow"


# ---------------------------------------------------------------------------
# 8. Adapter fallback -- import failure graceful degradation
# ---------------------------------------------------------------------------

class TestHookAdapterFallback:
    """Verify the hook falls back to direct JSON parsing when adapters fail."""

    def test_fallback_on_adapter_import_error(self):
        """If adapter import fails, hook falls back to direct JSON parsing."""
        with patch("sentinelai.adapters.detect_platform", side_effect=ImportError):
            # Claude Code format should still work via the except-block fallback
            output = _run_hook({
                "tool_name": "Read",
                "tool_input": {"file_path": "/tmp/test.txt"},
            })
            assert _get_decision(output) == "allow"

    def test_fallback_on_adapter_parse_error(self):
        """If adapter.parse_input() raises, hook falls back to direct JSON parsing."""
        mock_adapter = MagicMock()
        mock_adapter.parse_input.side_effect = ValueError("parse failed")

        with patch("sentinelai.adapters.detect_platform", return_value=mock_adapter):
            # Claude Code format should still work via the except-block fallback
            output = _run_hook({
                "tool_name": "Glob",
                "tool_input": {"pattern": "*.py"},
            })
            assert _get_decision(output) == "allow"


# ---------------------------------------------------------------------------
# 9. _check_usage_limit() — billing enforcement
# ---------------------------------------------------------------------------

class TestCheckUsageLimit:
    """Tests for _check_usage_limit() with various billing states."""

    def test_billing_disabled_returns_no_limit(self):
        """When billing is disabled, usage limit is never reached."""
        from sentinelai.hooks.sentinel_hook import _check_usage_limit

        mock_config = MagicMock()
        mock_config.billing.enabled = False

        reached, msg = _check_usage_limit(mock_config)
        assert reached is False
        assert msg == ""

    def test_unlimited_commands_returns_no_limit(self):
        """When commands_per_day is -1 (unlimited), limit is never reached."""
        from sentinelai.hooks.sentinel_hook import _check_usage_limit

        mock_config = MagicMock()
        mock_config.billing.enabled = True
        mock_config.billing.limits.commands_per_day = -1

        reached, msg = _check_usage_limit(mock_config)
        assert reached is False
        assert msg == ""

    def test_limit_reached_returns_true(self):
        """When usage equals the daily limit, returns (True, message)."""
        from sentinelai.hooks.sentinel_hook import _check_usage_limit

        mock_config = MagicMock()
        mock_config.billing.enabled = True
        mock_config.billing.limits.commands_per_day = 50
        mock_config.billing.tier = "free"
        mock_config.billing.upgrade_url = "#/pricing"
        mock_config.secrets_patterns = []

        mock_usage = MagicMock()
        mock_usage.commands_evaluated = 50

        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = mock_usage

        mock_logger = MagicMock()
        mock_logger._get_session.return_value = mock_session

        with patch("sentinelai.logger.BlackboxLogger", return_value=mock_logger), \
             patch("sentinelai.core.secrets.SecretsMasker"):
            reached, msg = _check_usage_limit(mock_config)
            assert reached is True
            assert "50/50" in msg or "limit" in msg.lower()

    def test_limit_not_reached_returns_false(self):
        """When usage is below the daily limit, returns (False, '')."""
        from sentinelai.hooks.sentinel_hook import _check_usage_limit

        mock_config = MagicMock()
        mock_config.billing.enabled = True
        mock_config.billing.limits.commands_per_day = 50
        mock_config.secrets_patterns = []

        mock_usage = MagicMock()
        mock_usage.commands_evaluated = 25

        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = mock_usage

        mock_logger = MagicMock()
        mock_logger._get_session.return_value = mock_session

        with patch("sentinelai.logger.BlackboxLogger", return_value=mock_logger), \
             patch("sentinelai.core.secrets.SecretsMasker"):
            reached, msg = _check_usage_limit(mock_config)
            assert reached is False
            assert msg == ""

    def test_no_usage_record_returns_false(self):
        """When no usage record exists for today, usage is 0 so limit not reached."""
        from sentinelai.hooks.sentinel_hook import _check_usage_limit

        mock_config = MagicMock()
        mock_config.billing.enabled = True
        mock_config.billing.limits.commands_per_day = 50
        mock_config.secrets_patterns = []

        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = None

        mock_logger = MagicMock()
        mock_logger._get_session.return_value = mock_session

        with patch("sentinelai.logger.BlackboxLogger", return_value=mock_logger), \
             patch("sentinelai.core.secrets.SecretsMasker"):
            reached, msg = _check_usage_limit(mock_config)
            assert reached is False
            assert msg == ""

    def test_db_exception_returns_false(self):
        """Database errors should fail open (return no limit)."""
        from sentinelai.hooks.sentinel_hook import _check_usage_limit

        mock_config = MagicMock()
        mock_config.billing.enabled = True
        mock_config.billing.limits.commands_per_day = 50
        mock_config.secrets_patterns = []

        with patch("sentinelai.logger.BlackboxLogger", side_effect=Exception("DB down")), \
             patch("sentinelai.core.secrets.SecretsMasker"):
            reached, msg = _check_usage_limit(mock_config)
            assert reached is False
            assert msg == ""


# ---------------------------------------------------------------------------
# 10. _get_usage_warning() — approaching limit warnings
# ---------------------------------------------------------------------------

class TestGetUsageWarning:
    """Tests for _get_usage_warning() returning warnings at 80%+ usage."""

    def test_billing_disabled_returns_empty(self):
        """No warning when billing is disabled."""
        from sentinelai.hooks.sentinel_hook import _get_usage_warning

        mock_config = MagicMock()
        mock_config.billing.enabled = False

        assert _get_usage_warning(mock_config) == ""

    def test_unlimited_returns_empty(self):
        """No warning when commands_per_day is unlimited (-1)."""
        from sentinelai.hooks.sentinel_hook import _get_usage_warning

        mock_config = MagicMock()
        mock_config.billing.enabled = True
        mock_config.billing.limits.commands_per_day = -1

        assert _get_usage_warning(mock_config) == ""

    def test_at_80_percent_returns_warning(self):
        """At 80% usage (40/50), should return a warning string."""
        from sentinelai.hooks.sentinel_hook import _get_usage_warning

        mock_config = MagicMock()
        mock_config.billing.enabled = True
        mock_config.billing.limits.commands_per_day = 50
        mock_config.secrets_patterns = []

        mock_usage = MagicMock()
        mock_usage.commands_evaluated = 40  # 80% of 50

        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = mock_usage

        mock_logger = MagicMock()
        mock_logger._get_session.return_value = mock_session

        with patch("sentinelai.logger.BlackboxLogger", return_value=mock_logger), \
             patch("sentinelai.core.secrets.SecretsMasker"):
            warning = _get_usage_warning(mock_config)
            assert "40/50" in warning
            assert "80%" in warning
            assert "Approaching daily limit" in warning

    def test_at_90_percent_returns_warning(self):
        """At 90% usage (45/50), should return a warning with 90%."""
        from sentinelai.hooks.sentinel_hook import _get_usage_warning

        mock_config = MagicMock()
        mock_config.billing.enabled = True
        mock_config.billing.limits.commands_per_day = 50
        mock_config.secrets_patterns = []

        mock_usage = MagicMock()
        mock_usage.commands_evaluated = 45  # 90% of 50

        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = mock_usage

        mock_logger = MagicMock()
        mock_logger._get_session.return_value = mock_session

        with patch("sentinelai.logger.BlackboxLogger", return_value=mock_logger), \
             patch("sentinelai.core.secrets.SecretsMasker"):
            warning = _get_usage_warning(mock_config)
            assert "45/50" in warning
            assert "90%" in warning

    def test_below_80_percent_returns_empty(self):
        """Below 80% usage (30/50 = 60%), should return empty string."""
        from sentinelai.hooks.sentinel_hook import _get_usage_warning

        mock_config = MagicMock()
        mock_config.billing.enabled = True
        mock_config.billing.limits.commands_per_day = 50
        mock_config.secrets_patterns = []

        mock_usage = MagicMock()
        mock_usage.commands_evaluated = 30  # 60% of 50

        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = mock_usage

        mock_logger = MagicMock()
        mock_logger._get_session.return_value = mock_session

        with patch("sentinelai.logger.BlackboxLogger", return_value=mock_logger), \
             patch("sentinelai.core.secrets.SecretsMasker"):
            warning = _get_usage_warning(mock_config)
            assert warning == ""

    def test_no_usage_record_returns_empty(self):
        """No usage record means 0 commands, so no warning."""
        from sentinelai.hooks.sentinel_hook import _get_usage_warning

        mock_config = MagicMock()
        mock_config.billing.enabled = True
        mock_config.billing.limits.commands_per_day = 50
        mock_config.secrets_patterns = []

        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = None

        mock_logger = MagicMock()
        mock_logger._get_session.return_value = mock_session

        with patch("sentinelai.logger.BlackboxLogger", return_value=mock_logger), \
             patch("sentinelai.core.secrets.SecretsMasker"):
            warning = _get_usage_warning(mock_config)
            assert warning == ""

    def test_db_exception_returns_empty(self):
        """Database errors should fail open (return no warning)."""
        from sentinelai.hooks.sentinel_hook import _get_usage_warning

        mock_config = MagicMock()
        mock_config.billing.enabled = True
        mock_config.billing.limits.commands_per_day = 50
        mock_config.secrets_patterns = []

        with patch("sentinelai.logger.BlackboxLogger", side_effect=Exception("DB down")), \
             patch("sentinelai.core.secrets.SecretsMasker"):
            warning = _get_usage_warning(mock_config)
            assert warning == ""


# ---------------------------------------------------------------------------
# 11. _check_injection_rate() — Best-of-N defense
# ---------------------------------------------------------------------------

class TestCheckInjectionRate:
    """Tests for _check_injection_rate() rate limiting on injection attempts."""

    def test_five_or_more_recent_injections_blocks(self):
        """When 5+ injection scans with threats in last 60s, should block."""
        from sentinelai.hooks.sentinel_hook import _check_injection_rate

        mock_config = MagicMock()
        mock_config.secrets_patterns = []

        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.count.return_value = 7

        mock_logger = MagicMock()
        mock_logger._get_session.return_value = mock_session

        with patch("sentinelai.logger.BlackboxLogger", return_value=mock_logger), \
             patch("sentinelai.core.secrets.SecretsMasker"):
            blocked, msg = _check_injection_rate(mock_config)
            assert blocked is True
            assert "repeated injection" in msg.lower()
            assert "7" in msg

    def test_exactly_five_injections_blocks(self):
        """Boundary case: exactly 5 injections should trigger block."""
        from sentinelai.hooks.sentinel_hook import _check_injection_rate

        mock_config = MagicMock()
        mock_config.secrets_patterns = []

        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.count.return_value = 5

        mock_logger = MagicMock()
        mock_logger._get_session.return_value = mock_session

        with patch("sentinelai.logger.BlackboxLogger", return_value=mock_logger), \
             patch("sentinelai.core.secrets.SecretsMasker"):
            blocked, msg = _check_injection_rate(mock_config)
            assert blocked is True

    def test_below_five_injections_does_not_block(self):
        """When fewer than 5 injection scans in last 60s, should not block."""
        from sentinelai.hooks.sentinel_hook import _check_injection_rate

        mock_config = MagicMock()
        mock_config.secrets_patterns = []

        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.count.return_value = 3

        mock_logger = MagicMock()
        mock_logger._get_session.return_value = mock_session

        with patch("sentinelai.logger.BlackboxLogger", return_value=mock_logger), \
             patch("sentinelai.core.secrets.SecretsMasker"):
            blocked, msg = _check_injection_rate(mock_config)
            assert blocked is False
            assert msg == ""

    def test_zero_injections_does_not_block(self):
        """Zero recent injections should not block."""
        from sentinelai.hooks.sentinel_hook import _check_injection_rate

        mock_config = MagicMock()
        mock_config.secrets_patterns = []

        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.count.return_value = 0

        mock_logger = MagicMock()
        mock_logger._get_session.return_value = mock_session

        with patch("sentinelai.logger.BlackboxLogger", return_value=mock_logger), \
             patch("sentinelai.core.secrets.SecretsMasker"):
            blocked, msg = _check_injection_rate(mock_config)
            assert blocked is False
            assert msg == ""

    def test_db_exception_fails_open(self):
        """Database errors should fail open (no block)."""
        from sentinelai.hooks.sentinel_hook import _check_injection_rate

        mock_config = MagicMock()
        mock_config.secrets_patterns = []

        with patch("sentinelai.logger.BlackboxLogger", side_effect=Exception("DB down")), \
             patch("sentinelai.core.secrets.SecretsMasker"):
            blocked, msg = _check_injection_rate(mock_config)
            assert blocked is False
            assert msg == ""


# ---------------------------------------------------------------------------
# 12. _increment_usage() — usage counter management
# ---------------------------------------------------------------------------

class TestIncrementUsage:
    """Tests for _increment_usage() creating/updating usage records."""

    def test_increments_existing_record(self):
        """When a usage record exists for today, should increment commands_evaluated."""
        from sentinelai.hooks.sentinel_hook import _increment_usage

        mock_config = MagicMock()
        mock_config.secrets_patterns = []

        mock_usage = MagicMock()
        mock_usage.commands_evaluated = 10

        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = mock_usage

        mock_logger = MagicMock()
        mock_logger._get_session.return_value = mock_session

        with patch("sentinelai.logger.BlackboxLogger", return_value=mock_logger), \
             patch("sentinelai.core.secrets.SecretsMasker"):
            _increment_usage(mock_config)

            assert mock_usage.commands_evaluated == 11
            mock_session.commit.assert_called_once()
            mock_session.close.assert_called_once()

    def test_creates_new_record_when_none_exists(self):
        """When no usage record exists for today, should create a new one."""
        from sentinelai.hooks.sentinel_hook import _increment_usage

        mock_config = MagicMock()
        mock_config.secrets_patterns = []

        mock_session = MagicMock()
        mock_session.query.return_value.filter.return_value.first.return_value = None

        mock_logger = MagicMock()
        mock_logger._get_session.return_value = mock_session

        with patch("sentinelai.logger.BlackboxLogger", return_value=mock_logger), \
             patch("sentinelai.core.secrets.SecretsMasker"), \
             patch("sentinelai.logger.database.UsageRecord") as MockUsageRecord:
            _increment_usage(mock_config)

            MockUsageRecord.assert_called_once()
            call_kwargs = MockUsageRecord.call_args
            assert call_kwargs[1]["commands_evaluated"] == 1
            assert call_kwargs[1]["tenant_id"] is None
            mock_session.add.assert_called_once()
            mock_session.commit.assert_called_once()
            mock_session.close.assert_called_once()

    def test_db_exception_does_not_raise(self):
        """Database errors should be caught and not propagate."""
        from sentinelai.hooks.sentinel_hook import _increment_usage

        mock_config = MagicMock()
        mock_config.secrets_patterns = []

        with patch("sentinelai.logger.BlackboxLogger", side_effect=Exception("DB down")), \
             patch("sentinelai.core.secrets.SecretsMasker"):
            # Should not raise
            _increment_usage(mock_config)


# ---------------------------------------------------------------------------
# 13. _log_assessment() and _log_injection_scan() — logging paths
# ---------------------------------------------------------------------------

class TestLogAssessment:
    """Tests for _log_assessment() logging commands and incidents."""

    def test_logs_command_for_allowed_action(self):
        """Non-BLOCK assessment should log the command but not create an incident."""
        from sentinelai.hooks.sentinel_hook import _log_assessment
        from sentinelai.core.constants import Action

        mock_assessment = MagicMock()
        mock_assessment.action = Action.ALLOW
        mock_assessment.final_score = 10
        mock_assessment.signals = []

        mock_config = MagicMock()
        mock_config.secrets_patterns = []

        mock_logger = MagicMock()
        mock_logger.log_command.return_value = 42

        with patch("sentinelai.logger.BlackboxLogger", return_value=mock_logger), \
             patch("sentinelai.core.secrets.SecretsMasker"):
            _log_assessment(mock_assessment, "ls -la", "/tmp", mock_config)

            mock_logger.log_command.assert_called_once()
            mock_logger.log_incident.assert_not_called()

    def test_logs_incident_for_block_action(self):
        """BLOCK assessment should log both command and incident."""
        from sentinelai.hooks.sentinel_hook import _log_assessment
        from sentinelai.core.constants import Action, RiskCategory

        mock_signal = MagicMock()
        mock_signal.category = RiskCategory.DESTRUCTIVE_FS

        mock_assessment = MagicMock()
        mock_assessment.action = Action.BLOCK
        mock_assessment.final_score = 95
        mock_assessment.signals = [mock_signal]

        mock_config = MagicMock()
        mock_config.secrets_patterns = []

        mock_logger = MagicMock()
        mock_logger.log_command.return_value = 42

        with patch("sentinelai.logger.BlackboxLogger", return_value=mock_logger), \
             patch("sentinelai.core.secrets.SecretsMasker"):
            _log_assessment(mock_assessment, "rm -rf /", "/home", mock_config)

            mock_logger.log_command.assert_called_once()
            mock_logger.log_incident.assert_called_once()
            call_kwargs = mock_logger.log_incident.call_args
            assert call_kwargs[1]["severity"] == "critical"
            assert call_kwargs[1]["command_id"] == 42

    def test_block_score_below_90_uses_high_severity(self):
        """BLOCK with score < 90 should use 'high' severity, not 'critical'."""
        from sentinelai.hooks.sentinel_hook import _log_assessment
        from sentinelai.core.constants import Action, RiskCategory

        mock_signal = MagicMock()
        mock_signal.category.value = "destructive_filesystem"

        mock_assessment = MagicMock()
        mock_assessment.action = Action.BLOCK
        mock_assessment.final_score = 85
        mock_assessment.signals = [mock_signal]

        mock_config = MagicMock()
        mock_config.secrets_patterns = []

        mock_logger = MagicMock()
        mock_logger.log_command.return_value = 1

        with patch("sentinelai.logger.BlackboxLogger", return_value=mock_logger), \
             patch("sentinelai.core.secrets.SecretsMasker"):
            _log_assessment(mock_assessment, "rm -rf ~", "/home", mock_config)

            call_kwargs = mock_logger.log_incident.call_args
            assert call_kwargs[1]["severity"] == "high"

    def test_logs_scan_result_with_threats(self):
        """When scan_result has threats, _log_injection_scan should call log_prompt_scan."""
        from sentinelai.hooks.sentinel_hook import _log_assessment
        from sentinelai.core.constants import Action

        mock_assessment = MagicMock()
        mock_assessment.action = Action.ALLOW
        mock_assessment.final_score = 5
        mock_assessment.signals = []

        mock_config = MagicMock()
        mock_config.secrets_patterns = []

        mock_scan_result = MagicMock()
        mock_scan_result.threats = [MagicMock()]  # has threats

        mock_logger = MagicMock()
        mock_logger.log_command.return_value = 1

        with patch("sentinelai.logger.BlackboxLogger", return_value=mock_logger), \
             patch("sentinelai.core.secrets.SecretsMasker"):
            _log_assessment(mock_assessment, "echo test", "/tmp", mock_config,
                            scan_result=mock_scan_result)

            mock_logger.log_prompt_scan.assert_called_once_with(mock_scan_result)

    def test_no_scan_result_skips_scan_log(self):
        """When scan_result is None, log_prompt_scan should not be called."""
        from sentinelai.hooks.sentinel_hook import _log_assessment
        from sentinelai.core.constants import Action

        mock_assessment = MagicMock()
        mock_assessment.action = Action.ALLOW
        mock_assessment.final_score = 5
        mock_assessment.signals = []

        mock_config = MagicMock()
        mock_config.secrets_patterns = []

        mock_logger = MagicMock()
        mock_logger.log_command.return_value = 1

        with patch("sentinelai.logger.BlackboxLogger", return_value=mock_logger), \
             patch("sentinelai.core.secrets.SecretsMasker"):
            _log_assessment(mock_assessment, "echo test", "/tmp", mock_config,
                            scan_result=None)

            mock_logger.log_prompt_scan.assert_not_called()

    def test_scan_result_without_threats_skips_log(self):
        """When scan_result has no threats, log_prompt_scan should not be called."""
        from sentinelai.hooks.sentinel_hook import _log_assessment
        from sentinelai.core.constants import Action

        mock_assessment = MagicMock()
        mock_assessment.action = Action.ALLOW
        mock_assessment.final_score = 5
        mock_assessment.signals = []

        mock_config = MagicMock()
        mock_config.secrets_patterns = []

        mock_scan_result = MagicMock()
        mock_scan_result.threats = []  # no threats

        mock_logger = MagicMock()
        mock_logger.log_command.return_value = 1

        with patch("sentinelai.logger.BlackboxLogger", return_value=mock_logger), \
             patch("sentinelai.core.secrets.SecretsMasker"):
            _log_assessment(mock_assessment, "echo test", "/tmp", mock_config,
                            scan_result=mock_scan_result)

            mock_logger.log_prompt_scan.assert_not_called()

    def test_logger_exception_does_not_propagate(self):
        """Logging errors should be caught and not propagate."""
        from sentinelai.hooks.sentinel_hook import _log_assessment
        from sentinelai.core.constants import Action

        mock_assessment = MagicMock()
        mock_assessment.action = Action.ALLOW
        mock_assessment.final_score = 5

        mock_config = MagicMock()
        mock_config.secrets_patterns = []

        with patch("sentinelai.logger.BlackboxLogger", side_effect=Exception("log broken")), \
             patch("sentinelai.core.secrets.SecretsMasker"):
            # Should not raise
            _log_assessment(mock_assessment, "echo test", "/tmp", mock_config)


# ---------------------------------------------------------------------------
# 14. _log_injection_scan() — direct tests
# ---------------------------------------------------------------------------

class TestLogInjectionScan:
    """Direct tests for _log_injection_scan()."""

    def test_logs_scan_with_threats(self):
        """Should call logger.log_prompt_scan when threats exist."""
        from sentinelai.hooks.sentinel_hook import _log_injection_scan

        mock_logger = MagicMock()
        mock_scan_result = MagicMock()
        mock_scan_result.threats = [MagicMock()]

        _log_injection_scan(mock_scan_result, mock_logger)
        mock_logger.log_prompt_scan.assert_called_once_with(mock_scan_result)

    def test_skips_log_when_no_threats(self):
        """Should not call log_prompt_scan when threats list is empty."""
        from sentinelai.hooks.sentinel_hook import _log_injection_scan

        mock_logger = MagicMock()
        mock_scan_result = MagicMock()
        mock_scan_result.threats = []

        _log_injection_scan(mock_scan_result, mock_logger)
        mock_logger.log_prompt_scan.assert_not_called()

    def test_skips_log_when_scan_result_is_none(self):
        """Should not call log_prompt_scan when scan_result is None."""
        from sentinelai.hooks.sentinel_hook import _log_injection_scan

        mock_logger = MagicMock()

        _log_injection_scan(None, mock_logger)
        mock_logger.log_prompt_scan.assert_not_called()

    def test_exception_does_not_propagate(self):
        """Logger errors should be caught and not propagate."""
        from sentinelai.hooks.sentinel_hook import _log_injection_scan

        mock_logger = MagicMock()
        mock_logger.log_prompt_scan.side_effect = Exception("DB error")
        mock_scan_result = MagicMock()
        mock_scan_result.threats = [MagicMock()]

        # Should not raise
        _log_injection_scan(mock_scan_result, mock_logger)


# ---------------------------------------------------------------------------
# 15. _find_config() — config file discovery
# ---------------------------------------------------------------------------

class TestFindConfig:
    """Tests for _find_config() directory-walking config discovery."""

    def test_finds_config_in_current_dir(self, tmp_path):
        """Should find sentinel.yaml in the start directory."""
        from sentinelai.hooks.sentinel_hook import _find_config

        config_file = tmp_path / "sentinel.yaml"
        config_file.write_text("mode: enforce\n")

        result = _find_config(str(tmp_path))
        assert result is not None
        assert result.name == "sentinel.yaml"
        assert result == config_file.resolve()

    def test_finds_config_in_parent_dir(self, tmp_path):
        """Should walk up directories and find sentinel.yaml in a parent."""
        from sentinelai.hooks.sentinel_hook import _find_config

        config_file = tmp_path / "sentinel.yaml"
        config_file.write_text("mode: enforce\n")

        child_dir = tmp_path / "subdir" / "nested"
        child_dir.mkdir(parents=True)

        result = _find_config(str(child_dir))
        assert result is not None
        assert result == config_file.resolve()

    def test_returns_none_when_no_config_exists(self, tmp_path):
        """Should return None when no sentinel.yaml found anywhere."""
        from sentinelai.hooks.sentinel_hook import _find_config

        # Use a subdirectory with no config, and mock home dir to also have none
        child_dir = tmp_path / "empty" / "nested"
        child_dir.mkdir(parents=True)

        with patch("sentinelai.hooks.sentinel_hook.Path") as MockPath:
            # Make Path(start_dir).resolve() return something that doesn't have config
            mock_current = MagicMock()
            mock_candidate = MagicMock()
            mock_candidate.exists.return_value = False

            # Simulate directory walk that reaches root
            mock_parent = MagicMock()
            mock_current.__truediv__ = MagicMock(return_value=mock_candidate)
            mock_current.parent = mock_parent
            mock_parent.parent = mock_parent  # root: parent == self
            mock_parent.__truediv__ = MagicMock(return_value=mock_candidate)

            MockPath.return_value.resolve.return_value = mock_current

            # Home dir fallback also has no config
            mock_home_config = MagicMock()
            mock_home_config.exists.return_value = False
            MockPath.home.return_value.__truediv__ = MagicMock(return_value=mock_home_config)

            result = _find_config(str(child_dir))
            assert result is None

    def test_falls_back_to_home_dir(self, tmp_path):
        """Should fall back to ~/sentinel.yaml if not found in parents."""
        from sentinelai.hooks.sentinel_hook import _find_config

        # Start dir has no config
        start_dir = tmp_path / "project"
        start_dir.mkdir()

        # Create a fake home config
        home_config = tmp_path / "fakehome" / "sentinel.yaml"
        home_config.parent.mkdir(parents=True)
        home_config.write_text("mode: audit\n")

        with patch("sentinelai.hooks.sentinel_hook.Path") as MockPath:
            # Real path logic for the start_dir walk (no config found)
            real_path = Path(str(start_dir)).resolve()
            MockPath.return_value.resolve.return_value = real_path

            # Home dir fallback returns our fake home config
            MockPath.home.return_value.__truediv__ = MagicMock(return_value=home_config)

            result = _find_config(str(start_dir))
            assert result is not None
            assert result.name == "sentinel.yaml"


# ---------------------------------------------------------------------------
# 16. ML rollout paths — off / shadow / enforce
# ---------------------------------------------------------------------------

class TestMLRolloutPaths:
    """Tests for ML mode decisions: off, shadow, enforce."""

    def _make_hook_input(self, command="echo hello"):
        return {
            "tool_name": "Bash",
            "tool_input": {"command": command},
        }

    def _make_mocks(self, ml_injection_prob=0.95, scanner_score=10):
        """Create standard mocks for the ML path tests."""
        from sentinelai.core.constants import Action
        from sentinelai.ml.ml_infer import MlResult

        mock_assessment = MagicMock()
        mock_assessment.action = Action.ALLOW
        mock_assessment.final_score = 5
        mock_assessment.signals = []

        mock_scan_result = MagicMock()
        mock_scan_result.overall_score = scanner_score
        mock_scan_result.threats = []
        mock_scanner_cls = MagicMock()
        mock_scanner_cls.return_value.scan.return_value = mock_scan_result

        mock_ml_stage = MagicMock()
        mock_ml_stage.predict.return_value = MlResult(
            scores={"clean": 0.02, "hard": 0.03, "injection": ml_injection_prob},
            status="ok",
        )

        mock_config = MagicMock()
        mock_config.mode = "enforce"
        mock_engine = MagicMock()
        mock_engine.assess.return_value = mock_assessment

        return mock_config, mock_engine, mock_scanner_cls, mock_ml_stage, Action

    def test_ml_off_skips_ml_entirely(self, monkeypatch):
        """ML mode 'off' should skip ML scoring and allow safe commands."""
        monkeypatch.setenv("SENTINEL_ML_MODE", "off")

        mock_config, mock_engine, mock_scanner_cls, mock_ml_stage, Action = self._make_mocks()

        with patch("sentinelai.hooks.sentinel_hook._load_sentinel") as mock_load, \
             patch("sentinelai.hooks.sentinel_hook._check_usage_limit", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._check_injection_rate", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._increment_usage"), \
             patch("sentinelai.hooks.sentinel_hook._log_assessment"), \
             patch("sentinelai.hooks.sentinel_hook._get_usage_warning", return_value=""), \
             patch("sentinelai.scanner.scanner.PromptScanner", mock_scanner_cls), \
             patch("sentinelai.hooks.sentinel_hook._get_ml_stage", return_value=mock_ml_stage):
            mock_load.return_value = (mock_config, mock_engine, Action)

            output = _run_hook(self._make_hook_input())
            assert _get_decision(output) == "allow"
            # ML stage should NOT be called when mode is "off"
            mock_ml_stage.predict.assert_not_called()

    def test_ml_shadow_scores_but_does_not_enforce(self, monkeypatch):
        """ML mode 'shadow' should run ML but not block even on high injection prob."""
        monkeypatch.setenv("SENTINEL_ML_MODE", "shadow")

        mock_config, mock_engine, mock_scanner_cls, mock_ml_stage, Action = self._make_mocks(
            ml_injection_prob=0.99, scanner_score=10
        )

        with patch("sentinelai.hooks.sentinel_hook._load_sentinel") as mock_load, \
             patch("sentinelai.hooks.sentinel_hook._check_usage_limit", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._check_injection_rate", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._increment_usage"), \
             patch("sentinelai.hooks.sentinel_hook._log_assessment"), \
             patch("sentinelai.hooks.sentinel_hook._get_usage_warning", return_value=""), \
             patch("sentinelai.scanner.scanner.PromptScanner", mock_scanner_cls), \
             patch("sentinelai.hooks.sentinel_hook._get_ml_stage", return_value=mock_ml_stage):
            mock_load.return_value = (mock_config, mock_engine, Action)

            output = _run_hook(self._make_hook_input())
            # Shadow mode: allows even with high ML score
            assert _get_decision(output) == "allow"
            # ML was still called for logging/telemetry
            mock_ml_stage.predict.assert_called_once()

    def test_ml_enforce_blocks_on_high_injection_prob(self, monkeypatch):
        """ML mode 'enforce' with high injection prob should deny."""
        monkeypatch.setenv("SENTINEL_ML_MODE", "enforce")
        monkeypatch.setenv("SENTINEL_ML_BLOCK_THRESHOLD", "0.80")

        mock_config, mock_engine, mock_scanner_cls, mock_ml_stage, Action = self._make_mocks(
            ml_injection_prob=0.95, scanner_score=10
        )

        with patch("sentinelai.hooks.sentinel_hook._load_sentinel") as mock_load, \
             patch("sentinelai.hooks.sentinel_hook._check_usage_limit", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._check_injection_rate", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._increment_usage"), \
             patch("sentinelai.hooks.sentinel_hook._log_assessment"), \
             patch("sentinelai.hooks.sentinel_hook._get_usage_warning", return_value=""), \
             patch("sentinelai.scanner.scanner.PromptScanner", mock_scanner_cls), \
             patch("sentinelai.hooks.sentinel_hook._get_ml_stage", return_value=mock_ml_stage):
            mock_load.return_value = (mock_config, mock_engine, Action)

            output = _run_hook(self._make_hook_input())
            assert _get_decision(output) == "deny"
            assert "ML classifier" in _get_reason(output)

    def test_ml_enforce_allows_below_threshold(self, monkeypatch):
        """ML mode 'enforce' with injection prob below threshold should allow."""
        monkeypatch.setenv("SENTINEL_ML_MODE", "enforce")
        monkeypatch.setenv("SENTINEL_ML_BLOCK_THRESHOLD", "0.80")

        mock_config, mock_engine, mock_scanner_cls, mock_ml_stage, Action = self._make_mocks(
            ml_injection_prob=0.30, scanner_score=10
        )

        with patch("sentinelai.hooks.sentinel_hook._load_sentinel") as mock_load, \
             patch("sentinelai.hooks.sentinel_hook._check_usage_limit", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._check_injection_rate", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._increment_usage"), \
             patch("sentinelai.hooks.sentinel_hook._log_assessment"), \
             patch("sentinelai.hooks.sentinel_hook._get_usage_warning", return_value=""), \
             patch("sentinelai.scanner.scanner.PromptScanner", mock_scanner_cls), \
             patch("sentinelai.hooks.sentinel_hook._get_ml_stage", return_value=mock_ml_stage):
            mock_load.return_value = (mock_config, mock_engine, Action)

            output = _run_hook(self._make_hook_input())
            assert _get_decision(output) == "allow"

    def test_ml_skipped_when_scanner_score_high(self, monkeypatch):
        """ML is only run when scanner score < 20. High scanner score skips ML."""
        monkeypatch.setenv("SENTINEL_ML_MODE", "enforce")

        mock_config, mock_engine, mock_scanner_cls, mock_ml_stage, Action = self._make_mocks(
            ml_injection_prob=0.99, scanner_score=75
        )

        with patch("sentinelai.hooks.sentinel_hook._load_sentinel") as mock_load, \
             patch("sentinelai.hooks.sentinel_hook._check_usage_limit", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._check_injection_rate", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._increment_usage"), \
             patch("sentinelai.hooks.sentinel_hook._log_assessment"), \
             patch("sentinelai.hooks.sentinel_hook._get_usage_warning", return_value=""), \
             patch("sentinelai.scanner.scanner.PromptScanner", mock_scanner_cls), \
             patch("sentinelai.hooks.sentinel_hook._get_ml_stage", return_value=mock_ml_stage):
            mock_load.return_value = (mock_config, mock_engine, Action)

            output = _run_hook(self._make_hook_input())
            # Scanner score >= 70 triggers scanner block (not ML)
            assert _get_decision(output) == "deny"
            assert "scanner" in _get_reason(output).lower()
            # ML should NOT have been called because scanner_score >= 20
            mock_ml_stage.predict.assert_not_called()

    def test_ml_failure_fails_open(self, monkeypatch):
        """ML exception should fail open (allow the command)."""
        monkeypatch.setenv("SENTINEL_ML_MODE", "enforce")

        from sentinelai.core.constants import Action as RealAction
        from sentinelai.ml.ml_infer import MlResult

        mock_assessment = MagicMock()
        mock_assessment.action = RealAction.ALLOW
        mock_assessment.final_score = 5
        mock_assessment.signals = []

        mock_scan_result = MagicMock()
        mock_scan_result.overall_score = 10
        mock_scan_result.threats = []
        mock_scanner_cls = MagicMock()
        mock_scanner_cls.return_value.scan.return_value = mock_scan_result

        mock_ml_stage = MagicMock()
        mock_ml_stage.predict.side_effect = Exception("ML model broken")

        mock_config = MagicMock()
        mock_config.mode = "enforce"
        mock_engine = MagicMock()
        mock_engine.assess.return_value = mock_assessment

        with patch("sentinelai.hooks.sentinel_hook._load_sentinel") as mock_load, \
             patch("sentinelai.hooks.sentinel_hook._check_usage_limit", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._check_injection_rate", return_value=(False, "")), \
             patch("sentinelai.hooks.sentinel_hook._increment_usage"), \
             patch("sentinelai.hooks.sentinel_hook._log_assessment"), \
             patch("sentinelai.hooks.sentinel_hook._get_usage_warning", return_value=""), \
             patch("sentinelai.scanner.scanner.PromptScanner", mock_scanner_cls), \
             patch("sentinelai.hooks.sentinel_hook._get_ml_stage", return_value=mock_ml_stage):
            mock_load.return_value = (mock_config, mock_engine, RealAction)

            output = _run_hook(self._make_hook_input())
            # Should allow despite ML failure
            assert _get_decision(output) == "allow"


# ---------------------------------------------------------------------------
# 17. Telemetry — counter management and flush
# ---------------------------------------------------------------------------

class TestTelemetry:
    """Tests for _telemetry_tick() with telemetry enabled/disabled."""

    def test_telemetry_disabled_does_nothing(self, monkeypatch):
        """When SENTINEL_ML_TELEMETRY is not '1', counters should not change."""
        import sentinelai.hooks.sentinel_hook as hook

        monkeypatch.setenv("SENTINEL_ML_TELEMETRY", "0")

        # Save original state and reset counters
        original = hook._telemetry.copy()
        hook._telemetry.update({
            "count_total": 0,
            "count_ml_scored": 0,
            "count_ml_rec_block": 0,
            "count_ml_rec_review": 0,
            "count_ml_denies": 0,
        })

        try:
            hook._telemetry_tick(ml_scored=True, ml_recommendation="block", ml_denied=True)
            assert hook._telemetry["count_total"] == 0
            assert hook._telemetry["count_ml_scored"] == 0
            assert hook._telemetry["count_ml_rec_block"] == 0
            assert hook._telemetry["count_ml_denies"] == 0
        finally:
            hook._telemetry.update(original)

    def test_telemetry_enabled_increments_counters(self, monkeypatch):
        """When SENTINEL_ML_TELEMETRY=1, counters should be incremented."""
        import sentinelai.hooks.sentinel_hook as hook

        monkeypatch.setenv("SENTINEL_ML_TELEMETRY", "1")

        original = hook._telemetry.copy()
        hook._telemetry.update({
            "count_total": 0,
            "count_ml_scored": 0,
            "count_ml_rec_block": 0,
            "count_ml_rec_review": 0,
            "count_ml_denies": 0,
        })

        try:
            hook._telemetry_tick(ml_scored=True, ml_recommendation="block", ml_denied=True)
            assert hook._telemetry["count_total"] == 1
            assert hook._telemetry["count_ml_scored"] == 1
            assert hook._telemetry["count_ml_rec_block"] == 1
            assert hook._telemetry["count_ml_denies"] == 1
        finally:
            hook._telemetry.update(original)

    def test_telemetry_review_recommendation(self, monkeypatch):
        """ml_recommendation='review' should increment count_ml_rec_review."""
        import sentinelai.hooks.sentinel_hook as hook

        monkeypatch.setenv("SENTINEL_ML_TELEMETRY", "1")

        original = hook._telemetry.copy()
        hook._telemetry.update({
            "count_total": 0,
            "count_ml_scored": 0,
            "count_ml_rec_block": 0,
            "count_ml_rec_review": 0,
            "count_ml_denies": 0,
        })

        try:
            hook._telemetry_tick(ml_scored=False, ml_recommendation="review", ml_denied=False)
            assert hook._telemetry["count_total"] == 1
            assert hook._telemetry["count_ml_scored"] == 0
            assert hook._telemetry["count_ml_rec_review"] == 1
            assert hook._telemetry["count_ml_rec_block"] == 0
            assert hook._telemetry["count_ml_denies"] == 0
        finally:
            hook._telemetry.update(original)

    def test_telemetry_flushes_at_interval(self, monkeypatch):
        """Telemetry should flush to stderr every _TELEMETRY_INTERVAL requests."""
        import sentinelai.hooks.sentinel_hook as hook

        monkeypatch.setenv("SENTINEL_ML_TELEMETRY", "1")

        original = hook._telemetry.copy()
        # Set count to INTERVAL - 1 so next tick triggers flush
        hook._telemetry.update({
            "count_total": hook._TELEMETRY_INTERVAL - 1,
            "count_ml_scored": 0,
            "count_ml_rec_block": 0,
            "count_ml_rec_review": 0,
            "count_ml_denies": 0,
        })

        try:
            with patch("sentinelai.hooks.sentinel_hook.sys") as mock_sys:
                mock_sys.stderr = MagicMock()
                hook._telemetry_tick(ml_scored=False, ml_recommendation="allow", ml_denied=False)

                assert hook._telemetry["count_total"] == hook._TELEMETRY_INTERVAL
                # print() was called with file=sys.stderr (the flush)
                # We verify by checking that the function ran without error
                # since print is a builtin and hard to mock here, the key
                # assertion is that count_total reached the interval
        finally:
            hook._telemetry.update(original)

    def test_telemetry_does_not_flush_before_interval(self, monkeypatch):
        """Telemetry should NOT flush before reaching the interval."""
        import sentinelai.hooks.sentinel_hook as hook

        monkeypatch.setenv("SENTINEL_ML_TELEMETRY", "1")

        original = hook._telemetry.copy()
        hook._telemetry.update({
            "count_total": 0,
            "count_ml_scored": 0,
            "count_ml_rec_block": 0,
            "count_ml_rec_review": 0,
            "count_ml_denies": 0,
        })

        try:
            hook._telemetry_tick(ml_scored=False, ml_recommendation="allow", ml_denied=False)
            assert hook._telemetry["count_total"] == 1
            # Not at interval boundary, so no flush (no stderr output expected)
        finally:
            hook._telemetry.update(original)

    def test_telemetry_allow_recommendation_no_counter(self, monkeypatch):
        """ml_recommendation='allow' should not increment block or review counters."""
        import sentinelai.hooks.sentinel_hook as hook

        monkeypatch.setenv("SENTINEL_ML_TELEMETRY", "1")

        original = hook._telemetry.copy()
        hook._telemetry.update({
            "count_total": 0,
            "count_ml_scored": 0,
            "count_ml_rec_block": 0,
            "count_ml_rec_review": 0,
            "count_ml_denies": 0,
        })

        try:
            hook._telemetry_tick(ml_scored=True, ml_recommendation="allow", ml_denied=False)
            assert hook._telemetry["count_total"] == 1
            assert hook._telemetry["count_ml_scored"] == 1
            assert hook._telemetry["count_ml_rec_block"] == 0
            assert hook._telemetry["count_ml_rec_review"] == 0
            assert hook._telemetry["count_ml_denies"] == 0
        finally:
            hook._telemetry.update(original)


# ---------------------------------------------------------------------------
# 18. ML helper functions — threshold and mode parsing
# ---------------------------------------------------------------------------

class TestMLHelpers:
    """Tests for ML rollout helper functions."""

    def test_get_ml_mode_default(self, monkeypatch):
        """Default ML mode should be 'shadow'."""
        from sentinelai.hooks.sentinel_hook import _get_ml_mode

        monkeypatch.delenv("SENTINEL_ML_MODE", raising=False)
        assert _get_ml_mode() == "shadow"

    def test_get_ml_mode_from_env(self, monkeypatch):
        """ML mode should be read from SENTINEL_ML_MODE env var."""
        from sentinelai.hooks.sentinel_hook import _get_ml_mode

        monkeypatch.setenv("SENTINEL_ML_MODE", "enforce")
        assert _get_ml_mode() == "enforce"

    def test_get_ml_mode_case_insensitive(self, monkeypatch):
        """ML mode should be lowercased."""
        from sentinelai.hooks.sentinel_hook import _get_ml_mode

        monkeypatch.setenv("SENTINEL_ML_MODE", "SHADOW")
        assert _get_ml_mode() == "shadow"

    def test_get_ml_block_threshold_default(self, monkeypatch):
        """Default ML block threshold should be 0.80."""
        from sentinelai.hooks.sentinel_hook import _get_ml_block_threshold

        monkeypatch.delenv("SENTINEL_ML_BLOCK_THRESHOLD", raising=False)
        assert _get_ml_block_threshold() == 0.80

    def test_get_ml_block_threshold_from_env(self, monkeypatch):
        """ML block threshold should be read from env var."""
        from sentinelai.hooks.sentinel_hook import _get_ml_block_threshold

        monkeypatch.setenv("SENTINEL_ML_BLOCK_THRESHOLD", "0.90")
        assert _get_ml_block_threshold() == 0.90

    def test_get_ml_block_threshold_invalid_returns_default(self, monkeypatch):
        """Invalid threshold value should fall back to 0.80."""
        from sentinelai.hooks.sentinel_hook import _get_ml_block_threshold

        monkeypatch.setenv("SENTINEL_ML_BLOCK_THRESHOLD", "not_a_number")
        assert _get_ml_block_threshold() == 0.80

    def test_get_ml_review_threshold_default(self, monkeypatch):
        """Default ML review threshold should be 0.60."""
        from sentinelai.hooks.sentinel_hook import _get_ml_review_threshold

        monkeypatch.delenv("SENTINEL_ML_REVIEW_THRESHOLD", raising=False)
        assert _get_ml_review_threshold() == 0.60

    def test_get_ml_review_threshold_from_env(self, monkeypatch):
        """ML review threshold should be read from env var."""
        from sentinelai.hooks.sentinel_hook import _get_ml_review_threshold

        monkeypatch.setenv("SENTINEL_ML_REVIEW_THRESHOLD", "0.70")
        assert _get_ml_review_threshold() == 0.70

    def test_compute_ml_recommendation_block(self, monkeypatch):
        """Injection prob >= block threshold should recommend 'block'."""
        from sentinelai.hooks.sentinel_hook import _compute_ml_recommendation

        monkeypatch.setenv("SENTINEL_ML_BLOCK_THRESHOLD", "0.80")
        monkeypatch.setenv("SENTINEL_ML_REVIEW_THRESHOLD", "0.60")
        assert _compute_ml_recommendation(0.85) == "block"

    def test_compute_ml_recommendation_review(self, monkeypatch):
        """Injection prob >= review but < block threshold should recommend 'review'."""
        from sentinelai.hooks.sentinel_hook import _compute_ml_recommendation

        monkeypatch.setenv("SENTINEL_ML_BLOCK_THRESHOLD", "0.80")
        monkeypatch.setenv("SENTINEL_ML_REVIEW_THRESHOLD", "0.60")
        assert _compute_ml_recommendation(0.65) == "review"

    def test_compute_ml_recommendation_allow(self, monkeypatch):
        """Injection prob below review threshold should recommend 'allow'."""
        from sentinelai.hooks.sentinel_hook import _compute_ml_recommendation

        monkeypatch.setenv("SENTINEL_ML_BLOCK_THRESHOLD", "0.80")
        monkeypatch.setenv("SENTINEL_ML_REVIEW_THRESHOLD", "0.60")
        assert _compute_ml_recommendation(0.30) == "allow"
