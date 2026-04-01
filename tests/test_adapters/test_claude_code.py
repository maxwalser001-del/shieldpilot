"""I1: ClaudeCodeAdapter unit tests -- parse/format roundtrip."""

from __future__ import annotations

import json

import pytest

from sentinelai.adapters.claude_code import ClaudeCodeAdapter
from sentinelai.adapters.base import CommandInput, CommandResult


@pytest.fixture
def adapter():
    return ClaudeCodeAdapter()


class TestParseInput:
    """Test ClaudeCodeAdapter.parse_input()."""

    def test_basic_bash_command(self, adapter):
        raw = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
        })
        cmd = adapter.parse_input(raw)
        assert cmd.tool_name == "Bash"
        assert cmd.tool_input == {"command": "ls -la"}

    def test_extracts_cwd(self, adapter):
        raw = json.dumps({
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/test.py", "content": "print('hi')"},
            "cwd": "/home/user/project",
        })
        cmd = adapter.parse_input(raw)
        assert cmd.cwd == "/home/user/project"
        assert cmd.tool_name == "Write"

    def test_preserves_metadata(self, adapter):
        raw = json.dumps({
            "tool_name": "Edit",
            "tool_input": {"file_path": "/tmp/a.py"},
            "tool_use_id": "toolu_abc123",
            "session_id": "sess_xyz789",
        })
        cmd = adapter.parse_input(raw)
        assert cmd.metadata["tool_use_id"] == "toolu_abc123"
        assert cmd.metadata["session_id"] == "sess_xyz789"

    def test_unknown_keys_in_metadata(self, adapter):
        raw = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": "echo hi"},
            "custom_field": "value123",
        })
        cmd = adapter.parse_input(raw)
        assert cmd.metadata["custom_field"] == "value123"

    def test_empty_input_raises(self, adapter):
        with pytest.raises(ValueError, match="Empty input"):
            adapter.parse_input("")

    def test_invalid_json_raises(self, adapter):
        with pytest.raises(ValueError, match="Invalid JSON"):
            adapter.parse_input("{not valid json")

    def test_missing_tool_name_defaults_empty(self, adapter):
        raw = json.dumps({"tool_input": {"command": "ls"}})
        cmd = adapter.parse_input(raw)
        assert cmd.tool_name == ""

    def test_non_dict_tool_input_defaults_empty(self, adapter):
        raw = json.dumps({"tool_name": "Bash", "tool_input": "not a dict"})
        cmd = adapter.parse_input(raw)
        assert cmd.tool_input == {}


class TestFormatOutput:
    """Test ClaudeCodeAdapter.format_output()."""

    def test_allow_output(self, adapter):
        result = CommandResult(decision="allow", risk_score=0)
        output = json.loads(adapter.format_output(result))
        hook = output["hookSpecificOutput"]
        assert hook["hookEventName"] == "PreToolUse"
        assert hook["permissionDecision"] == "allow"

    def test_deny_output_with_reasons(self, adapter):
        result = CommandResult(
            decision="deny",
            risk_score=95,
            reasons=["Destructive command: rm -rf /"],
        )
        output = json.loads(adapter.format_output(result))
        hook = output["hookSpecificOutput"]
        assert hook["permissionDecision"] == "deny"
        assert "rm -rf" in hook["permissionDecisionReason"]

    def test_ask_output(self, adapter):
        result = CommandResult(
            decision="ask",
            risk_score=55,
            reasons=["Elevated risk detected"],
        )
        output = json.loads(adapter.format_output(result))
        hook = output["hookSpecificOutput"]
        assert hook["permissionDecision"] == "ask"
        assert "Elevated risk" in hook["permissionDecisionReason"]

    def test_allow_with_reasons(self, adapter):
        result = CommandResult(
            decision="allow",
            risk_score=10,
            reasons=["Audit mode: logged for review"],
        )
        output = json.loads(adapter.format_output(result))
        hook = output["hookSpecificOutput"]
        assert hook["permissionDecision"] == "allow"
        assert "Audit mode" in hook.get("permissionDecisionReason", "")

    def test_deny_no_reasons(self, adapter):
        result = CommandResult(decision="deny", risk_score=90)
        output = json.loads(adapter.format_output(result))
        hook = output["hookSpecificOutput"]
        assert hook["permissionDecision"] == "deny"
        assert "permissionDecisionReason" not in hook

    def test_multiple_reasons_joined(self, adapter):
        result = CommandResult(
            decision="deny",
            risk_score=85,
            reasons=["Reason A", "Reason B"],
        )
        output = json.loads(adapter.format_output(result))
        reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        assert "Reason A" in reason
        assert "Reason B" in reason


class TestRoundtrip:
    """Test parse -> format roundtrip produces valid protocol output."""

    def test_parse_then_format_allow(self, adapter):
        raw = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": "echo hello"},
            "cwd": "/tmp",
        })
        cmd = adapter.parse_input(raw)
        assert cmd.tool_name == "Bash"

        result = CommandResult(decision="allow", risk_score=0)
        output = json.loads(adapter.format_output(result))
        assert output["hookSpecificOutput"]["permissionDecision"] == "allow"

    def test_parse_then_format_deny(self, adapter):
        raw = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
        })
        cmd = adapter.parse_input(raw)
        assert cmd.tool_input["command"] == "rm -rf /"

        result = CommandResult(
            decision="deny",
            risk_score=100,
            reasons=["Destructive filesystem operation"],
        )
        output = json.loads(adapter.format_output(result))
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"


class TestPlatform:
    def test_platform_name(self, adapter):
        assert adapter.get_platform() == "claude_code"


class TestCommandResultValidation:
    def test_invalid_decision_raises(self):
        with pytest.raises(ValueError, match="must be one of"):
            CommandResult(decision="invalid")

    def test_all_valid_decisions(self):
        for d in ("allow", "deny", "ask"):
            r = CommandResult(decision=d)
            assert r.decision == d
