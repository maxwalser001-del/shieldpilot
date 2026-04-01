"""I2: Adapter Layer Tests — all 3 adapters + detect_platform.

Tests parse_input, format_output, get_platform for:
- ClaudeCodeAdapter
- OpenClawAdapter
- GenericAdapter
Plus detect_platform auto-detection and error handling.
"""

from __future__ import annotations

import json

import pytest

from sentinelai.adapters import detect_platform
from sentinelai.adapters.base import CommandInput, CommandResult
from sentinelai.adapters.claude_code import ClaudeCodeAdapter
from sentinelai.adapters.generic import GenericAdapter
from sentinelai.adapters.openclaw import OpenClawAdapter


# ── ClaudeCodeAdapter ──────────────────────────────────────────


class TestClaudeCodeAdapterParseInput:
    def test_valid_bash_input(self):
        adapter = ClaudeCodeAdapter()
        raw = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls -la"}, "cwd": "/tmp"})
        cmd = adapter.parse_input(raw)
        assert cmd.tool_name == "Bash"
        assert cmd.tool_input == {"command": "ls -la"}
        assert cmd.cwd == "/tmp"

    def test_preserves_metadata(self):
        adapter = ClaudeCodeAdapter()
        raw = json.dumps({
            "tool_name": "Read",
            "tool_input": {"file_path": "test.txt"},
            "tool_use_id": "toolu_abc",
            "session_id": "sess_xyz",
        })
        cmd = adapter.parse_input(raw)
        assert cmd.metadata["tool_use_id"] == "toolu_abc"
        assert cmd.metadata["session_id"] == "sess_xyz"

    def test_empty_input_raises(self):
        adapter = ClaudeCodeAdapter()
        with pytest.raises(ValueError, match="Empty"):
            adapter.parse_input("")

    def test_invalid_json_raises(self):
        adapter = ClaudeCodeAdapter()
        with pytest.raises(ValueError, match="Invalid JSON"):
            adapter.parse_input("{broken json")

    def test_missing_fields_returns_defaults(self):
        adapter = ClaudeCodeAdapter()
        raw = json.dumps({"other": "data"})
        cmd = adapter.parse_input(raw)
        assert cmd.tool_name == ""
        assert cmd.tool_input == {}


class TestClaudeCodeAdapterFormatOutput:
    def test_allow_decision(self):
        adapter = ClaudeCodeAdapter()
        result = CommandResult(decision="allow")
        output = json.loads(adapter.format_output(result))
        assert output["hookSpecificOutput"]["permissionDecision"] == "allow"

    def test_deny_with_reasons(self):
        adapter = ClaudeCodeAdapter()
        result = CommandResult(decision="deny", risk_score=90, reasons=["Destructive"])
        output = json.loads(adapter.format_output(result))
        assert output["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "Destructive" in output["hookSpecificOutput"]["permissionDecisionReason"]

    def test_ask_decision(self):
        adapter = ClaudeCodeAdapter()
        result = CommandResult(decision="ask", risk_score=55, reasons=["Elevated risk"])
        output = json.loads(adapter.format_output(result))
        assert output["hookSpecificOutput"]["permissionDecision"] == "ask"

    def test_platform_name(self):
        assert ClaudeCodeAdapter().get_platform() == "claude_code"


# ── OpenClawAdapter ────────────────────────────────────────────


class TestOpenClawAdapterParseInput:
    def test_valid_shell_input(self):
        adapter = OpenClawAdapter()
        raw = json.dumps({
            "event": "preToolExecution",
            "tool": {"name": "shell", "parameters": {"command": "pwd"}},
            "context": {"workingDir": "/home/user"},
        })
        cmd = adapter.parse_input(raw)
        assert cmd.tool_name == "Bash"  # shell -> Bash mapping
        assert cmd.tool_input == {"command": "pwd"}
        assert cmd.cwd == "/home/user"

    def test_tool_name_mapping(self):
        adapter = OpenClawAdapter()
        mappings = {
            "shell": "Bash",
            "writeFile": "Write",
            "editFile": "Edit",
            "readFile": "Read",
            "search": "Grep",
        }
        for oc_name, sp_name in mappings.items():
            raw = json.dumps({
                "event": "preToolExecution",
                "tool": {"name": oc_name, "parameters": {}},
            })
            cmd = adapter.parse_input(raw)
            assert cmd.tool_name == sp_name, f"{oc_name} should map to {sp_name}"

    def test_unknown_tool_passthrough(self):
        adapter = OpenClawAdapter()
        raw = json.dumps({
            "event": "preToolExecution",
            "tool": {"name": "customTool", "parameters": {"x": 1}},
        })
        cmd = adapter.parse_input(raw)
        assert cmd.tool_name == "customTool"

    def test_missing_tool_raises(self):
        adapter = OpenClawAdapter()
        raw = json.dumps({"event": "preToolExecution"})
        with pytest.raises(ValueError, match="missing required 'tool'"):
            adapter.parse_input(raw)

    def test_empty_input_raises(self):
        adapter = OpenClawAdapter()
        with pytest.raises(ValueError, match="Empty"):
            adapter.parse_input("")

    def test_session_id_in_metadata(self):
        adapter = OpenClawAdapter()
        raw = json.dumps({
            "event": "preToolExecution",
            "tool": {"name": "shell", "parameters": {}},
            "context": {"workingDir": "/tmp", "sessionId": "oc-123"},
        })
        cmd = adapter.parse_input(raw)
        assert cmd.metadata["session_id"] == "oc-123"


class TestOpenClawAdapterFormatOutput:
    def test_allow_output(self):
        adapter = OpenClawAdapter()
        result = CommandResult(decision="allow")
        output = json.loads(adapter.format_output(result))
        assert output == {"action": "allow"}

    def test_deny_output(self):
        adapter = OpenClawAdapter()
        result = CommandResult(decision="deny", risk_score=85, reasons=["Blocked"])
        output = json.loads(adapter.format_output(result))
        assert output["action"] == "deny"
        assert output["riskScore"] == 85
        assert "Blocked" in output["message"]

    def test_ask_maps_to_review(self):
        adapter = OpenClawAdapter()
        result = CommandResult(decision="ask", risk_score=55, reasons=["Elevated"])
        output = json.loads(adapter.format_output(result))
        assert output["action"] == "review"

    def test_incident_id_included(self):
        adapter = OpenClawAdapter()
        result = CommandResult(decision="deny", risk_score=90, reasons=["X"], incident_id=42)
        output = json.loads(adapter.format_output(result))
        assert output["incidentId"] == 42

    def test_platform_name(self):
        assert OpenClawAdapter().get_platform() == "openclaw"


# ── GenericAdapter ─────────────────────────────────────────────


class TestGenericAdapterParseInput:
    def test_minimal_input(self):
        adapter = GenericAdapter()
        raw = json.dumps({"command": "echo hello"})
        cmd = adapter.parse_input(raw)
        assert cmd.tool_name == "Bash"
        assert cmd.tool_input == {"command": "echo hello"}

    def test_custom_tool_name(self):
        adapter = GenericAdapter()
        raw = json.dumps({"command": "cat file.txt", "tool": "Read"})
        cmd = adapter.parse_input(raw)
        assert cmd.tool_name == "Read"

    def test_cwd_extraction(self):
        adapter = GenericAdapter()
        raw = json.dumps({"command": "ls", "cwd": "/var/log"})
        cmd = adapter.parse_input(raw)
        assert cmd.cwd == "/var/log"

    def test_empty_command(self):
        adapter = GenericAdapter()
        raw = json.dumps({"command": ""})
        cmd = adapter.parse_input(raw)
        assert cmd.tool_input == {}

    def test_empty_input_raises(self):
        adapter = GenericAdapter()
        with pytest.raises(ValueError, match="Empty"):
            adapter.parse_input("")

    def test_extra_fields_in_metadata(self):
        adapter = GenericAdapter()
        raw = json.dumps({"command": "ls", "custom_field": "value"})
        cmd = adapter.parse_input(raw)
        assert cmd.metadata["custom_field"] == "value"


class TestGenericAdapterFormatOutput:
    def test_allow_output(self):
        adapter = GenericAdapter()
        result = CommandResult(decision="allow", risk_score=5)
        output = json.loads(adapter.format_output(result))
        assert output["allowed"] is True
        assert output["risk_score"] == 5

    def test_deny_output(self):
        adapter = GenericAdapter()
        result = CommandResult(decision="deny", risk_score=85, reasons=["Bad"])
        output = json.loads(adapter.format_output(result))
        assert output["allowed"] is False
        assert "review" not in output

    def test_ask_includes_review_flag(self):
        adapter = GenericAdapter()
        result = CommandResult(decision="ask", risk_score=55)
        output = json.loads(adapter.format_output(result))
        assert output["allowed"] is False
        assert output["review"] is True

    def test_platform_name(self):
        assert GenericAdapter().get_platform() == "generic"


# ── detect_platform ────────────────────────────────────────────


class TestDetectPlatform:
    def test_claude_code_format(self):
        raw = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}})
        adapter = detect_platform(raw)
        assert adapter.get_platform() == "claude_code"

    def test_openclaw_format(self):
        raw = json.dumps({
            "event": "preToolExecution",
            "tool": {"name": "shell", "parameters": {}},
        })
        adapter = detect_platform(raw)
        assert adapter.get_platform() == "openclaw"

    def test_generic_format(self):
        raw = json.dumps({"command": "ls -la"})
        adapter = detect_platform(raw)
        assert adapter.get_platform() == "generic"

    def test_invalid_json_returns_generic(self):
        adapter = detect_platform("{bad json")
        assert adapter.get_platform() == "generic"

    def test_empty_string_returns_generic(self):
        adapter = detect_platform("")
        assert adapter.get_platform() == "generic"

    def test_non_dict_returns_generic(self):
        adapter = detect_platform(json.dumps([1, 2, 3]))
        assert adapter.get_platform() == "generic"

    def test_unknown_keys_returns_generic(self):
        adapter = detect_platform(json.dumps({"foo": "bar"}))
        assert adapter.get_platform() == "generic"


# ── CommandResult validation ───────────────────────────────────


class TestCommandResultValidation:
    def test_valid_decisions(self):
        for d in ("allow", "deny", "ask"):
            CommandResult(decision=d)

    def test_invalid_decision_raises(self):
        with pytest.raises(ValueError, match="must be one of"):
            CommandResult(decision="block")
