"""I2: OpenClawAdapter unit tests -- event mapping and tool name normalization."""

from __future__ import annotations

import json

import pytest

from sentinelai.adapters.openclaw import OpenClawAdapter
from sentinelai.adapters.base import CommandInput, CommandResult


@pytest.fixture
def adapter():
    return OpenClawAdapter()


class TestParseInput:
    """Test OpenClawAdapter.parse_input()."""

    def test_basic_shell_command(self, adapter):
        raw = json.dumps({
            "event": "preToolExecution",
            "tool": {"name": "shell", "parameters": {"command": "ls -la"}},
        })
        cmd = adapter.parse_input(raw)
        assert cmd.tool_name == "Bash"  # shell -> Bash mapping
        assert cmd.tool_input == {"command": "ls -la"}

    def test_extracts_working_dir(self, adapter):
        raw = json.dumps({
            "event": "preToolExecution",
            "tool": {"name": "shell", "parameters": {}},
            "context": {"workingDir": "/home/user/project"},
        })
        cmd = adapter.parse_input(raw)
        assert cmd.cwd == "/home/user/project"

    def test_extracts_session_id(self, adapter):
        raw = json.dumps({
            "event": "preToolExecution",
            "tool": {"name": "shell", "parameters": {}},
            "context": {"sessionId": "oc-sess-abc123"},
        })
        cmd = adapter.parse_input(raw)
        assert cmd.metadata["session_id"] == "oc-sess-abc123"

    def test_preserves_event_type(self, adapter):
        raw = json.dumps({
            "event": "preToolExecution",
            "tool": {"name": "shell", "parameters": {}},
        })
        cmd = adapter.parse_input(raw)
        assert cmd.metadata["event"] == "preToolExecution"

    def test_preserves_original_tool_name(self, adapter):
        raw = json.dumps({
            "event": "preToolExecution",
            "tool": {"name": "writeFile", "parameters": {}},
        })
        cmd = adapter.parse_input(raw)
        assert cmd.metadata["original_tool_name"] == "writeFile"

    def test_empty_input_raises(self, adapter):
        with pytest.raises(ValueError, match="Empty input"):
            adapter.parse_input("")

    def test_invalid_json_raises(self, adapter):
        with pytest.raises(ValueError, match="Invalid JSON"):
            adapter.parse_input("not json")

    def test_missing_tool_block_raises(self, adapter):
        raw = json.dumps({"event": "preToolExecution"})
        with pytest.raises(ValueError, match="missing required 'tool'"):
            adapter.parse_input(raw)

    def test_extra_top_level_fields_in_metadata(self, adapter):
        raw = json.dumps({
            "event": "preToolExecution",
            "tool": {"name": "shell", "parameters": {}},
            "traceId": "trace-123",
        })
        cmd = adapter.parse_input(raw)
        assert cmd.metadata["traceId"] == "trace-123"


class TestToolNameMapping:
    """Verify all OpenClaw tool names map to ShieldPilot canonical names."""

    MAPPINGS = [
        ("shell", "Bash"),
        ("bash", "Bash"),
        ("writeFile", "Write"),
        ("write_file", "Write"),
        ("editFile", "Edit"),
        ("edit_file", "Edit"),
        ("readFile", "Read"),
        ("read_file", "Read"),
        ("search", "Grep"),
        ("glob", "Glob"),
        ("webSearch", "WebSearch"),
        ("webFetch", "WebFetch"),
    ]

    @pytest.mark.parametrize("oc_name,expected", MAPPINGS)
    def test_tool_mapping(self, adapter, oc_name, expected):
        raw = json.dumps({
            "event": "preToolExecution",
            "tool": {"name": oc_name, "parameters": {}},
        })
        cmd = adapter.parse_input(raw)
        assert cmd.tool_name == expected

    def test_unknown_tool_passthrough(self, adapter):
        raw = json.dumps({
            "event": "preToolExecution",
            "tool": {"name": "customTool", "parameters": {"arg": "val"}},
        })
        cmd = adapter.parse_input(raw)
        assert cmd.tool_name == "customTool"  # passthrough


class TestFormatOutput:
    """Test OpenClawAdapter.format_output()."""

    def test_allow_output(self, adapter):
        result = CommandResult(decision="allow", risk_score=0)
        output = json.loads(adapter.format_output(result))
        assert output["action"] == "allow"
        assert "message" not in output

    def test_deny_output(self, adapter):
        result = CommandResult(
            decision="deny",
            risk_score=85,
            reasons=["Destructive command"],
        )
        output = json.loads(adapter.format_output(result))
        assert output["action"] == "deny"
        assert output["riskScore"] == 85
        assert "Destructive" in output["message"]

    def test_ask_maps_to_review(self, adapter):
        """OpenClaw uses 'review' instead of 'ask'."""
        result = CommandResult(
            decision="ask",
            risk_score=55,
            reasons=["Elevated risk"],
        )
        output = json.loads(adapter.format_output(result))
        assert output["action"] == "review"
        assert output["riskScore"] == 55

    def test_deny_includes_incident_id(self, adapter):
        result = CommandResult(
            decision="deny",
            risk_score=90,
            reasons=["Blocked"],
            incident_id=42,
        )
        output = json.loads(adapter.format_output(result))
        assert output["incidentId"] == 42

    def test_allow_no_incident_id(self, adapter):
        result = CommandResult(decision="allow", risk_score=0)
        output = json.loads(adapter.format_output(result))
        assert "incidentId" not in output


class TestPlatform:
    def test_platform_name(self, adapter):
        assert adapter.get_platform() == "openclaw"
