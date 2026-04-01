"""I3: GenericAdapter unit tests -- fallback behaviour + detect_platform."""

from __future__ import annotations

import json

import pytest

from sentinelai.adapters.generic import GenericAdapter
from sentinelai.adapters.base import CommandInput, CommandResult
from sentinelai.adapters import detect_platform


@pytest.fixture
def adapter():
    return GenericAdapter()


class TestParseInput:
    """Test GenericAdapter.parse_input()."""

    def test_basic_command(self, adapter):
        raw = json.dumps({"command": "ls -la"})
        cmd = adapter.parse_input(raw)
        assert cmd.tool_name == "Bash"  # default tool
        assert cmd.tool_input == {"command": "ls -la"}

    def test_custom_tool_name(self, adapter):
        raw = json.dumps({"command": "cat foo.py", "tool": "Read"})
        cmd = adapter.parse_input(raw)
        assert cmd.tool_name == "Read"

    def test_extracts_cwd(self, adapter):
        raw = json.dumps({"command": "pwd", "cwd": "/tmp"})
        cmd = adapter.parse_input(raw)
        assert cmd.cwd == "/tmp"

    def test_defaults_tool_to_bash(self, adapter):
        raw = json.dumps({"command": "echo hi"})
        cmd = adapter.parse_input(raw)
        assert cmd.tool_name == "Bash"

    def test_defaults_cwd_to_empty(self, adapter):
        raw = json.dumps({"command": "echo hi"})
        cmd = adapter.parse_input(raw)
        assert cmd.cwd == ""

    def test_empty_command(self, adapter):
        raw = json.dumps({"command": ""})
        cmd = adapter.parse_input(raw)
        assert cmd.tool_input == {}  # empty command -> empty dict

    def test_missing_command_key(self, adapter):
        raw = json.dumps({"tool": "Bash"})
        cmd = adapter.parse_input(raw)
        assert cmd.tool_input == {}  # no command -> empty dict

    def test_extra_fields_in_metadata(self, adapter):
        raw = json.dumps({"command": "ls", "source": "cli", "version": "1.0"})
        cmd = adapter.parse_input(raw)
        assert cmd.metadata["source"] == "cli"
        assert cmd.metadata["version"] == "1.0"

    def test_empty_input_raises(self, adapter):
        with pytest.raises(ValueError, match="Empty input"):
            adapter.parse_input("")

    def test_invalid_json_raises(self, adapter):
        with pytest.raises(ValueError, match="Invalid JSON"):
            adapter.parse_input("{broken")


class TestFormatOutput:
    """Test GenericAdapter.format_output()."""

    def test_allow_output(self, adapter):
        result = CommandResult(decision="allow", risk_score=5)
        output = json.loads(adapter.format_output(result))
        assert output["allowed"] is True
        assert output["risk_score"] == 5
        assert output["reasons"] == []
        assert output["incident_id"] is None

    def test_deny_output(self, adapter):
        result = CommandResult(
            decision="deny",
            risk_score=90,
            reasons=["Blocked"],
            incident_id=7,
        )
        output = json.loads(adapter.format_output(result))
        assert output["allowed"] is False
        assert output["risk_score"] == 90
        assert output["reasons"] == ["Blocked"]
        assert output["incident_id"] == 7

    def test_ask_output_has_review_flag(self, adapter):
        result = CommandResult(
            decision="ask",
            risk_score=50,
            reasons=["Needs review"],
        )
        output = json.loads(adapter.format_output(result))
        assert output["allowed"] is False
        assert output["review"] is True

    def test_allow_has_no_review_flag(self, adapter):
        result = CommandResult(decision="allow")
        output = json.loads(adapter.format_output(result))
        assert "review" not in output

    def test_deny_has_no_review_flag(self, adapter):
        result = CommandResult(decision="deny", risk_score=95)
        output = json.loads(adapter.format_output(result))
        assert "review" not in output


class TestPlatform:
    def test_platform_name(self, adapter):
        assert adapter.get_platform() == "generic"


# ── detect_platform fallback tests ────────────────────────────


class TestDetectPlatform:
    """Test auto-detection and fallback to GenericAdapter."""

    def test_detect_claude_code(self):
        raw = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}})
        adapter = detect_platform(raw)
        assert adapter.get_platform() == "claude_code"

    def test_detect_openclaw(self):
        raw = json.dumps({
            "event": "preToolExecution",
            "tool": {"name": "shell", "parameters": {}},
        })
        adapter = detect_platform(raw)
        assert adapter.get_platform() == "openclaw"

    def test_detect_generic_with_command(self):
        raw = json.dumps({"command": "ls -la"})
        adapter = detect_platform(raw)
        assert adapter.get_platform() == "generic"

    def test_fallback_unknown_format(self):
        raw = json.dumps({"unknown": "data"})
        adapter = detect_platform(raw)
        assert adapter.get_platform() == "generic"

    def test_fallback_invalid_json(self):
        adapter = detect_platform("not json at all")
        assert adapter.get_platform() == "generic"

    def test_fallback_empty_string(self):
        adapter = detect_platform("")
        assert adapter.get_platform() == "generic"

    def test_fallback_non_dict_json(self):
        adapter = detect_platform("[1, 2, 3]")
        assert adapter.get_platform() == "generic"

    def test_openclaw_without_tool_dict_falls_through(self):
        """event + tool as string (not dict) should NOT match OpenClaw."""
        raw = json.dumps({"event": "preToolExecution", "tool": "shell"})
        adapter = detect_platform(raw)
        # tool is a string, not dict -> not OpenClaw
        assert adapter.get_platform() == "generic"

    def test_claude_code_minimal(self):
        raw = json.dumps({"tool_name": "X", "tool_input": {}})
        adapter = detect_platform(raw)
        assert adapter.get_platform() == "claude_code"
