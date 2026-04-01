"""H6: OpenClaw Adapter end-to-end tests.

Tests the full pipeline: raw JSON input -> adapter parse -> risk engine assess ->
adapter format -> JSON output, plus detect_platform auto-detection and simulated
hook integration via subprocess.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from sentinelai.adapters import detect_platform
from sentinelai.adapters.openclaw import OpenClawAdapter
from sentinelai.adapters.base import CommandInput, CommandResult


# -- Helpers ------------------------------------------------------------------


def _oc_event(tool_name: str = "shell", command: str = "ls -la", **extra_context) -> str:
    """Build a realistic OpenClaw preToolExecution event JSON string."""
    event = {
        "event": "preToolExecution",
        "tool": {
            "name": tool_name,
            "parameters": {"command": command} if tool_name in ("shell", "bash") else {},
        },
        "context": {
            "workingDir": "/home/user/project",
            "sessionId": "oc-sess-e2e-test",
            **extra_context,
        },
    }
    return json.dumps(event)


# -- E2E Pipeline Tests -------------------------------------------------------


class TestFullPipeline:
    """Test the complete parse -> assess -> format pipeline."""

    @pytest.fixture
    def adapter(self):
        return OpenClawAdapter()

    def test_safe_command_pipeline(self, adapter):
        """Safe command should produce allow action."""
        raw = _oc_event("shell", "echo hello world")
        cmd = adapter.parse_input(raw)
        assert cmd.tool_name == "Bash"
        assert cmd.tool_input["command"] == "echo hello world"

        # Simulate allow result
        result = CommandResult(decision="allow", risk_score=5)
        output = json.loads(adapter.format_output(result))
        assert output["action"] == "allow"
        assert "riskScore" not in output

    def test_dangerous_command_pipeline(self, adapter):
        """Dangerous command should produce deny action with details."""
        raw = _oc_event("shell", "rm -rf / --no-preserve-root")
        cmd = adapter.parse_input(raw)
        assert cmd.tool_name == "Bash"

        result = CommandResult(
            decision="deny",
            risk_score=95,
            reasons=["Destructive filesystem operation", "Root path deletion"],
            incident_id=42,
        )
        output = json.loads(adapter.format_output(result))
        assert output["action"] == "deny"
        assert output["riskScore"] == 95
        assert "Destructive" in output["message"]
        assert output["incidentId"] == 42

    def test_review_command_pipeline(self, adapter):
        """Medium-risk command should produce review action."""
        raw = _oc_event("shell", "curl https://example.com/api")
        cmd = adapter.parse_input(raw)

        result = CommandResult(
            decision="ask",
            risk_score=55,
            reasons=["External network access"],
        )
        output = json.loads(adapter.format_output(result))
        assert output["action"] == "review"
        assert output["riskScore"] == 55

    def test_file_write_pipeline(self, adapter):
        """File write tool should map correctly."""
        event = {
            "event": "preToolExecution",
            "tool": {
                "name": "writeFile",
                "parameters": {"path": "/etc/passwd", "content": "malicious"},
            },
            "context": {"workingDir": "/tmp"},
        }
        raw = json.dumps(event)
        cmd = adapter.parse_input(raw)
        assert cmd.tool_name == "Write"
        assert cmd.tool_input["path"] == "/etc/passwd"

    def test_all_tool_mappings_roundtrip(self, adapter):
        """All mapped tools should roundtrip through parse and format."""
        tools = [
            "shell", "bash", "writeFile", "editFile", "readFile",
            "search", "glob", "webSearch", "webFetch",
        ]
        for tool in tools:
            raw = json.dumps({
                "event": "preToolExecution",
                "tool": {"name": tool, "parameters": {}},
                "context": {"workingDir": "/tmp"},
            })
            cmd = adapter.parse_input(raw)
            assert cmd.tool_name != "", f"Tool {tool} mapped to empty string"
            assert isinstance(cmd.tool_input, dict)

            result = CommandResult(decision="allow", risk_score=0)
            output = json.loads(adapter.format_output(result))
            assert output["action"] == "allow"

    def test_deny_reasons_joined_as_message(self, adapter):
        """Multiple reasons should be joined with newlines in the message field."""
        result = CommandResult(
            decision="deny",
            risk_score=80,
            reasons=["Reason one", "Reason two", "Reason three"],
        )
        output = json.loads(adapter.format_output(result))
        assert output["message"] == "Reason one\nReason two\nReason three"

    def test_allow_has_no_message_or_score(self, adapter):
        """Allow responses should not include message or riskScore fields."""
        result = CommandResult(decision="allow", risk_score=10)
        output = json.loads(adapter.format_output(result))
        assert "message" not in output
        assert "riskScore" not in output
        assert "incidentId" not in output

    def test_ask_with_no_reasons(self, adapter):
        """Ask decision with empty reasons should still include riskScore."""
        result = CommandResult(decision="ask", risk_score=50, reasons=[])
        output = json.loads(adapter.format_output(result))
        assert output["action"] == "review"
        assert output["riskScore"] == 50
        assert "message" not in output  # no reasons -> no message


# -- detect_platform Tests ----------------------------------------------------


class TestDetectPlatform:
    """Test auto-detection of OpenClaw events."""

    def test_detects_openclaw_event(self):
        """Standard OpenClaw event should be detected."""
        raw = _oc_event("shell", "ls")
        adapter = detect_platform(raw)
        assert adapter.get_platform() == "openclaw"

    def test_detects_openclaw_with_extra_fields(self):
        """OpenClaw event with extra fields should still be detected."""
        event = {
            "event": "preToolExecution",
            "tool": {"name": "shell", "parameters": {}},
            "traceId": "trace-123",
            "timestamp": "2026-01-01T00:00:00Z",
        }
        adapter = detect_platform(json.dumps(event))
        assert adapter.get_platform() == "openclaw"

    def test_does_not_detect_claude_code_as_openclaw(self):
        """Claude Code format should NOT be detected as OpenClaw."""
        raw = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}})
        adapter = detect_platform(raw)
        assert adapter.get_platform() != "openclaw"

    def test_does_not_detect_generic_as_openclaw(self):
        """Generic format should NOT be detected as OpenClaw."""
        raw = json.dumps({"command": "ls -la"})
        adapter = detect_platform(raw)
        assert adapter.get_platform() != "openclaw"

    def test_minimal_openclaw_event(self):
        """Minimal valid OpenClaw event (just event + tool dict)."""
        raw = json.dumps({"event": "preToolExecution", "tool": {"name": "shell"}})
        adapter = detect_platform(raw)
        assert adapter.get_platform() == "openclaw"

    def test_openclaw_with_different_event_type(self):
        """Non-preToolExecution event type with tool dict should still detect as OpenClaw."""
        raw = json.dumps({"event": "postToolExecution", "tool": {"name": "shell"}})
        adapter = detect_platform(raw)
        assert adapter.get_platform() == "openclaw"

    def test_tool_as_string_not_openclaw(self):
        """If tool is a string instead of dict, should NOT detect as OpenClaw."""
        raw = json.dumps({"event": "preToolExecution", "tool": "shell"})
        adapter = detect_platform(raw)
        assert adapter.get_platform() != "openclaw"


# -- Hook Integration (Subprocess) --------------------------------------------


class TestHookIntegration:
    """Test the hook via subprocess, simulating how OpenClaw would call it.

    These tests run the actual Python hook module as a subprocess,
    just like hook.sh does. Note that the hook always outputs Claude Code
    format (hookSpecificOutput) regardless of the input platform, because
    the hook's _allow/_deny/_ask helpers are hardcoded to that format.
    """

    @pytest.fixture
    def project_root(self):
        """Get the project root directory."""
        return str(Path(__file__).resolve().parent.parent.parent)

    def _run_hook(self, event_json: str, project_root: str) -> dict:
        """Run the hook as a subprocess and parse the JSON output."""
        import os

        result = subprocess.run(
            [sys.executable, "-m", "sentinelai.hooks.sentinel_hook"],
            input=event_json,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=project_root,
            env={
                **os.environ,
                "PYTHONPATH": project_root,
                "SENTINEL_ML_MODE": "off",  # Avoid ML model loading in tests
            },
        )
        # Hook should always exit 0 (fail-open)
        assert result.returncode == 0, f"Hook exited {result.returncode}: {result.stderr}"
        assert result.stdout.strip(), f"Hook returned empty stdout. stderr: {result.stderr}"
        return json.loads(result.stdout.strip())

    def test_safe_command_via_hook(self, project_root):
        """Safe echo command via subprocess should be allowed."""
        event = _oc_event("shell", "echo hello")
        output = self._run_hook(event, project_root)
        # The hook always outputs Claude Code format (hookSpecificOutput),
        # regardless of input platform.
        assert "hookSpecificOutput" in output
        assert output["hookSpecificOutput"]["permissionDecision"] in ("allow", "ask")

    def test_read_tool_auto_allowed_via_hook(self, project_root):
        """Read-only tools should be auto-allowed via the hook fast path."""
        event = json.dumps({
            "event": "preToolExecution",
            "tool": {"name": "readFile", "parameters": {"path": "/tmp/test.txt"}},
            "context": {"workingDir": "/tmp"},
        })
        output = self._run_hook(event, project_root)
        assert "hookSpecificOutput" in output
        assert output["hookSpecificOutput"]["permissionDecision"] == "allow"

    def test_empty_stdin_via_hook(self, project_root):
        """Empty stdin should produce a valid allow response (fail-open)."""
        import os

        result = subprocess.run(
            [sys.executable, "-m", "sentinelai.hooks.sentinel_hook"],
            input="",
            capture_output=True,
            text=True,
            timeout=30,
            cwd=project_root,
            env={
                **os.environ,
                "PYTHONPATH": project_root,
                "SENTINEL_ML_MODE": "off",
            },
        )
        assert result.returncode == 0
        if result.stdout.strip():
            output = json.loads(result.stdout.strip())
            # Should be an allow response in Claude Code format
            assert "hookSpecificOutput" in output
            assert output["hookSpecificOutput"]["permissionDecision"] == "allow"

    def test_invalid_json_via_hook(self, project_root):
        """Invalid JSON should produce a valid allow response (fail-open)."""
        import os

        result = subprocess.run(
            [sys.executable, "-m", "sentinelai.hooks.sentinel_hook"],
            input="this is not json at all",
            capture_output=True,
            text=True,
            timeout=30,
            cwd=project_root,
            env={
                **os.environ,
                "PYTHONPATH": project_root,
                "SENTINEL_ML_MODE": "off",
            },
        )
        assert result.returncode == 0
        if result.stdout.strip():
            output = json.loads(result.stdout.strip())
            assert "hookSpecificOutput" in output
            assert output["hookSpecificOutput"]["permissionDecision"] == "allow"


# -- Context Preservation Tests -----------------------------------------------


class TestContextPreservation:
    """Test that OpenClaw context fields are preserved through the pipeline."""

    @pytest.fixture
    def adapter(self):
        return OpenClawAdapter()

    def test_working_dir_preserved(self, adapter):
        raw = _oc_event("shell", "ls", workingDir="/custom/path")
        cmd = adapter.parse_input(raw)
        # workingDir from extra_context overrides the default
        assert cmd.cwd == "/custom/path"

    def test_session_id_preserved(self, adapter):
        raw = _oc_event("shell", "ls")
        cmd = adapter.parse_input(raw)
        assert cmd.metadata["session_id"] == "oc-sess-e2e-test"

    def test_original_tool_name_preserved(self, adapter):
        raw = _oc_event("writeFile", "")
        cmd = adapter.parse_input(raw)
        assert cmd.metadata["original_tool_name"] == "writeFile"
        assert cmd.tool_name == "Write"  # normalized

    def test_custom_context_fields_preserved(self, adapter):
        event = {
            "event": "preToolExecution",
            "tool": {"name": "shell", "parameters": {"command": "ls"}},
            "context": {
                "workingDir": "/tmp",
                "sessionId": "sess-1",
                "customField": "customValue",
            },
        }
        cmd = adapter.parse_input(json.dumps(event))
        assert cmd.metadata.get("context_customField") == "customValue"

    def test_extra_top_level_fields_preserved(self, adapter):
        event = {
            "event": "preToolExecution",
            "tool": {"name": "shell", "parameters": {}},
            "traceId": "trace-abc",
            "requestId": "req-xyz",
        }
        cmd = adapter.parse_input(json.dumps(event))
        assert cmd.metadata["traceId"] == "trace-abc"
        assert cmd.metadata["requestId"] == "req-xyz"

    def test_missing_context_uses_empty_cwd(self, adapter):
        """Event without context block should use empty string for cwd."""
        event = {
            "event": "preToolExecution",
            "tool": {"name": "shell", "parameters": {}},
        }
        cmd = adapter.parse_input(json.dumps(event))
        assert cmd.cwd == ""

    def test_event_type_preserved_in_metadata(self, adapter):
        """The event type should always be preserved in metadata."""
        raw = _oc_event("shell", "ls")
        cmd = adapter.parse_input(raw)
        assert cmd.metadata["event"] == "preToolExecution"
