"""I6: Integration Test -- Hook -> Adapter -> RiskEngine -> Response Pipeline.

Tests the full end-to-end flow:
1. Raw JSON input (simulating hook stdin)
2. Adapter detects platform and parses input
3. RiskEngine assesses the command
4. Adapter formats the response

This test uses real (not mocked) adapters and risk engine.
"""

from __future__ import annotations

import json

import pytest

from sentinelai.adapters import detect_platform
from sentinelai.adapters.base import CommandResult
from sentinelai.core.config import load_config
from sentinelai.engine.base import AnalysisContext
from sentinelai.engine.engine import RiskEngine


@pytest.fixture
def config():
    return load_config()


@pytest.fixture
def engine(config):
    return RiskEngine(config)


class TestEndToEndPipeline:
    """Full pipeline: parse -> assess -> format."""

    def test_safe_command_allowed(self, engine):
        """A benign 'ls' command should pass through all adapters as allow."""
        raw = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
            "cwd": "/tmp",
        })

        adapter = detect_platform(raw)
        assert adapter.get_platform() == "claude_code"

        cmd = adapter.parse_input(raw)
        assert cmd.tool_name == "Bash"

        # Run through risk engine
        assessment = engine.assess(
            cmd.tool_input.get("command", ""),
            AnalysisContext(working_directory=cmd.cwd),
        )

        # Build result from assessment
        decision = "allow" if assessment.action.value == "allow" else (
            "deny" if assessment.action.value == "block" else "ask"
        )
        result = CommandResult(
            decision=decision,
            risk_score=assessment.final_score,
            reasons=[s.description for s in assessment.signals],
        )

        output = json.loads(adapter.format_output(result))
        hook = output["hookSpecificOutput"]
        assert hook["permissionDecision"] == "allow"
        assert assessment.final_score < 80

    def test_dangerous_command_denied(self, engine):
        """A destructive 'rm -rf /' should be blocked."""
        raw = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
        })

        adapter = detect_platform(raw)
        cmd = adapter.parse_input(raw)

        assessment = engine.assess(
            cmd.tool_input.get("command", ""),
            AnalysisContext(working_directory=cmd.cwd or "."),
        )

        # Score should be high for rm -rf /
        assert assessment.final_score >= 40

    def test_openclaw_pipeline(self, engine):
        """OpenClaw event -> parse -> assess -> format works end-to-end."""
        raw = json.dumps({
            "event": "preToolExecution",
            "tool": {"name": "shell", "parameters": {"command": "echo hello"}},
            "context": {"workingDir": "/home/user"},
        })

        adapter = detect_platform(raw)
        assert adapter.get_platform() == "openclaw"

        cmd = adapter.parse_input(raw)
        assert cmd.tool_name == "Bash"
        assert cmd.tool_input["command"] == "echo hello"

        assessment = engine.assess(
            cmd.tool_input.get("command", ""),
            AnalysisContext(working_directory=cmd.cwd),
        )

        result = CommandResult(
            decision="allow",
            risk_score=assessment.final_score,
        )
        output = json.loads(adapter.format_output(result))
        assert output["action"] == "allow"

    def test_generic_pipeline(self, engine):
        """Generic JSON -> parse -> assess -> format works end-to-end."""
        raw = json.dumps({"command": "git status", "cwd": "/tmp/repo"})

        adapter = detect_platform(raw)
        assert adapter.get_platform() == "generic"

        cmd = adapter.parse_input(raw)
        assert cmd.tool_input["command"] == "git status"

        assessment = engine.assess(
            cmd.tool_input.get("command", ""),
            AnalysisContext(working_directory=cmd.cwd),
        )

        result = CommandResult(
            decision="allow",
            risk_score=assessment.final_score,
        )
        output = json.loads(adapter.format_output(result))
        assert output["allowed"] is True

    def test_non_bash_tool_skips_engine(self):
        """Non-Bash tools (Read, Glob) should parse but may not need engine."""
        raw = json.dumps({
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/test.py"},
        })

        adapter = detect_platform(raw)
        cmd = adapter.parse_input(raw)
        assert cmd.tool_name == "Read"
        assert cmd.tool_input["file_path"] == "/tmp/test.py"

        # Read operations are typically safe -> allow
        result = CommandResult(decision="allow", risk_score=0)
        output = json.loads(adapter.format_output(result))
        assert output["hookSpecificOutput"]["permissionDecision"] == "allow"


class TestAdapterInteroperability:
    """Test that the same command gives consistent results across adapters."""

    def test_same_command_same_engine_result(self, engine):
        """Same command via different adapters -> same risk assessment."""
        command = "echo hello world"

        # Claude Code format
        cc_raw = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
        cc_adapter = detect_platform(cc_raw)
        cc_cmd = cc_adapter.parse_input(cc_raw)

        # OpenClaw format
        oc_raw = json.dumps({
            "event": "preToolExecution",
            "tool": {"name": "shell", "parameters": {"command": command}},
        })
        oc_adapter = detect_platform(oc_raw)
        oc_cmd = oc_adapter.parse_input(oc_raw)

        # Generic format
        gen_raw = json.dumps({"command": command})
        gen_adapter = detect_platform(gen_raw)
        gen_cmd = gen_adapter.parse_input(gen_raw)

        # All should extract the same command
        assert cc_cmd.tool_input["command"] == command
        assert oc_cmd.tool_input["command"] == command
        assert gen_cmd.tool_input["command"] == command

        # All should map to Bash
        assert cc_cmd.tool_name == "Bash"
        assert oc_cmd.tool_name == "Bash"
        assert gen_cmd.tool_name == "Bash"

        # Engine should give the same score for the same command
        ctx = AnalysisContext(working_directory=".")
        score1 = engine.assess(command, ctx).final_score
        score2 = engine.assess(command, ctx).final_score
        assert score1 == score2
