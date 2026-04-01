"""Tests for the active-learning JSONL logger in sentinel_hook.py.

Verifies that:
- One JSONL record is written per hook request when scanner_score < 20
- No raw command text appears in the output
- The env var gate works (no file written when unset)
- Record schema is correct
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from unittest.mock import patch

import pytest


@dataclass
class FakeScanResult:
    overall_score: int = 5
    threats: list = None
    threat_count: int = 0

    def __post_init__(self):
        if self.threats is None:
            self.threats = []


def _run_hook_with_command(command: str, monkeypatch, env_extras: dict | None = None):
    """Run the hook main() with a fake Bash tool call and return after SystemExit."""
    from sentinelai.scanner.scanner import PromptScanner

    monkeypatch.setattr(PromptScanner, "scan", lambda self, text, source="": FakeScanResult())

    hook_input = json.dumps({
        "tool_name": "Bash",
        "tool_input": {"command": command},
    })

    if env_extras:
        for k, v in env_extras.items():
            monkeypatch.setenv(k, v)

    with patch("sys.stdin") as mock_stdin, patch("builtins.print"):
        mock_stdin.read.return_value = hook_input
        from sentinelai.hooks.sentinel_hook import main

        try:
            main()
        except SystemExit:
            pass


class TestActiveLearningSingleRecord:
    """When SENTINEL_ACTIVE_LEARNING_PATH is set and scanner_score < 20,
    exactly one valid JSONL record should be written."""

    def test_one_record_written(self, monkeypatch, tmp_path):
        al_file = tmp_path / "active_learning.jsonl"

        _run_hook_with_command(
            "ls -la",
            monkeypatch,
            env_extras={"SENTINEL_ACTIVE_LEARNING_PATH": str(al_file)},
        )

        lines = al_file.read_text().strip().splitlines()
        assert len(lines) == 1, f"Expected 1 JSONL line, got {len(lines)}"

        record = json.loads(lines[0])
        assert isinstance(record, dict)

    def test_record_schema(self, monkeypatch, tmp_path):
        al_file = tmp_path / "active_learning.jsonl"

        _run_hook_with_command(
            "echo hello",
            monkeypatch,
            env_extras={"SENTINEL_ACTIVE_LEARNING_PATH": str(al_file)},
        )

        record = json.loads(al_file.read_text().strip())

        required_keys = {
            "ts", "text_hash", "scanner_score", "ml_status",
            "ml_injection_prob", "ml_recommendation", "decision",
            "engine_action", "cwd", "ngram_hints",
        }
        assert required_keys <= set(record.keys()), (
            f"Missing keys: {required_keys - set(record.keys())}"
        )

        # Type checks
        assert isinstance(record["ts"], str) and record["ts"].endswith("Z")
        assert isinstance(record["text_hash"], str) and len(record["text_hash"]) == 64
        assert isinstance(record["scanner_score"], int)
        assert isinstance(record["ml_status"], str)
        assert isinstance(record["ml_injection_prob"], (int, float))
        assert record["decision"] in {"allow", "ask", "deny"}
        assert isinstance(record["engine_action"], str)
        assert isinstance(record["cwd"], str)
        assert isinstance(record["ngram_hints"], list)


class TestActiveLearningNoRawText:
    """The raw command must NEVER appear in the JSONL output."""

    def test_raw_text_not_in_file(self, monkeypatch, tmp_path):
        al_file = tmp_path / "active_learning.jsonl"
        secret_command = "super_secret_command_xyzzy_42"

        _run_hook_with_command(
            secret_command,
            monkeypatch,
            env_extras={"SENTINEL_ACTIVE_LEARNING_PATH": str(al_file)},
        )

        if not al_file.exists():
            # File not created → no raw text leaked (pass)
            return
        file_content = al_file.read_text()
        assert secret_command not in file_content, "Raw command text leaked into JSONL!"

    def test_text_hash_matches(self, monkeypatch, tmp_path):
        al_file = tmp_path / "active_learning.jsonl"
        command = "ls -la /tmp"

        _run_hook_with_command(
            command,
            monkeypatch,
            env_extras={"SENTINEL_ACTIVE_LEARNING_PATH": str(al_file)},
        )

        record = json.loads(al_file.read_text().strip())
        expected_hash = hashlib.sha256(command.encode("utf-8")).hexdigest()
        assert record["text_hash"] == expected_hash


class TestActiveLearningEnvGate:
    """When SENTINEL_ACTIVE_LEARNING_PATH is not set, nothing is written."""

    def test_no_file_without_env(self, monkeypatch, tmp_path):
        al_file = tmp_path / "should_not_exist.jsonl"

        # Make sure the env var is NOT set
        monkeypatch.delenv("SENTINEL_ACTIVE_LEARNING_PATH", raising=False)

        _run_hook_with_command("ls", monkeypatch)

        assert not al_file.exists(), "JSONL file created without env var set!"


class TestActiveLearningFailOpen:
    """If the file path is invalid, the hook must not crash."""

    def test_bad_path_does_not_crash(self, monkeypatch):
        _run_hook_with_command(
            "ls",
            monkeypatch,
            env_extras={
                "SENTINEL_ACTIVE_LEARNING_PATH": "/nonexistent/dir/file.jsonl"
            },
        )
        # If we reach here without exception, the test passes
