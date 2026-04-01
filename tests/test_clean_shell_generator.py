"""Tests for the clean shell command generator."""

from __future__ import annotations

import os
import re
import subprocess
import sys

import pytest

OUTPUT_FILE = "clean_shell_5k.txt"


@pytest.fixture(scope="module", autouse=True)
def _generate(tmp_path_factory):
    """Run generator once for all tests in this module."""
    cwd = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    result = subprocess.run(
        [sys.executable, "tests/generate_clean_shell_commands.py"],
        capture_output=True, text=True, cwd=cwd, timeout=30,
    )
    assert result.returncode == 0, f"Generator failed:\n{result.stderr}"


class TestCleanShellGenerator:

    def _load(self):
        cwd = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(cwd, OUTPUT_FILE)
        with open(path) as f:
            return [l.strip() for l in f if l.strip()]

    def test_file_exists(self):
        cwd = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        assert os.path.isfile(os.path.join(cwd, OUTPUT_FILE))

    def test_line_count(self):
        lines = self._load()
        assert len(lines) == 5000, f"Expected 5000 lines, got {len(lines)}"

    def test_line_format(self):
        lines = self._load()
        pattern = re.compile(r"^CLEAN \|\| .+")
        bad = [l for l in lines if not pattern.match(l)]
        assert len(bad) == 0, f"Bad format lines: {bad[:5]}"

    def test_uniqueness(self):
        lines = self._load()
        texts = [l.split(" || ", 1)[1] for l in lines]
        unique_rate = len(set(texts)) / len(texts)
        assert unique_rate >= 0.85, f"Uniqueness {unique_rate:.2%} < 85%"

    def test_no_dangerous_commands(self):
        lines = self._load()
        for l in lines:
            cmd = l.split(" || ", 1)[1].lower()
            assert "rm -rf /" not in cmd
            assert "sudo " not in cmd
            assert "chmod 777 /etc" not in cmd
            assert "/proc/" not in cmd
            assert "/sys/" not in cmd
