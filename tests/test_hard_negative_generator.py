"""Tests for the HARD negative generator."""

from __future__ import annotations

import os
import re
import subprocess
import sys

import pytest

OUTPUT_FILE = "hard_negatives_2k.txt"


@pytest.fixture(scope="module", autouse=True)
def _generate(tmp_path_factory):
    """Run generator once for all tests in this module."""
    cwd = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    result = subprocess.run(
        [sys.executable, "tests/generate_hard_negatives.py"],
        capture_output=True, text=True, cwd=cwd, timeout=30,
    )
    assert result.returncode == 0, f"Generator failed:\n{result.stderr}"


class TestHardNegativeGenerator:

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
        assert len(lines) == 2500, f"Expected 2500 lines, got {len(lines)}"

    def test_line_format(self):
        lines = self._load()
        pattern = re.compile(r"^HARD \|\| .+")
        bad = [l for l in lines if not pattern.match(l)]
        assert len(bad) == 0, f"Bad format lines: {bad[:5]}"

    def test_uniqueness(self):
        lines = self._load()
        texts = [l.split(" || ", 1)[1] for l in lines]
        unique_rate = len(set(texts)) / len(texts)
        assert unique_rate >= 0.90, f"Uniqueness {unique_rate:.2%} < 90%"

    def test_no_attack_directives(self):
        """HARD negatives should not contain actionable attack instructions."""
        lines = self._load()
        directive_patterns = [
            r"ignore (?:all |your |previous |system )(?:rules|instructions|guidelines)",
            r"bypass (?:all |the )?(?:safety|security|content) (?:filters|rules|checks)",
            r"disable (?:all |your )?(?:safety|content|security) (?:filters|rules|mode)",
            r"enter (?:debug|admin|unrestricted|raw) mode",
            r"you are now (?:a|an|in) (?:unrestricted|unfiltered|jailbroken)",
        ]
        for l in lines:
            text = l.split(" || ", 1)[1].lower()
            for pat in directive_patterns:
                assert not re.search(pat, text), f"Attack directive found: {text[:80]}"
