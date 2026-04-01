"""Smoke tests for sentinelai.ml.analyze_logs.

Creates a tiny JSONL sample, runs analyze_logs on it, and verifies
the candidate_set.jsonl is written correctly.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

import pytest


TINY_LOG = [
    {
        "ts": "2025-01-15T10:00:00Z",
        "text_hash": "a" * 64,
        "scanner_score": 0,
        "ml_status": "ok",
        "ml_injection_prob": 0.15,
        "ml_recommendation": "allow",
        "decision": "allow",
        "engine_action": "allow",
        "cwd": "/tmp",
        "ngram_hints": ["list", "files"],
    },
    {
        "ts": "2025-01-15T10:01:00Z",
        "text_hash": "b" * 64,
        "scanner_score": 5,
        "ml_status": "ok",
        "ml_injection_prob": 0.72,
        "ml_recommendation": "review",
        "decision": "allow",
        "engine_action": "allow",
        "cwd": "/tmp",
        "ngram_hints": ["override", "system"],
    },
    {
        "ts": "2025-01-15T10:02:00Z",
        "text_hash": "c" * 64,
        "scanner_score": 3,
        "ml_status": "ok",
        "ml_injection_prob": 0.88,
        "ml_recommendation": "block",
        "decision": "allow",
        "engine_action": "allow",
        "cwd": "/tmp",
        "ngram_hints": ["ignore", "instructions", "mode"],
    },
    {
        "ts": "2025-01-15T10:03:00Z",
        "text_hash": "d" * 64,
        "scanner_score": 0,
        "ml_status": "ok",
        "ml_injection_prob": 0.05,
        "ml_recommendation": "allow",
        "decision": "allow",
        "engine_action": "allow",
        "cwd": "/home",
        "ngram_hints": ["help", "debug"],
    },
    {
        "ts": "2025-01-15T10:04:00Z",
        "text_hash": "e" * 64,
        "scanner_score": 75,
        "ml_status": "skipped",
        "ml_injection_prob": 0.0,
        "ml_recommendation": "allow",
        "decision": "deny",
        "engine_action": "block",
        "cwd": "/tmp",
        "ngram_hints": [],
    },
]


@pytest.fixture
def log_file(tmp_path):
    p = tmp_path / "test_al.jsonl"
    with open(p, "w") as f:
        for rec in TINY_LOG:
            f.write(json.dumps(rec) + "\n")
    return str(p)


class TestAnalyzeLogsSmoke:
    """Run analyze_logs via subprocess and check output."""

    def test_exits_zero(self, log_file, tmp_path):
        out_path = str(tmp_path / "candidates.jsonl")
        result = subprocess.run(
            [
                sys.executable, "-m", "sentinelai.ml.analyze_logs",
                "--log", log_file,
                "--out", out_path,
            ],
            capture_output=True, text=True,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            timeout=30,
        )
        assert result.returncode == 0, (
            f"analyze_logs exited {result.returncode}\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )

    def test_candidate_set_written(self, log_file, tmp_path):
        out_path = str(tmp_path / "candidates.jsonl")
        subprocess.run(
            [
                sys.executable, "-m", "sentinelai.ml.analyze_logs",
                "--log", log_file,
                "--out", out_path,
            ],
            capture_output=True, text=True,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            timeout=30,
        )
        assert os.path.isfile(out_path), "candidate_set.jsonl not created"

    def test_candidate_set_has_correct_records(self, log_file, tmp_path):
        """Only records with scanner_score<20 AND (0.60<=prob<=0.90 OR rec in review/block)."""
        out_path = str(tmp_path / "candidates.jsonl")
        subprocess.run(
            [
                sys.executable, "-m", "sentinelai.ml.analyze_logs",
                "--log", log_file,
                "--out", out_path,
            ],
            capture_output=True, text=True,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            timeout=30,
        )
        with open(out_path) as f:
            candidates = [json.loads(line) for line in f if line.strip()]

        # From TINY_LOG:
        # rec "b" (score=5, prob=0.72, rec=review) -> YES
        # rec "c" (score=3, prob=0.88, rec=block) -> YES
        # rec "a" (score=0, prob=0.15, rec=allow) -> NO (prob < 0.60)
        # rec "d" (score=0, prob=0.05, rec=allow) -> NO
        # rec "e" (score=75, ...) -> NO (scanner_score >= 20)
        assert len(candidates) == 2, f"Expected 2 candidates, got {len(candidates)}"

        hashes = {c["text_hash"] for c in candidates}
        assert "b" * 64 in hashes
        assert "c" * 64 in hashes

    def test_candidate_set_no_raw_text(self, log_file, tmp_path):
        """Candidate set must not contain any field called 'raw_text' or 'command'."""
        out_path = str(tmp_path / "candidates.jsonl")
        subprocess.run(
            [
                sys.executable, "-m", "sentinelai.ml.analyze_logs",
                "--log", log_file,
                "--out", out_path,
            ],
            capture_output=True, text=True,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            timeout=30,
        )
        with open(out_path) as f:
            for line in f:
                rec = json.loads(line)
                assert "raw_text" not in rec
                assert "command" not in rec
                assert "text" not in rec

    def test_output_contains_histogram(self, log_file, tmp_path):
        out_path = str(tmp_path / "candidates.jsonl")
        result = subprocess.run(
            [
                sys.executable, "-m", "sentinelai.ml.analyze_logs",
                "--log", log_file,
                "--out", out_path,
            ],
            capture_output=True, text=True,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            timeout=30,
        )
        assert "Histogram" in result.stdout
        assert "ml_recommendation" in result.stdout

    def test_missing_log_exits_one(self, tmp_path):
        result = subprocess.run(
            [
                sys.executable, "-m", "sentinelai.ml.analyze_logs",
                "--log", str(tmp_path / "nonexistent.jsonl"),
            ],
            capture_output=True, text=True,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            timeout=30,
        )
        assert result.returncode == 1


class TestAnalyzeLogsImport:
    """Verify the module imports cleanly."""

    def test_import(self):
        from sentinelai.ml.analyze_logs import main, load_records, write_candidate_set
        assert callable(main)
        assert callable(load_records)
        assert callable(write_candidate_set)
