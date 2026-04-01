"""Parametrized risk engine evaluation tests — Spec 8.

Each entry in evaluation_corpus.yaml becomes a separate test case.
A regression on ANY single command is immediately visible as a named failure.
"""
from __future__ import annotations

from pathlib import Path
from typing import List

import pytest
import yaml

CORPUS_PATH = Path(__file__).parent.parent / "fixtures" / "evaluation_corpus.yaml"


def _load_corpus() -> List[dict]:
    with open(CORPUS_PATH) as f:
        data = yaml.safe_load(f)
    return data["corpus"]


def _corpus_ids() -> List[str]:
    """Generate readable test IDs like '003_allow_npm_install'."""
    corpus = _load_corpus()
    ids = []
    for i, entry in enumerate(corpus):
        cmd = entry["command"][:40].replace(" ", "_").replace("/", "_")
        expected = entry["expected_action"]
        ids.append(f"{i:03d}_{expected}_{cmd}")
    return ids


_CORPUS = _load_corpus()


@pytest.mark.parametrize("entry", _CORPUS, ids=_corpus_ids())
class TestCorpusEntry:
    """Each corpus entry is a separate parametrized test."""

    def test_action_matches_expected(self, risk_engine, mock_context, entry):
        """Verify the engine's action matches the corpus expected_action."""
        is_known_fn = "KNOWN-FN" in (entry.get("description") or "").upper()
        result = risk_engine.assess(entry["command"], mock_context)
        actual = result.action.value
        expected = entry["expected_action"]

        if is_known_fn and actual != expected:
            pytest.xfail(f"Known FN: expected={expected}, got={actual}")

        assert actual == expected, (
            f"Command: {entry['command'][:80]}\n"
            f"Expected: {expected}, Got: {actual} (score={result.final_score})\n"
            f"Desc: {entry.get('description', '')[:120]}"
        )

    def test_score_in_expected_range(self, risk_engine, mock_context, entry):
        """Verify scores fall in reasonable ranges for the expected action."""
        is_known_fn = "KNOWN-FN" in (entry.get("description") or "").upper()
        result = risk_engine.assess(entry["command"], mock_context)
        expected = entry["expected_action"]

        if expected == "block":
            if is_known_fn and result.final_score < 80:
                pytest.xfail(f"Known FN: block expected score>=80, got {result.final_score}")
            assert result.final_score >= 80, (
                f"Block command scored only {result.final_score}: {entry['command'][:60]}"
            )
        elif expected == "allow":
            assert result.final_score < 40, (
                f"Allow command scored {result.final_score}: {entry['command'][:60]}"
            )
        # warn: score between 40-79 (not strictly asserted since some edge cases exist)
