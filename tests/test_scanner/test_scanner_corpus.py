"""Parametrized prompt scanner evaluation tests -- Spec 8.

Each entry in scanner_eval_corpus.yaml becomes a separate test case.
"""
from __future__ import annotations

from pathlib import Path
from typing import List

import pytest
import yaml

from sentinelai.scanner.scanner import PromptScanner

CORPUS_PATH = Path(__file__).parent.parent / "fixtures" / "scanner_eval_corpus.yaml"


def _load_corpus() -> List[dict]:
    with open(CORPUS_PATH) as f:
        data = yaml.safe_load(f)
    return data["corpus"]


def _corpus_ids() -> List[str]:
    corpus = _load_corpus()
    ids = []
    for i, entry in enumerate(corpus):
        detect = "attack" if entry["should_detect"] else "benign"
        cat = entry.get("category") or "none"
        text_slug = entry["text"][:30].replace(" ", "_").replace("\n", "\\n")
        # Remove chars that cause pytest ID issues
        for ch in "[]{}()<>:;/\\'\"":
            text_slug = text_slug.replace(ch, "")
        ids.append(f"{i:03d}_{detect}_{cat}_{text_slug}")
    return ids


_CORPUS = _load_corpus()


@pytest.fixture(scope="module")
def scanner():
    return PromptScanner()


@pytest.mark.parametrize("entry", _CORPUS, ids=_corpus_ids())
class TestScannerCorpusEntry:

    def test_detection(self, scanner, entry):
        """Attack entries must fire threats; benign entries must not."""
        result = scanner.scan(entry["text"], source="eval-corpus")
        has_threats = len(result.threats) > 0

        if entry["should_detect"]:
            assert has_threats, (
                f"MISS: Expected detection for: {entry['text'][:80]}\n"
                f"Category: {entry.get('category')}\n"
                f"Score: {result.overall_score}"
            )
        else:
            assert not has_threats, (
                f"FALSE POSITIVE: Unexpected detection for benign: {entry['text'][:80]}\n"
                f"Threats: {[(t.category, t.pattern_name) for t in result.threats]}\n"
                f"Score: {result.overall_score}"
            )

    def test_category_match(self, scanner, entry):
        """If should_detect, the expected category must appear in threats.
        Benign entries must have no threats (no category to match).
        """
        result = scanner.scan(entry["text"], source="eval-corpus")

        if not entry["should_detect"]:
            # Benign entries: verify no threats exist (no category to match)
            assert len(result.threats) == 0, (
                f"Benign entry should have no threats but got: "
                f"{[(t.category, t.pattern_name) for t in result.threats]}\n"
                f"Text: {entry['text'][:80]}"
            )
            return

        expected_cat = entry.get("category")
        if expected_cat is None:
            # Attack entry with no expected category -- just verify threats exist
            assert len(result.threats) > 0, (
                f"Attack entry should have threats: {entry['text'][:80]}"
            )
            return

        found_cats = {t.category for t in result.threats}

        assert expected_cat in found_cats, (
            f"Expected category '{expected_cat}' not in {found_cats}\n"
            f"Text: {entry['text'][:80]}"
        )

    def test_score_range(self, scanner, entry):
        """Verify scores fall in expected ranges."""
        result = scanner.scan(entry["text"], source="eval-corpus")

        if entry["should_detect"]:
            min_score = entry.get("min_score", 1)
            assert result.overall_score >= min_score, (
                f"Score {result.overall_score} below min {min_score}: "
                f"{entry['text'][:80]}"
            )
        else:
            max_score = entry.get("max_score", 0)
            assert result.overall_score <= max_score, (
                f"Score {result.overall_score} above max {max_score}: "
                f"{entry['text'][:80]}"
            )
