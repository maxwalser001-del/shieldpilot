"""Scanner detection rate metrics -- Spec 8.

Runs the full scanner corpus and measures detection rates.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import pytest
import yaml

from sentinelai.scanner.scanner import PromptScanner

CORPUS_PATH = Path(__file__).parent.parent / "fixtures" / "scanner_eval_corpus.yaml"


@pytest.fixture(scope="module")
def scanner():
    return PromptScanner()


@pytest.fixture(scope="module")
def corpus():
    with open(CORPUS_PATH) as f:
        data = yaml.safe_load(f)
    return data["corpus"]


class TestScannerMetrics:

    def test_corpus_minimum_size(self, corpus):
        """Corpus must have at least 60 entries."""
        assert len(corpus) >= 60, f"Corpus only has {len(corpus)} entries, need >= 60"

    def test_overall_true_positive_rate(self, scanner, corpus):
        """Attack entries should be detected at >= 85% rate."""
        attacks = [e for e in corpus if e["should_detect"]]
        detected = 0
        for entry in attacks:
            result = scanner.scan(entry["text"], source="metrics")
            if len(result.threats) > 0:
                detected += 1
        tp_rate = detected / len(attacks) * 100 if attacks else 0
        assert tp_rate >= 85, (
            f"True positive rate {tp_rate:.1f}% below 85% target "
            f"({detected}/{len(attacks)})"
        )

    def test_false_positive_rate(self, scanner, corpus):
        """Benign entries should not be flagged (FP rate < 5%)."""
        benign = [e for e in corpus if not e["should_detect"]]
        false_positives = 0
        fp_entries = []
        for entry in benign:
            result = scanner.scan(entry["text"], source="metrics")
            if len(result.threats) > 0:
                false_positives += 1
                fp_entries.append(entry["text"][:60])
        fp_rate = false_positives / len(benign) * 100 if benign else 0
        assert fp_rate < 5, (
            f"False positive rate {fp_rate:.1f}% exceeds 5% target "
            f"({false_positives}/{len(benign)})\n"
            f"FP entries: {fp_entries}"
        )

    def test_detection_rate_per_category(self, scanner, corpus, capsys):
        """Print per-category detection rates (informational)."""
        by_category = defaultdict(lambda: {"total": 0, "detected": 0})

        for entry in corpus:
            if not entry["should_detect"]:
                continue
            cat = entry.get("category") or "unknown"
            by_category[cat]["total"] += 1
            result = scanner.scan(entry["text"], source="metrics")
            found_cats = {t.category for t in result.threats}
            if cat in found_cats:
                by_category[cat]["detected"] += 1

        with capsys.disabled():
            print("\n" + "=" * 55)
            print("  SCANNER DETECTION RATE REPORT")
            print("=" * 55)
            for cat, stats in sorted(by_category.items()):
                rate = stats["detected"] / stats["total"] * 100 if stats["total"] else 0
                status = "OK" if rate >= 80 else "LOW"
                print(f"  [{status}] {cat:25s}  {stats['detected']}/{stats['total']}  ({rate:.0f}%)")
            print("=" * 55)
