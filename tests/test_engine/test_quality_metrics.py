"""Risk engine quality metrics -- Spec 8.

Runs the engine against the evaluation corpus and measures
false positive/negative rates per category.

The corpus lives at ``tests/fixtures/evaluation_corpus.yaml`` and contains
80-100 labeled commands with expected_action (allow/warn/block), category,
and description fields.

Key design decisions
--------------------
* ``test_overall_accuracy`` asserts >= 70 % overall accuracy.
* ``test_no_false_negatives_on_critical`` ensures no command expected to
  BLOCK is actually ALLOWed, *except* known false negatives documented in
  the corpus (whitelisted base commands like cat/echo).
* ``test_false_positive_rate_benign`` keeps the FP rate on benign commands
  below 10 %.
* ``test_report_per_category`` prints a human-readable per-category
  accuracy report to stdout (always passes -- informational only).
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import pytest
import yaml

from sentinelai.core.constants import Action


CORPUS_PATH = Path(__file__).parent.parent / "fixtures" / "evaluation_corpus.yaml"


@pytest.fixture
def corpus():
    """Load evaluation corpus from YAML fixture."""
    with open(CORPUS_PATH) as f:
        data = yaml.safe_load(f)
    return data["corpus"]


class TestQualityMetrics:
    """Run engine against corpus and report accuracy."""

    # ------------------------------------------------------------------
    # Structural sanity
    # ------------------------------------------------------------------

    def test_corpus_loads(self, corpus):
        """Verify corpus is valid YAML and contains enough entries."""
        assert len(corpus) >= 50, (
            f"Corpus has only {len(corpus)} entries; expected >= 50"
        )
        for entry in corpus:
            assert "command" in entry, f"Missing 'command' key: {entry}"
            assert entry["expected_action"] in ("allow", "warn", "block"), (
                f"Invalid expected_action: {entry['expected_action']}"
            )

    # ------------------------------------------------------------------
    # Overall accuracy
    # ------------------------------------------------------------------

    def test_overall_accuracy(self, risk_engine, mock_context, corpus):
        """Overall accuracy should be above 70 %."""
        correct = 0
        total = len(corpus)
        misses: list[dict] = []

        for entry in corpus:
            result = risk_engine.assess(entry["command"], mock_context)
            actual = result.action.value
            expected = entry["expected_action"]
            if actual == expected:
                correct += 1
            else:
                misses.append({
                    "command": entry["command"][:80],
                    "expected": expected,
                    "actual": actual,
                    "score": result.final_score,
                    "desc": entry["description"][:60],
                })

        accuracy = correct / total * 100
        miss_summary = "\n".join(
            f"  [{m['expected']}->{m['actual']} s={m['score']}] "
            f"{m['command'][:60]}  ({m['desc']})"
            for m in misses
        )
        assert accuracy >= 70, (
            f"Overall accuracy {accuracy:.1f}% is below 70% target.\n"
            f"Misses ({len(misses)}/{total}):\n{miss_summary}"
        )

    # ------------------------------------------------------------------
    # False negatives on critical commands
    # ------------------------------------------------------------------

    def test_no_false_negatives_on_critical(self, risk_engine, mock_context, corpus):
        """Commands expected to BLOCK should never be ALLOWed.

        False negatives on critical threats are the worst kind of error.
        Commands documented as KNOWN-FN (e.g. whitelisted cat/echo) are
        excluded from this assertion.
        """
        false_negatives: list[dict] = []
        block_entries = [e for e in corpus if e["expected_action"] == "block"]

        for entry in block_entries:
            result = risk_engine.assess(entry["command"], mock_context)
            if result.action == Action.ALLOW:
                false_negatives.append({
                    "command": entry["command"],
                    "expected": "block",
                    "actual": result.action.value,
                    "score": result.final_score,
                    "description": entry["description"],
                })

        # Filter out KNOWN false negatives (documented in corpus description)
        known_fn = [
            fn for fn in false_negatives
            if "KNOWN-FN" in fn["description"].upper()
        ]
        unexpected_fn = [fn for fn in false_negatives if fn not in known_fn]

        if known_fn:
            print(f"\n  Known false negatives (whitelisted commands): {len(known_fn)}")
            for fn in known_fn:
                print(f"    {fn['command'][:60]}  score={fn['score']}")

        assert len(unexpected_fn) == 0, (
            f"Unexpected false negatives ({len(unexpected_fn)}):\n"
            + "\n".join(
                f"  [{fn['actual']} s={fn['score']}] {fn['command'][:60]}  "
                f"({fn['description'][:60]})"
                for fn in unexpected_fn
            )
        )

    # ------------------------------------------------------------------
    # False positive rate on benign commands
    # ------------------------------------------------------------------

    def test_false_positive_rate_benign(self, risk_engine, mock_context, corpus):
        """Benign commands should not be blocked (FP rate < 10 %)."""
        allow_entries = [e for e in corpus if e["expected_action"] == "allow"]
        false_positives: list[dict] = []

        for entry in allow_entries:
            result = risk_engine.assess(entry["command"], mock_context)
            if result.action == Action.BLOCK:
                false_positives.append({
                    "command": entry["command"],
                    "actual": result.action.value,
                    "score": result.final_score,
                    "description": entry["description"],
                })

        fp_count = len(false_positives)
        total = len(allow_entries)
        fp_rate = fp_count / total * 100 if total else 0

        fp_detail = "\n".join(
            f"  [BLOCK s={fp['score']}] {fp['command'][:60]}  ({fp['description'][:60]})"
            for fp in false_positives
        )
        assert fp_rate < 10, (
            f"False positive rate {fp_rate:.1f}% ({fp_count}/{total}) "
            f"exceeds 10% target.\n{fp_detail}"
        )

    # ------------------------------------------------------------------
    # Warn-to-block misclassification (benign commands should not WARN)
    # ------------------------------------------------------------------

    def test_benign_warn_rate(self, risk_engine, mock_context, corpus):
        """Benign commands that unexpectedly WARN should be below 15 %."""
        allow_entries = [e for e in corpus if e["expected_action"] == "allow"]
        false_warns: list[dict] = []

        for entry in allow_entries:
            result = risk_engine.assess(entry["command"], mock_context)
            if result.action == Action.WARN:
                false_warns.append({
                    "command": entry["command"],
                    "score": result.final_score,
                    "description": entry["description"],
                })

        fw_count = len(false_warns)
        total = len(allow_entries)
        fw_rate = fw_count / total * 100 if total else 0

        assert fw_rate < 15, (
            f"Benign-to-warn rate {fw_rate:.1f}% ({fw_count}/{total}) "
            f"exceeds 15% target."
        )

    # ------------------------------------------------------------------
    # Per-category accuracy report (informational — always passes)
    # ------------------------------------------------------------------

    def test_report_per_category(self, risk_engine, mock_context, corpus, capsys):
        """Print per-category accuracy report (informational)."""
        by_category: dict[str, dict] = defaultdict(
            lambda: {"correct": 0, "total": 0, "errors": []}
        )

        for entry in corpus:
            result = risk_engine.assess(entry["command"], mock_context)
            actual = result.action.value
            expected = entry["expected_action"]
            cat = entry.get("category") or "benign"

            by_category[cat]["total"] += 1
            if actual == expected:
                by_category[cat]["correct"] += 1
            else:
                by_category[cat]["errors"].append({
                    "command": entry["command"][:60],
                    "expected": expected,
                    "actual": actual,
                    "score": result.final_score,
                })

        # Compute totals
        total_correct = sum(s["correct"] for s in by_category.values())
        total_entries = sum(s["total"] for s in by_category.values())
        overall_acc = total_correct / total_entries * 100 if total_entries else 0

        # Print report
        print("\n" + "=" * 60)
        print("  RISK ENGINE QUALITY REPORT")
        print("=" * 60)
        print(f"\n  Overall accuracy: {total_correct}/{total_entries} ({overall_acc:.1f}%)\n")

        for cat, stats in sorted(by_category.items()):
            acc = stats["correct"] / stats["total"] * 100 if stats["total"] else 0
            status = "OK" if acc >= 70 else "LOW"
            print(
                f"  [{status}] {cat:30s}  "
                f"{stats['correct']:2d}/{stats['total']:2d} ({acc:5.1f}%)"
            )
            for err in stats["errors"]:
                print(
                    f"        MISS: {err['command'][:55]}"
                    f" | expected={err['expected']}, got={err['actual']}"
                    f" (score={err['score']})"
                )

        print("\n" + "=" * 60)

        # Always passes — this test is informational
        assert True

    # ------------------------------------------------------------------
    # Confusion matrix (informational — always passes)
    # ------------------------------------------------------------------

    def test_confusion_matrix(self, risk_engine, mock_context, corpus, capsys):
        """Print a 3x3 confusion matrix (allow/warn/block)."""
        matrix: dict[str, dict[str, int]] = {
            "allow": {"allow": 0, "warn": 0, "block": 0},
            "warn":  {"allow": 0, "warn": 0, "block": 0},
            "block": {"allow": 0, "warn": 0, "block": 0},
        }

        for entry in corpus:
            result = risk_engine.assess(entry["command"], mock_context)
            expected = entry["expected_action"]
            actual = result.action.value
            matrix[expected][actual] += 1

        print("\n" + "-" * 50)
        print("  CONFUSION MATRIX (expected \\ actual)")
        print("-" * 50)
        header = f"  {'':>10s}  {'allow':>7s}  {'warn':>7s}  {'block':>7s}"
        print(header)
        for expected_label in ("allow", "warn", "block"):
            row = matrix[expected_label]
            print(
                f"  {expected_label:>10s}  "
                f"{row['allow']:7d}  {row['warn']:7d}  {row['block']:7d}"
            )
        print("-" * 50)

        assert True
