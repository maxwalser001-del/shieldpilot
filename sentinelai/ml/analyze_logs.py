"""Analyze ShieldPilot active-learning JSONL logs.

Reads active-learning records and produces:
- ml_recommendation distribution (allow / review / block)
- Histogram of ml_injection_prob (10 bins)
- Top N hashes by injection probability
- Percentage of records with scanner_score == 0
- candidate_set.jsonl for targeted retraining

Usage:
    python3 -m sentinelai.ml.analyze_logs --log /tmp/shieldpilot_active_learning.jsonl
    python3 -m sentinelai.ml.analyze_logs --log al.jsonl --last 500 --out candidates.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter


def _header(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def load_records(path: str, last_n: int) -> list[dict]:
    """Load up to *last_n* JSONL records from *path*."""
    records: list[dict] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    if len(records) > last_n:
        records = records[-last_n:]
    return records


def print_recommendation_counts(records: list[dict]) -> None:
    _header("ml_recommendation Distribution")
    counts = Counter(r.get("ml_recommendation", "unknown") for r in records)
    total = len(records)
    for rec in ["allow", "review", "block", "unknown"]:
        c = counts.get(rec, 0)
        pct = 100 * c / total if total else 0
        if c > 0:
            print(f"  {rec:>8s}: {c:>6d}  ({pct:5.1f}%)")


def print_prob_histogram(records: list[dict]) -> None:
    _header("ml_injection_prob Histogram")
    bins = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
    counts = [0] * (len(bins) - 1)
    for r in records:
        p = r.get("ml_injection_prob", 0.0)
        for i in range(len(bins) - 1):
            if bins[i] <= p < bins[i + 1] or (i == len(bins) - 2 and p == 1.0):
                counts[i] += 1
                break

    total = len(records)
    for i in range(len(bins) - 1):
        lo, hi = bins[i], bins[i + 1]
        c = counts[i]
        pct = 100 * c / total if total else 0
        bar = "#" * int(pct / 2)
        print(f"  [{lo:.1f}-{hi:.1f})  {c:>6d}  ({pct:5.1f}%)  {bar}")


def print_top_hashes(records: list[dict], top_n: int = 30) -> None:
    _header(f"Top {top_n} Hashes by ml_injection_prob")
    sorted_recs = sorted(
        records, key=lambda r: r.get("ml_injection_prob", 0.0), reverse=True
    )
    print(f"  {'#':>3s}  {'text_hash':>18s}  {'ml_prob':>8s}  {'scanner':>8s}  {'rec':>8s}  {'decision':>8s}")
    print(f"  {'---':>3s}  {'------------------':>18s}  {'--------':>8s}  {'--------':>8s}  {'--------':>8s}  {'--------':>8s}")
    for i, r in enumerate(sorted_recs[:top_n], 1):
        h = r.get("text_hash", "?")[:14] + "..."
        prob = r.get("ml_injection_prob", 0.0)
        sc = r.get("scanner_score", -1)
        rec = r.get("ml_recommendation", "?")
        dec = r.get("decision", "?")
        print(f"  {i:>3d}  {h:>18s}  {prob:>8.4f}  {sc:>8d}  {rec:>8s}  {dec:>8s}")


def print_scanner_zero_pct(records: list[dict]) -> None:
    _header("Scanner Score == 0 Rate")
    zero = sum(1 for r in records if r.get("scanner_score", -1) == 0)
    total = len(records)
    pct = 100 * zero / total if total else 0
    print(f"  scanner_score == 0: {zero}/{total} ({pct:.1f}%)")
    print(f"  (These are commands the regex scanner found completely clean)")


def write_candidate_set(records: list[dict], out_path: str) -> int:
    """Write candidate records for targeted retraining.

    Selection criteria:
    - scanner_score < 20
    - ml_injection_prob between 0.60 and 0.90 OR ml_recommendation in {review, block}

    Only hashed fields are written — never raw text.
    """
    candidates = []
    for r in records:
        sc = r.get("scanner_score")
        prob = r.get("ml_injection_prob", 0.0)
        rec = r.get("ml_recommendation", "allow")

        if sc is None or sc >= 20:
            continue

        prob_in_range = 0.60 <= prob <= 0.90
        rec_flagged = rec in ("review", "block")

        if prob_in_range or rec_flagged:
            candidates.append({
                "text_hash": r.get("text_hash"),
                "scanner_score": sc,
                "ml_status": r.get("ml_status"),
                "ml_injection_prob": prob,
                "ml_recommendation": rec,
                "decision": r.get("decision"),
                "engine_action": r.get("engine_action"),
                "ngram_hints": r.get("ngram_hints", []),
                "ts": r.get("ts"),
            })

    with open(out_path, "w", encoding="utf-8") as f:
        for c in candidates:
            f.write(json.dumps(c) + "\n")

    return len(candidates)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Analyze ShieldPilot active-learning logs"
    )
    ap.add_argument("--log", required=True, help="Path to active-learning JSONL")
    ap.add_argument(
        "--last", type=int, default=2000,
        help="Analyze only the last N records (default: 2000)",
    )
    ap.add_argument(
        "--out", default="candidate_set.jsonl",
        help="Output path for candidate set (default: candidate_set.jsonl)",
    )
    ap.add_argument(
        "--top", type=int, default=30,
        help="Number of top hashes to print (default: 30)",
    )
    args = ap.parse_args(argv)

    if not os.path.isfile(args.log):
        print(f"ERROR: Log file not found: {args.log}", file=sys.stderr)
        return 1

    records = load_records(args.log, args.last)
    if not records:
        print("ERROR: No valid records in log file.", file=sys.stderr)
        return 1

    _header(f"ShieldPilot Active-Learning Log Analysis")
    print(f"  Log file: {args.log}")
    print(f"  Records loaded: {len(records)}")

    print_recommendation_counts(records)
    print_prob_histogram(records)
    print_top_hashes(records, args.top)
    print_scanner_zero_pct(records)

    # Write candidate set
    n_candidates = write_candidate_set(records, args.out)
    _header("Candidate Set for Retraining")
    print(f"  Written {n_candidates} candidates to {args.out}")
    print(f"  Selection: scanner_score < 20 AND (0.60 <= ml_prob <= 0.90 OR rec in {{review, block}})")

    # Quick readiness check
    _header("Rollout Decision Hints")
    total = len(records)
    block_count = sum(1 for r in records if r.get("ml_recommendation") == "block")
    review_count = sum(1 for r in records if r.get("ml_recommendation") == "review")

    if total < 200:
        print(f"  WAIT: Only {total} records. Need 200+ for reliable assessment.")
    else:
        block_rate = block_count / total
        review_rate = review_count / total
        if block_rate > 0.05:
            print(f"  CAUTION: {block_count} block recommendations ({block_rate:.1%}).")
            print(f"  Review candidate_set.jsonl ngram_hints for false positives.")
        elif review_rate > 0.15:
            print(f"  NOTE: {review_count} review recommendations ({review_rate:.1%}).")
            print(f"  Consider raising SENTINEL_ML_REVIEW_THRESHOLD before enforce.")
        else:
            print(f"  LOOKS GOOD: block rate {block_rate:.1%}, review rate {review_rate:.1%}.")
            print(f"  Safe to proceed with enforce at SENTINEL_ML_BLOCK_THRESHOLD=0.90.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
