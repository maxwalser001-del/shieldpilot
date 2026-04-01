"""Evaluate (and optionally train) the ShieldPilot ML injection classifier.

Usage:
    # Evaluate an existing model on a dataset
    python -m sentinelai.ml.eval --data dataset.txt

    # Train a new model and evaluate it
    python -m sentinelai.ml.eval --data dataset.txt --train

    # Custom model path and seed
    python -m sentinelai.ml.eval --data dataset.txt --model my_model.joblib --seed 42
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

from .labels import EXTERNAL_TO_INTERNAL, ID_TO_LABEL, LABEL_TO_ID, LABELS
from .ml_train import load_dataset


def _print_header(title: str) -> None:
    print(f"\n{'=' * 60}")
    print(f"  {title}")
    print(f"{'=' * 60}")


def _print_split_counts(name: str, y: list[int]) -> None:
    counts = Counter(y)
    parts = [f"{ID_TO_LABEL[k]}: {counts.get(k, 0)}" for k in sorted(counts)]
    print(f"  {name:>5s} ({len(y):>5d}):  {', '.join(parts)}")


def _print_confusion_matrix(y_true: list[int], y_pred: list[int]) -> None:
    _print_header("Confusion Matrix")
    cm = confusion_matrix(y_true, y_pred, labels=list(range(len(LABELS))))
    # Header row
    header = "          " + "  ".join(f"{ID_TO_LABEL[i]:>10s}" for i in range(len(LABELS)))
    print(header)
    print("          " + "  ".join("-" * 10 for _ in LABELS))
    for i, row in enumerate(cm):
        cells = "  ".join(f"{v:>10d}" for v in row)
        print(f"{ID_TO_LABEL[i]:>10s}  {cells}")
    print(f"\n  Rows = actual, Columns = predicted")


def _threshold_sweep(
    y_true: list[int], proba: np.ndarray, labels_list: list[str]
) -> str | None:
    """Sweep injection thresholds and print a table.

    Returns the suggested threshold or None.
    """
    _print_header("Injection Threshold Sweep (test set)")

    injection_id = LABEL_TO_ID["injection"]
    hard_id = LABEL_TO_ID["hard"]

    injection_probs = proba[:, injection_id]

    # Masks for actual classes
    is_injection = np.array([y == injection_id for y in y_true])
    is_hard = np.array([y == hard_id for y in y_true])

    n_injection = is_injection.sum()
    n_hard = is_hard.sum()

    thresholds = [0.50, 0.60, 0.70, 0.80, 0.90]

    print(f"\n  {'Threshold':>10s}  {'Inj Recall':>10s}  {'Inj Prec':>10s}  {'HARD FPR':>10s}")
    print(f"  {'-' * 10}  {'-' * 10}  {'-' * 10}  {'-' * 10}")

    best_threshold = None
    results = []

    for t in thresholds:
        pred_injection = injection_probs >= t

        # Injection recall: of actual injections, how many caught
        inj_recall = pred_injection[is_injection].sum() / max(n_injection, 1)

        # Injection precision: of predicted injections, how many are real
        n_pred_inj = pred_injection.sum()
        inj_precision = (
            pred_injection[is_injection].sum() / max(n_pred_inj, 1)
            if n_pred_inj > 0
            else 0.0
        )

        # HARD false positive rate: of actual HARD samples, how many flagged as injection
        hard_fpr = pred_injection[is_hard].sum() / max(n_hard, 1) if n_hard > 0 else 0.0

        print(f"  {t:>10.2f}  {inj_recall:>10.3f}  {inj_precision:>10.3f}  {hard_fpr:>10.3f}")
        results.append((t, inj_recall, inj_precision, hard_fpr))

    # Suggest threshold
    _print_header("Threshold Recommendation")

    candidates = [
        (t, rec, prec, fpr)
        for t, rec, prec, fpr in results
        if rec >= 0.95 and fpr <= 0.05
    ]

    if candidates:
        best = candidates[0]  # smallest threshold meeting criteria
        best_threshold = best[0]
        print(
            f"  Suggested: {best_threshold:.2f}\n"
            f"  (injection recall {best[1]:.3f}, HARD FPR {best[3]:.3f})\n"
            f"  Meets target: recall >= 0.95 AND HARD FPR <= 0.05"
        )
    else:
        # Find best tradeoff: maximize recall - FPR
        best_score = -1.0
        best_row = results[0]
        for row in results:
            score = row[1] - row[3]  # recall - hard_fpr
            if score > best_score:
                best_score = score
                best_row = row
        best_threshold = best_row[0]
        print(
            f"  No threshold meets both targets (recall >= 0.95, HARD FPR <= 0.05).\n"
            f"  Best tradeoff: {best_threshold:.2f}\n"
            f"  (injection recall {best_row[1]:.3f}, HARD FPR {best_row[3]:.3f})\n"
            f"  Consider collecting more training data for HARD cases."
        )

    return f"{best_threshold:.2f}"


def build_pipeline() -> Pipeline:
    """Build the standard ShieldPilot ML pipeline."""
    base = LogisticRegression(max_iter=5000, class_weight="balanced")
    clf = CalibratedClassifierCV(base, method="sigmoid", cv=3)
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    ngram_range=(1, 3),
                    min_df=2,
                    max_df=0.95,
                    lowercase=True,
                ),
            ),
            ("clf", clf),
        ]
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Evaluate ShieldPilot ML injection classifier"
    )
    ap.add_argument(
        "--data", required=True, help="Path to dataset (LABEL || TEXT per line)"
    )
    ap.add_argument(
        "--model",
        default="sentinelai/ml/ml_model.joblib",
        help="Path to model file (default: sentinelai/ml/ml_model.joblib)",
    )
    ap.add_argument("--seed", type=int, default=13, help="Random seed (default: 13)")
    ap.add_argument(
        "--train",
        action="store_true",
        help="Train a new model before evaluating (saves to --model path)",
    )
    args = ap.parse_args(argv)

    # ── Load dataset ──────────────────────────────────────────
    rows = load_dataset(args.data)
    X = [t for _, t in rows]
    y = [LABEL_TO_ID[l] for l, _ in rows]

    _print_header("Dataset Summary")
    _print_split_counts("total", y)

    # ── Stratified split: 80/10/10 ────────────────────────────
    # First split: 80% train, 20% temp
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.20, random_state=args.seed, stratify=y
    )
    # Second split: 50/50 of temp → 10% val, 10% test
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=args.seed, stratify=y_temp
    )

    _print_split_counts("train", y_train)
    _print_split_counts("val", y_val)
    _print_split_counts("test", y_test)

    # ── Train or load model ───────────────────────────────────
    if args.train:
        _print_header("Training")
        pipe = build_pipeline()
        pipe.fit(X_train, y_train)
        joblib.dump(pipe, args.model)
        print(f"  Model saved to {args.model}")
        print(f"  Training samples: {len(X_train)}")
    else:
        _print_header("Loading Model")
        try:
            pipe = joblib.load(args.model)
            print(f"  Loaded from {args.model}")
        except FileNotFoundError:
            print(f"  ERROR: Model not found at {args.model}")
            print(f"  Run with --train to train a new model first.")
            return 1

    # ── Evaluate on test set ──────────────────────────────────
    y_pred = pipe.predict(X_test)
    proba = pipe.predict_proba(X_test)

    _print_header("Classification Report (test set)")
    report = classification_report(
        y_test,
        y_pred,
        target_names=LABELS,
        digits=3,
        zero_division=0,
    )
    print(report)

    _print_confusion_matrix(y_test, y_pred)

    # ── Threshold sweep ───────────────────────────────────────
    suggested = _threshold_sweep(y_test, proba, LABELS)

    # ── Val set performance (quick sanity check) ──────────────
    if len(X_val) > 0:
        y_val_pred = pipe.predict(X_val)
        _print_header("Validation Set (sanity check)")
        val_report = classification_report(
            y_val,
            y_val_pred,
            target_names=LABELS,
            digits=3,
            zero_division=0,
        )
        print(val_report)

    print(f"\nDone. Suggested injection threshold: {suggested}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
