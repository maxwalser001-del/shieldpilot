"""Train the ML classifier for prompt injection detection.

Usage:
    python -m sentinelai.ml.ml_train --data dataset_10k.txt --out sentinelai/ml/ml_model.joblib

Dataset format (one per line):
    LABEL || TEXT
Labels: INJECTION, CLEAN, HARD
"""

from __future__ import annotations

import argparse

import joblib
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from .labels import EXTERNAL_TO_INTERNAL, LABEL_TO_ID


def load_dataset(path: str):
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if "||" not in line:
                continue
            left, right = line.split("||", 1)
            ext_label = left.strip().upper()
            text = right.strip()
            if ext_label not in EXTERNAL_TO_INTERNAL:
                continue
            label = EXTERNAL_TO_INTERNAL[ext_label]
            rows.append((label, text))
    if not rows:
        raise ValueError(
            "Dataset is empty or invalid format. Expected: LABEL || TEXT per line."
        )
    return rows


def main():
    ap = argparse.ArgumentParser(description="Train ShieldPilot ML injection classifier")
    ap.add_argument(
        "--data", required=True, help="Path to dataset file with lines LABEL || TEXT"
    )
    ap.add_argument("--out", default="sentinelai/ml/ml_model.joblib")
    args = ap.parse_args()

    rows = load_dataset(args.data)
    X = [t for _, t in rows]
    y = [LABEL_TO_ID[l] for l, _ in rows]

    base = LogisticRegression(max_iter=5000, class_weight="balanced")
    clf = CalibratedClassifierCV(base, method="sigmoid", cv=3)

    pipe = Pipeline(
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

    pipe.fit(X, y)
    joblib.dump(pipe, args.out)
    print(f"Saved model to {args.out}. Rows used: {len(rows)}")


if __name__ == "__main__":
    main()
