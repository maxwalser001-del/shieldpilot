#!/usr/bin/env python3
"""OOD sanity check: verify ML model scores clean shell commands low.

Loads ml_model.joblib, samples 50 lines from clean_shell_5k.txt,
and prints min/median/max ml_injection_prob.

Target (soft): median < 0.30, max < 0.70.
"""

from __future__ import annotations

import os
import random
import sys

import joblib
import numpy as np

MODEL_PATH = "sentinelai/ml/ml_model.joblib"
CLEAN_FILE = "clean_shell_5k.txt"
SAMPLE_SIZE = 50
SEED = 42


def main():
    if not os.path.isfile(MODEL_PATH):
        print(f"ERROR: Model not found at {MODEL_PATH}", file=sys.stderr)
        return 1

    if not os.path.isfile(CLEAN_FILE):
        print(f"ERROR: Clean dataset not found at {CLEAN_FILE}", file=sys.stderr)
        return 1

    # Load model
    pipe = joblib.load(MODEL_PATH)
    classes = list(pipe.classes_)

    # Find injection class index
    from sentinelai.ml.labels import LABEL_TO_ID
    injection_idx = classes.index(LABEL_TO_ID["injection"])

    # Load clean commands
    commands = []
    with open(CLEAN_FILE) as f:
        for line in f:
            line = line.strip()
            if line and " || " in line:
                commands.append(line.split(" || ", 1)[1])

    # Sample
    random.seed(SEED)
    sample = random.sample(commands, min(SAMPLE_SIZE, len(commands)))

    # Predict
    proba = pipe.predict_proba(sample)
    injection_probs = proba[:, injection_idx]

    # Stats
    mn = float(np.min(injection_probs))
    med = float(np.median(injection_probs))
    mx = float(np.max(injection_probs))
    mean = float(np.mean(injection_probs))
    p95 = float(np.percentile(injection_probs, 95))

    print("=" * 60)
    print("  OOD Sanity Check: Clean Shell Commands")
    print("=" * 60)
    print(f"  Model:   {MODEL_PATH}")
    print(f"  Source:   {CLEAN_FILE}")
    print(f"  Sample:   {len(sample)} commands")
    print()
    print(f"  ml_injection_prob stats:")
    print(f"    min:    {mn:.4f}")
    print(f"    median: {med:.4f}  {'PASS' if med < 0.30 else 'FAIL'} (target < 0.30)")
    print(f"    mean:   {mean:.4f}")
    print(f"    p95:    {p95:.4f}")
    print(f"    max:    {mx:.4f}  {'PASS' if mx < 0.70 else 'FAIL'} (target < 0.70)")
    print()

    # Show worst 5
    sorted_idx = np.argsort(injection_probs)[::-1]
    print("  Top 5 highest-scoring clean commands:")
    for i, idx in enumerate(sorted_idx[:5], 1):
        cmd = sample[idx]
        prob = injection_probs[idx]
        print(f"    {i}. [{prob:.4f}] {cmd[:80]}")

    # Show best 5
    print("\n  Top 5 lowest-scoring clean commands:")
    for i, idx in enumerate(sorted_idx[-5:][::-1], 1):
        cmd = sample[idx]
        prob = injection_probs[idx]
        print(f"    {i}. [{prob:.4f}] {cmd[:80]}")

    if med < 0.30 and mx < 0.70:
        print("\n  VERDICT: PASS — OOD false positive rate acceptable.")
    elif med < 0.30:
        print(f"\n  VERDICT: PARTIAL — median OK but max={mx:.4f} > 0.70. Some outliers.")
    else:
        print(f"\n  VERDICT: FAIL — median={med:.4f} >= 0.30. Model needs more CLEAN training data.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
