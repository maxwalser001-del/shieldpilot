#!/usr/bin/env python3
"""Build dataset_mix_v3.txt from multiple sources.

Inputs:
  - dataset_10k_dedup.txt (existing deduped dataset)
  - boosters_holdout.txt (holdout boosters — generated if missing)
  - clean_shell_5k.txt (clean shell commands — generated if missing)
  - hard_negatives_2k.txt (HARD negatives — generated if missing)

Process:
  1. Load all sources
  2. Deduplicate globally by TEXT
  3. Cap per-class counts with reproducible sampling (seed 13):
     - INJECTION: max 6000
     - CLEAN: max 6000
     - HARD: max 2500
  4. Shuffle and write dataset_mix_v3.txt

Output: dataset_mix_v3.txt at repo root (LABEL || TEXT per line)
"""

from __future__ import annotations

import os
import random
import subprocess
import sys
from collections import Counter

SEED = 13
OUTPUT_FILE = "dataset_mix_v3.txt"

CAPS = {
    "INJECTION": 6000,
    "CLEAN": 6000,
    "HARD": 2500,
}

INPUT_FILES = [
    "dataset_10k_dedup.txt",
    "boosters_holdout.txt",
    "clean_shell_5k.txt",
    "hard_negatives_2k.txt",
]

GENERATORS = {
    "boosters_holdout.txt": "tests/generate_hard_holdout_boosters.py",
    "clean_shell_5k.txt": "tests/generate_clean_shell_commands.py",
    "hard_negatives_2k.txt": "tests/generate_hard_negatives.py",
}


def _ensure_file(filename: str) -> None:
    """Generate file if it doesn't exist."""
    if os.path.isfile(filename):
        return
    gen = GENERATORS.get(filename)
    if gen and os.path.isfile(gen):
        print(f"  Generating {filename} via {gen}...")
        result = subprocess.run(
            [sys.executable, gen],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode != 0:
            print(f"  ERROR: {gen} failed:\n{result.stderr}", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"  ERROR: {filename} not found and no generator available.", file=sys.stderr)
        sys.exit(1)


def load_file(path: str) -> list[tuple[str, str]]:
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or " || " not in line:
                continue
            label, text = line.split(" || ", 1)
            rows.append((label.upper(), text))
    return rows


def main():
    print(f"Building {OUTPUT_FILE} (seed={SEED})")

    # Ensure all inputs exist
    for f in INPUT_FILES:
        _ensure_file(f)

    # Load all sources
    all_rows: list[tuple[str, str]] = []
    for f in INPUT_FILES:
        rows = load_file(f)
        print(f"  Loaded {f}: {len(rows)} rows")
        all_rows.extend(rows)

    print(f"  Total before dedup: {len(all_rows)}")

    # Global dedup by text
    seen: set[str] = set()
    deduped: list[tuple[str, str]] = []
    for label, text in all_rows:
        if text not in seen:
            seen.add(text)
            deduped.append((label, text))

    print(f"  After global dedup: {len(deduped)}")
    counts = Counter(l for l, _ in deduped)
    for label in ["INJECTION", "CLEAN", "HARD"]:
        print(f"    {label}: {counts.get(label, 0)}")

    # Cap per-class counts
    random.seed(SEED)
    by_class: dict[str, list[tuple[str, str]]] = {}
    for label, text in deduped:
        by_class.setdefault(label, []).append((label, text))

    final: list[tuple[str, str]] = []
    for label, cap in CAPS.items():
        pool = by_class.get(label, [])
        if len(pool) > cap:
            random.shuffle(pool)
            pool = pool[:cap]
        final.extend(pool)
        print(f"  Capped {label}: {len(pool)} (cap={cap})")

    random.shuffle(final)

    # Write
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for label, text in final:
            f.write(f"{label} || {text}\n")

    final_counts = Counter(l for l, _ in final)
    print(f"\n  Written {len(final)} samples to {OUTPUT_FILE}")
    for label in ["INJECTION", "CLEAN", "HARD"]:
        print(f"    {label}: {final_counts.get(label, 0)}")


if __name__ == "__main__":
    main()
