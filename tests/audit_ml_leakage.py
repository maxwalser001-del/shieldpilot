#!/usr/bin/env python3
"""ML Dataset Leakage & Reality Check Audit.

Part A: Dedup, hard-holdout split, train+eval on both
Part B: Top ngram artifact inspection
Part C: Active-learning log analysis

Read-only on production code. Creates dataset_10k_dedup.txt.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

# ── Constants ──────────────────────────────────────────────────
LABELS = ["clean", "hard", "injection"]
LABEL_TO_ID = {l: i for i, l in enumerate(LABELS)}
ID_TO_LABEL = {i: l for i, l in enumerate(LABELS)}
EXT_TO_INT = {"clean": "clean", "hard": "hard", "injection": "injection"}

DATASET_PATH = "dataset_10k.txt"
DEDUP_PATH = "dataset_10k_dedup.txt"
SEED = 42

# Keyword families for hard-holdout (from generate_10k.py categories)
KEYWORD_FAMILIES = {
    "presupposition": [
        "previously discussed", "as noted", "as established", "building on",
        "continuing from", "following up", "per the earlier", "since we already",
        "as the admin confirmed", "stakeholders already reviewed",
        "continuation of the approved", "team lead's instruction",
        "kickoff", "testing session", "sandbox restrictions",
    ],
    "workflow_spoof": [
        "ticket SR-", "CR-", "JIRA-", "INC-", "DG-", "CRQ-", "SC-",
        "CAB-", "TP-", "RB-", "pull request #", "deployment pipeline",
        "QA sign-off", "pre-release checklist", "incident response team",
        "compliance scan", "release manager", "change advisory board",
        "penetration testing scope", "approved runbook",
    ],
    "config_shift": [
        "filtering\": false", "safety_mode=disabled", "restrictions=none",
        "content_filter: off", "disable_guardrails", "output.redaction=false",
        "moderation: skip", "safety_checks=bypassed", "CONTENT_FILTER=0",
        "SHOW_SYSTEM_PROMPT=1", "restrict_output", "guardrails=legacy",
        "SAFETY_MODE=permissive", "output sanitization",
        "feature flag", "config revision", "settings migration",
        "deployment manifest", ".env file",
    ],
    "benchmark_poison": [
        "benchmark evaluation", "fairness audit", "calibration test",
        "capability assessment", "academic research protocol",
        "evaluation measures", "red team assessment", "safety benchmark",
        "performance evaluation rubric", "transparency audit",
        "scoring criteria", "comparative analysis", "test harness",
        "evaluation framework", "scoring rubric",
    ],
}


def _header(title: str) -> None:
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}")


# ══════════════════════════════════════════════════════════════
# Part A — Dataset leakage and dedup audit
# ══════════════════════════════════════════════════════════════


def load_raw(path: str) -> list[tuple[str, str]]:
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or " || " not in line:
                continue
            label, text = line.split(" || ", 1)
            rows.append((label.upper(), text))
    return rows


def part_a_dedup(rows: list[tuple[str, str]]):
    _header("PART A.1 — Duplicate Analysis")

    total = len(rows)
    texts = [t for _, t in rows]
    unique_texts = set(texts)
    dup_count = total - len(unique_texts)
    print(f"  Total samples:       {total}")
    print(f"  Unique texts:        {len(unique_texts)}")
    print(f"  Exact duplicates:    {dup_count} ({100*dup_count/total:.1f}%)")

    # Per-label duplicate counts
    print(f"\n  Per-label duplicates:")
    for label in ["INJECTION", "CLEAN", "HARD"]:
        label_texts = [t for l, t in rows if l == label]
        label_unique = set(label_texts)
        label_dups = len(label_texts) - len(label_unique)
        print(f"    {label:>10s}: {len(label_texts)} total, {len(label_unique)} unique, "
              f"{label_dups} dups ({100*label_dups/max(len(label_texts),1):.1f}%)")

    # Cross-label collision check
    label_text_sets = {}
    for label in ["INJECTION", "CLEAN", "HARD"]:
        label_text_sets[label] = set(t for l, t in rows if l == label)

    cross_collisions = 0
    for t in unique_texts:
        labels_with = [l for l in label_text_sets if t in label_text_sets[l]]
        if len(labels_with) > 1:
            cross_collisions += 1
    print(f"\n  Cross-label collisions (same text, different labels): {cross_collisions}")

    # ── A.2: Deduplicate ──
    _header("PART A.2 — Deduplicated Dataset")

    seen = set()
    dedup_rows = []
    for label, text in rows:
        if text not in seen:
            seen.add(text)
            dedup_rows.append((label, text))

    # Save
    with open(DEDUP_PATH, "w", encoding="utf-8") as f:
        for label, text in dedup_rows:
            f.write(f"{label} || {text}\n")

    dedup_counts = Counter(l for l, _ in dedup_rows)
    print(f"  Saved {len(dedup_rows)} unique samples to {DEDUP_PATH}")
    for label in ["INJECTION", "CLEAN", "HARD"]:
        print(f"    {label:>10s}: {dedup_counts.get(label, 0)}")

    return dedup_rows


def classify_family(text: str) -> str | None:
    """Assign a text to a keyword family, or None."""
    text_lower = text.lower()
    for family, keywords in KEYWORD_FAMILIES.items():
        for kw in keywords:
            if kw.lower() in text_lower:
                return family
    return None


def part_a_hard_holdout(dedup_rows: list[tuple[str, str]]):
    _header("PART A.3 — Hard Holdout Split (by keyword family)")

    # Classify each row
    family_map: dict[str, list[tuple[str, str]]] = {}
    unclassified = []
    for label, text in dedup_rows:
        fam = classify_family(text)
        if fam:
            family_map.setdefault(fam, []).append((label, text))
        else:
            unclassified.append((label, text))

    print(f"  Family distribution:")
    for fam in sorted(family_map):
        fam_labels = Counter(l for l, _ in family_map[fam])
        print(f"    {fam:>20s}: {len(family_map[fam]):>5d}  "
              f"(INJ={fam_labels.get('INJECTION',0)}, "
              f"CLN={fam_labels.get('CLEAN',0)}, "
              f"HRD={fam_labels.get('HARD',0)})")
    print(f"    {'(no family)':>20s}: {len(unclassified):>5d}")

    # Hold out 2 families for test
    # Pick the two with most INJECTION samples
    fam_inj_count = {f: sum(1 for l, _ in rows if l == "INJECTION")
                     for f, rows in family_map.items()}
    sorted_fams = sorted(fam_inj_count, key=fam_inj_count.get, reverse=True)

    if len(sorted_fams) >= 2:
        holdout_fams = sorted_fams[:2]
    else:
        holdout_fams = sorted_fams[:1]

    print(f"\n  Held-out families: {holdout_fams}")

    # Build train vs test
    holdout_test = []
    train_pool = list(unclassified)
    for fam in sorted(family_map):
        if fam in holdout_fams:
            holdout_test.extend(family_map[fam])
        else:
            train_pool.extend(family_map[fam])

    print(f"  Train pool: {len(train_pool)}")
    print(f"  Holdout test: {len(holdout_test)}")

    train_labels = Counter(l for l, _ in train_pool)
    test_labels = Counter(l for l, _ in holdout_test)
    print(f"  Train labels: {dict(train_labels)}")
    print(f"  Test labels:  {dict(test_labels)}")

    return train_pool, holdout_test, holdout_fams


def build_pipeline() -> Pipeline:
    base = LogisticRegression(max_iter=5000, class_weight="balanced")
    clf = CalibratedClassifierCV(base, method="sigmoid", cv=3)
    return Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 3), min_df=2, max_df=0.95, lowercase=True)),
        ("clf", clf),
    ])


def train_and_eval(X_train, y_train, X_test, y_test, title: str) -> Pipeline:
    _header(f"Train + Eval: {title}")

    pipe = build_pipeline()
    pipe.fit(X_train, y_train)

    y_pred = pipe.predict(X_test)
    proba = pipe.predict_proba(X_test)

    print(f"\n  Train: {len(X_train)}, Test: {len(X_test)}")
    train_counts = Counter(y_train)
    test_counts = Counter(y_test)
    print(f"  Train dist: {', '.join(f'{ID_TO_LABEL[k]}={v}' for k, v in sorted(train_counts.items()))}")
    print(f"  Test dist:  {', '.join(f'{ID_TO_LABEL[k]}={v}' for k, v in sorted(test_counts.items()))}")

    print(f"\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=LABELS, digits=3, zero_division=0))

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred, labels=list(range(len(LABELS))))
    print(f"  Confusion Matrix (rows=actual, cols=predicted):")
    header = "          " + "  ".join(f"{LABELS[i]:>10s}" for i in range(len(LABELS)))
    print(header)
    for i, row in enumerate(cm):
        cells = "  ".join(f"{v:>10d}" for v in row)
        print(f"  {LABELS[i]:>10s}  {cells}")

    # Threshold sweep
    injection_id = LABEL_TO_ID["injection"]
    hard_id = LABEL_TO_ID["hard"]
    injection_probs = proba[:, injection_id]
    is_injection = np.array([y == injection_id for y in y_test])
    is_hard = np.array([y == hard_id for y in y_test])
    n_inj = is_injection.sum()
    n_hard = is_hard.sum()

    print(f"\n  Threshold Sweep:")
    print(f"  {'Thresh':>8s}  {'Inj Recall':>10s}  {'Inj Prec':>10s}  {'HARD FPR':>10s}")
    print(f"  {'--------':>8s}  {'----------':>10s}  {'----------':>10s}  {'----------':>10s}")

    for t in [0.50, 0.60, 0.70, 0.80, 0.90]:
        pred_inj = injection_probs >= t
        recall = pred_inj[is_injection].sum() / max(n_inj, 1)
        n_pred = pred_inj.sum()
        prec = pred_inj[is_injection].sum() / max(n_pred, 1) if n_pred > 0 else 0.0
        fpr = pred_inj[is_hard].sum() / max(n_hard, 1) if n_hard > 0 else 0.0
        print(f"  {t:>8.2f}  {recall:>10.3f}  {prec:>10.3f}  {fpr:>10.3f}")

    return pipe


def part_a_train_eval(dedup_rows, train_pool, holdout_test):
    _header("PART A.4 — Training & Evaluation")

    # (a) Normal stratified split on dedup dataset
    X_all = [t for _, t in dedup_rows]
    y_all = [LABEL_TO_ID[l.lower()] for l, _ in dedup_rows]

    X_train, X_test, y_train, y_test = train_test_split(
        X_all, y_all, test_size=0.20, random_state=SEED, stratify=y_all
    )

    pipe_normal = train_and_eval(
        X_train, y_train, X_test, y_test,
        "Normal Stratified Split (dedup)"
    )

    # (b) Hard holdout split
    X_ho_train = [t for _, t in train_pool]
    y_ho_train = [LABEL_TO_ID[l.lower()] for l, _ in train_pool]
    X_ho_test = [t for _, t in holdout_test]
    y_ho_test = [LABEL_TO_ID[l.lower()] for l, _ in holdout_test]

    pipe_holdout = None
    if len(X_ho_test) > 0 and len(set(y_ho_test)) > 0:
        pipe_holdout = train_and_eval(
            X_ho_train, y_ho_train, X_ho_test, y_ho_test,
            "Hard Holdout (unseen keyword families)"
        )
    else:
        print("  [SKIP] Holdout test set empty or single-class.")

    return pipe_normal, pipe_holdout


# ══════════════════════════════════════════════════════════════
# Part B — Artifact Inspection
# ══════════════════════════════════════════════════════════════


def part_b_ngrams(pipe: Pipeline):
    _header("PART B — Top Ngram Feature Inspection")

    tfidf: TfidfVectorizer = pipe.named_steps["tfidf"]
    clf_wrapper = pipe.named_steps["clf"]

    # Extract the base LogisticRegression from inside CalibratedClassifierCV
    # CalibratedClassifierCV stores calibrated classifiers in .calibrated_classifiers_
    # Each has a .estimator with .coef_
    # Average coefficients across CV folds for stability
    feature_names = tfidf.get_feature_names_out()

    try:
        coefs_sum = np.zeros((len(LABELS), len(feature_names)))
        n_cal = len(clf_wrapper.calibrated_classifiers_)
        for cal_clf in clf_wrapper.calibrated_classifiers_:
            base_est = cal_clf.estimator
            coefs_sum += base_est.coef_
        avg_coefs = coefs_sum / n_cal
    except Exception as e:
        print(f"  Could not extract coefficients: {e}")
        return

    injection_id = LABEL_TO_ID["injection"]
    clean_id = LABEL_TO_ID["clean"]
    hard_id = LABEL_TO_ID["hard"]

    # Injection vs Clean: features that push toward injection (positive coef for injection class)
    inj_coefs = avg_coefs[injection_id]
    clean_coefs = avg_coefs[clean_id]
    hard_coefs = avg_coefs[hard_id]

    # Differential: injection - clean
    diff_inj_clean = inj_coefs - clean_coefs
    top30_inj_clean = np.argsort(diff_inj_clean)[-30:][::-1]

    print(f"\n  Top 30 ngrams: INJECTION vs CLEAN (highest differential)")
    print(f"  {'Rank':>4s}  {'Ngram':>35s}  {'Inj coef':>10s}  {'Cln coef':>10s}  {'Diff':>10s}")
    print(f"  {'----':>4s}  {'-----':>35s}  {'--------':>10s}  {'--------':>10s}  {'----':>10s}")
    flagged_artifacts_ic = []
    for rank, idx in enumerate(top30_inj_clean, 1):
        ngram = feature_names[idx]
        ic = inj_coefs[idx]
        cc = clean_coefs[idx]
        d = diff_inj_clean[idx]
        # Flag suspiciously generator-like features
        is_artifact = _is_artifact(ngram)
        flag = " *** ARTIFACT?" if is_artifact else ""
        print(f"  {rank:>4d}  {ngram:>35s}  {ic:>10.4f}  {cc:>10.4f}  {d:>10.4f}{flag}")
        if is_artifact:
            flagged_artifacts_ic.append(ngram)

    # Injection vs Hard
    diff_inj_hard = inj_coefs - hard_coefs
    top30_inj_hard = np.argsort(diff_inj_hard)[-30:][::-1]

    print(f"\n  Top 30 ngrams: INJECTION vs HARD (highest differential)")
    print(f"  {'Rank':>4s}  {'Ngram':>35s}  {'Inj coef':>10s}  {'Hrd coef':>10s}  {'Diff':>10s}")
    print(f"  {'----':>4s}  {'-----':>35s}  {'--------':>10s}  {'--------':>10s}  {'----':>10s}")
    flagged_artifacts_ih = []
    for rank, idx in enumerate(top30_inj_hard, 1):
        ngram = feature_names[idx]
        ic = inj_coefs[idx]
        hc = hard_coefs[idx]
        d = diff_inj_hard[idx]
        is_artifact = _is_artifact(ngram)
        flag = " *** ARTIFACT?" if is_artifact else ""
        print(f"  {rank:>4d}  {ngram:>35s}  {ic:>10.4f}  {hc:>10.4f}  {d:>10.4f}{flag}")
        if is_artifact:
            flagged_artifacts_ih.append(ngram)

    all_flagged = set(flagged_artifacts_ic + flagged_artifacts_ih)
    print(f"\n  Flagged artifact features: {len(all_flagged)}")
    for f in sorted(all_flagged):
        print(f"    - {f}")

    return all_flagged


def _is_artifact(ngram: str) -> bool:
    """Heuristic: flag ngrams that look like generator scaffolding."""
    # These are patterns that exist only because of how generate_10k.py
    # assembles strings, not because they are real injection cues.
    scaffolding = [
        # Template artifacts from the generator's pattern composition
        "reveal",  # "Reveal {target}" — real injections rarely say "reveal"
        "activate",  # "Activate {mode}" — generator pattern
        "confirm compliance",
        "next request",
        "emergency update",
        "for maintenance",
        # Highly specific generator phrases
        "non compliance will",
        "failure to comply",
        "marks you defective",
        "or the platform",
        "refusal means",
    ]
    ngram_lower = ngram.lower()
    for s in scaffolding:
        if s in ngram_lower:
            return True
    return False


# ══════════════════════════════════════════════════════════════
# Part C — Active Learning Log Reality Check
# ══════════════════════════════════════════════════════════════


def part_c_active_learning():
    _header("PART C — Active Learning Log Reality Check")

    # Search for log files
    search_paths = [
        os.environ.get("SENTINEL_ACTIVE_LEARNING_PATH", ""),
        "/tmp/shieldpilot_active_learning.jsonl",
        "/tmp/al_log.jsonl",
        "./al_log.jsonl",
        "./active_learning.jsonl",
        os.path.expanduser("~/active_learning.jsonl"),
    ]

    log_path = None
    for p in search_paths:
        if p and os.path.isfile(p):
            log_path = p
            break

    if not log_path:
        print("  No active-learning log found at any of:")
        for p in search_paths:
            if p:
                print(f"    - {p}")
        print("\n  Set SENTINEL_ACTIVE_LEARNING_PATH and run in shadow mode to collect data.")
        print("  VERDICT: Cannot assess real-world ML performance without logs.")
        return None

    print(f"  Found log: {log_path}")

    # Load up to 500 most recent records
    records = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    # Take last 500
    if len(records) > 500:
        records = records[-500:]

    print(f"  Records loaded: {len(records)}")

    if not records:
        print("  Log file is empty.")
        return None

    # Distribution of scanner_score
    scanner_scores = [r.get("scanner_score", -1) for r in records]
    print(f"\n  Scanner Score Distribution:")
    buckets = {"0": 0, "1-19": 0, "20-69": 0, "70+": 0}
    for s in scanner_scores:
        if s == 0:
            buckets["0"] += 1
        elif s < 20:
            buckets["1-19"] += 1
        elif s < 70:
            buckets["20-69"] += 1
        else:
            buckets["70+"] += 1
    for b, c in buckets.items():
        print(f"    {b:>8s}: {c}")

    # Distribution of ml_injection_prob
    ml_probs = [r.get("ml_injection_prob", 0.0) for r in records]
    print(f"\n  ML Injection Probability Distribution:")
    prob_buckets = {"< 0.20": 0, "0.20-0.59": 0, "0.60-0.79": 0, ">= 0.80": 0}
    for p in ml_probs:
        if p < 0.20:
            prob_buckets["< 0.20"] += 1
        elif p < 0.60:
            prob_buckets["0.20-0.59"] += 1
        elif p < 0.80:
            prob_buckets["0.60-0.79"] += 1
        else:
            prob_buckets[">= 0.80"] += 1
    for b, c in prob_buckets.items():
        print(f"    {b:>12s}: {c}")

    # Counts of ml_recommendation
    recommendations = Counter(r.get("ml_recommendation", "unknown") for r in records)
    print(f"\n  ML Recommendation Counts:")
    for rec, cnt in recommendations.most_common():
        print(f"    {rec:>8s}: {cnt}")

    # Top 20 hashes with highest ml_injection_prob
    sorted_records = sorted(records, key=lambda r: r.get("ml_injection_prob", 0.0), reverse=True)
    print(f"\n  Top 20 Hashes by ML Injection Probability:")
    print(f"  {'Rank':>4s}  {'text_hash':>20s}  {'ml_prob':>8s}  {'scanner':>8s}  {'rec':>8s}  {'decision':>8s}")
    for i, r in enumerate(sorted_records[:20], 1):
        h = r.get("text_hash", "?")[:16] + "..."
        prob = r.get("ml_injection_prob", 0.0)
        sc = r.get("scanner_score", -1)
        rec = r.get("ml_recommendation", "?")
        dec = r.get("decision", "?")
        print(f"  {i:>4d}  {h:>20s}  {prob:>8.4f}  {sc:>8d}  {rec:>8s}  {dec:>8s}")

    return records


# ══════════════════════════════════════════════════════════════
# Conclusion
# ══════════════════════════════════════════════════════════════


def conclusion(dedup_rows, holdout_fams, pipe_normal, pipe_holdout, flagged_artifacts, al_records):
    _header("CONCLUSION — Shadow-to-Enforce Readiness Assessment")

    issues = []
    strengths = []

    # Dataset quality
    n_total = 10000
    n_dedup = len(dedup_rows)
    dup_rate = (n_total - n_dedup) / n_total
    if dup_rate > 0.30:
        issues.append(f"High duplicate rate ({dup_rate:.0%}): model may memorize exact phrases")
    elif dup_rate > 0.10:
        issues.append(f"Moderate duplicate rate ({dup_rate:.0%}): some memorization risk")
    else:
        strengths.append(f"Low duplicate rate ({dup_rate:.0%})")

    # Artifact features
    if flagged_artifacts and len(flagged_artifacts) > 5:
        issues.append(f"{len(flagged_artifacts)} artifact features detected — model may rely on "
                      "generator scaffolding rather than real attack patterns")
    elif flagged_artifacts:
        issues.append(f"{len(flagged_artifacts)} minor artifact features (acceptable if holdout performs well)")
    else:
        strengths.append("No obvious artifact features in top ngrams")

    # Active learning logs
    if al_records is None:
        issues.append("No active-learning logs available — cannot validate real-world performance")
    elif len(al_records) < 50:
        issues.append(f"Only {len(al_records)} AL records — insufficient for real-world validation")
    else:
        # Check false positive rate in real logs
        block_recs = [r for r in al_records if r.get("ml_recommendation") == "block"]
        total_recs = len(al_records)
        block_rate = len(block_recs) / total_recs if total_recs > 0 else 0
        if block_rate > 0.10:
            issues.append(f"High block recommendation rate in real logs ({block_rate:.0%}) — "
                          "likely too many false positives")
        else:
            strengths.append(f"Block recommendation rate in real logs: {block_rate:.0%}")

    print(f"\n  STRENGTHS:")
    for s in strengths:
        print(f"    + {s}")

    print(f"\n  ISSUES:")
    for i in issues:
        print(f"    - {i}")

    # Threshold recommendation
    print(f"\n  THRESHOLD RECOMMENDATION:")
    if not issues or (len(issues) == 1 and "artifact" in issues[0].lower() and len(flagged_artifacts) <= 3):
        print(f"    Safe to proceed: shadow -> enforce")
        print(f"    Recommended SENTINEL_ML_BLOCK_THRESHOLD = 0.80")
        print(f"    Recommended SENTINEL_ML_REVIEW_THRESHOLD = 0.60")
    elif al_records is None:
        print(f"    NOT YET SAFE to enforce.")
        print(f"    Run in shadow mode for >= 48 hours with active-learning logging enabled,")
        print(f"    then re-run this audit to validate real-world performance.")
        print(f"    If holdout eval looks good, start with conservative threshold:")
        print(f"    Recommended SENTINEL_ML_BLOCK_THRESHOLD = 0.90 (conservative)")
    else:
        print(f"    Proceed with caution.")
        print(f"    Recommended SENTINEL_ML_BLOCK_THRESHOLD = 0.90 (conservative)")
        print(f"    Recommended SENTINEL_ML_REVIEW_THRESHOLD = 0.70")
        print(f"    Address issues above before lowering thresholds.")


# ══════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════


def main():
    _header("ShieldPilot ML Leakage & Reality Check Audit")
    print(f"  Dataset: {DATASET_PATH}")
    print(f"  Seed: {SEED}")

    # Part A
    rows = load_raw(DATASET_PATH)
    dedup_rows = part_a_dedup(rows)
    train_pool, holdout_test, holdout_fams = part_a_hard_holdout(dedup_rows)
    pipe_normal, pipe_holdout = part_a_train_eval(dedup_rows, train_pool, holdout_test)

    # Part B
    flagged = part_b_ngrams(pipe_normal)

    # Part C
    al_records = part_c_active_learning()

    # Conclusion
    conclusion(dedup_rows, holdout_fams, pipe_normal, pipe_holdout, flagged, al_records)


if __name__ == "__main__":
    main()
