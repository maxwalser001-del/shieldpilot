"""Evaluate generated dataset against PromptScanner."""
from sentinelai.scanner.scanner import PromptScanner

scanner = PromptScanner()

# Read dataset
with open("tests/dataset.txt", "r") as f:
    lines = f.readlines()

results = {"INJECTION": {"hit": 0, "miss": 0, "missed_examples": []},
           "CLEAN": {"ok": 0, "fp": 0, "fp_examples": []},
           "HARD": {"ok": 0, "fp": 0, "fp_examples": []}}

for line in lines:
    line = line.strip()
    if not line or " || " not in line:
        continue
    label, text = line.split(" || ", 1)

    r = scanner.scan(text, source="eval")
    score = r.overall_score
    patterns = [t.pattern_name for t in r.threats[:2]]

    if label == "INJECTION":
        if score > 0:
            results["INJECTION"]["hit"] += 1
        else:
            results["INJECTION"]["miss"] += 1
            if len(results["INJECTION"]["missed_examples"]) < 20:
                results["INJECTION"]["missed_examples"].append(text[:80])
    elif label == "CLEAN":
        if score == 0:
            results["CLEAN"]["ok"] += 1
        else:
            results["CLEAN"]["fp"] += 1
            if len(results["CLEAN"]["fp_examples"]) < 10:
                results["CLEAN"]["fp_examples"].append((text[:80], patterns))
    elif label == "HARD":
        if score == 0:
            results["HARD"]["ok"] += 1
        else:
            results["HARD"]["fp"] += 1
            if len(results["HARD"]["fp_examples"]) < 10:
                results["HARD"]["fp_examples"].append((text[:80], patterns))

print("=" * 70)
print("  GENERATED DATASET EVALUATION")
print("=" * 70)

inj = results["INJECTION"]
total_inj = inj["hit"] + inj["miss"]
print(f"\n  INJECTION: {inj['hit']}/{total_inj} ({100*inj['hit']/max(1,total_inj):.1f}%)")
if inj["missed_examples"]:
    print(f"\n  Missed examples ({len(inj['missed_examples'])}):")
    for ex in inj["missed_examples"][:10]:
        print(f"    - {ex}")

cln = results["CLEAN"]
total_cln = cln["ok"] + cln["fp"]
print(f"\n  CLEAN: {cln['ok']}/{total_cln} true negatives ({100*cln['ok']/max(1,total_cln):.1f}%)")
if cln["fp_examples"]:
    print(f"\n  False positives ({len(cln['fp_examples'])}):")
    for ex, pats in cln["fp_examples"]:
        print(f"    - {ex} | {pats}")

hrd = results["HARD"]
total_hrd = hrd["ok"] + hrd["fp"]
print(f"\n  HARD: {hrd['ok']}/{total_hrd} true negatives ({100*hrd['ok']/max(1,total_hrd):.1f}%)")
if hrd["fp_examples"]:
    print(f"\n  False positives ({len(hrd['fp_examples'])}):")
    for ex, pats in hrd["fp_examples"]:
        print(f"    - {ex} | {pats}")

print(f"\n{'=' * 70}")
