from typing import Dict

LABELS = ["clean", "hard", "injection"]
LABEL_TO_ID: Dict[str, int] = {l: i for i, l in enumerate(LABELS)}
ID_TO_LABEL: Dict[int, str] = {i: l for l, i in LABEL_TO_ID.items()}

EXTERNAL_TO_INTERNAL = {
    "CLEAN": "clean",
    "HARD": "hard",
    "INJECTION": "injection",
}
