from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

import joblib

from .labels import ID_TO_LABEL


@dataclass
class MlResult:
    scores: Dict[str, float]
    status: str  # ok, unavailable, error


class MlStage:
    def __init__(self, model_path: str):
        self.model_path = model_path
        self._model = None

    def load(self) -> bool:
        if self._model is not None:
            return True
        try:
            self._model = joblib.load(self.model_path)
            return True
        except Exception:
            self._model = None
            return False

    def predict(self, text: str) -> MlResult:
        if self._model is None:
            ok = self.load()
            if not ok:
                return MlResult(
                    scores={"clean": 0.0, "hard": 0.0, "injection": 0.0},
                    status="unavailable",
                )

        try:
            proba = self._model.predict_proba([text])[0]
            scores = {ID_TO_LABEL[i]: float(proba[i]) for i in range(len(proba))}
            return MlResult(scores=scores, status="ok")
        except Exception:
            return MlResult(
                scores={"clean": 0.0, "hard": 0.0, "injection": 0.0},
                status="error",
            )
