"""Optional ML-based prompt injection classifier.

Uses the ProtectAI DeBERTa-v3 model (protectai/deberta-v3-base-prompt-injection-v2)
when ``transformers`` is installed.  Falls back silently to pattern-only detection
when the dependency is absent or the model has not been downloaded.

Install ML dependencies::

    pip install shieldpilot[ml]
    sentinel ml-setup   # downloads the model weights

Usage::

    from sentinelai.ml.classifier import PromptInjectionClassifier

    clf = PromptInjectionClassifier()
    result = clf.classify("ignore all previous instructions")
    # {"is_injection": True, "confidence": 0.97, "label": "INJECTION",
    #  "score": 97, "status": "ok"}
"""

from __future__ import annotations

import logging
import threading
from typing import Dict

logger = logging.getLogger(__name__)

# HuggingFace model to use for classification.
_MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"

# Maximum characters fed to the model (DeBERTa has a 512-token window).
_MAX_INPUT_CHARS = 2000

# Per-call wall-clock timeout in seconds.
_TIMEOUT_S = 0.1  # 100 ms

# Labels the model may return that indicate an injection attempt.
_INJECTION_LABELS = frozenset({
    "INJECTION",
    "PROMPT_INJECTION",
    "INJECTED",
    "1",
})

# Singleton instance — module-level cache so the model is loaded only once
# per process even if multiple PromptScanner objects are created.
_singleton: "PromptInjectionClassifier | None" = None
_singleton_lock = threading.Lock()


def get_classifier() -> "PromptInjectionClassifier":
    """Return the process-wide classifier singleton (lazy-init)."""
    global _singleton
    if _singleton is None:
        with _singleton_lock:
            if _singleton is None:
                _singleton = PromptInjectionClassifier()
    return _singleton


class PromptInjectionClassifier:
    """ML-based prompt injection classifier with lazy loading and timeout.

    Attributes
    ----------
    is_available:
        ``True`` when ``transformers`` is importable.
    is_loaded:
        ``True`` when the model weights are resident in memory.
    """

    def __init__(self) -> None:
        self._pipeline = None
        self._available: bool | None = None  # None = not yet probed
        self._load_attempted = False
        self._load_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    @property
    def is_available(self) -> bool:
        """Return True when the transformers package is importable."""
        if self._available is None:
            self._available = self._check_dependencies()
        return self._available

    @property
    def is_loaded(self) -> bool:
        """Return True when the model pipeline is resident in memory."""
        return self._pipeline is not None

    def load_model(self) -> bool:
        """Load model weights into memory.

        Returns
        -------
        bool
            ``True`` on success, ``False`` when unavailable or on error.
        """
        with self._load_lock:
            if self._load_attempted:
                return self._pipeline is not None
            self._load_attempted = True

            if not self.is_available:
                return False

            try:
                from transformers import pipeline  # type: ignore

                self._pipeline = pipeline(
                    "text-classification",
                    model=_MODEL_ID,
                    truncation=True,
                    max_length=512,
                )
                logger.info("ML classifier loaded: %s", _MODEL_ID)
                return True
            except Exception as exc:
                logger.debug("ML classifier load failed: %s", exc)
                self._pipeline = None
                return False

    def classify(self, text: str) -> Dict[str, object]:
        """Classify *text* as injection or safe.

        Always returns a dict — never raises.

        Returns
        -------
        dict with keys:
            is_injection (bool), confidence (float 0-1),
            label (str), score (int 0-100), status (str).

        status values:
            ``"ok"``          — successful ML prediction
            ``"unavailable"`` — transformers not installed
            ``"not_loaded"``  — model not downloaded yet
            ``"timeout"``     — classification exceeded 100 ms
            ``"error"``       — unexpected exception
        """
        if not self.is_available:
            return _make_result(False, 0.0, "UNAVAILABLE", "unavailable")

        if self._pipeline is None:
            ok = self.load_model()
            if not ok:
                return _make_result(False, 0.0, "NOT_LOADED", "not_loaded")

        return self._run_with_timeout(text)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _check_dependencies() -> bool:
        try:
            import transformers  # type: ignore  # noqa: F401
            return True
        except ImportError:
            return False

    def _run_with_timeout(self, text: str) -> Dict[str, object]:
        """Run inference in a daemon thread with a hard 100 ms wall-clock limit."""
        truncated = text[:_MAX_INPUT_CHARS]

        result_holder: list = [None]
        error_holder: list = [None]

        def _infer() -> None:
            try:
                out = self._pipeline(truncated)  # type: ignore[misc]
                result_holder[0] = out
            except Exception as exc:
                error_holder[0] = exc

        t = threading.Thread(target=_infer, daemon=True)
        t.start()
        t.join(timeout=_TIMEOUT_S)

        if t.is_alive():
            # Thread still running → timed out.
            return _make_result(False, 0.0, "TIMEOUT", "timeout")

        if error_holder[0] is not None:
            logger.debug("ML classify error: %s", error_holder[0])
            return _make_result(False, 0.0, "ERROR", "error")

        raw = result_holder[0]
        if raw is None:
            return _make_result(False, 0.0, "ERROR", "error")

        # pipeline returns a list when called on a single string
        if isinstance(raw, list):
            raw = raw[0]

        label: str = str(raw.get("label", "SAFE")).upper()
        confidence: float = float(raw.get("score", 0.0))
        is_injection = label in _INJECTION_LABELS

        return _make_result(is_injection, confidence, label, "ok")


# ------------------------------------------------------------------
# Private helpers
# ------------------------------------------------------------------


def _make_result(
    is_injection: bool,
    confidence: float,
    label: str,
    status: str,
) -> Dict[str, object]:
    """Build the canonical classify() return dict."""
    score = int(confidence * 100) if is_injection else 0
    return {
        "is_injection": is_injection,
        "confidence": confidence,
        "label": label,
        "score": score,
        "status": status,
    }
