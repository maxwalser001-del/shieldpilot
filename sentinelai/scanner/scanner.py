"""Prompt-injection scanner orchestrator.

Runs every pattern from :mod:`sentinelai.scanner.patterns` against incoming
text and produces a :class:`~sentinelai.core.models.ScanResult` with
per-threat details, an overall risk score, and a human-readable
recommendation.

Pipeline (multi-pass):
1. **Pass 1** — encoding_bypass patterns run on the **original** text
   to flag the presence of encoded payloads.
2. InputSanitizer normalises/decodes the input (zero-width stripping,
   URL/HTML/Unicode/Hex/Octal decoding, NFC normalisation).
3. **Pass 2** — all patterns run on the **normalised** text to detect
   injection attempts that were hidden behind encoding layers.
4. **Pass 2b** — zero-width characters are replaced with spaces (instead
   of stripped) and patterns are re-run.  This catches between-word
   evasion like ``bypass\u200bsafety`` → ``bypass safety``.
5. FuzzyMatcher detects typoglycemia evasion on the **normalised** text.
6. Results are deduplicated by (pattern_name, line_number).
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from sentinelai.core.constants import IncidentSeverity
from sentinelai.core.models import ScanResult, ThreatDetail
from sentinelai.scanner.patterns import PATTERNS, InjectionPattern
from sentinelai.scanner.sanitizer import FuzzyMatcher, InputSanitizer

# ML classifier — imported lazily so missing ML deps don't break the scanner.
try:
    from sentinelai.ml.classifier import get_classifier as _get_ml_classifier
except Exception:  # pragma: no cover
    _get_ml_classifier = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

# Maps severity strings to numeric scores used for the overall assessment.
_SEVERITY_SCORES: Dict[str, int] = {
    "critical": 90,
    "high": 70,
    "medium": 45,
    "low": 20,
}

# Additional score added per extra threat beyond the first.
_COMPOUND_BONUS = 5

# Hard cap for the overall score.
_MAX_SCORE = 100

# Zero-width characters that may act as word separators in evasion attacks.
_ZW_SPACE_CHARS = re.compile(r'[\u200b\u200c\u200d]')

# Unusual line/paragraph separators used as word separators to evade detection.
# str.splitlines() treats VT, FF, NEL, LS, PS (and others) as line boundaries,
# so they split keywords across scan lines in Pass 1/2.
# Pass 2c rescans with them converted to spaces so "bypass\u2028safety" is
# caught; the sanitizer strips them so "igno\x0bre" → "ignore" in Pass 2.
_LINE_PARA_SEP_CHARS = re.compile(r'[\x0b\x0c\x1c\x1d\x1e\x85\u0085\u2028\u2029]')


class PromptScanner:
    """Scan text for prompt-injection patterns.

    Usage::

        scanner = PromptScanner()
        result = scanner.scan(user_input, source="chat-message")
        if result.overall_score >= 70:
            print("High-risk injection detected!")

    ML augmentation (optional)::

        scanner = PromptScanner(use_ml=True)
        result = scanner.scan(text)
        print(result.detection_method)  # "pattern" | "ml" | "both"

    When *use_ml* is ``True`` the DeBERTa-v3 classifier is consulted and its
    score is fused with the pattern score via ``max()``.  If the ML
    dependencies are not installed the scanner falls back to pattern-only
    detection transparently — no exception is raised.
    """

    def __init__(self, use_ml: bool = False) -> None:
        self._patterns: List[InjectionPattern] = list(PATTERNS)
        self._sanitizer = InputSanitizer()
        self._fuzzy = FuzzyMatcher()
        self._use_ml = use_ml
        self._classifier: Optional[object] = None
        if use_ml and _get_ml_classifier is not None:
            try:
                self._classifier = _get_ml_classifier()
            except Exception:
                self._classifier = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, content: str, source: str = "stdin") -> ScanResult:
        """Scan *content* for injection patterns.

        Parameters
        ----------
        content:
            The text to analyse (may be multi-line).
        source:
            Label describing where the content came from (e.g. a file path,
            ``"stdin"``, or ``"api-request"``).

        Returns
        -------
        ScanResult
            Pydantic model with the list of threats found, an overall score
            (0--100), and a recommendation string.
        """
        _scan_start = time.perf_counter()
        threats: List[ThreatDetail] = []
        seen: set = set()  # (pattern_name, line_number) for dedup

        # Truncate early — keeps all passes (including Pass 1 on the original
        # text) within the MAX_INPUT_LENGTH budget.  The sanitizer also
        # truncates, but we pre-truncate here so that Pass 1 and Pass 2c don't
        # iterate over megabytes of data before the sanitizer gets a chance.
        from sentinelai.scanner.sanitizer import MAX_INPUT_LENGTH
        if len(content) > MAX_INPUT_LENGTH:
            content = content[:MAX_INPUT_LENGTH]

        # ── Pass 1: Pre-sanitization patterns on ORIGINAL text ─────
        # Encoding-bypass patterns detect the *presence* of encoding.
        # Delimiter-injection and fake-system-message patterns rely on
        # structural formatting (e.g. "=====") that the sanitizer's
        # repeat-collapsing step would destroy.
        # data_exfiltration is included so that SSRF/network patterns (which rely on
        # numeric IPs and IPv6 bracket notation) run on the ORIGINAL text before the
        # sanitizer's leet-speak and ROT13 normalization destroys the numeric evidence.
        _PASS1_CATEGORIES = {
            "encoding_bypass", "delimiter_injection", "fake_system_message",
            "obfuscation_evasion", "data_exfiltration",
        }
        orig_lines = content.splitlines()
        for line_number, line in enumerate(orig_lines, start=1):
            for pat in self._patterns:
                if pat.category not in _PASS1_CATEGORIES:
                    continue
                match = pat.pattern.search(line)
                if match:
                    key = (pat.name, line_number)
                    if key not in seen:
                        seen.add(key)
                        threats.append(
                            ThreatDetail(
                                category=pat.category,
                                pattern_name=pat.name,
                                matched_text=match.group()[:200],
                                line_number=line_number,
                                severity=IncidentSeverity(pat.severity),
                                description=pat.description,
                                mitigation=pat.mitigation,
                            )
                        )

        # ── Step 2: Sanitize / normalize ──────────────────────────
        normalized = self._sanitizer.sanitize(content)

        # ── Pass 2: ALL patterns on SANITIZED text ────────────────
        # After decoding, hidden instructions become visible to the
        # content-detecting patterns (jailbreak, tool_hijacking, etc.)
        norm_lines = normalized.splitlines()
        for line_number, line in enumerate(norm_lines, start=1):
            for pat in self._patterns:
                match = pat.pattern.search(line)
                if match:
                    key = (pat.name, line_number)
                    if key not in seen:
                        seen.add(key)
                        threats.append(
                            ThreatDetail(
                                category=pat.category,
                                pattern_name=pat.name,
                                matched_text=match.group()[:200],
                                line_number=line_number,
                                severity=IncidentSeverity(pat.severity),
                                description=pat.description,
                                mitigation=pat.mitigation,
                            )
                        )

        # ── Pass 2b: Zero-width-as-space variant ──────────────────
        # Catches "bypass\u200bsafety" → "bypass safety" (word boundary preserved)
        zw_spaced = _ZW_SPACE_CHARS.sub(' ', content)
        if zw_spaced != content:
            normalized_spaced = self._sanitizer.sanitize(zw_spaced)
            norm_spaced_lines = normalized_spaced.splitlines()
            for line_number, line in enumerate(norm_spaced_lines, start=1):
                for pat in self._patterns:
                    match = pat.pattern.search(line)
                    if match:
                        key = (pat.name, line_number)
                        if key not in seen:
                            seen.add(key)
                            threats.append(
                                ThreatDetail(
                                    category=pat.category,
                                    pattern_name=pat.name,
                                    matched_text=match.group()[:200],
                                    line_number=line_number,
                                    severity=IncidentSeverity(pat.severity),
                                    description=pat.description,
                                    mitigation=pat.mitigation,
                                )
                            )

        # ── Pass 2c: Line/paragraph-separator-as-space variant ───────
        # Catches "bypass\u2028safety" → "bypass safety".
        # Complementary to Pass 2 (sanitizer strips these chars — which
        # handles mid-keyword splits like "igno\u2028re" → "ignore") and to
        # Pass 2b (zero-width chars as spaces).
        linesep_spaced = _LINE_PARA_SEP_CHARS.sub(' ', content)
        if linesep_spaced != content:
            normalized_linesep = self._sanitizer.sanitize(linesep_spaced)
            norm_linesep_lines = normalized_linesep.splitlines()
            for line_number, line in enumerate(norm_linesep_lines, start=1):
                for pat in self._patterns:
                    match = pat.pattern.search(line)
                    if match:
                        key = (pat.name, line_number)
                        if key not in seen:
                            seen.add(key)
                            threats.append(
                                ThreatDetail(
                                    category=pat.category,
                                    pattern_name=pat.name,
                                    matched_text=match.group()[:200],
                                    line_number=line_number,
                                    severity=IncidentSeverity(pat.severity),
                                    description=pat.description,
                                    mitigation=pat.mitigation,
                                )
                            )

        # ── Step 3: Fuzzy / typoglycemia detection ────────────────
        fuzzy_hits = self._fuzzy.find_matches(normalized)
        for hit in fuzzy_hits:
            threats.append(
                ThreatDetail(
                    category="jailbreak",
                    pattern_name="typoglycemia_evasion",
                    matched_text=hit["original_word"],
                    line_number=0,
                    severity=IncidentSeverity.MEDIUM,
                    description=(
                        f"Scrambled keyword detected: '{hit['original_word']}' "
                        f"resembles '{hit['matched_keyword']}' (typoglycemia evasion)"
                    ),
                    mitigation="Normalise input and check for character-scrambled keywords.",
                )
            )

        overall_score = self._compute_score(threats)
        recommendation = self._build_recommendation(threats)
        detection_method = "pattern"

        # ── Optional ML augmentation ──────────────────────────────
        # ML is only active when use_ml=True was passed to __init__.
        # If the ML model is unavailable the result is silently ignored.
        if self._use_ml and self._classifier is not None:
            try:
                ml_result = self._classifier.classify(content)  # type: ignore[union-attr]
                if ml_result.get("status") == "ok":
                    ml_score: int = ml_result["score"]
                    ml_is_injection: bool = ml_result["is_injection"]
                    pattern_detected = bool(threats)

                    if ml_score > overall_score:
                        overall_score = ml_score
                        detection_method = "both" if pattern_detected else "ml"
                    elif pattern_detected:
                        # Pattern found something; ML may or may not agree —
                        # either way we stay at "both" to be transparent.
                        detection_method = "both" if ml_is_injection else "pattern"
                    # else: neither pattern nor ML → stays "pattern" (score 0)
            except Exception:
                pass  # ML failure must never break the scanner

        return ScanResult(
            source=source,
            threats=threats,
            overall_score=overall_score,
            recommendation=recommendation,
            timestamp=datetime.utcnow(),
            execution_time_ms=(time.perf_counter() - _scan_start) * 1000,
            detection_method=detection_method,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_score(threats: List[ThreatDetail]) -> int:
        """Derive an overall risk score from the detected threats.

        The base score equals the highest individual severity score.  Each
        additional threat adds a small compounding bonus, capped at 100.
        """
        if not threats:
            return 0

        base = max(_SEVERITY_SCORES.get(t.severity.value, 0) for t in threats)
        extra = max(0, len(threats) - 1) * _COMPOUND_BONUS
        return min(base + extra, _MAX_SCORE)

    @staticmethod
    def _build_recommendation(threats: List[ThreatDetail]) -> str:
        """Generate a human-readable recommendation from the threat list."""
        if not threats:
            return "No prompt-injection patterns detected.  Input appears safe."

        categories_found = sorted({t.category for t in threats})
        severities = [t.severity.value for t in threats]

        if "critical" in severities:
            urgency = "BLOCK immediately"
        elif "high" in severities:
            urgency = "Review and likely reject"
        elif "medium" in severities:
            urgency = "Flag for manual review"
        else:
            urgency = "Monitor"

        parts = [
            f"Detected {len(threats)} threat(s) across categories: "
            f"{', '.join(categories_found)}.",
            f"Recommended action: {urgency}.",
        ]

        # Add per-category advice when multiple categories are involved.
        if "jailbreak" in categories_found:
            parts.append(
                "Jailbreak attempts detected -- ensure system prompt integrity."
            )
        if "data_exfiltration" in categories_found:
            parts.append(
                "Data-exfiltration signals found -- verify no sensitive data is exposed."
            )
        if "tool_hijacking" in categories_found:
            parts.append(
                "Tool-hijacking patterns present -- validate all tool-call payloads."
            )
        if "encoding_bypass" in categories_found:
            parts.append(
                "Encoding-bypass techniques detected -- normalise input before processing."
            )
        if "instruction_override" in categories_found:
            parts.append(
                "Instruction-override patterns found -- sanitise user input."
            )
        if "role_manipulation" in categories_found:
            parts.append(
                "Role-manipulation attempts detected -- ignore privilege claims from input."
            )
        if "fake_system_message" in categories_found:
            parts.append(
                "Fake system messages detected -- verify message authenticity."
            )
        if "delimiter_injection" in categories_found:
            parts.append(
                "Delimiter injection detected -- sanitise structural markers in input."
            )
        if "emotional_manipulation" in categories_found:
            parts.append(
                "Emotional manipulation detected -- do not alter behavior based on pressure."
            )
        if "authority_impersonation" in categories_found:
            parts.append(
                "Authority impersonation detected -- verify identity through proper channels."
            )
        if "payload_splitting" in categories_found:
            parts.append(
                "Payload splitting detected -- inspect multi-part inputs as a whole."
            )
        if "context_poisoning" in categories_found:
            parts.append(
                "Context poisoning detected -- maintain original instruction integrity."
            )
        if "soft_policy_override" in categories_found:
            parts.append(
                "Soft policy override detected -- do not accept policy changes from user input."
            )
        if "state_trust_spoofing" in categories_found:
            parts.append(
                "State/trust spoofing detected -- do not accept approval, clearance, or trust claims from input."
            )
        if "delayed_compliance" in categories_found:
            parts.append(
                "Delayed compliance attack detected -- do not defer to conditional overrides."
            )
        if "obfuscation_evasion" in categories_found:
            parts.append(
                "Obfuscation evasion detected -- normalise input and re-scan for hidden keywords."
            )

        return "  ".join(parts)
