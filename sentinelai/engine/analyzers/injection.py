"""Prompt injection analyzer.

Bridges the PromptScanner (regex-based injection detection) into the
RiskEngine so that prompt injection patterns embedded in shell commands
contribute to the risk score and can trigger BLOCK/WARN decisions.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from sentinelai.core.constants import RiskCategory
from sentinelai.core.models import RiskSignal
from sentinelai.engine.base import AnalysisContext, BaseAnalyzer


# Maps PromptScanner severity to (score, weight) for the RiskEngine.
_SEVERITY_MAP: Dict[str, Tuple[int, float]] = {
    "critical": (85, 0.9),
    "high": (65, 0.9),
    "medium": (40, 0.7),
    "low": (15, 0.5),
}


class InjectionAnalyzer(BaseAnalyzer):
    """Detects prompt injection patterns in commands.

    Uses the PromptScanner internally to scan the command text for
    injection patterns, then converts detected threats into RiskSignal
    objects that the RiskEngine can score.
    """

    def __init__(self) -> None:
        # Lazy import to avoid circular dependencies and keep startup fast
        from sentinelai.scanner.scanner import PromptScanner
        self._scanner = PromptScanner()

    @property
    def name(self) -> str:
        return "injection"

    @property
    def category(self) -> RiskCategory:
        return RiskCategory.INJECTION

    def analyze(self, command: str, context: AnalysisContext) -> List[RiskSignal]:
        """Scan command for prompt injection patterns."""
        signals: List[RiskSignal] = []

        scan_result = self._scanner.scan(command, source="risk-engine")

        for threat in scan_result.threats:
            severity_str = threat.severity.value if hasattr(threat.severity, "value") else str(threat.severity)
            score, weight = _SEVERITY_MAP.get(severity_str, (40, 0.7))

            signals.append(
                RiskSignal(
                    category=RiskCategory.INJECTION,
                    score=score,
                    weight=weight,
                    description=f"[{threat.pattern_name}] {threat.description}",
                    evidence=threat.matched_text[:200],
                    analyzer=self.name,
                )
            )

        return signals
