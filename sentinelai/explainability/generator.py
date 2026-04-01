"""Non-technical incident explanation generator.

Translates raw RiskSignals into human-readable explanations for
non-technical users. Computes explanations on-the-fly from stored
signal data -- no database changes required.
"""

from __future__ import annotations

import json
from typing import Any, Optional

from pydantic import BaseModel

from sentinelai.explainability.templates import (
    CATEGORY_TEMPLATES,
    ExplanationTemplate,
    FALLBACK_TEMPLATE,
)

# Score threshold: >= this value uses "dangerous" user_impact text
_DANGER_THRESHOLD = 70


class IncidentExplanation(BaseModel):
    """Non-technical explanation of a security incident."""

    display_title: str
    what_happened: str
    why_blocked: str
    severity_explanation: str
    user_impact: str
    action_guidance: str
    hypothetical: str
    technical_details: dict[str, Any]


def generate_explanation(
    *,
    signals_json: str,
    risk_score: int,
    severity: str,
    category: str,
    command_preview: Optional[str] = None,
) -> IncidentExplanation:
    """Generate a non-technical explanation from raw signal data.

    Args:
        signals_json: JSON string of RiskSignal dicts (from CommandLog.signals_json).
        risk_score: Final computed risk score (0-100).
        severity: Incident severity (critical/high/medium/low).
        category: Primary risk category string.
        command_preview: Optional truncated command for context.

    Returns:
        IncidentExplanation with all 6 fields populated.
    """
    signals = _parse_signals(signals_json)
    dominant = _find_dominant_signal(signals)

    # Template from dominant signal's category, then incident category, then fallback
    template_key = (dominant.get("category", "") if dominant else "") or category
    template = CATEGORY_TEMPLATES.get(template_key, FALLBACK_TEMPLATE)

    severity_explanation = _pick_severity_text(template, risk_score)

    is_dangerous = risk_score >= _DANGER_THRESHOLD
    user_impact = (
        template.user_impact_dangerous if is_dangerous else template.user_impact_safe
    )
    action_guidance = (
        template.action_guidance_dangerous if is_dangerous else template.action_guidance_safe
    )

    technical_details = {
        "risk_score": risk_score,
        "severity": severity,
        "category": category,
        "signals_count": len(signals),
        "analyzers_triggered": sorted(
            {s.get("analyzer", "unknown") for s in signals}
        ),
        "signals": [
            {
                "category": s.get("category", ""),
                "score": s.get("score", 0),
                "weight": s.get("weight", 1.0),
                "description": s.get("description", ""),
                "analyzer": s.get("analyzer", ""),
            }
            for s in signals
        ],
    }

    return IncidentExplanation(
        display_title=template.display_title,
        what_happened=template.what_happened,
        why_blocked=template.why_blocked,
        severity_explanation=severity_explanation,
        user_impact=user_impact,
        action_guidance=action_guidance,
        hypothetical=template.hypothetical,
        technical_details=technical_details,
    )


def _parse_signals(signals_json: str) -> list[dict]:
    """Parse signals JSON, returning empty list on failure."""
    try:
        result = json.loads(signals_json) if signals_json else []
        return result if isinstance(result, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


def _find_dominant_signal(signals: list[dict]) -> Optional[dict]:
    """Return the signal with the highest weighted score."""
    if not signals:
        return None
    return max(signals, key=lambda s: s.get("score", 0) * s.get("weight", 1.0))


def _pick_severity_text(template: ExplanationTemplate, score: int) -> str:
    """Select the appropriate severity explanation based on numeric score."""
    if score >= 90:
        return template.severity_critical
    elif score >= 70:
        return template.severity_high
    elif score >= 40:
        return template.severity_medium
    else:
        return template.severity_low
