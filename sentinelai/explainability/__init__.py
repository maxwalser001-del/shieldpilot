"""Non-technical incident explainability module."""

from sentinelai.explainability.generator import (
    IncidentExplanation,
    generate_explanation,
)

__all__ = ["generate_explanation", "IncidentExplanation"]
