"""Base analyzer interface and analysis context.

All risk analyzers must implement the BaseAnalyzer abstract class.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

from sentinelai.core.config import SentinelConfig
from sentinelai.core.constants import RiskCategory
from sentinelai.core.models import RiskSignal


class AnalysisContext(BaseModel):
    """Shared context passed to all analyzers during evaluation."""

    working_directory: str = "."
    environment: Dict[str, str] = Field(default_factory=dict)
    config: Optional[SentinelConfig] = None
    previous_commands: List[str] = Field(default_factory=list)


class BaseAnalyzer(ABC):
    """Abstract base class for all risk analyzers.

    Each analyzer inspects a command for a specific category of risk
    and returns zero or more RiskSignal objects.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable name of this analyzer."""
        ...

    @property
    @abstractmethod
    def category(self) -> RiskCategory:
        """The primary risk category this analyzer covers."""
        ...

    @abstractmethod
    def analyze(self, command: str, context: AnalysisContext) -> List[RiskSignal]:
        """Analyze a command and return risk signals.

        Args:
            command: The shell command string to analyze.
            context: Shared analysis context (working dir, env, config, history).

        Returns:
            List of RiskSignal objects. Empty list means no risk detected.
        """
        ...
