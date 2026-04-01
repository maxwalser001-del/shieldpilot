"""Plugin interface for ShieldPilot extensions.

All plugins must subclass SentinelPlugin and implement the required
properties. Hook methods are optional — the default implementations
are no-ops.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from sentinelai.core.config import SentinelConfig
from sentinelai.core.models import RiskAssessment, ScanResult


class SentinelPlugin(ABC):
    """Abstract base class for ShieldPilot plugins.

    Plugins are loaded dynamically from the plugins directory.
    They can hook into the command evaluation lifecycle at several points.

    Example minimal plugin:

        class MyPlugin(SentinelPlugin):
            @property
            def name(self) -> str:
                return "my_plugin"

            @property
            def version(self) -> str:
                return "1.0.0"

            def on_incident(self, incident_data: dict) -> None:
                print(f"Incident: {incident_data['title']}")
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name for this plugin."""
        ...

    @property
    @abstractmethod
    def version(self) -> str:
        """Version string for this plugin."""
        ...

    def on_load(self, config: SentinelConfig) -> None:
        """Called when the plugin is loaded. Use for initialization."""
        pass

    def pre_execute(
        self, command: str, assessment: RiskAssessment
    ) -> Optional[RiskAssessment]:
        """Called before a command is executed (after risk assessment).

        Return a modified RiskAssessment to override, or None to keep original.
        """
        return None

    def post_execute(
        self, command: str, output: str, exit_code: int
    ) -> None:
        """Called after a command has been executed."""
        pass

    def on_risk_score(
        self, assessment: RiskAssessment
    ) -> Optional[RiskAssessment]:
        """Called when a risk score is computed.

        Return a modified RiskAssessment to override, or None to keep original.
        """
        return None

    def on_incident(self, incident_data: dict) -> None:
        """Called when a security incident is created.

        incident_data contains: severity, category, title, description, evidence.
        """
        pass

    def on_scan(self, scan_result: ScanResult) -> Optional[ScanResult]:
        """Called when a prompt scan completes.

        Return a modified ScanResult to override, or None to keep original.
        """
        return None
