"""Pydantic data transfer models used across ShieldPilot."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field

from sentinelai.core.constants import (
    Action,
    IncidentSeverity,
    RiskCategory,
    RiskLevel,
)


def format_limit_exceeded(
    limit: int,
    used: int,
    tier: str,
    upgrade_url: str,
    resource: str = "command",
) -> dict:
    """Standard limit-exceeded payload used by both Hook and API."""
    return {
        "error": f"Daily {resource} limit reached",
        "limit": limit,
        "used": used,
        "tier": tier,
        "upgrade_url": upgrade_url,
    }


class RiskSignal(BaseModel):
    """A single risk signal produced by an analyzer."""

    category: RiskCategory
    score: int = Field(ge=0, le=100, description="Risk contribution score 0-100")
    weight: float = Field(ge=0.0, le=1.0, description="Signal weight multiplier")
    description: str
    evidence: str  # the matched pattern or context
    analyzer: str  # which analyzer produced this signal


class RiskAssessment(BaseModel):
    """Complete risk assessment for a command."""

    command: str
    final_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    action: Action
    signals: List[RiskSignal] = Field(default_factory=list)
    llm_used: bool = False
    llm_reasoning: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    execution_time_ms: float = 0.0


class ThreatDetail(BaseModel):
    """A single threat detected in a prompt scan."""

    category: str
    pattern_name: str
    matched_text: str
    line_number: int = 0
    severity: IncidentSeverity
    description: str
    mitigation: str


class ScanResult(BaseModel):
    """Complete result of a prompt injection scan."""

    source: str  # file path or "stdin"
    threats: List[ThreatDetail] = Field(default_factory=list)
    overall_score: int = Field(ge=0, le=100, default=0)
    recommendation: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    execution_time_ms: float = 0.0
    # "pattern" | "ml" | "both" — how the final score was derived
    detection_method: str = "pattern"


class ExecutionResult(BaseModel):
    """Result of a sandboxed command execution."""

    command: str
    exit_code: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    execution_time_ms: float = 0.0


class ChainVerificationResult(BaseModel):
    """Result of log chain integrity verification."""

    valid: bool
    total_entries: int = 0
    verified_entries: int = 0
    first_broken_entry: Optional[int] = None
    message: str = ""


class DashboardStats(BaseModel):
    """Aggregated statistics for the dashboard."""

    # Time-windowed stats (default 24h)
    total_commands: int = 0
    blocked_commands: int = 0
    warned_commands: int = 0
    allowed_commands: int = 0
    average_risk_score: float = 0.0
    total_incidents: int = 0
    unresolved_incidents: int = 0
    total_scans: int = 0
    top_risk_categories: List[dict] = Field(default_factory=list)
    timeline: List[dict] = Field(default_factory=list)

    # All-time stats
    all_time_total: int = 0
    all_time_blocked: int = 0
    all_time_warned: int = 0
    all_time_allowed: int = 0
    all_time_incidents: int = 0
    all_time_scans: int = 0
