"""Enums and constants used across ShieldPilot."""

from enum import Enum


class RiskLevel(str, Enum):
    """Risk severity levels mapped to score ranges.

    NOTE: These levels are for human-readable labeling and reporting only.
    They do NOT determine the hook's action thresholds (allow/warn/block).
    Action thresholds come from ``SentinelConfig.risk_thresholds`` (default:
    block >= 80, warn >= 40, allow < 40) and are applied by
    ``RiskEngine._determine_action()``.  The score-to-level mapping below
    is purely cosmetic — a score of 79 is labeled HIGH but still results
    in WARN (not BLOCK), because the block threshold is 80.
    """
    CRITICAL = "critical"   # 90-100
    HIGH = "high"           # 70-89
    MEDIUM = "medium"       # 40-69
    LOW = "low"             # 10-39
    NONE = "none"           # 0-9


class RiskCategory(str, Enum):
    """Categories of security risk signals."""
    DESTRUCTIVE_FS = "destructive_filesystem"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    NETWORK_EXFILTRATION = "network_exfiltration"
    CREDENTIAL_ACCESS = "credential_access"
    PERSISTENCE = "persistence"
    OBFUSCATION = "obfuscation"
    MALWARE_PATTERN = "malware_pattern"
    SUPPLY_CHAIN = "supply_chain"
    INJECTION = "injection"


class Action(str, Enum):
    """Actions the system can take on a command."""
    BLOCK = "block"
    WARN = "warn"
    ALLOW = "allow"


class IncidentSeverity(str, Enum):
    """Severity levels for security incidents."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


def score_to_risk_level(score: int) -> RiskLevel:
    """Convert a numeric risk score (0-100) to a RiskLevel enum."""
    if score >= 90:
        return RiskLevel.CRITICAL
    elif score >= 70:
        return RiskLevel.HIGH
    elif score >= 40:
        return RiskLevel.MEDIUM
    elif score >= 10:
        return RiskLevel.LOW
    else:
        return RiskLevel.NONE
