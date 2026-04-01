"""Rich style constants for CLI output.

Color semantics:
  Green  = safe/allowed/verified
  Amber  = warning/medium risk
  Red    = blocked/critical/error
  Purple = LLM/AI-related
  Cyan   = chain integrity/system health
  Dim    = metadata/timestamps/secondary info
"""

from __future__ import annotations

from rich.theme import Theme

# Style mapping used across all CLI output
SENTINEL_STYLES = {
    # Action badges
    "allow": "bold green",
    "warn": "bold yellow",
    "block": "bold red",
    "clean": "bold green",
    "alert": "bold red",

    # Score display by risk level
    "score.none": "dim green",
    "score.low": "green",
    "score.medium": "yellow",
    "score.high": "red",
    "score.critical": "bold red",

    # Severity badges
    "severity.critical": "bold red",
    "severity.high": "red",
    "severity.medium": "yellow",
    "severity.low": "dim yellow",
    "severity.info": "dim cyan",

    # Risk categories
    "category": "cyan",

    # Structural elements
    "header": "bold white",
    "label": "dim",
    "value": "white",
    "muted": "dim",
    "timestamp": "dim cyan",
    "command_text": "white",
    "hash": "dim",

    # Special indicators
    "llm": "magenta",
    "chain.ok": "green",
    "chain.broken": "bold red",
    "incident.id": "bold yellow",

    # Interactive
    "prompt": "bold white",
    "hint": "dim italic",

    # Errors
    "error": "bold red",
    "warning": "yellow",
    "success": "bold green",

    # Banner
    "banner": "bold cyan",
    "version": "dim cyan",
}

SENTINEL_THEME = Theme(SENTINEL_STYLES)

# Action symbols (ASCII-safe, no emoji)
SYMBOLS = {
    "allow": "[allow] ALLOW [/allow]",
    "warn": "[warn] WARN  [/warn]",
    "block": "[block] BLOCK [/block]",
    "clean": "[clean] CLEAN [/clean]",
    "alert": "[alert] ALERT [/alert]",
    "check": "[chain.ok]OK[/chain.ok]",
    "cross": "[chain.broken]BROKEN[/chain.broken]",
    "dot": "[muted]·[/muted]",
    "arrow": "[muted]>[/muted]",
}


def score_style(score: int) -> str:
    """Return the Rich style name for a given risk score."""
    if score >= 90:
        return "score.critical"
    elif score >= 70:
        return "score.high"
    elif score >= 40:
        return "score.medium"
    elif score >= 10:
        return "score.low"
    else:
        return "score.none"


def severity_style(severity: str) -> str:
    """Return the Rich style name for a given severity level."""
    return f"severity.{severity.lower()}"
