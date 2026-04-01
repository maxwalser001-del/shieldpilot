"""Output formatting functions for CLI display.

Each function takes a data model and renders it using Rich.
Follows the UX spec: minimal by default, detailed with --verbose.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from sentinelai.cli.styles import SENTINEL_THEME, SYMBOLS, score_style, severity_style
from sentinelai.core.constants import Action
from sentinelai.core.models import (
    ChainVerificationResult,
    DashboardStats,
    RiskAssessment,
    ScanResult,
    ThreatDetail,
)

console = Console(theme=SENTINEL_THEME)


def render_assessment(
    assessment: RiskAssessment,
    verbose: bool = False,
    as_json: bool = False,
) -> None:
    """Render a risk assessment result to the terminal.

    ALLOW: one line, green badge
    WARN:  signals shown automatically
    BLOCK: signals shown, incident note
    """
    if as_json:
        data = {"schema_version": "1.0", **assessment.model_dump(mode="json")}
        console.print_json(data=data)
        return

    action = assessment.action
    score = assessment.final_score
    cmd = assessment.command
    style = score_style(score)

    # Main verdict line
    badge = SYMBOLS[action.value]
    line = Text()
    console.print(f" {badge}  {cmd:<50s} [{style}]score: {score}[/{style}]")

    # Show signals for WARN and BLOCK, or when verbose
    show_signals = action in (Action.WARN, Action.BLOCK) or verbose
    if show_signals and assessment.signals:
        console.print()
        console.print("  [label]Signals:[/label]")
        for signal in assessment.signals:
            cat = signal.category.value if hasattr(signal.category, "value") else signal.category
            console.print(
                f"   [category]{cat:<24s}[/category] "
                f"{signal.description:<45s} "
                f"[{style}]score: {signal.score}[/{style}]"
            )

    # LLM reasoning
    if assessment.llm_used and assessment.llm_reasoning:
        console.print()
        console.print("  [llm]AI Analysis:[/llm]")
        console.print(f"   [llm]\"{assessment.llm_reasoning}\"[/llm]")

    # Verbose details
    if verbose:
        console.print()
        console.print(f"  [label]Details:[/label]")
        console.print(f"   Risk level:     {assessment.risk_level.value}")
        console.print(f"   Analyzers:      {len(set(s.analyzer for s in assessment.signals))} contributed signals")
        console.print(f"   Execution time: {assessment.execution_time_ms:.1f}ms")
        console.print(f"   LLM used:       {'Yes' if assessment.llm_used else 'No'}")

    # Block notice
    if action == Action.BLOCK:
        console.print()
        console.print("  [block]Command blocked and logged.[/block]")

    console.print()


def render_scan_result(
    result: ScanResult,
    verbose: bool = False,
    as_json: bool = False,
) -> None:
    """Render a prompt injection scan result."""
    if as_json:
        data = {"schema_version": "1.0", **result.model_dump(mode="json")}
        console.print_json(data=data)
        return

    source = result.source
    threat_count = len(result.threats)
    score = result.overall_score

    if threat_count == 0:
        console.print(f" {SYMBOLS['clean']}  {source:<50s} [score.none]threats: 0[/score.none]")
        console.print()
        console.print("  [muted]No prompt injection patterns detected.[/muted]")
    else:
        style = score_style(score)
        console.print(
            f" {SYMBOLS['alert']}  {source:<30s} "
            f"[{style}]threats: {threat_count}  score: {score}[/{style}]"
        )
        console.print()

        for i, threat in enumerate(result.threats, 1):
            sev_style = severity_style(threat.severity.value if hasattr(threat.severity, "value") else threat.severity)
            console.print(
                f"  [bold]#{i}[/bold]  [{sev_style}]{threat.severity.value if hasattr(threat.severity, 'value') else threat.severity:<8s}[/{sev_style}] "
                f"[header]{threat.pattern_name}[/header]"
            )
            if threat.line_number > 0:
                console.print(f"      [muted]Line {threat.line_number}:[/muted] \"{_truncate(threat.matched_text, 60)}\"")
            else:
                console.print(f"      [muted]Match:[/muted] \"{_truncate(threat.matched_text, 60)}\"")
            console.print(f"      [hint]Mitigation: {threat.mitigation}[/hint]")
            console.print()

    if result.recommendation:
        console.print(f"  [label]Recommendation:[/label] {result.recommendation}")

    console.print()


def render_status(
    stats: DashboardStats,
    config_summary: dict,
    chain_ok: bool = True,
    as_json: bool = False,
) -> None:
    """Render the sentinel status overview."""
    if as_json:
        data = {
            "schema_version": "1.0",
            "stats": stats.model_dump(),
            "config": config_summary,
            "chain_integrity": chain_ok,
        }
        console.print_json(data=data)
        return

    mode = config_summary.get("mode", "enforce").upper()
    version = config_summary.get("version", "0.1.0")

    console.print(f"  [banner]SHIELDPILOT[/banner] [version]v{version}[/version]"
                  f"                    [label]Mode:[/label] [header]{mode}[/header]")
    console.print()

    # Stats line
    console.print(
        f"  [label]Last 24h:[/label] {stats.total_commands} commands"
        f" | [block]{stats.blocked_commands} blocked[/block]"
        f" | [warn]{stats.warned_commands} warned[/warn]"
        f" | [label]avg score[/label] {stats.average_risk_score:.1f}"
    )

    # Incidents
    if stats.unresolved_incidents > 0:
        console.print(
            f"  [label]Incidents:[/label] [incident.id]{stats.unresolved_incidents} open[/incident.id]"
        )
    else:
        console.print("  [label]Incidents:[/label] [muted]none open[/muted]")

    # Health
    chain_status = "[chain.ok]verified[/chain.ok]" if chain_ok else "[chain.broken]BROKEN[/chain.broken]"
    llm_status = config_summary.get("llm_enabled", False)
    sandbox_status = config_summary.get("sandbox_enabled", True)

    console.print(
        f"  [label]Health:[/label]    Chain {chain_status}"
        f" | LLM {'on' if llm_status else 'off'}"
        f" | Sandbox {'on' if sandbox_status else 'off'}"
    )
    console.print()


def render_command_table(
    commands: list,
    total: int,
    limit: int = 20,
    as_json: bool = False,
) -> None:
    """Render command log table."""
    if as_json:
        rows = []
        for cmd in commands:
            rows.append({
                "id": cmd.id,
                "timestamp": str(cmd.timestamp),
                "command": cmd.command,
                "risk_score": cmd.risk_score,
                "action": cmd.action_taken,
                "llm_used": cmd.llm_used,
            })
        console.print_json(data={"schema_version": "1.0", "items": rows, "total": total})
        return

    table = Table(show_header=True, header_style="header", box=None, pad_edge=False)
    table.add_column("ID", style="muted", width=6)
    table.add_column("Time", style="timestamp", width=10)
    table.add_column("Command", style="command_text", max_width=40)
    table.add_column("Score", justify="right", width=6)
    table.add_column("Action", width=7)
    table.add_column("LLM", width=4)

    for cmd in commands:
        score = cmd.risk_score
        style = score_style(score)
        action_style = cmd.action_taken  # allow/warn/block — matches our style names
        time_str = cmd.timestamp.strftime("%H:%M:%S") if cmd.timestamp else ""

        table.add_row(
            str(cmd.id),
            time_str,
            _truncate(cmd.command, 40),
            f"[{style}]{score}[/{style}]",
            f"[{action_style}]{cmd.action_taken.upper()}[/{action_style}]",
            "[llm]*[/llm]" if cmd.llm_used else "",
        )

    console.print(table)

    if total > limit:
        console.print(
            f"\n  [muted]Showing {min(limit, len(commands))} of {total}. "
            f"Use --limit, --action, --risk-min, --search to filter.[/muted]"
        )
    console.print()


def render_chain_verification(
    results: dict,
    as_json: bool = False,
) -> None:
    """Render chain integrity verification results."""
    if as_json:
        console.print_json(data={"schema_version": "1.0", **results})
        return

    console.print("  [header]Chain Integrity Verification[/header]")
    console.print()

    all_ok = True
    for table_name, result in results.items():
        if isinstance(result, dict):
            valid = result.get("valid", False)
            total = result.get("total_entries", 0)
        else:
            valid = result.valid
            total = result.total_entries

        status = SYMBOLS["check"] if valid else SYMBOLS["cross"]
        console.print(f"  {table_name:<20s} {total:>6d} entries  {status}")

        if not valid:
            all_ok = False
            msg = result.get("message", "") if isinstance(result, dict) else result.message
            console.print(f"    [chain.broken]{msg}[/chain.broken]")

    console.print()
    if all_ok:
        console.print("  [chain.ok]All chains intact. No tampering detected.[/chain.ok]")
    else:
        console.print("  [chain.broken]ALERT: Log integrity compromised. Investigate immediately.[/chain.broken]")
    console.print()


def render_config(config_data: dict, as_json: bool = False) -> None:
    """Render current configuration summary."""
    if as_json:
        console.print_json(data={"schema_version": "1.0", **config_data})
        return

    console.print("  [header]Configuration[/header]")
    console.print()
    console.print(f"  [label]Mode:[/label]             {config_data.get('mode', 'enforce')}")
    console.print(f"  [label]Block threshold:[/label]  >= {config_data.get('block_threshold', 80)}")
    console.print(f"  [label]Warn threshold:[/label]   >= {config_data.get('warn_threshold', 40)}")
    console.print()

    llm = config_data.get("llm_enabled", False)
    sandbox = config_data.get("sandbox_enabled", True)
    chain = config_data.get("chain_hashing", True)
    console.print(f"  [label]LLM:[/label]              {'enabled' if llm else 'disabled'}")
    console.print(f"  [label]Sandbox:[/label]          {'enabled' if sandbox else 'disabled'}")
    console.print(f"  [label]Chain hashing:[/label]    {'enabled' if chain else 'disabled'}")
    console.print()

    wl = config_data.get("whitelist_count", 0)
    bl = config_data.get("blacklist_count", 0)
    pp = config_data.get("protected_paths_count", 0)
    sp = config_data.get("secret_patterns_count", 0)
    console.print(f"  [label]Whitelist:[/label]        {wl} commands")
    console.print(f"  [label]Blacklist:[/label]        {bl} patterns")
    console.print(f"  [label]Protected paths:[/label]  {pp} paths")
    console.print(f"  [label]Secret patterns:[/label]  {sp} regex rules")
    console.print()


def render_error(message: str, hint: str = "") -> None:
    """Render an error message with optional actionable hint."""
    console.print(f"  [error]Error:[/error] {message}")
    if hint:
        console.print(f"  [hint]{hint}[/hint]")
    console.print()


def render_warning(message: str) -> None:
    """Render a warning message."""
    console.print(f"  [warning]Warning:[/warning] {message}")


def render_banner() -> None:
    """Render the ShieldPilot welcome banner for init wizard."""
    console.print()
    console.print(Panel(
        "[banner]SHIELDPILOT[/banner]  [version]v0.1.0[/version]\n"
        "[muted]Security for autonomous AI coding agents[/muted]",
        border_style="dim cyan",
        padding=(1, 4),
    ))
    console.print()


def _truncate(text: str, max_len: int) -> str:
    """Truncate text with ellipsis if too long."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."
