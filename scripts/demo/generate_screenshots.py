#!/usr/bin/env python3
"""
ShieldPilot Product Hunt Screenshot Generator

Generates impressive CLI demo outputs showing:
1. sentinel mcp-scan    — MCP config security audit
2. sentinel supply-chain-audit — requirements.txt security audit

Run: python3 scripts/demo/generate_screenshots.py
Outputs: scripts/demo/output/mcp_scan.txt
         scripts/demo/output/supply_chain.txt
         scripts/demo/output/combined.txt
"""

import io
import os
import sys
import time
from pathlib import Path

from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.rule import Rule
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# ── ShieldPilot Brand Theme ────────────────────────────────────
THEME = Theme({
    "allow":     "bold green",
    "warn":      "bold yellow",
    "block":     "bold red",
    "score.low": "green",
    "score.mid": "yellow",
    "score.high":"bold red",
    "label":     "bold cyan",
    "category":  "cyan",
    "dim":       "dim white",
    "accent":    "bold #39D2C0",
    "header":    "bold white on #0D1117",
    "finding":   "bold red",
    "info":      "dim cyan",
    "ok":        "bold green",
    "critical":  "bold red",
    "high":      "red",
    "medium":    "yellow",
    "low":       "dim yellow",
})

OUTPUT_DIR = Path(__file__).parent / "output"
OUTPUT_DIR.mkdir(exist_ok=True)


def make_console(record: bool = False) -> Console:
    return Console(theme=THEME, record=record, width=100, highlight=False)


# ── MCP Scan Demo ──────────────────────────────────────────────

def demo_mcp_scan(console: Console) -> None:
    mcp_path = Path(__file__).parent / "mcp-config.json"

    console.print()
    console.print(Panel.fit(
        "[accent]ShieldPilot[/accent]  [bold white]MCP Configuration Security Audit[/bold white]",
        border_style="#39D2C0",
        padding=(0, 2),
    ))
    console.print()
    console.print(f"  [label]Target:[/label]  {mcp_path}")
    console.print(f"  [label]Profile:[/label] strict (block >= 60)")
    console.print()

    # Simulate scanning progress
    with Progress(
        SpinnerColumn(style="#39D2C0"),
        TextColumn("[cyan]{task.description}"),
        BarColumn(bar_width=40, style="#39D2C0", complete_style="#39D2C0"),
        TextColumn("[dim]{task.completed}/{task.total} servers[/dim]"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning MCP servers...", total=5)
        for _ in range(5):
            time.sleep(0.05)
            progress.advance(task)

    console.print()
    console.print(Rule("[dim]Scan Results[/dim]", style="dim #39D2C0"))
    console.print()

    # Results table
    table = Table(
        show_header=True,
        header_style="bold #39D2C0",
        border_style="dim",
        expand=True,
        row_styles=["", "dim"],
    )
    table.add_column("Server", style="bold white", min_width=16)
    table.add_column("Finding", min_width=40)
    table.add_column("Severity", justify="center", min_width=10)
    table.add_column("Score", justify="right", min_width=6)

    findings = [
        ("filesystem",    "Hardcoded AWS_SECRET_ACCESS_KEY in env",      "CRITICAL", "97"),
        ("filesystem",    "Hardcoded DB_PASSWORD in env",                 "CRITICAL", "95"),
        ("filesystem",    "Hardcoded API key (sk-prod-...)",              "CRITICAL", "93"),
        ("filesystem",    "Root filesystem access ( / ) — no path restriction", "HIGH", "82"),
        ("web-fetcher",   "ALLOWED_HOSTS=* enables SSRF to any host",    "HIGH",     "81"),
        ("web-fetcher",   "MAX_REDIRECTS=100 enables redirect chain abuse","MEDIUM",  "62"),
        ("code-executor", "SANDBOX=false — unrestricted code execution",  "CRITICAL", "99"),
        ("code-executor", "AUTH_REQUIRED=false — unauthenticated access", "CRITICAL", "96"),
        ("code-executor", "ALLOW_SYSTEM_CALLS=true — OS-level access",   "CRITICAL", "94"),
        ("database",      "Cleartext credentials in DATABASE_URL",        "CRITICAL", "92"),
        ("database",      "Connects to internal network (company.internal)","HIGH",   "78"),
        ("slack",         "Hardcoded SLACK_BOT_TOKEN (xoxb-...)",         "CRITICAL", "91"),
        ("slack",         "POST_AS_USER=true — can impersonate users",    "HIGH",     "76"),
    ]

    sev_styles = {
        "CRITICAL": "[critical]CRITICAL[/critical]",
        "HIGH":     "[high]HIGH    [/high]",
        "MEDIUM":   "[medium]MEDIUM  [/medium]",
        "LOW":      "[low]LOW     [/low]",
    }
    score_styles = {
        "CRITICAL": "score.high",
        "HIGH":     "score.high",
        "MEDIUM":   "score.mid",
        "LOW":      "score.low",
    }

    for server, finding, sev, score in findings:
        table.add_row(
            server,
            finding,
            sev_styles[sev],
            f"[{score_styles[sev]}]{score}[/{score_styles[sev]}]",
        )

    console.print(table)
    console.print()

    # Summary panel
    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold white", min_width=22)
    summary.add_column()
    summary.add_row("Servers scanned:",  "[bold white]5[/bold white]")
    summary.add_row("Total findings:",   "[bold white]13[/bold white]")
    summary.add_row("Critical:",         "[critical]6[/critical]")
    summary.add_row("High:",             "[high]4[/high]")
    summary.add_row("Medium:",           "[medium]2[/medium]")
    summary.add_row("Servers blocked:",  "[block]3 / 5[/block]")
    summary.add_row("Hardcoded secrets:", "[critical]4 exposed[/critical]")
    summary.add_row("Overall risk:",     "[block]CRITICAL[/block]")

    console.print(Panel(
        summary,
        title="[accent]Audit Summary[/accent]",
        border_style="#39D2C0",
        padding=(0, 2),
    ))
    console.print()
    console.print(
        "  [block]✗  3 MCP servers BLOCKED — dangerous configuration detected[/block]"
    )
    console.print(
        "  [warn]⚠  2 MCP servers WARNED — review before use[/warn]"
    )
    console.print(
        "  [ok]✓  0 MCP servers passed without findings[/ok]"
    )
    console.print()
    console.print(
        "  [info]Run [accent]sentinel dashboard[/accent] to view full incident report → http://localhost:8420[/info]"
    )
    console.print()


# ── Supply Chain Audit Demo ────────────────────────────────────

def demo_supply_chain(console: Console) -> None:
    req_path = Path(__file__).parent / "requirements-demo.txt"

    console.print()
    console.print(Panel.fit(
        "[accent]ShieldPilot[/accent]  [bold white]Supply Chain Security Audit[/bold white]",
        border_style="#39D2C0",
        padding=(0, 2),
    ))
    console.print()
    console.print(f"  [label]Target:[/label]  {req_path}")
    console.print(f"  [label]Checks:[/label]  typosquatting · unpinned versions · abandoned packages · dependency confusion")
    console.print()

    with Progress(
        SpinnerColumn(style="#39D2C0"),
        TextColumn("[cyan]{task.description}"),
        BarColumn(bar_width=40, style="#39D2C0", complete_style="#39D2C0"),
        TextColumn("[dim]{task.completed}/{task.total} packages[/dim]"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Auditing packages...", total=27)
        for _ in range(27):
            time.sleep(0.02)
            progress.advance(task)

    console.print()
    console.print(Rule("[dim]Typosquatting Detections[/dim]", style="dim #39D2C0"))
    console.print()

    typo_table = Table(
        show_header=True,
        header_style="bold #39D2C0",
        border_style="dim",
        expand=True,
    )
    typo_table.add_column("Package in requirements.txt", style="bold white", min_width=24)
    typo_table.add_column("Looks like", style="bold cyan", min_width=18)
    typo_table.add_column("Confidence", justify="center", min_width=12)
    typo_table.add_column("Action", justify="center", min_width=10)

    typo_findings = [
        ("colourama",       "colorama",    "99%",  "BLOCK"),
        ("djano",           "django",      "97%",  "BLOCK"),
        ("reqeusts",        "requests",    "98%",  "BLOCK"),
        ("urllib4",         "urllib3",     "94%",  "BLOCK"),
        ("nump0",           "numpy",       "96%",  "BLOCK"),
        ("panadas",         "pandas",      "95%",  "BLOCK"),
        ("boto",            "boto3",       "88%",  "WARN"),
        ("crypt0graphy",    "cryptography","93%",  "BLOCK"),
    ]

    for pkg, real, conf, action in typo_findings:
        action_fmt = f"[block]{action}[/block]" if action == "BLOCK" else f"[warn]{action}[/warn]"
        typo_table.add_row(pkg, real, conf, action_fmt)

    console.print(typo_table)
    console.print()
    console.print(Rule("[dim]Unpinned & Risky Packages[/dim]", style="dim #39D2C0"))
    console.print()

    unpinned_table = Table(
        show_header=True,
        header_style="bold #39D2C0",
        border_style="dim",
        expand=True,
    )
    unpinned_table.add_column("Package", style="bold white", min_width=24)
    unpinned_table.add_column("Issue", min_width=48)
    unpinned_table.add_column("Risk", justify="center", min_width=10)

    unpinned_findings = [
        ("pycrypto",          "Abandoned 2013 · 7 known CVEs (CVE-2018-6594...)",   "CRITICAL"),
        ("django (unpinned)", "No version pin — supply chain substitution risk",     "HIGH"),
        ("flask (unpinned)",  "No version pin — supply chain substitution risk",     "HIGH"),
        ("fastapi (unpinned)","No version pin — supply chain substitution risk",     "HIGH"),
        ("requests (unpinned)","No version pin — supply chain substitution risk",    "HIGH"),
        ("internal-auth-utils","Not on PyPI — dependency confusion attack surface",  "CRITICAL"),
        ("company-shared-models","Not on PyPI — dependency confusion attack surface","CRITICAL"),
        ("acme-corp-utils",   "Not on PyPI — dependency confusion attack surface",   "CRITICAL"),
    ]

    sev_map = {"CRITICAL": "[critical]CRITICAL[/critical]", "HIGH": "[high]HIGH[/high]", "MEDIUM": "[medium]MEDIUM[/medium]"}
    for pkg, issue, risk in unpinned_findings:
        unpinned_table.add_row(pkg, issue, sev_map[risk])

    console.print(unpinned_table)
    console.print()

    # Summary
    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold white", min_width=28)
    summary.add_column()
    summary.add_row("Packages scanned:",          "[bold white]27[/bold white]")
    summary.add_row("Typosquatting detections:",   "[block]8[/block]")
    summary.add_row("Dependency confusion risks:", "[critical]3[/critical]")
    summary.add_row("Unpinned versions:",          "[high]5[/high]")
    summary.add_row("Abandoned packages:",         "[critical]1 (pycrypto)[/critical]")
    summary.add_row("Packages blocked:",           "[block]7[/block]")
    summary.add_row("Packages warned:",            "[warn]1[/warn]")
    summary.add_row("Safe to install:",            "[ok]12[/ok]")
    summary.add_row("Overall risk:",               "[block]CRITICAL — do not install[/block]")

    console.print(Panel(
        summary,
        title="[accent]Audit Summary[/accent]",
        border_style="#39D2C0",
        padding=(0, 2),
    ))
    console.print()
    console.print(
        "  [block]✗  7 packages BLOCKED — probable malicious packages detected[/block]"
    )
    console.print(
        "  [warn]⚠  1 package WARNED — verify before installing[/warn]"
    )
    console.print(
        "  [info]Recommendation: Run [accent]pip-audit[/accent] and pin all versions with [accent]pip-compile[/accent][/info]"
    )
    console.print()
    console.print(
        "  [info]Run [accent]sentinel dashboard[/accent] to view full report → http://localhost:8420[/info]"
    )
    console.print()


# ── Main ───────────────────────────────────────────────────────

def save_output(name: str, render_fn, console_kwargs: dict = None) -> str:
    """Render to a recording console and save ANSI output."""
    c = make_console(record=True)
    render_fn(c)
    text = c.export_text()

    # Also save with ANSI codes for terminal screenshot tools
    out_path = OUTPUT_DIR / f"{name}.txt"
    out_path.write_text(text, encoding="utf-8")
    return text


def main():
    # Print to real terminal
    real_console = make_console()

    real_console.print()
    real_console.print(Rule("[accent]ShieldPilot — Product Hunt Demo[/accent]", style="#39D2C0"))

    real_console.print()
    real_console.print("[accent]═══ Demo 1: sentinel mcp-scan ═══[/accent]")
    demo_mcp_scan(real_console)

    real_console.print()
    real_console.print(Rule(style="dim"))
    real_console.print()
    real_console.print("[accent]═══ Demo 2: sentinel supply-chain-audit ═══[/accent]")
    demo_supply_chain(real_console)

    # Save outputs
    real_console.print(Rule("[dim]Saving outputs...[/dim]", style="dim"))

    mcp_text = save_output("mcp_scan", demo_mcp_scan)
    sc_text = save_output("supply_chain", demo_supply_chain)

    # Combined output
    combined_c = make_console(record=True)
    demo_mcp_scan(combined_c)
    combined_c.print()
    combined_c.print(Rule(style="dim"))
    combined_c.print()
    demo_supply_chain(combined_c)
    combined_text = combined_c.export_text()
    (OUTPUT_DIR / "combined.txt").write_text(combined_text, encoding="utf-8")

    real_console.print()
    real_console.print(f"  [ok]✓[/ok] [bold]{OUTPUT_DIR}/mcp_scan.txt[/bold]")
    real_console.print(f"  [ok]✓[/ok] [bold]{OUTPUT_DIR}/supply_chain.txt[/bold]")
    real_console.print(f"  [ok]✓[/ok] [bold]{OUTPUT_DIR}/combined.txt[/bold]")
    real_console.print()
    real_console.print(
        "  [info]Use a terminal screenshot tool (e.g. [accent]silicon[/accent] or [accent]iTerm2[/accent]) to capture these outputs.[/info]"
    )
    real_console.print()


if __name__ == "__main__":
    main()
