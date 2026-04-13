"""ShieldPilot CLI — primary user interface.

Entry point registered in pyproject.toml as `sentinel`.
All subcommands are defined here using Typer.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.prompt import Confirm, Prompt

from sentinelai.cli.styles import SENTINEL_THEME

app = typer.Typer(
    name="sentinel",
    help="ShieldPilot — Security for autonomous AI coding agents",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console(theme=SENTINEL_THEME)

# ── Global state ──────────────────────────────────────────────

_config_path: Optional[str] = None


def _version_callback(value: bool):
    if value:
        from sentinelai import __version__
        console.print(f"ShieldPilot v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    config: Optional[str] = typer.Option(
        None, "--config", "-c", help="Path to sentinel.yaml"
    ),
    version: bool = typer.Option(
        False, "--version", "-V", help="Show version and exit",
        callback=_version_callback, is_eager=True,
    ),
):
    """ShieldPilot — Security for autonomous AI coding agents."""
    global _config_path
    _config_path = config


def _load_config():
    """Load config with error handling."""
    from sentinelai.core.config import load_config
    from sentinelai.cli.formatters import render_error

    try:
        return load_config(_config_path)
    except Exception as e:
        render_error(
            f"Failed to load configuration: {e}",
            "Run 'sentinel init' to create a config, or use --config PATH.",
        )
        raise typer.Exit(code=2)


def _is_interactive() -> bool:
    """Check if stdout is a TTY (interactive terminal)."""
    return sys.stdout.isatty()


# ── sentinel run ──────────────────────────────────────────────


@app.command()
def run(
    command: str = typer.Argument(..., help="Shell command to evaluate"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Auto-confirm warnings"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Evaluate only, don't execute"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM evaluation"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output"),
):
    """Evaluate a shell command for security risk, then execute if safe."""
    from sentinelai.cli.formatters import render_assessment, render_error, render_warning
    from sentinelai.core.constants import Action

    config = _load_config()

    # Disable LLM if requested
    if no_llm:
        config.llm.enabled = False

    # Build engine and assess
    from sentinelai.engine import RiskEngine
    from sentinelai.engine.base import AnalysisContext

    engine = RiskEngine(config)
    context = AnalysisContext(
        working_directory=os.getcwd(),
        environment=dict(os.environ),
        config=config,
    )

    # Show spinner for LLM evaluation
    if config.llm.enabled and not output_json and not quiet:
        with console.status("[llm]  Evaluating with AI...[/llm]", spinner="dots"):
            assessment = engine.assess(command, context)
    else:
        assessment = engine.assess(command, context)

    # Render the assessment
    if not quiet:
        render_assessment(assessment, verbose=verbose, as_json=output_json)

    # Log the assessment
    try:
        from sentinelai.core.secrets import SecretsMasker
        from sentinelai.logger import BlackboxLogger

        masker = SecretsMasker(config.secrets_patterns)
        logger = BlackboxLogger(config=config.logging, masker=masker)
    except Exception:
        logger = None

    action = assessment.action

    # Determine whether to execute
    should_execute = False

    if config.mode == "disabled":
        should_execute = True
    elif config.mode == "audit":
        # Audit mode: log everything, execute everything
        should_execute = True
    elif action == Action.ALLOW:
        should_execute = True
    elif action == Action.WARN:
        if dry_run:
            should_execute = False
        elif yes:
            should_execute = True
        elif _is_interactive():
            should_execute = Confirm.ask("  [prompt]Proceed?[/prompt]", default=False)
        else:
            # Non-interactive: fail-safe, treat WARN as BLOCK
            if not output_json:
                render_warning("Non-interactive mode: WARN treated as BLOCK (fail-safe).")
            should_execute = False
    elif action == Action.BLOCK:
        should_execute = False

    # Execute if allowed
    exit_code = None
    output = None

    if should_execute and not dry_run:
        try:
            from sentinelai.sandbox import CommandSandbox
            sandbox = CommandSandbox(config.sandbox)
            result = sandbox.execute(command, working_dir=os.getcwd())

            exit_code = result.exit_code
            output = result.stdout

            # Print command output
            if result.stdout and not output_json:
                sys.stdout.write(result.stdout)
            if result.stderr and not output_json:
                sys.stderr.write(result.stderr)

            if result.timed_out and not output_json:
                render_warning(f"Command timed out after {config.sandbox.timeout}s.")

        except Exception as e:
            if not output_json:
                render_error(f"Execution failed: {e}")
            exit_code = 1

    # Log the result
    if logger:
        try:
            incident_id = None
            cmd_id = logger.log_command(
                assessment=assessment,
                output=output,
                executed=should_execute and not dry_run,
                exit_code=exit_code,
                working_directory=os.getcwd(),
            )

            # Create incident for BLOCK actions
            if action == Action.BLOCK:
                severity = "critical" if assessment.final_score >= 90 else "high"
                incident_id = logger.log_incident(
                    severity=severity,
                    category=assessment.signals[0].category.value if assessment.signals else "unknown",
                    title=f"Blocked: {command[:80]}",
                    description=f"Command blocked with risk score {assessment.final_score}",
                    evidence=command,
                    command_id=cmd_id,
                )
                if not output_json and not quiet:
                    console.print(
                        f"  [incident.id]Incident #{incident_id} created "
                        f"({severity}).[/incident.id]"
                    )
                    console.print()
        except Exception:
            pass  # Don't fail the command because of logging errors

    # Set exit code
    if action == Action.BLOCK:
        raise typer.Exit(code=1)
    elif action == Action.WARN and not should_execute:
        raise typer.Exit(code=1)
    elif exit_code is not None and exit_code != 0:
        raise typer.Exit(code=exit_code)


# ── sentinel scan ─────────────────────────────────────────────


@app.command()
def scan(
    file_path: str = typer.Argument(..., help="File to scan, or '-' for stdin"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show matched pattern details"),
    output_json: bool = typer.Option(False, "--json", help="Output results as JSON"),
    exit_code: bool = typer.Option(
        False, "--exit-code", help="Exit with code 1 if threats found (for CI)"
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only show threat count"),
    use_ml: bool = typer.Option(
        False, "--use-ml", help="Augment pattern scan with ML model (requires shieldpilot[ml])"
    ),
):
    """Scan a file or stdin for prompt injection patterns."""
    from sentinelai.cli.formatters import render_error, render_scan_result

    # Read content
    if file_path == "-":
        content = sys.stdin.read()
        source = "stdin"
    else:
        path = Path(file_path)
        if not path.exists():
            render_error(
                f"File not found: {file_path}",
                "Check the path and try again.",
            )
            raise typer.Exit(code=2)
        content = path.read_text(encoding="utf-8", errors="replace")
        source = str(path.name)

    # Scan
    from sentinelai.scanner import PromptScanner

    scanner = PromptScanner(use_ml=use_ml)
    result = scanner.scan(content, source=source)

    # Render
    if not quiet:
        render_scan_result(result, verbose=verbose, as_json=output_json)

    # Log
    config = _load_config()
    try:
        from sentinelai.core.secrets import SecretsMasker
        from sentinelai.logger import BlackboxLogger

        masker = SecretsMasker(config.secrets_patterns)
        logger = BlackboxLogger(config=config.logging, masker=masker)
        logger.log_prompt_scan(result)
    except Exception:
        pass

    # Exit code for CI
    if exit_code and len(result.threats) > 0:
        raise typer.Exit(code=1)


# ── sentinel mcp-scan ─────────────────────────────────────────


@app.command(name="mcp-scan")
def mcp_scan(
    target: str = typer.Argument(
        ...,
        help="Path to an MCP config file (JSON) or a directory to scan recursively",
    ),
    output_json: bool = typer.Option(False, "--json", help="Output results as JSON"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only print finding count summary"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show all findings including INFO"),
    exit_code_flag: bool = typer.Option(
        False, "--exit-code", help="Exit with code 1 if any findings (for CI/CD)"
    ),
    min_severity: str = typer.Option(
        "LOW",
        "--min-severity",
        help="Minimum severity to report: CRITICAL, HIGH, MEDIUM, LOW, INFO",
    ),
):
    """Scan MCP server config files for security vulnerabilities.

    Detects SSRF risks, missing authentication, hardcoded secrets,
    over-privileged tool definitions, insecure transport, and known
    vulnerable dependencies.

    Examples:

      sentinel mcp-scan ~/Library/Application\\ Support/Claude/claude_desktop_config.json

      sentinel mcp-scan ./my-mcp-servers/ --json

      sentinel mcp-scan config.json --exit-code --min-severity HIGH
    """
    from sentinelai.scanner.mcp_scanner import MCPFindingSeverity, MCPScanner
    from sentinelai.cli.formatters import render_error

    # Validate min_severity
    try:
        min_sev = MCPFindingSeverity(min_severity.upper())
    except ValueError:
        render_error(
            f"Invalid --min-severity '{min_severity}'",
            "Valid values: CRITICAL, HIGH, MEDIUM, LOW, INFO",
        )
        raise typer.Exit(code=2)

    path = Path(target)
    if not path.exists():
        render_error(f"Path not found: {target}", "Check the path and try again.")
        raise typer.Exit(code=2)

    scanner = MCPScanner()
    if path.is_dir():
        result = scanner.scan_directory(path)
    else:
        result = scanner.scan_file(path)

    # Filter by severity
    filtered_findings = [
        f for f in result.findings if f.severity.order <= min_sev.order
    ]

    if output_json:
        import json as _json
        out = result.to_dict()
        out["findings"] = [f.to_dict() for f in filtered_findings]
        out["summary"] = {sev: sum(1 for f in filtered_findings if f.severity.value == sev)
                          for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
        console.print_json(data=out)
    elif quiet:
        summary = {sev: sum(1 for f in filtered_findings if f.severity.value == sev)
                   for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
        parts = [f"{sev}: {count}" for sev, count in summary.items() if count > 0]
        console.print(", ".join(parts) if parts else "No findings")
    else:
        _render_mcp_result(result, filtered_findings, verbose=verbose)

    if exit_code_flag and filtered_findings:
        raise typer.Exit(code=1)


def _render_mcp_result(result, findings, verbose: bool = False) -> None:
    """Pretty-print MCP scan results using Rich."""
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from sentinelai.scanner.mcp_scanner import MCPFindingSeverity

    _SEV_STYLE = {
        MCPFindingSeverity.CRITICAL: "bold red",
        MCPFindingSeverity.HIGH: "red",
        MCPFindingSeverity.MEDIUM: "yellow",
        MCPFindingSeverity.LOW: "cyan",
        MCPFindingSeverity.INFO: "dim",
    }
    _SEV_BADGE = {
        MCPFindingSeverity.CRITICAL: "  CRIT ",
        MCPFindingSeverity.HIGH: "  HIGH ",
        MCPFindingSeverity.MEDIUM: "  MED  ",
        MCPFindingSeverity.LOW: "  LOW  ",
        MCPFindingSeverity.INFO: "  INFO ",
    }

    console.print()
    console.print(f"  [bold]ShieldPilot MCP Security Scanner[/bold]")
    console.print(f"  Scanned [bold]{len(result.scanned_files)}[/bold] file(s) "
                  f"in [dim]{result.execution_time_ms:.0f}ms[/dim]")
    console.print()

    if not findings:
        console.print("  [green]✓  No findings — MCP config looks clean.[/green]")
        console.print()
        return

    # Summary bar
    sev_counts = {sev: sum(1 for f in findings if f.severity.value == sev)
                  for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}
    summary_parts = []
    for sev, count in sev_counts.items():
        if count:
            style = _SEV_STYLE[MCPFindingSeverity(sev)]
            summary_parts.append(f"[{style}]{sev}: {count}[/{style}]")
    console.print("  " + "  ".join(summary_parts))
    console.print()

    # Findings table
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
    table.add_column("SEV", width=8)
    table.add_column("CATEGORY", width=22)
    table.add_column("SERVER", width=20)
    table.add_column("DESCRIPTION")

    for f in sorted(findings, key=lambda x: x.severity.order):
        style = _SEV_STYLE[f.severity]
        badge = _SEV_BADGE[f.severity]
        table.add_row(
            Text(badge, style=style),
            f.category.value,
            f.server_name or "—",
            f.description[:90] + ("…" if len(f.description) > 90 else ""),
        )

    console.print(table)

    # Verbose: full details per finding
    if verbose:
        console.print()
        for i, f in enumerate(sorted(findings, key=lambda x: x.severity.order), 1):
            style = _SEV_STYLE[f.severity]
            console.print(f"  [{style}]{'─' * 60}[/{style}]")
            console.print(f"  [{style}]{f.severity.value}[/{style}]  {f.category.value}  "
                          f"— server: [bold]{f.server_name or '(file-level)'}[/bold]")
            console.print(f"  File: {f.file_path}:{f.line_number}")
            console.print(f"  [bold]Issue:[/bold] {f.description}")
            console.print(f"  [bold]Evidence:[/bold] {f.evidence}")
            console.print(f"  [bold]Fix:[/bold] {f.recommendation}")
            console.print()

    console.print(f"  [dim]Total findings: {len(findings)}[/dim]")
    console.print()


# ── sentinel logs ─────────────────────────────────────────────


@app.command()
def logs(
    action: Optional[str] = typer.Option(None, "--action", "-a", help="Filter: allow/warn/block"),
    risk_min: Optional[int] = typer.Option(None, "--risk-min", help="Minimum risk score"),
    risk_max: Optional[int] = typer.Option(None, "--risk-max", help="Maximum risk score"),
    search: Optional[str] = typer.Option(None, "--search", "-s", help="Search in commands"),
    limit: int = typer.Option(20, "--limit", "-l", help="Number of entries"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
    export_csv: bool = typer.Option(False, "--csv", help="Export as CSV"),
):
    """Browse and search activity logs."""
    from sentinelai.cli.formatters import render_command_table, render_error

    config = _load_config()

    try:
        from sentinelai.core.secrets import SecretsMasker
        from sentinelai.logger import BlackboxLogger

        masker = SecretsMasker(config.secrets_patterns)
        logger = BlackboxLogger(config=config.logging, masker=masker)
    except Exception as e:
        render_error(f"Cannot open database: {e}", f"Check: ls -la {config.logging.database}")
        raise typer.Exit(code=2)

    commands, total = logger.query_commands(
        action=action,
        risk_min=risk_min,
        risk_max=risk_max,
        search=search,
        limit=limit,
    )

    if export_csv:
        # CSV export
        import csv
        import io

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["id", "timestamp", "command", "risk_score", "action", "executed", "llm_used"])
        for cmd in commands:
            writer.writerow([
                cmd.id, cmd.timestamp, cmd.command, cmd.risk_score,
                cmd.action_taken, cmd.executed, cmd.llm_used,
            ])
        sys.stdout.write(buf.getvalue())
        return

    render_command_table(commands, total, limit=limit, as_json=output_json)


# ── sentinel status ───────────────────────────────────────────


@app.command()
def status(
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show system overview and health."""
    from sentinelai import __version__
    from sentinelai.cli.formatters import render_error, render_status

    config = _load_config()

    try:
        from sentinelai.core.secrets import SecretsMasker
        from sentinelai.logger import BlackboxLogger

        masker = SecretsMasker(config.secrets_patterns)
        logger = BlackboxLogger(config=config.logging, masker=masker)
        stats = logger.get_stats(hours=24)

        # Quick chain check (just commands table for speed)
        chain_result = logger.verify_chain("commands")
        chain_ok = chain_result.valid
    except Exception:
        from sentinelai.core.models import DashboardStats
        stats = DashboardStats()
        chain_ok = True

    config_summary = {
        "version": __version__,
        "mode": config.mode,
        "llm_enabled": config.llm.enabled,
        "sandbox_enabled": config.sandbox.enabled,
    }

    render_status(stats, config_summary, chain_ok=chain_ok, as_json=output_json)


# ── sentinel perf ────────────────────────────────────────────


@app.command()
def perf(
    last: int = typer.Option(100, "--last", "-n", help="Number of recent commands to analyze"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Show performance statistics from recent command assessments."""
    import statistics

    from sentinelai.core.secrets import SecretsMasker
    from sentinelai.logger import BlackboxLogger
    from sentinelai.logger.database import CommandLog

    config = _load_config()
    masker = SecretsMasker(config.secrets_patterns)
    logger = BlackboxLogger(config=config.logging, masker=masker)
    session = logger._get_session()

    try:
        entries = (
            session.query(CommandLog.execution_time_ms)
            .filter(CommandLog.execution_time_ms != None)  # noqa: E711
            .order_by(CommandLog.id.desc())
            .limit(last)
            .all()
        )

        if not entries:
            if output_json:
                print(json.dumps({"schema_version": "1.0", "error": "No commands with timing data"}))
            else:
                console.print("  No commands with timing data found.")
            return

        latencies = sorted([e.execution_time_ms for e in entries])
        n = len(latencies)

        def pct(p):
            k = int((n - 1) * p / 100)
            return latencies[min(k, n - 1)]

        stats = {
            "schema_version": "1.0",
            "sample_size": n,
            "p50_ms": round(pct(50), 1),
            "p95_ms": round(pct(95), 1),
            "p99_ms": round(pct(99), 1),
            "min_ms": round(latencies[0], 1),
            "max_ms": round(latencies[-1], 1),
            "mean_ms": round(statistics.mean(latencies), 1),
        }

        if output_json:
            print(json.dumps(stats))
        else:
            console.print(f"\n  [bold]Performance Stats[/bold] (last {n} commands)\n")
            console.print(f"  p50:  {stats['p50_ms']:>8.1f} ms")
            console.print(f"  p95:  {stats['p95_ms']:>8.1f} ms")
            console.print(f"  p99:  {stats['p99_ms']:>8.1f} ms")
            console.print(f"  min:  {stats['min_ms']:>8.1f} ms")
            console.print(f"  max:  {stats['max_ms']:>8.1f} ms")
            console.print(f"  mean: {stats['mean_ms']:>8.1f} ms")
            console.print()
    finally:
        session.close()


# ── sentinel config ───────────────────────────────────────────


@app.command()
def config(
    validate: bool = typer.Option(False, "--validate", help="Validate config file"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """View and validate current configuration."""
    from sentinelai.cli.formatters import render_config, render_error

    cfg = _load_config()

    if validate:
        console.print("  [success]Configuration is valid.[/success]")
        console.print()
        return

    config_data = {
        "mode": cfg.mode,
        "block_threshold": cfg.risk_thresholds.block,
        "warn_threshold": cfg.risk_thresholds.warn,
        "llm_enabled": cfg.llm.enabled,
        "sandbox_enabled": cfg.sandbox.enabled,
        "chain_hashing": cfg.logging.chain_hashing,
        "whitelist_count": len(cfg.whitelist.commands),
        "blacklist_count": len(cfg.blacklist.commands),
        "protected_paths_count": len(cfg.protected_paths),
        "secret_patterns_count": len(cfg.secrets_patterns),
    }

    render_config(config_data, as_json=output_json)


# ── sentinel verify ───────────────────────────────────────────


@app.command()
def verify(
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Verify log chain integrity for tamper detection."""
    from sentinelai.cli.formatters import render_chain_verification, render_error

    config = _load_config()

    try:
        from sentinelai.core.secrets import SecretsMasker
        from sentinelai.logger import BlackboxLogger

        masker = SecretsMasker(config.secrets_patterns)
        logger = BlackboxLogger(config=config.logging, masker=masker)
    except Exception as e:
        render_error(f"Cannot open database: {e}")
        raise typer.Exit(code=2)

    tables = ["commands", "prompt_scans", "file_changes", "network_access", "incidents"]
    results = {}
    all_ok = True

    for table in tables:
        result = logger.verify_chain_with_alert(table)
        results[table] = {
            "valid": result.valid,
            "total_entries": result.total_entries,
            "verified_entries": result.verified_entries,
            "message": result.message,
        }
        if not result.valid:
            all_ok = False

    render_chain_verification(results, as_json=output_json)

    if not all_ok:
        raise typer.Exit(code=1)


# ── sentinel init ─────────────────────────────────────────────


@app.command()
def init(
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing config"),
):
    """Set up ShieldPilot for your project."""
    import platform
    import shutil

    from sentinelai.cli.formatters import render_banner, render_error

    config_path = Path("sentinel.yaml")
    if config_path.exists() and not force:
        render_error(
            "sentinel.yaml already exists in this directory.",
            "Use 'sentinel init --force' to overwrite.",
        )
        raise typer.Exit(code=1)

    render_banner()

    # Step 2: Auto-detect environment
    console.print("  [label]Detecting environment...[/label]")
    console.print(f"    Working directory: [value]{os.getcwd()}[/value]")
    console.print(f"    Platform:          [value]{platform.system()} {platform.release()}[/value]")
    console.print(f"    Python:            [value]{platform.python_version()}[/value]")

    git_repo = Path(".git").exists()
    console.print(f"    Git repository:    [value]{'Yes' if git_repo else 'No'}[/value]")

    env_files = list(Path(".").glob(".env*"))
    if env_files:
        console.print(f"    Env files found:   [warn]{len(env_files)}[/warn]")
    console.print()

    # Step 3: Choose mode
    mode = Prompt.ask(
        "  [prompt]Operating mode[/prompt]",
        choices=["enforce", "audit", "disabled"],
        default="enforce",
    )

    # Step 4: LLM opt-in
    use_llm = Confirm.ask(
        "  [prompt]Enable AI-powered analysis? (requires ANTHROPIC_API_KEY)[/prompt]",
        default=False,
    )
    console.print()

    # Step 5: Generate config
    import yaml

    config_data = {
        "sentinel": {
            "mode": mode,
            "risk_thresholds": {"block": 80, "warn": 40, "allow": 0},
            "llm": {"enabled": use_llm, "model": "claude-sonnet-4-20250514", "score_range": [40, 79]},
            "whitelist": {
                "commands": ["ls", "cat", "echo", "pwd", "whoami", "date", "head", "tail",
                            "wc", "grep", "find", "which", "man", "help"],
            },
            "blacklist": {
                "commands": ["rm -rf /", "rm -rf /*", "mkfs", "dd if=/dev/zero", ":(){:|:&};:"],
                "domains": ["pastebin.com", "transfer.sh", "ngrok.io", "requestbin.com"],
            },
            "protected_paths": ["/etc", "/var", "/boot", "~/.ssh", "~/.aws", "~/.gnupg", "~/.config"],
            "secrets_patterns": [
                '(?i)(api[_-]?key|secret|password|token|credential)\\s*[=:]\\s*[\'"]?[A-Za-z0-9+/=]{16,}',
                'AKIA[0-9A-Z]{16}',
                'sk-[a-zA-Z0-9]{20,}',
                'ghp_[a-zA-Z0-9]{36}',
            ],
            "sandbox": {
                "enabled": True, "timeout": 30, "max_memory_mb": 512,
                "restricted_env_vars": ["AWS_SECRET_ACCESS_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"],
            },
            "plugins": {"enabled": True, "directory": "plugins"},
            "logging": {"database": "sentinel.db", "chain_hashing": True, "retention_days": 90},
            "auth": {
                "secret_key": "CHANGE-ME-IN-PRODUCTION-" + os.urandom(16).hex(),
                "algorithm": "HS256",
                "access_token_expire_minutes": 1440,
                "default_admin_user": "admin",
                "default_admin_password": os.urandom(12).hex(),
            },
            "billing": {"enabled": False, "tier": "free"},
        }
    }

    with open(config_path, "w") as f:
        yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)

    # Initialize database
    from sentinelai.logger.database import init_database
    init_database("sentinel.db")

    console.print(f"  [success]Created[/success] sentinel.yaml")
    console.print(f"  [success]Created[/success] sentinel.db")
    console.print()

    # Quick Start panel
    from rich.panel import Panel
    console.print(Panel(
        "[label]Wrap your AI agent commands:[/label]\n"
        "  $ sentinel run \"your-agent-command-here\"\n\n"
        "[label]Scan prompts for injection:[/label]\n"
        "  $ sentinel scan system-prompt.md\n\n"
        "[label]View your dashboard:[/label]\n"
        "  $ sentinel dashboard",
        title="[header]Quick Start[/header]",
        border_style="dim cyan",
        padding=(1, 2),
    ))
    console.print()


# ── sentinel dashboard ────────────────────────────────────────


@app.command()
def dashboard(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Bind address"),
    port: int = typer.Option(8420, "--port", "-p", help="Port number"),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload on changes"),
):
    """Launch the web dashboard."""
    import socket

    config = _load_config()

    console.print()
    console.print("  [banner]Starting ShieldPilot Dashboard...[/banner]")
    console.print()

    # Get local network address
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        local_ip = "127.0.0.1"

    console.print(f"  [label]Local:[/label]    [value]http://localhost:{port}[/value]")
    if host == "0.0.0.0":
        console.print(f"  [label]Network:[/label]  [value]http://{local_ip}:{port}[/value]")
    console.print()
    console.print(f"  [label]Default admin user:[/label] [value]{config.auth.default_admin_user}[/value]")
    console.print(f"  [label]Admin password:[/label]    [value](see sentinel.yaml or set SHIELDPILOT_ADMIN_PASSWORD env var)[/value]")
    console.print()
    console.print("  [warn]Set a strong admin password via SHIELDPILOT_ADMIN_PASSWORD env var.[/warn]")
    console.print("  [muted]Press Ctrl+C to stop.[/muted]")
    console.print()

    import uvicorn

    uvicorn.run(
        "sentinelai.api.app:create_app",
        host=host,
        port=port,
        reload=reload,
        factory=True,
        log_level="warning",
    )


# ── sentinel ml-setup ────────────────────────────────────────


@app.command("ml-setup")
def ml_setup():
    """Download the ProtectAI DeBERTa-v3 prompt injection model.

    Requires the ML extras to be installed first::

        pip install shieldpilot[ml]
    """
    console.print()
    console.print("  [header]ShieldPilot ML Setup[/header]")
    console.print()

    try:
        import transformers  # type: ignore  # noqa: F401
    except ImportError:
        console.print(
            "  [warn]transformers is not installed.[/warn]\n"
            "  Install ML dependencies first:\n\n"
            "    [value]pip install shieldpilot\\[ml\\][/value]\n"
        )
        raise typer.Exit(code=1)

    from sentinelai.ml.classifier import PromptInjectionClassifier, _MODEL_ID

    console.print(f"  Downloading model: [value]{_MODEL_ID}[/value]")
    console.print("  [muted](This may take a few minutes on first run.)[/muted]")
    console.print()

    clf = PromptInjectionClassifier()
    with console.status("  Loading model weights...", spinner="dots"):
        ok = clf.load_model()

    if ok:
        console.print("  [success]Model ready.[/success]")
        console.print()
        console.print("  Test it now:")
        console.print('    [value]sentinel ml-test "ignore all previous instructions"[/value]')
    else:
        console.print(
            "  [warn]Model download failed.[/warn]\n"
            "  Check your internet connection and that transformers is installed."
        )
        raise typer.Exit(code=1)
    console.print()


# ── sentinel ml-test ──────────────────────────────────────────


@app.command("ml-test")
def ml_test(
    text: str = typer.Argument(..., help="Text to classify"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Run a quick ML injection classification on TEXT.

    Example::

        sentinel ml-test "ignore all previous instructions"
    """
    import json as _json

    from sentinelai.ml.classifier import PromptInjectionClassifier

    clf = PromptInjectionClassifier()
    with console.status("  Classifying...", spinner="dots") if not output_json else _null_ctx():
        result = clf.classify(text)

    if output_json:
        print(_json.dumps(result))
        return

    console.print()
    console.print("  [header]ML Classification Result[/header]")
    console.print()
    status = result.get("status", "unknown")

    if status == "unavailable":
        console.print(
            "  [warn]ML model unavailable.[/warn]\n"
            "  Install: [value]pip install shieldpilot\\[ml\\][/value]\n"
            "  Then:    [value]sentinel ml-setup[/value]"
        )
    elif status == "not_loaded":
        console.print(
            "  [warn]Model weights not downloaded yet.[/warn]\n"
            "  Run: [value]sentinel ml-setup[/value]"
        )
    elif status == "timeout":
        console.print("  [warn]Classification timed out (>100 ms).[/warn]")
    elif status == "error":
        console.print("  [warn]Classification error — check logs.[/warn]")
    else:
        is_inj = result.get("is_injection", False)
        conf = float(result.get("confidence", 0.0))
        label = result.get("label", "?")
        score = result.get("score", 0)

        verdict = "[block] INJECTION [/block]" if is_inj else "[allow] SAFE [/allow]"
        console.print(f"  Verdict:     {verdict}")
        console.print(f"  Label:       [value]{label}[/value]")
        console.print(f"  Confidence:  [value]{conf:.1%}[/value]")
        console.print(f"  ML Score:    [value]{score}/100[/value]")

    console.print()


class _null_ctx:
    """Minimal no-op context manager used to skip the status spinner in JSON mode."""

    def __enter__(self):
        return self

    def __exit__(self, *_):
        pass


# ── sentinel hook ─────────────────────────────────────────────


hook_app = typer.Typer(
    name="hook",
    help="Manage Claude Code integration hooks.",
    no_args_is_help=True,
)
app.add_typer(hook_app, name="hook")


def _get_settings_path(scope: str) -> Path:
    """Get the Claude Code settings file path for the given scope."""
    if scope == "user":
        return Path.home() / ".claude" / "settings.json"
    elif scope == "project":
        return Path(".claude") / "settings.json"
    else:  # local
        return Path(".claude") / "settings.local.json"


def _read_settings(path: Path) -> dict:
    """Read Claude Code settings file, return empty dict if not found."""
    if path.exists():
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _write_settings(path: Path, settings: dict) -> None:
    """Write Claude Code settings file, creating parent dirs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, indent=2) + "\n")


def _get_hook_command() -> str:
    """Build the hook command string that invokes sentinel_hook.py."""
    # Use the Python interpreter that has sentinelai installed
    hook_module = "sentinelai.hooks.sentinel_hook"
    return f"{sys.executable} -m {hook_module}"


SENTINEL_HOOK_MARKER = "sentinelai"  # used to identify our hook entries


@hook_app.command("install")
def hook_install(
    scope: str = typer.Option(
        "user",
        "--scope",
        "-s",
        help="Where to install: user (~/.claude), project (.claude), or local (.claude local)",
    ),
):
    """Install ShieldPilot as a Claude Code security hook.

    Enables autonomous mode: Claude Code runs without permission prompts
    while ShieldPilot silently evaluates every action. Safe commands auto-
    approve, risky commands pause for your review, and dangerous commands
    are blocked outright.
    """
    from sentinelai.cli.formatters import render_error

    if scope not in ("user", "project", "local"):
        render_error(
            f"Invalid scope '{scope}'.",
            "Use: --scope user | project | local",
        )
        raise typer.Exit(code=2)

    settings_path = _get_settings_path(scope)
    settings = _read_settings(settings_path)

    hook_cmd = _get_hook_command()

    # Build the hook entry
    sentinel_hook_entry = {
        "type": "command",
        "command": hook_cmd,
        "timeout": 10,
    }

    # Ensure hooks.PreToolUse exists
    if "hooks" not in settings:
        settings["hooks"] = {}
    if "PreToolUse" not in settings["hooks"]:
        settings["hooks"]["PreToolUse"] = []

    # Check if already installed
    pre_tool_hooks = settings["hooks"]["PreToolUse"]
    already_installed = False
    for entry in pre_tool_hooks:
        hooks_list = entry.get("hooks", [])
        for h in hooks_list:
            if SENTINEL_HOOK_MARKER in h.get("command", ""):
                already_installed = True
                break

    if already_installed:
        console.print("  [warn]ShieldPilot hook is already installed.[/warn]")
        console.print(f"  [muted]Settings: {settings_path}[/muted]")
        console.print()
        return

    # Add our hook — no matcher means it intercepts ALL tools
    # The hook script itself decides what to allow/block
    pre_tool_hooks.append({
        "hooks": [sentinel_hook_entry],
    })

    _write_settings(settings_path, settings)

    console.print()
    console.print("  [success]ShieldPilot autonomous mode enabled for Claude Code.[/success]")
    console.print()
    console.print(f"  [label]Scope:[/label]    {scope}")
    console.print(f"  [label]Settings:[/label] [value]{settings_path}[/value]")
    console.print(f"  [label]Hook:[/label]     PreToolUse → all tools")
    console.print()
    console.print("  [header]How it works:[/header]")
    console.print("  Claude Code now runs without interruptions. ShieldPilot")
    console.print("  silently evaluates every action in the background.")
    console.print()
    console.print("  [allow] score 0-39  [/allow]  Auto-approved — runs without prompt")
    console.print("  [warn] score 40-79 [/warn]  Pauses for your review")
    console.print("  [block] score 80+   [/block]  Blocked — incident logged to dashboard")
    console.print()
    console.print("  [label]What's protected:[/label]")
    console.print("    Bash: destructive commands, exfiltration, privilege escalation")
    console.print("    File writes: protected paths (/etc, ~/.ssh, ~/.aws, etc.)")
    console.print("    Supply chain: typosquatting, untrusted installs")
    console.print()
    console.print("  [muted]View activity: sentinel dashboard (http://localhost:8420)[/muted]")
    console.print("  [muted]To remove:     sentinel hook uninstall[/muted]")
    console.print()


@hook_app.command("uninstall")
def hook_uninstall(
    scope: str = typer.Option(
        "user",
        "--scope",
        "-s",
        help="Scope to uninstall from: user, project, or local",
    ),
):
    """Remove ShieldPilot hook from Claude Code."""
    from sentinelai.cli.formatters import render_error

    if scope not in ("user", "project", "local"):
        render_error(
            f"Invalid scope '{scope}'.",
            "Use: --scope user | project | local",
        )
        raise typer.Exit(code=2)

    settings_path = _get_settings_path(scope)
    settings = _read_settings(settings_path)

    if "hooks" not in settings or "PreToolUse" not in settings.get("hooks", {}):
        console.print("  [muted]No ShieldPilot hook found to uninstall.[/muted]")
        console.print()
        return

    # Filter out our hook entries
    pre_tool_hooks = settings["hooks"]["PreToolUse"]
    filtered = []
    removed = False

    for entry in pre_tool_hooks:
        hooks_list = entry.get("hooks", [])
        clean_hooks = [
            h for h in hooks_list
            if SENTINEL_HOOK_MARKER not in h.get("command", "")
        ]
        if len(clean_hooks) < len(hooks_list):
            removed = True
        if clean_hooks:
            entry["hooks"] = clean_hooks
            filtered.append(entry)

    if not removed:
        console.print("  [muted]No ShieldPilot hook found to uninstall.[/muted]")
        console.print()
        return

    settings["hooks"]["PreToolUse"] = filtered

    # Clean up empty structures
    if not settings["hooks"]["PreToolUse"]:
        del settings["hooks"]["PreToolUse"]
    if not settings["hooks"]:
        del settings["hooks"]

    _write_settings(settings_path, settings)

    console.print()
    console.print("  [success]ShieldPilot hook removed from Claude Code.[/success]")
    console.print(f"  [muted]Settings: {settings_path}[/muted]")
    console.print()


@hook_app.command("status")
def hook_status():
    """Show current hook installation status across all scopes."""
    console.print()
    console.print("  [header]Claude Code Hook Status[/header]")
    console.print()

    found_any = False
    for scope in ("user", "project", "local"):
        settings_path = _get_settings_path(scope)
        settings = _read_settings(settings_path)

        installed = False
        if "hooks" in settings and "PreToolUse" in settings.get("hooks", {}):
            for entry in settings["hooks"]["PreToolUse"]:
                for h in entry.get("hooks", []):
                    if SENTINEL_HOOK_MARKER in h.get("command", ""):
                        installed = True
                        break

        if installed:
            found_any = True
            console.print(f"  [success]●[/success] {scope:<10s} [success]Installed[/success]  [muted]{settings_path}[/muted]")
        else:
            exists = settings_path.exists()
            if exists:
                console.print(f"  [muted]○[/muted] {scope:<10s} [muted]Not installed[/muted]  [muted]{settings_path}[/muted]")
            else:
                console.print(f"  [muted]○[/muted] {scope:<10s} [muted]Not installed[/muted]  [muted](no settings file)[/muted]")

    console.print()
    if not found_any:
        console.print("  [muted]Run 'sentinel hook install' to get started.[/muted]")
        console.print()


@hook_app.command("test")
def hook_test(
    command: str = typer.Argument(
        "echo hello", help="Command to test through the hook"
    ),
):
    """Test what ShieldPilot would do with a command.

    Simulates the hook evaluation without actually blocking anything.
    """
    from sentinelai.cli.formatters import render_assessment

    console.print()
    console.print(f"  [header]Hook Test[/header]")
    console.print(f"  [label]Command:[/label] [value]{command}[/value]")
    console.print()

    config = _load_config()
    config.llm.enabled = False  # Match hook behavior

    from sentinelai.engine import RiskEngine
    from sentinelai.engine.base import AnalysisContext
    from sentinelai.core.constants import Action

    engine = RiskEngine(config)
    context = AnalysisContext(
        working_directory=os.getcwd(),
        environment=dict(os.environ),
        config=config,
    )

    assessment = engine.assess(command, context)
    render_assessment(assessment, verbose=True)

    # Show what the hook would return
    console.print("  [label]Hook decision:[/label]")
    if assessment.action == Action.BLOCK:
        console.print("  [block] DENY [/block]  Claude Code would be prevented from running this command.")
    elif assessment.action == Action.WARN:
        console.print("  [warn] ASK  [/warn]  Claude Code would ask for your approval before running.")
    else:
        console.print("  [allow] ALLOW [/allow]  Claude Code would run this command automatically.")
    console.print()


# ── sentinel monitor ─────────────────────────────────────────


@app.command()
def monitor(
    baseline_action: str = typer.Option(
        ..., "--baseline", help="Action: 'record' or 'check'"
    ),
    baseline_file: str = typer.Option(
        "sentinel_baseline.json", "--file", "-f", help="Path to baseline JSON file"
    ),
    tool: Optional[str] = typer.Option(None, "--tool", help="Tool name for 'check'"),
    args_json: Optional[str] = typer.Option(
        None, "--args", help="Tool arguments as JSON string for 'check'"
    ),
    baseline_size: int = typer.Option(50, "--size", help="Number of calls to record"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Monitor agent behavior against a recorded baseline.

    Examples:

      sentinel monitor --baseline record --file baseline.json --size 50

      sentinel monitor --baseline check --file baseline.json --tool Bash --args '{"command":"curl https://evil.example.com"}'
    """
    from sentinelai.cli.formatters import render_error
    from sentinelai.monitor import BehaviorMonitor

    if baseline_action == "record":
        monitor_inst = BehaviorMonitor(baseline_size=baseline_size)
        path = Path(baseline_file)
        # If file already exists, load it and report status.
        if path.exists():
            monitor_inst.load_baseline(path)
            stats = monitor_inst.get_stats()
            if not output_json:
                console.print(
                    f"  [label]Loaded existing baseline:[/label] "
                    f"{stats['total_recorded']}/{stats['baseline_size']} calls recorded"
                )
                if stats["is_complete"]:
                    console.print("  [allow]Baseline is complete.[/allow]")
                else:
                    console.print(
                        f"  [warn]Baseline incomplete.[/warn] "
                        f"Record {stats['baseline_size'] - stats['total_recorded']} more calls."
                    )
            else:
                console.print_json(json.dumps(stats))
        else:
            if not output_json:
                console.print(
                    f"  [label]New baseline file:[/label] {path}\n"
                    f"  Run your agent and let ShieldPilot record {baseline_size} tool calls.\n"
                    f"  The baseline will be saved automatically by the hook integration."
                )
            monitor_inst.save_baseline(path)
            if not output_json:
                console.print(f"  [allow]Empty baseline saved to {path}[/allow]")

    elif baseline_action == "check":
        if not tool:
            render_error("--tool is required for 'check' mode.", "Example: --tool Bash")
            raise typer.Exit(code=2)

        path = Path(baseline_file)
        if not path.exists():
            render_error(
                f"Baseline file not found: {baseline_file}",
                "Run: sentinel monitor --baseline record first.",
            )
            raise typer.Exit(code=2)

        monitor_inst = BehaviorMonitor()
        monitor_inst.load_baseline(path)

        arguments: dict = {}
        if args_json:
            try:
                arguments = json.loads(args_json)
            except json.JSONDecodeError as e:
                render_error(f"Invalid JSON in --args: {e}", "Example: --args '{\"command\":\"ls\"}'")
                raise typer.Exit(code=2)

        result = monitor_inst.score(tool, arguments)

        if output_json:
            console.print_json(
                json.dumps({
                    "tool": tool,
                    "score": result.score,
                    "is_anomaly": result.is_anomaly,
                    "alerts": result.alerts,
                    "details": result.details,
                })
            )
        else:
            score_pct = int(result.score * 100)
            if result.is_anomaly:
                console.print(f"  [block]ANOMALY[/block]  Score: {score_pct}/100")
            else:
                console.print(f"  [allow]NORMAL[/allow]   Score: {score_pct}/100")
            for alert in result.alerts:
                console.print(f"  [warn]  ! {alert}[/warn]")
            if not result.alerts:
                console.print("  No anomaly signals detected.")
    else:
        render_error(
            f"Unknown --baseline action: '{baseline_action}'",
            "Use 'record' or 'check'.",
        )
        raise typer.Exit(code=2)


# ── sentinel policy ───────────────────────────────────────────


@app.command()
def policy(
    check: Optional[str] = typer.Option(None, "--check", help="Command string to evaluate"),
    policy_name: Optional[str] = typer.Option(
        None, "--policy", "-p",
        help="Policy preset: 'default', 'production', 'development', or path to YAML"
    ),
    tool: str = typer.Option("bash", "--tool", "-t", help="Tool name (default: bash)"),
    policy_file: Optional[str] = typer.Option(None, "--file", "-f", help="Path to custom policy YAML"),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON"),
):
    """Evaluate a command against a policy.

    Examples:

      sentinel policy --check "rm -rf /" --policy production

      sentinel policy --check "curl http://example.com" --policy default

      sentinel policy --check "ls -la" --file my_policy.yaml
    """
    from pathlib import Path as _Path
    from sentinelai.cli.formatters import render_error
    from sentinelai.policy import PolicyEngine

    if check is None:
        render_error("--check <command> is required.", "Example: sentinel policy --check 'rm -rf /' --policy production")
        raise typer.Exit(code=2)

    engine = PolicyEngine()

    # Resolve which policy to load
    _defaults_dir = _Path(__file__).parent.parent / "policy" / "defaults"

    if policy_file:
        p = _Path(policy_file)
        if not p.exists():
            render_error(f"Policy file not found: {policy_file}")
            raise typer.Exit(code=2)
        engine.load_policy(p)
    elif policy_name:
        _presets = {
            "default": _defaults_dir / "default_safe.yaml",
            "production": _defaults_dir / "strict_production.yaml",
            "development": _defaults_dir / "development.yaml",
        }
        preset_path = _presets.get(policy_name.lower())
        if preset_path and preset_path.exists():
            engine.load_policy(preset_path)
        else:
            # Try as a direct file path
            p = _Path(policy_name)
            if p.exists():
                engine.load_policy(p)
            else:
                render_error(
                    f"Unknown policy: '{policy_name}'",
                    f"Use one of: default, production, development — or provide a file path.",
                )
                raise typer.Exit(code=2)
    else:
        # Default to default_safe
        default_policy = _defaults_dir / "default_safe.yaml"
        if default_policy.exists():
            engine.load_policy(default_policy)

    decision = engine.evaluate(tool, check)

    if output_json:
        console.print_json(
            json.dumps({
                "tool": tool,
                "command": check,
                "action": decision.action,
                "policy": decision.policy_name,
                "reason": decision.reason,
                "matched_rule": {
                    "tool": decision.matched_rule.tool,
                    "pattern": decision.matched_rule.pattern,
                    "severity": decision.matched_rule.severity,
                    "reason": decision.matched_rule.reason,
                } if decision.matched_rule else None,
            })
        )
    else:
        if decision.action == "deny":
            console.print(f"  [block] DENY [/block]  {decision.reason or 'Blocked by policy'}")
        elif decision.action == "warn":
            console.print(f"  [warn] WARN [/warn]  {decision.reason or 'Flagged by policy'}")
        else:
            console.print(f"  [allow] ALLOW [/allow]  {decision.reason or 'Permitted by policy'}")

        if decision.matched_rule:
            console.print(
                f"  [dim]Policy:[/dim] {decision.policy_name}  "
                f"[dim]Rule:[/dim] {decision.matched_rule.tool}:{decision.matched_rule.pattern}  "
                f"[dim]Severity:[/dim] {decision.matched_rule.severity}"
            )
        console.print()

    if decision.action == "deny":
        raise typer.Exit(code=1)


# ── sentinel supply-chain-audit ───────────────────────────────


@app.command("supply-chain-audit")
def supply_chain_audit(
    project_path: Optional[str] = typer.Argument(
        None,
        help="Project directory to scan (discovers requirements*.txt, package.json, pyproject.toml)",
    ),
    requirements: Optional[str] = typer.Option(
        None, "--requirements", "-r", help="Path to a specific requirements.txt file"
    ),
    package_json: Optional[str] = typer.Option(
        None, "--package-json", "-p", help="Path to a specific package.json file"
    ),
    pyproject: Optional[str] = typer.Option(
        None, "--pyproject", help="Path to a specific pyproject.toml file"
    ),
    output_json: bool = typer.Option(False, "--json", help="Output results as JSON"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show all findings including low severity"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Only show finding count"),
):
    """Audit dependency files for supply-chain security risks.

    Checks for known malicious packages, unpinned versions, typosquatting,
    and license conflicts. Exits with code 1 when findings are present (CI-ready).

    \b
    Examples:
      sentinel supply-chain-audit .
      sentinel supply-chain-audit --requirements requirements.txt
      sentinel supply-chain-audit --package-json package.json --json
    """
    from sentinelai.scanner.supply_chain_scanner import SupplyChainFinding, SupplyChainReport, SupplyChainScanner
    from rich.panel import Panel
    from rich.table import Table

    scanner = SupplyChainScanner()
    reports: list[SupplyChainReport] = []

    # Scan explicit files first
    explicit_files = [
        (requirements, "requirements"),
        (package_json, "package_json"),
        (pyproject, "pyproject_toml"),
    ]
    for file_path, label in explicit_files:
        if not file_path:
            continue
        p = Path(file_path)
        if not p.exists():
            console.print(f"  [error]File not found:[/error] {file_path}")
            raise typer.Exit(code=2)
        try:
            reports.append(scanner.scan_file(p))
        except ValueError as exc:
            console.print(f"  [error]{exc}[/error]")
            raise typer.Exit(code=2)

    # Scan directory if given (and no explicit files)
    if project_path and not any(f for f, _ in explicit_files if f):
        p = Path(project_path)
        if not p.exists():
            console.print(f"  [error]Path not found:[/error] {project_path}")
            raise typer.Exit(code=2)
        if p.is_dir():
            reports.append(scanner.scan_directory(p))
        else:
            try:
                reports.append(scanner.scan_file(p))
            except ValueError as exc:
                console.print(f"  [error]{exc}[/error]")
                raise typer.Exit(code=2)

    # Default: scan current directory
    if not reports:
        reports.append(scanner.scan_directory(Path(".")))

    # Merge
    all_findings: list[SupplyChainFinding] = []
    all_sources: list[str] = []
    total_packages = 0
    for r in reports:
        all_findings.extend(r.findings)
        all_sources.extend(r.source_files)
        total_packages += r.total_packages

    from sentinelai.scanner.supply_chain_scanner import SupplyChainReport
    merged = SupplyChainReport(
        source_files=all_sources,
        findings=all_findings,
        total_packages=total_packages,
    )

    if output_json:
        import json as _json
        console.print_json(data=merged.to_dict())
        if merged.has_findings:
            raise typer.Exit(code=1)
        return

    if quiet:
        console.print(
            f"  {len(merged.findings)} finding(s) across {merged.total_packages} package(s) "
            f"in {len(merged.source_files)} file(s)."
        )
        if merged.has_findings:
            raise typer.Exit(code=1)
        return

    # Human-readable output
    console.print()
    console.print("  [header]Supply Chain Audit[/header]")
    console.print()
    console.print(f"  [label]Files scanned:[/label]  {len(merged.source_files)}")
    for src in merged.source_files:
        console.print(f"    [muted]{src}[/muted]")
    console.print(f"  [label]Packages found:[/label] {merged.total_packages}")
    console.print(f"  [label]Findings:[/label]       {len(merged.findings)}")
    if merged.critical_count:
        console.print(f"    [block]{merged.critical_count} critical[/block]")
    if merged.high_count:
        console.print(f"    [warn]{merged.high_count} high[/warn]")
    if merged.medium_count:
        console.print(f"    {merged.medium_count} medium")
    if merged.low_count:
        console.print(f"    [muted]{merged.low_count} low[/muted]")
    console.print()

    if not merged.findings:
        console.print("  [success]No supply chain issues found.[/success]")
        console.print()
        return

    # Filter by verbosity: always show critical+high+medium, low only with --verbose
    shown = [
        f for f in merged.findings
        if verbose or f.severity in ("critical", "high", "medium")
    ]
    hidden = len(merged.findings) - len(shown)

    _SEVERITY_BADGE = {
        "critical": "[block] CRIT [/block]",
        "high":     "[warn] HIGH [/warn]",
        "medium":   " MED      ",
        "low":      "[muted] LOW  [/muted]",
    }

    _TYPE_LABEL = {
        "malicious":       "malicious package",
        "unpinned":        "unpinned version",
        "typosquat":       "typosquat risk",
        "license_conflict": "license conflict",
        "parse_error":     "parse error",
    }

    for finding in shown:
        badge = _SEVERITY_BADGE.get(finding.severity, finding.severity.upper())
        type_label = _TYPE_LABEL.get(finding.finding_type, finding.finding_type)
        pkg_ver = finding.package + (f"@{finding.version}" if finding.version else "")
        console.print(f"  {badge}  [value]{pkg_ver:<30s}[/value]  [category]{type_label}[/category]")
        console.print(f"         [muted]{finding.description}[/muted]")
        console.print(f"         [hint]Fix: {finding.recommendation}[/hint]")
        if finding.similar_to:
            console.print(f"         [label]Similar to:[/label] [value]{finding.similar_to}[/value]")
        if finding.source_file:
            console.print(f"         [label]Source:[/label] [muted]{finding.source_file}[/muted]")
        console.print()

    if hidden:
        console.print(f"  [muted]{hidden} low-severity finding(s) hidden. Use --verbose to show all.[/muted]")
        console.print()

    raise typer.Exit(code=1)


# ── sentinel scan-content ─────────────────────────────────────


@app.command("scan-content")
def scan_content(
    file: Optional[str] = typer.Option(
        None, "--file", "-f", help="Path to file to scan"
    ),
    url: Optional[str] = typer.Option(
        None, "--url", "-u", help="URL to fetch and scan"
    ),
    stdin: bool = typer.Option(
        False, "--stdin", help="Read content from stdin"
    ),
    content_type: str = typer.Option(
        "auto",
        "--type",
        "-t",
        help="Content type: html | json | text | markdown | auto",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show finding details"),
    output_json: bool = typer.Option(False, "--json", help="Output results as JSON"),
    exit_code: bool = typer.Option(
        False, "--exit-code", help="Exit with code 1 if threats found (for CI)"
    ),
):
    """Scan a document, web page, or tool output for indirect prompt injection.

    Detects hidden instructions embedded in HTML comments, CSS-hidden elements,
    JSON fields, zero-width Unicode characters, Markdown alt-text, and more.

    Examples:

      sentinel scan-content --file page.html

      sentinel scan-content --url https://example.com

      cat response.json | sentinel scan-content --stdin --type json
    """
    from sentinelai.cli.formatters import render_error

    # ── Validate options ──────────────────────────────────────────
    sources = [bool(file), bool(url), stdin]
    if sum(sources) != 1:
        render_error(
            "Specify exactly one of --file, --url, or --stdin.",
            "Example: sentinel scan-content --file document.html",
        )
        raise typer.Exit(code=2)

    if content_type not in ("auto", "html", "json", "text", "markdown"):
        render_error(
            f"Unknown content type '{content_type}'.",
            "Use: html | json | text | markdown | auto",
        )
        raise typer.Exit(code=2)

    # ── Load content ──────────────────────────────────────────────
    if stdin:
        content = sys.stdin.read()
        source = "stdin"

    elif file:
        path = Path(file)
        if not path.exists():
            render_error(
                f"File not found: {file}",
                "Check the path and try again.",
            )
            raise typer.Exit(code=2)
        content = path.read_text(encoding="utf-8", errors="replace")
        source = str(path.name)
        # Auto-detect type from extension if not overridden.
        if content_type == "auto":
            ext = path.suffix.lower()
            if ext in (".html", ".htm"):
                content_type = "html"
            elif ext == ".json":
                content_type = "json"
            elif ext in (".md", ".markdown"):
                content_type = "markdown"

    else:  # url
        try:
            import httpx

            response = httpx.get(url, follow_redirects=True, timeout=15)
            response.raise_for_status()
            content = response.text
            source = url
            # Infer type from Content-Type header when auto.
            if content_type == "auto":
                ct_header = response.headers.get("content-type", "")
                if "html" in ct_header:
                    content_type = "html"
                elif "json" in ct_header:
                    content_type = "json"
        except Exception as exc:  # noqa: BLE001
            render_error(
                f"Failed to fetch URL: {exc}",
                "Check the URL and your network connection.",
            )
            raise typer.Exit(code=2)

    # ── Scan ──────────────────────────────────────────────────────
    from sentinelai.scanner import IndirectInjectionScanner

    scanner = IndirectInjectionScanner()
    result = scanner.scan(content, source=source, content_type=content_type)

    # ── Render ────────────────────────────────────────────────────
    if output_json:
        import dataclasses

        def _finding_to_dict(f):
            return {
                "vector": f.vector,
                "extracted_text": f.extracted_text[:200],
                "location": f.location,
                "severity": f.severity,
                "description": f.description,
            }

        out = {
            "source": result.source,
            "content_type": result.content_type,
            "overall_risk": result.overall_risk,
            "is_suspicious": result.is_suspicious,
            "findings_count": len(result.findings),
            "findings": [_finding_to_dict(f) for f in result.findings],
            "injection_threats": (
                [
                    {
                        "category": t.category,
                        "pattern_name": t.pattern_name,
                        "severity": t.severity.value,
                        "matched_text": t.matched_text[:200],
                    }
                    for t in result.scan_result.threats
                ]
                if result.scan_result
                else []
            ),
            "execution_time_ms": round(result.execution_time_ms, 2),
        }
        console.print(json.dumps(out, indent=2))
    else:
        console.print()

        # Risk badge
        if result.overall_risk == 0:
            badge = "[allow] SAFE [/allow]"
        elif result.overall_risk < 40:
            badge = "[warn] SUSPICIOUS [/warn]"
        else:
            badge = "[block] MALICIOUS [/block]"

        console.print(
            f"  {badge}  [label]Source:[/label] [value]{result.source}[/value]  "
            f"[label]Type:[/label] [value]{result.content_type}[/value]  "
            f"[label]Risk:[/label] [value]{result.overall_risk}/100[/value]"
        )
        console.print()

        if not result.findings:
            console.print("  [muted]No indirect injection vectors detected.[/muted]")
        else:
            console.print(
                f"  [label]Structural hiding vectors found:[/label] "
                f"[value]{len(result.findings)}[/value]"
            )
            if verbose:
                for i, f in enumerate(result.findings, 1):
                    sev_tag = (
                        "[block]"
                        if f.severity in ("critical", "high")
                        else "[warn]"
                    )
                    sev_close = "[/block]" if f.severity in ("critical", "high") else "[/warn]"
                    console.print(
                        f"\n  {sev_tag}{f.severity.upper()}{sev_close} "
                        f"[label]{f.vector}[/label]"
                    )
                    console.print(f"    [muted]Location:[/muted] {f.location}")
                    console.print(f"    [muted]Extracted:[/muted] {f.extracted_text[:120]}")
                    console.print(f"    [muted]Why:[/muted] {f.description}")

        if result.scan_result and result.scan_result.threats:
            console.print()
            console.print(
                f"  [label]Injection patterns in hidden content:[/label] "
                f"[value]{len(result.scan_result.threats)}[/value]"
            )
            if verbose:
                for t in result.scan_result.threats:
                    console.print(
                        f"    [block]{t.severity.value.upper()}[/block] "
                        f"[label]{t.category}[/label] — {t.pattern_name}"
                    )
                    console.print(f"      Matched: {t.matched_text[:100]}")

        console.print()
        if result.scan_result:
            console.print(f"  [muted]{result.scan_result.recommendation}[/muted]")
        console.print()

    # ── Exit code ─────────────────────────────────────────────────
    if exit_code and result.is_suspicious:
        raise typer.Exit(code=1)


# ── Entry point ───────────────────────────────────────────────

if __name__ == "__main__":
    app()
