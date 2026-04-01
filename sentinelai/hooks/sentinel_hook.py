#!/usr/bin/env python3
"""ShieldPilot hook for Claude Code — autonomous mode.

Intercepts every tool call Claude Code makes. For Bash commands, runs
the full risk engine. For file-write tools (Write, Edit, NotebookEdit),
checks against protected paths. Everything else is auto-allowed.

Decision flow:
  ALLOW  → permissionDecision: "allow"  → runs without prompt
  WARN   → permissionDecision: "ask"    → user sees a prompt
  BLOCK  → permissionDecision: "deny"   → rejected, incident logged

This lets Claude Code run fully autonomously while ShieldPilot acts
as a silent guardian — you only get interrupted when something is
actually dangerous.

Install via:  sentinel hook install

Failure Policy Matrix (how errors are handled per mode):
| Error Type              | enforce    | audit      | disabled   |
|------------------------|------------|------------|------------|
| Invalid/empty stdin    | allow      | allow      | allow      |
| Config missing/broken  | allow      | allow      | allow      |
| Analyzer exception     | continue   | continue   | N/A        |
| Logger/DB exception    | allow*     | allow*     | allow      |
| Usage limit exceeded   | deny       | allow(log) | allow      |
| Unexpected hook crash  | fail_mode  | fail_mode  | allow      |
* Decision already made; logging failure doesn't change it.
fail_mode: set via sentinel.yaml `fail_mode: open|closed` or SENTINEL_FAIL_MODE env var.
  open   (default) → allow on crash (availability-first)
  closed            → deny  on crash (security-first, recommended for production)
"""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

# Suppress all warnings to keep hook output clean
import warnings
warnings.filterwarnings("ignore")

logger = logging.getLogger(__name__)


def _is_fail_closed() -> bool:
    """Return True when SENTINEL_FAIL_MODE=closed is set.

    Controls error handling throughout the hook:
      - fail-open  (default): errors → allow  (never block legitimate work)
      - fail-closed          : errors → deny   (security-first; may block if hook crashes)

    Set via environment variable: SENTINEL_FAIL_MODE=closed
    Config value takes precedence if config loads successfully.
    """
    return os.environ.get("SENTINEL_FAIL_MODE", "open").lower() == "closed"


def _fail_decision(reason: str = "ShieldPilot hook error") -> None:
    """Allow or deny based on the configured fail-mode."""
    if _is_fail_closed():
        _deny(f"ShieldPilot fail-closed: {reason}")
    else:
        _allow()


# ── ML Stage (lazy-loaded singleton) ─────────────────────────
from sentinelai.ml.ml_infer import MlStage

ML_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "ml", "ml_model.joblib"
)
_ml_stage = None


def _get_ml_stage():
    global _ml_stage
    if _ml_stage is None:
        _ml_stage = MlStage(ML_MODEL_PATH)
    return _ml_stage


# ── ML Rollout Configuration ─────────────────────────────────
# SENTINEL_ML_MODE: "off" | "shadow" (default) | "enforce"
# SENTINEL_ML_BLOCK_THRESHOLD: float, default 0.80
# SENTINEL_ML_REVIEW_THRESHOLD: float, default 0.60


def _get_ml_mode() -> str:
    return os.environ.get("SENTINEL_ML_MODE", "shadow").lower()


def _get_ml_block_threshold() -> float:
    try:
        return float(os.environ.get("SENTINEL_ML_BLOCK_THRESHOLD", "0.80"))
    except (ValueError, TypeError):
        return 0.80


def _get_ml_review_threshold() -> float:
    try:
        return float(os.environ.get("SENTINEL_ML_REVIEW_THRESHOLD", "0.60"))
    except (ValueError, TypeError):
        return 0.60


def _compute_ml_recommendation(ml_injection_prob: float) -> str:
    if ml_injection_prob >= _get_ml_block_threshold():
        return "block"
    if ml_injection_prob >= _get_ml_review_threshold():
        return "review"
    return "allow"


# ── ML Telemetry (opt-in via SENTINEL_ML_TELEMETRY=1) ────────
# In-memory counters, flushed to stderr every 100 requests.
# Never contains raw text. Off by default.

_telemetry = {
    "count_total": 0,
    "count_ml_scored": 0,
    "count_ml_rec_block": 0,
    "count_ml_rec_review": 0,
    "count_ml_denies": 0,
}
_TELEMETRY_INTERVAL = 100


def _telemetry_enabled() -> bool:
    return os.environ.get("SENTINEL_ML_TELEMETRY", "") == "1"


def _telemetry_tick(
    ml_scored: bool = False,
    ml_recommendation: str = "allow",
    ml_denied: bool = False,
) -> None:
    """Increment telemetry counters and flush every _TELEMETRY_INTERVAL requests.

    Writes a single JSON line to stderr. Never raises.
    """
    if not _telemetry_enabled():
        return

    try:
        _telemetry["count_total"] += 1
        if ml_scored:
            _telemetry["count_ml_scored"] += 1
        if ml_recommendation == "block":
            _telemetry["count_ml_rec_block"] += 1
        elif ml_recommendation == "review":
            _telemetry["count_ml_rec_review"] += 1
        if ml_denied:
            _telemetry["count_ml_denies"] += 1

        if _telemetry["count_total"] % _TELEMETRY_INTERVAL == 0:
            line = json.dumps({
                "ml_mode": _get_ml_mode(),
                **_telemetry,
            })
            print(line, file=sys.stderr)
    except Exception:
        pass  # telemetry must never interfere


def _log_active_learning(
    raw_text: str,
    scanner_score: int,
    ml_status: str,
    ml_injection_prob: float,
    ml_recommendation: str,
    decision: str,
    engine_action: str,
    cwd: str,
) -> None:
    """Append one JSONL record for active-learning retraining.

    Only called when scanner_score < 20 and SENTINEL_ACTIVE_LEARNING_PATH
    is set.  Never stores raw command text — only a SHA-256 hash.
    Fails open on any error.
    """
    import hashlib
    from datetime import datetime

    al_path = os.environ.get("SENTINEL_ACTIVE_LEARNING_PATH")
    if not al_path:
        return

    try:
        text_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

        # Extract top TF-IDF ngrams from the loaded model (if available)
        ngram_hints: list[str] = []
        try:
            stage = _get_ml_stage()
            model = stage._model
            if model is not None:
                tfidf = model.named_steps["tfidf"]
                vec = tfidf.transform([raw_text])
                names = tfidf.get_feature_names_out()
                row = vec.toarray()[0]
                top_idx = row.argsort()[-5:][::-1]
                ngram_hints = [str(names[i]) for i in top_idx if row[i] > 0]
        except Exception:
            ngram_hints = []

        record = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "text_hash": text_hash,
            "scanner_score": scanner_score,
            "ml_status": ml_status,
            "ml_injection_prob": ml_injection_prob,
            "ml_recommendation": ml_recommendation,
            "decision": decision,
            "engine_action": engine_action,
            "cwd": cwd,
            "ngram_hints": ngram_hints,
        }

        with open(al_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception:
        pass  # fail open — active learning must never block


def _allow(reason: str = "", extra: dict | None = None):
    """Auto-approve: command runs without any prompt."""
    response = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
        }
    }
    if reason:
        response["hookSpecificOutput"]["permissionDecisionReason"] = reason
    if extra:
        response["hookSpecificOutput"].update(extra)
    print(json.dumps(response))
    sys.exit(0)


def _ask(reason: str, extra: dict | None = None):
    """Escalate to user: show a permission prompt with context."""
    response = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": reason,
        }
    }
    if extra:
        response["hookSpecificOutput"].update(extra)
    print(json.dumps(response))
    sys.exit(0)


def _deny(reason: str, extra: dict | None = None):
    """Block: command is rejected outright."""
    response = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    if extra:
        response["hookSpecificOutput"].update(extra)
    print(json.dumps(response))
    sys.exit(0)


def _fail_mode_exit(reason: str, fail_mode: str = "open") -> None:
    """Handle unexpected hook errors per configured fail_mode.

    fail_mode=open  (default): allow the command so work is not blocked.
    fail_mode=closed: deny the command to prevent unguarded execution.
    The fail_mode can be set via sentinel.yaml (fail_mode: closed) or
    the SENTINEL_FAIL_MODE environment variable.
    """
    _fm = (fail_mode or os.environ.get("SENTINEL_FAIL_MODE", "open")).lower().strip()
    if _fm == "closed":
        _deny(f"ShieldPilot: hook error, denied by fail_mode=closed\n{reason}")
    else:
        _allow(f"ShieldPilot: hook error, allowed by fail_mode=open\n{reason}")


def _format_signals(signals, max_count: int = 3) -> str:
    """Format risk signals into a readable string."""
    lines = []
    for s in signals[:max_count]:
        cat = s.category.value if hasattr(s.category, "value") else s.category
        lines.append(f"  [{cat}] {s.description} (score: {s.score})")
    return "\n".join(lines)


def _check_protected_path(file_path: str, config) -> bool:
    """Return True if file_path falls under a protected path."""
    try:
        from sentinelai.core.path_utils import is_path_under
        return any(is_path_under(file_path, pp) for pp in config.protected_paths)
    except Exception:
        return False


def _load_sentinel():
    """Load ShieldPilot config and engine. Returns (config, engine, Action) or raises."""
    from sentinelai.core.config import load_config
    from sentinelai.engine import RiskEngine
    from sentinelai.core.constants import Action

    cwd = os.getcwd()
    config_path = _find_config(cwd)
    config = load_config(str(config_path) if config_path else None)
    config.llm.enabled = False  # Too slow for hooks

    engine = RiskEngine(config)
    return config, engine, Action


def _check_usage_limit(config) -> tuple[bool, str]:
    """Check if daily usage limit is reached.

    Returns (limit_reached, message).
    Note: The hook has no user context -- super-admin bypass is handled
    in the API layer (deps.py), not here.
    """
    if not config.billing.enabled:
        return False, ""

    limits = config.billing.limits
    if limits.commands_per_day < 0:  # unlimited
        return False, ""

    try:
        from datetime import date
        from sentinelai.core.secrets import SecretsMasker
        from sentinelai.logger import BlackboxLogger
        from sentinelai.logger.database import UsageRecord

        masker = SecretsMasker(config.secrets_patterns)
        logger = BlackboxLogger(config=config.logging, masker=masker)
        session = logger._get_session()

        today = date.today().isoformat()
        usage = (
            session.query(UsageRecord)
            .filter(UsageRecord.date == today, UsageRecord.tenant_id == None)
            .first()
        )
        session.close()

        commands_used = usage.commands_evaluated if usage else 0

        if commands_used >= limits.commands_per_day:
            from sentinelai.core.models import format_limit_exceeded
            payload = format_limit_exceeded(
                limit=limits.commands_per_day,
                used=commands_used,
                tier=config.billing.tier,
                upgrade_url=config.billing.upgrade_url,
            )
            msg = (
                f"{payload['error']} ({payload['used']}/{payload['limit']})\n"
                f"Tier: {payload['tier']}\n"
                f"Upgrade at: {payload['upgrade_url']}"
            )
            return True, msg

        return False, ""
    except Exception:
        return False, ""


def _get_usage_warning(config) -> str:
    """Return a warning string if usage is at 80%+ of the daily limit.

    Returns empty string if no warning needed.
    """
    if not config.billing.enabled:
        return ""

    limits = config.billing.limits
    if limits.commands_per_day < 0:
        return ""

    try:
        from datetime import date
        from sentinelai.core.secrets import SecretsMasker
        from sentinelai.logger import BlackboxLogger
        from sentinelai.logger.database import UsageRecord

        masker = SecretsMasker(config.secrets_patterns)
        logger = BlackboxLogger(config=config.logging, masker=masker)
        session = logger._get_session()

        today = date.today().isoformat()
        usage = (
            session.query(UsageRecord)
            .filter(UsageRecord.date == today, UsageRecord.tenant_id == None)
            .first()
        )
        session.close()

        commands_used = usage.commands_evaluated if usage else 0
        threshold = int(limits.commands_per_day * 0.8)

        if commands_used >= threshold:
            pct = int(commands_used / limits.commands_per_day * 100)
            return (
                f"ShieldPilot: {commands_used}/{limits.commands_per_day} "
                f"commands used ({pct}%). Approaching daily limit."
            )
        return ""
    except Exception:
        return ""


# Commands matching these prefixes bypass the injection rate limiter.
# These are common development tools that should never be blocked just
# because injection detection was triggered by test content.
_INJECTION_RATE_EXEMPT_PREFIXES = (
    "python3 -m pytest",
    "python3 -m py_compile",
    "python3 -c \"from sentinelai",
    "python3 -c 'from sentinelai",
    "python3 -c \"import sentinelai",
    "python3 -c 'import sentinelai",
    "git ",
    "ls",
    "pwd",
    "whoami",
    "echo ",
    "cat ",
    "head ",
    "tail ",
    "wc ",
    "which ",
    "pip ",
    "pip3 ",
    "python3 -m pip",
    "npm ",
    "node ",
    "mkdir ",
    "cp ",
    "mv ",
    "touch ",
    "chmod ",
    "cd ",
)


def _check_injection_rate(config, command: str = "") -> tuple[bool, str]:
    """Check if recent injection detections exceed the rate threshold.

    Queries PromptScanLog for scans with threats in the last 60 seconds.
    If >= 5 are found, the source is considered to be running a repeated
    injection attack (Best-of-N pattern).

    Commands matching _INJECTION_RATE_EXEMPT_PREFIXES (or config-defined
    rate_limit_exempt prefixes) bypass this check entirely — they are
    common dev tools that should never be blocked just because injection
    detection was triggered by test content.

    Returns (blocked, message).
    """
    # Whitelist bypass: safe commands are never blocked by the injection rate limiter
    cmd_stripped = command.strip()
    if cmd_stripped:
        for prefix in _INJECTION_RATE_EXEMPT_PREFIXES:
            if cmd_stripped.startswith(prefix):
                return False, ""

        # Also check config-defined whitelist commands
        try:
            for wl_cmd in config.whitelist.commands:
                if cmd_stripped == wl_cmd or cmd_stripped.startswith(wl_cmd + " "):
                    return False, ""
        except (AttributeError, TypeError):
            pass  # config may not have the field yet — fail open

        # Also check config-defined rate_limit_exempt prefixes (if defined)
        try:
            for prefix in config.whitelist.rate_limit_exempt:
                if cmd_stripped.startswith(prefix):
                    return False, ""
        except (AttributeError, TypeError):
            pass  # config may not have the field yet — fail open

    try:
        from datetime import datetime, timedelta
        from sentinelai.core.secrets import SecretsMasker
        from sentinelai.logger import BlackboxLogger
        from sentinelai.logger.database import PromptScanLog

        masker = SecretsMasker(config.secrets_patterns)
        logger = BlackboxLogger(config=config.logging, masker=masker)
        session = logger._get_session()

        cutoff = datetime.utcnow() - timedelta(seconds=60)
        count = (
            session.query(PromptScanLog)
            .filter(
                PromptScanLog.threat_count > 0,
                PromptScanLog.timestamp >= cutoff,
            )
            .count()
        )
        session.close()

        if count >= 5:
            return True, (
                f"Temporarily blocked: repeated injection attempts detected "
                f"({count} in last 60s). Please wait before retrying."
            )
        return False, ""
    except Exception:
        return False, ""


def _increment_usage(config) -> None:
    """Increment today's command usage counter. Best-effort, never raises.

    Always tracks usage regardless of billing state — the billing flag
    only controls whether limits are enforced, not whether usage is recorded.
    """
    try:
        from datetime import date, timedelta
        from sentinelai.core.secrets import SecretsMasker
        from sentinelai.logger import BlackboxLogger
        from sentinelai.logger.database import UsageRecord

        masker = SecretsMasker(config.secrets_patterns)
        logger = BlackboxLogger(config=config.logging, masker=masker)
        session = logger._get_session()

        today = date.today().isoformat()
        usage = (
            session.query(UsageRecord)
            .filter(UsageRecord.date == today, UsageRecord.tenant_id == None)
            .first()
        )

        if usage:
            usage.commands_evaluated += 1
        else:
            usage = UsageRecord(
                tenant_id=None,
                date=today,
                commands_evaluated=1,
                scans_performed=0,
                llm_calls=0,
                api_requests=0,
            )
            session.add(usage)

        session.commit()

        # Occasional cleanup: delete usage records older than 30 days
        # (~1% chance per call to avoid overhead on every command)
        import random
        if random.random() < 0.01:
            cutoff = (date.today() - timedelta(days=30)).isoformat()
            session.query(UsageRecord).filter(UsageRecord.date < cutoff).delete()
            session.commit()

        session.close()
    except Exception as e:
        logging.getLogger(__name__).error("ShieldPilot usage error: %s", e)


def main() -> None:
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            _allow()
    except Exception:
        _allow()

    # ── Platform detection via Adapter Layer ───────────────────
    # Instead of hardcoding Claude Code JSON field names, we use
    # detect_platform() to auto-select the correct adapter and
    # parse_input() to extract tool_name/tool_input/cwd in a
    # platform-agnostic way.  This makes the hook work with any
    # supported platform (Claude Code, OpenClaw, Generic).
    try:
        from sentinelai.adapters import detect_platform

        adapter = detect_platform(raw)
        cmd = adapter.parse_input(raw)
        tool_name = cmd.tool_name
        tool_input = cmd.tool_input
        cwd = cmd.cwd or os.getcwd()
    except Exception:
        # Fallback: direct JSON parsing (backward compat if adapter import fails)
        try:
            data = json.loads(raw)
            tool_name = data.get("tool_name", "")
            tool_input = data.get("tool_input", {})
            cwd = data.get("cwd", os.getcwd())
        except (json.JSONDecodeError, Exception):
            _allow()

    # ── Non-Bash tools: fast path ──────────────────────────────
    # Auto-allow read-only tools immediately
    if tool_name in ("Read", "Glob", "Grep", "WebSearch", "WebFetch",
                      "TodoWrite", "AskUserQuestion"):
        _allow()

    # For write tools, check protected paths
    if tool_name in ("Write", "Edit", "NotebookEdit"):
        file_path = tool_input.get("file_path", "")
        if file_path:
            try:
                config, _, _ = _load_sentinel()
                if config.mode == "disabled":
                    _allow("ShieldPilot disabled")
                if _check_protected_path(file_path, config):
                    if config.mode == "audit":
                        _allow(
                            f"ShieldPilot audit: write to protected path\n"
                            f"Path: {file_path}"
                        )
                    _deny(
                        f"ShieldPilot: Write to protected path blocked\n"
                        f"Path: {file_path}\n"
                        f"Protected paths are configured in sentinel.yaml"
                    )
                else:
                    _allow()
            except Exception:
                _allow()
        else:
            _allow()

    # For non-Bash, non-file tools we don't recognize, just allow
    if tool_name != "Bash":
        _allow()

    # ── Bash commands: full risk engine ────────────────────────
    command = tool_input.get("command", "")
    if not command:
        _allow()

    try:
        from sentinelai.engine.base import AnalysisContext
        from sentinelai.core.constants import Action

        config, engine, Action = _load_sentinel()

        # ── Mode check ─────────────────────────────────────────
        if config.mode == "disabled":
            _allow("ShieldPilot disabled")

        # ── Check usage limit ─────────────────────────────────
        limit_reached, limit_msg = _check_usage_limit(config)
        if limit_reached:
            if config.mode == "audit":
                _allow(f"ShieldPilot audit: {limit_msg}")
            _deny(f"ShieldPilot: {limit_msg}")

        # ── Check injection rate (Best-of-N defense) ─────────
        injection_blocked, injection_msg = _check_injection_rate(config, command=command)
        if injection_blocked:
            if config.mode == "audit":
                _allow(f"ShieldPilot audit: {injection_msg}")
            _deny(f"ShieldPilot: {injection_msg}")

        context = AnalysisContext(
            working_directory=cwd,
            environment=dict(os.environ),
            config=config,
        )

        assessment = engine.assess(command, context)

        # Increment usage counter (best-effort)
        _increment_usage(config)

        # ── Single PromptScanner pass (reused by logger + ML gate) ──
        _scan_result = None
        try:
            from sentinelai.scanner.scanner import PromptScanner

            _scan_result = PromptScanner().scan(command, source="hook-command")
        except Exception:
            pass  # fail open — scanner failure must not block

        # Log every command (best-effort, never blocks on failure)
        _log_assessment(assessment, command, cwd, config, scan_result=_scan_result)

        # ── ML Stage: secondary classifier for low-score commands ──
        ml_mode = _get_ml_mode()  # off, shadow, enforce
        ml_scores = {"clean": 0.0, "hard": 0.0, "injection": 0.0}
        ml_status = "skipped"
        ml_recommendation = "allow"
        scanner_score = _scan_result.overall_score if _scan_result else None

        if ml_mode == "off":
            ml_status = "skipped_off"
        else:
            try:
                if scanner_score is not None and scanner_score < 20:
                    _ml_res = _get_ml_stage().predict(command)
                    ml_scores = _ml_res.scores
                    ml_status = _ml_res.status
            except Exception:
                pass  # fail open — ML failure must not block

        ml_injection_prob = ml_scores.get("injection", 0.0)
        if ml_status == "ok":
            ml_recommendation = _compute_ml_recommendation(ml_injection_prob)

        ml_extra = {
            "ml_scores": ml_scores,
            "ml_status": ml_status,
            "ml_injection_prob": ml_injection_prob,
            "ml_mode": ml_mode,
            "ml_recommendation": ml_recommendation,
        }

        # ── Determine final decision for this request ─────────
        ml_block_threshold = _get_ml_block_threshold()
        ml_would_block = (
            scanner_score is not None
            and scanner_score < 20
            and ml_status == "ok"
            and ml_injection_prob >= ml_block_threshold
        )

        if config.mode == "audit":
            _decision = "allow"
        elif scanner_score is not None and scanner_score >= 70:
            _decision = "deny"
        elif ml_mode == "enforce" and ml_would_block:
            _decision = "deny"
        elif assessment.action == Action.BLOCK:
            _decision = "deny"
        elif assessment.action == Action.WARN:
            _decision = "ask"
        else:
            _decision = "allow"

        # ── Telemetry tick (best-effort, stderr only) ──────────
        _telemetry_tick(
            ml_scored=(ml_status == "ok"),
            ml_recommendation=ml_recommendation,
            ml_denied=(ml_mode == "enforce" and ml_would_block),
        )

        # ── Active-learning log (only for low-score commands) ──
        if scanner_score is not None and scanner_score < 20:
            _log_active_learning(
                raw_text=command,
                scanner_score=scanner_score,
                ml_status=ml_status,
                ml_injection_prob=ml_injection_prob,
                ml_recommendation=ml_recommendation,
                decision=_decision,
                engine_action=assessment.action.value
                if hasattr(assessment.action, "value")
                else str(assessment.action),
                cwd=cwd,
            )

        # ── Execute decision ──────────────────────────────────
        if config.mode == "audit":
            _allow(
                f"ShieldPilot audit (risk {assessment.final_score}/100)",
                extra=ml_extra,
            )

        if scanner_score is not None and scanner_score >= 70:
            _deny(
                f"ShieldPilot BLOCKED by scanner (injection score {scanner_score}/100)\n"
                f"Command: {command}",
                extra=ml_extra,
            )

        # ML blocking (only in enforce mode)
        if ml_mode == "enforce" and ml_would_block:
            _deny(
                f"ShieldPilot BLOCKED by ML classifier "
                f"(injection probability {ml_injection_prob:.2f})\n"
                f"Command: {command}",
                extra=ml_extra,
            )

        # ── Risk Engine Decision ──────────────────────────────
        if assessment.action == Action.BLOCK:
            signal_text = _format_signals(assessment.signals)
            _deny(
                f"ShieldPilot BLOCKED (risk {assessment.final_score}/100)\n"
                f"Command: {command}\n"
                f"Signals:\n{signal_text}",
                extra=ml_extra,
            )

        elif assessment.action == Action.WARN:
            signal_text = _format_signals(assessment.signals)
            _ask(
                f"ShieldPilot FLAGGED (risk {assessment.final_score}/100)\n"
                f"Signals:\n{signal_text}",
                extra=ml_extra,
            )

        else:
            # Safe — auto-approve, include usage warning if approaching limit
            usage_warning = _get_usage_warning(config)
            _allow(usage_warning, extra=ml_extra)

    except ImportError:
        logger.error("ShieldPilot not found in Python path")
        _fail_mode_exit("ShieldPilot not installed")
    except Exception as e:
        logger.error("ShieldPilot hook error: %s", e)
        # Respect fail_mode: try to read config, fall back to env var
        _fail_mode = "open"
        try:
            _fc = _load_sentinel()[0]
            _fail_mode = getattr(_fc, "fail_mode", "open")
        except Exception:
            _fail_mode = os.environ.get("SENTINEL_FAIL_MODE", "open").lower()
        _fail_mode_exit(f"Hook error: {e}", _fail_mode)


def _log_assessment(assessment, command: str, cwd: str, config, *, scan_result=None) -> None:
    """Log the assessment to the database. Best-effort, never raises."""
    try:
        from sentinelai.core.secrets import SecretsMasker
        from sentinelai.core.constants import Action
        from sentinelai.logger import BlackboxLogger

        masker = SecretsMasker(config.secrets_patterns)
        logger = BlackboxLogger(config=config.logging, masker=masker)
        cmd_id = logger.log_command(
            assessment=assessment,
            output=None,
            executed=assessment.action != Action.BLOCK,
            exit_code=None,
            working_directory=cwd,
        )

        if assessment.action == Action.BLOCK:
            severity = "critical" if assessment.final_score >= 90 else "high"
            logger.log_incident(
                severity=severity,
                category=assessment.signals[0].category.value if assessment.signals else "unknown",
                title=f"Blocked: {command[:80]}",
                description=(
                    f"Command blocked with risk score {assessment.final_score} "
                    f"(via Claude Code hook)"
                ),
                evidence=command,
                command_id=cmd_id,
            )

        # Log prompt injection scan (reuses pre-computed result)
        _log_injection_scan(scan_result, logger)

    except Exception as e:
        logging.getLogger(__name__).error("ShieldPilot log error: %s", e)


def _log_injection_scan(scan_result, logger) -> None:
    """Log a pre-computed scan result if threats were found. Best-effort."""
    try:
        if scan_result is not None and scan_result.threats:
            logger.log_prompt_scan(scan_result)
    except Exception as e:
        logger.error("ShieldPilot scan log error: %s", e)


def _find_config(start_dir: str) -> Path | None:
    """Walk up from start_dir to find sentinel.yaml."""
    current = Path(start_dir).resolve()
    for _ in range(20):
        candidate = current / "sentinel.yaml"
        if candidate.exists():
            return candidate
        parent = current.parent
        if parent == current:
            break
        current = parent

    home_config = Path.home() / "sentinel.yaml"
    if home_config.exists():
        return home_config

    return None


if __name__ == "__main__":
    main()
