"""Dashboard endpoints: stats, analytics, and streaming (SSE)."""

from __future__ import annotations

import asyncio
import json
from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import func

from sentinelai.api.auth import TokenData, decode_token
from sentinelai.api.deps import (
    get_config,
    get_daily_usage_for_user,
    get_logger,
    is_super_admin,
    require_verified_email,
)
from sentinelai.api.routers._shared import _sanitize_text
from sentinelai.core.config import SentinelConfig
from sentinelai.logger import BlackboxLogger
from sentinelai.logger.database import (
    CommandLog,
    IncidentLog,
    PromptScanLog,
)


# ── Period helper ────────────────────────────────────────────

_PERIOD_HOURS = {"24h": 24, "7d": 168, "30d": 720}


def _period_to_hours(period: str) -> int:
    """Convert period string to hours. Defaults to 24h."""
    return _PERIOD_HOURS.get(period, 24)

router = APIRouter()


# ── Stats ─────────────────────────────────────────────────────


@router.get(
    "/api/stats",
    tags=["Dashboard"],
    summary="Get dashboard statistics",
    description="Return aggregated security statistics (allowed, warned, blocked commands, incidents, scans) for the specified time window. Includes top blocked commands and risk score distribution. All-time data is restricted to admins.",
    response_description="Aggregated security statistics for the given time window",
)
def get_stats(
    hours: int = Query(24, ge=1, le=720),
    user: TokenData = Depends(require_verified_email),
    config: SentinelConfig = Depends(get_config),
    logger: BlackboxLogger = Depends(get_logger),
):
    """Get dashboard statistics for the given time period."""
    stats = logger.get_stats(hours=hours)
    stats_dict = stats.model_dump()

    # Redact all all-time data for non-admin users (admin OR super-admin see everything)
    if user.role != "admin" and not is_super_admin(user, config):
        stats_dict["all_time_blocked"] = None
        stats_dict["all_time_warned"] = None
        stats_dict["all_time_allowed"] = None
        stats_dict["all_time_incidents"] = None
        stats_dict["all_time_scans"] = None
        stats_dict["all_time_total"] = None
        stats_dict["all_time_blocked_available"] = False
    else:
        stats_dict["all_time_blocked_available"] = True

    # ── K1: Top blocked commands + score distribution ────────────
    cutoff = datetime.utcnow() - timedelta(hours=hours)
    session = logger._get_session()
    try:
        # Top 5 most-blocked commands (aggregated by first 60 chars)
        top_blocked_rows = (
            session.query(
                func.substr(CommandLog.command, 1, 60).label("cmd"),
                func.count().label("cnt"),
            )
            .filter(
                CommandLog.action_taken == "block",
                CommandLog.timestamp >= cutoff,
            )
            .group_by(func.substr(CommandLog.command, 1, 60))
            .order_by(func.count().desc())
            .limit(5)
            .all()
        )
        stats_dict["top_blocked_commands"] = [
            {"command": row.cmd or "", "count": row.cnt}
            for row in top_blocked_rows
        ]

        # Risk score distribution histogram (5 buckets)
        score_buckets = [
            ("0-19", 0, 19),
            ("20-39", 20, 39),
            ("40-59", 40, 59),
            ("60-79", 60, 79),
            ("80-100", 80, 100),
        ]
        score_distribution = []
        for label, lo, hi in score_buckets:
            count = (
                session.query(func.count())
                .select_from(CommandLog)
                .filter(
                    CommandLog.timestamp >= cutoff,
                    CommandLog.risk_score >= lo,
                    CommandLog.risk_score <= hi,
                )
                .scalar()
            ) or 0
            score_distribution.append({"range": label, "count": count})
        stats_dict["score_distribution"] = score_distribution
    except Exception:
        stats_dict["top_blocked_commands"] = []
        stats_dict["score_distribution"] = []
    finally:
        session.close()

    return stats_dict


# ── Analytics ────────────────────────────────────────────────


class DailyAnalyticsEntry(BaseModel):
    """Single day of usage analytics."""
    date: str
    commands: int = 0
    blocked: int = 0
    warned: int = 0
    scans: int = 0
    incidents: int = 0


class CategoryCount(BaseModel):
    """Signal category with occurrence count."""
    category: str
    count: int


class AnalyticsTrends(BaseModel):
    """Percentage change comparing current period vs previous period."""
    commands_trend: float = 0.0
    blocked_trend: float = 0.0
    scans_trend: float = 0.0


class AnalyticsResponse(BaseModel):
    """Full analytics response for the dashboard widget."""
    daily: List[DailyAnalyticsEntry]
    top_categories: List[CategoryCount]
    trends: AnalyticsTrends


def _extract_signal_category(signal_name: str) -> str:
    """Extract category from a signal name (text before the first colon).

    Example: "filesystem_access: rm -rf /" -> "filesystem_access"
    """
    if ":" in signal_name:
        return signal_name.split(":")[0].strip()
    return signal_name.strip()


def _compute_trend(current: int, previous: int) -> float:
    """Compute percentage change between two values.

    Returns 0.0 if previous is 0 (avoid division by zero).
    """
    if previous == 0:
        return 0.0
    return round(((current - previous) / previous) * 100, 1)


@router.get(
    "/api/stats/analytics",
    tags=["Dashboard"],
    summary="Get daily usage analytics",
    description=(
        "Return daily breakdown of commands, blocked, warned, scans, and "
        "incidents for the requested number of days. Includes top signal "
        "categories and trend percentages comparing current vs previous period."
    ),
    response_model=AnalyticsResponse,
    response_description="Daily analytics data with trends and top categories",
)
def get_analytics(
    days: int = Query(7, ge=1, le=30),
    user: TokenData = Depends(require_verified_email),
    config: SentinelConfig = Depends(get_config),
    logger: BlackboxLogger = Depends(get_logger),
):
    """Get daily usage analytics for the dashboard widget."""
    # Non-admin users are limited to 7 days max
    if user.role != "admin" and not is_super_admin(user, config):
        days = min(days, 7)

    session = logger._get_session()
    try:
        now = datetime.utcnow()
        current_start = now - timedelta(days=days)
        previous_start = current_start - timedelta(days=days)

        # ── Daily command aggregation (current period) ──────────────
        # SQLite func.date() extracts YYYY-MM-DD from datetime columns
        cmd_daily = (
            session.query(
                func.date(CommandLog.timestamp).label("day"),
                func.count().label("total"),
                func.sum(
                    func.iif(CommandLog.action_taken == "block", 1, 0)
                ).label("blocked"),
                func.sum(
                    func.iif(CommandLog.action_taken == "warn", 1, 0)
                ).label("warned"),
            )
            .filter(CommandLog.timestamp >= current_start)
            .group_by(func.date(CommandLog.timestamp))
            .all()
        )

        # Index by date for easy lookup
        cmd_by_date: Dict[str, Dict[str, int]] = {}
        for row in cmd_daily:
            cmd_by_date[row.day] = {
                "commands": row.total,
                "blocked": row.blocked or 0,
                "warned": row.warned or 0,
            }

        # ── Daily scan aggregation ──────────────────────────────────
        scan_daily = (
            session.query(
                func.date(PromptScanLog.timestamp).label("day"),
                func.count().label("total"),
            )
            .filter(PromptScanLog.timestamp >= current_start)
            .group_by(func.date(PromptScanLog.timestamp))
            .all()
        )
        scans_by_date: Dict[str, int] = {
            row.day: row.total for row in scan_daily
        }

        # ── Daily incident aggregation ──────────────────────────────
        inc_daily = (
            session.query(
                func.date(IncidentLog.timestamp).label("day"),
                func.count().label("total"),
            )
            .filter(IncidentLog.timestamp >= current_start)
            .group_by(func.date(IncidentLog.timestamp))
            .all()
        )
        incs_by_date: Dict[str, int] = {
            row.day: row.total for row in inc_daily
        }

        # ── Build daily entries (most recent first) ─────────────────
        daily_entries: List[DailyAnalyticsEntry] = []
        for offset in range(days):
            day_dt = now - timedelta(days=offset)
            day_str = day_dt.strftime("%Y-%m-%d")
            cmd_data = cmd_by_date.get(day_str, {})
            daily_entries.append(DailyAnalyticsEntry(
                date=day_str,
                commands=cmd_data.get("commands", 0),
                blocked=cmd_data.get("blocked", 0),
                warned=cmd_data.get("warned", 0),
                scans=scans_by_date.get(day_str, 0),
                incidents=incs_by_date.get(day_str, 0),
            ))

        # ── Top signal categories (current period) ──────────────────
        category_counter: Counter = Counter()
        cmd_signals = (
            session.query(CommandLog.signals_json)
            .filter(CommandLog.timestamp >= current_start)
            .all()
        )
        for (signals_json_str,) in cmd_signals:
            if not signals_json_str:
                continue
            try:
                signals = json.loads(signals_json_str)
                for signal in signals:
                    name = signal.get("name", "")
                    if name:
                        category_counter[_extract_signal_category(name)] += 1
            except (json.JSONDecodeError, TypeError):
                continue

        top_categories = [
            CategoryCount(category=cat, count=cnt)
            for cat, cnt in category_counter.most_common(10)
        ]

        # ── Trends: current period vs previous period ───────────────
        current_cmds = (
            session.query(func.count())
            .select_from(CommandLog)
            .filter(CommandLog.timestamp >= current_start)
            .scalar()
        ) or 0
        previous_cmds = (
            session.query(func.count())
            .select_from(CommandLog)
            .filter(
                CommandLog.timestamp >= previous_start,
                CommandLog.timestamp < current_start,
            )
            .scalar()
        ) or 0

        current_blocked = (
            session.query(func.count())
            .select_from(CommandLog)
            .filter(
                CommandLog.timestamp >= current_start,
                CommandLog.action_taken == "block",
            )
            .scalar()
        ) or 0
        previous_blocked = (
            session.query(func.count())
            .select_from(CommandLog)
            .filter(
                CommandLog.timestamp >= previous_start,
                CommandLog.timestamp < current_start,
                CommandLog.action_taken == "block",
            )
            .scalar()
        ) or 0

        current_scans = (
            session.query(func.count())
            .select_from(PromptScanLog)
            .filter(PromptScanLog.timestamp >= current_start)
            .scalar()
        ) or 0
        previous_scans = (
            session.query(func.count())
            .select_from(PromptScanLog)
            .filter(
                PromptScanLog.timestamp >= previous_start,
                PromptScanLog.timestamp < current_start,
            )
            .scalar()
        ) or 0

        trends = AnalyticsTrends(
            commands_trend=_compute_trend(current_cmds, previous_cmds),
            blocked_trend=_compute_trend(current_blocked, previous_blocked),
            scans_trend=_compute_trend(current_scans, previous_scans),
        )

        return AnalyticsResponse(
            daily=daily_entries,
            top_categories=top_categories,
            trends=trends,
        )
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"error": "analytics_error", "message": str(e)},
        )
    finally:
        session.close()


# ── Real-Time Streaming (SSE) ────────────────────────────────


@router.get(
    "/api/stats/stream",
    tags=["Streaming"],
    summary="Stream dashboard statistics (SSE)",
    description="Stream real-time dashboard statistics via Server-Sent Events. Token is passed as a query parameter since EventSource does not support custom headers.",
    response_description="Server-Sent Events stream with real-time stats updates",
)
async def stats_stream(
    request: Request,
    hours: int = Query(24, ge=1, le=720),
    token: Optional[str] = Query(None),
    config: SentinelConfig = Depends(get_config),
    logger: BlackboxLogger = Depends(get_logger),
):
    """Stream dashboard statistics in real-time via Server-Sent Events.

    Note: Accepts token via query param for EventSource compatibility
    (EventSource doesn't support custom headers).
    """
    # Validate token from query param (EventSource doesn't support headers)
    if not token:
        raise HTTPException(status_code=401, detail={"error": "Token required"})
    user = decode_token(token, config.auth)
    if not user:
        raise HTTPException(status_code=401, detail={"error": "Invalid token"})

    async def event_generator():
        last_stats_hash = None
        # Reuse a single session per SSE connection (closed on disconnect)
        session = logger._get_session()

        try:
            while True:
                # Check if client disconnected
                if await request.is_disconnected():
                    break

                try:
                    # Reuse SSE session for stats aggregation (avoids
                    # creating + closing a new session every poll cycle)
                    stats = logger.get_stats(hours=hours, session=session)
                    stats_dict = stats.model_dump()

                    # Redact all all-time data for non-admin users
                    if user.role != "admin" and not is_super_admin(user, config):
                        stats_dict["all_time_blocked"] = None
                        stats_dict["all_time_warned"] = None
                        stats_dict["all_time_allowed"] = None
                        stats_dict["all_time_incidents"] = None
                        stats_dict["all_time_scans"] = None
                        stats_dict["all_time_total"] = None
                        stats_dict["all_time_blocked_available"] = False
                    else:
                        stats_dict["all_time_blocked_available"] = True

                    # Include usage data for real-time meter updates (scans + commands)
                    # Reuse the SSE session to avoid creating a new one each iteration
                    try:
                        from sentinelai.api.deps import _get_daily_usage_internal, get_user_tier_limits, is_super_admin

                        if is_super_admin(user, config):
                            from sentinelai.api.deps import UsageInfo
                            usage_info = UsageInfo(
                                tier="unlimited", commands_used=0, commands_limit=-1,
                                scans_used=0, scans_limit=-1, commands_remaining=-1,
                                scans_remaining=-1, limit_reached=False, upgrade_url="", is_admin=True,
                            )
                        else:
                            user_tier, user_limits = get_user_tier_limits(user, config, logger, session=session)
                            user_is_admin = user.role == "admin" or is_super_admin(user, config)
                            usage_info = _get_daily_usage_internal(
                                logger, config,
                                user_tier=user_tier, user_limits=user_limits,
                                is_admin=user_is_admin, session=session,
                                user_email=user.email,
                            )
                        stats_dict["usage"] = usage_info.model_dump()
                    except Exception:
                        stats_dict["usage"] = None

                    current_hash = hash(json.dumps(stats_dict, sort_keys=True, default=str))

                    # Only send if stats or usage changed
                    if current_hash != last_stats_hash:
                        yield f"data: {json.dumps(stats_dict, default=str)}\n\n"
                        last_stats_hash = current_hash

                    # Expire cached objects so next iteration sees fresh data
                    session.expire_all()

                except Exception:
                    # Session broken -- recreate it
                    session.close()
                    session = logger._get_session()

                await asyncio.sleep(3)  # Check every 3 seconds
        finally:
            session.close()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get(
    "/api/activity/stream",
    tags=["Streaming"],
    summary="Stream activity feed (SSE)",
    description="Stream new activity events (commands, incidents, scans) in real-time via Server-Sent Events. Falls back to polling on the client side if SSE is unavailable.",
    response_description="Server-Sent Events stream with real-time activity events",
)
async def activity_stream(
    request: Request,
    token: Optional[str] = Query(None),
    config: SentinelConfig = Depends(get_config),
    logger: BlackboxLogger = Depends(get_logger),
):
    """Stream activity feed in real-time via Server-Sent Events.

    Note: Accepts token via query param for EventSource compatibility.
    """
    # Validate token from query param
    if not token:
        raise HTTPException(status_code=401, detail={"error": "Token required"})
    user = decode_token(token, config.auth)
    if not user:
        raise HTTPException(status_code=401, detail={"error": "Invalid token"})

    async def event_generator():
        last_cmd_id = 0
        last_inc_id = 0
        last_scan_id = 0
        first_run = True
        session = logger._get_session()

        try:
            while True:
                if await request.is_disconnected():
                    break

                try:
                    events = []

                    if first_run:
                        cmds = session.query(CommandLog).order_by(CommandLog.id.desc()).limit(20).all()
                        incs = session.query(IncidentLog).order_by(IncidentLog.id.desc()).limit(10).all()
                        scans = session.query(PromptScanLog).order_by(PromptScanLog.id.desc()).limit(10).all()
                        first_run = False
                    else:
                        cmds = session.query(CommandLog).filter(CommandLog.id > last_cmd_id).order_by(CommandLog.id.desc()).all()
                        incs = session.query(IncidentLog).filter(IncidentLog.id > last_inc_id).order_by(IncidentLog.id.desc()).all()
                        scans = session.query(PromptScanLog).filter(PromptScanLog.id > last_scan_id).order_by(PromptScanLog.id.desc()).all()

                    for cmd in cmds:
                        events.append({
                            "type": "CMD",
                            "timestamp": cmd.timestamp.isoformat() if cmd.timestamp else None,
                            "summary": cmd.command[:60] if cmd.command else "",
                            "score": cmd.risk_score,
                            "action": cmd.action_taken,
                            "id": cmd.id,
                        })
                        last_cmd_id = max(last_cmd_id, cmd.id)

                    for inc in incs:
                        events.append({
                            "type": "INC",
                            "timestamp": inc.timestamp.isoformat() if inc.timestamp else None,
                            "summary": f"#{inc.id} {inc.title[:50] if inc.title else ''}",
                            "severity": inc.severity,
                            "id": inc.id,
                        })
                        last_inc_id = max(last_inc_id, inc.id)

                    for scan in scans:
                        events.append({
                            "type": "SCAN",
                            "timestamp": scan.timestamp.isoformat() if scan.timestamp else None,
                            "summary": f"Risk: {scan.overall_score}",
                            "score": scan.overall_score,
                            "id": scan.id,
                        })
                        last_scan_id = max(last_scan_id, scan.id)

                    events.sort(key=lambda x: x.get("timestamp") or "", reverse=True)

                    for event in events:
                        yield f"data: {json.dumps(event)}\n\n"

                    # Expire cached objects so next iteration sees fresh data
                    session.expire_all()

                except Exception:
                    # Session broken -- recreate it
                    session.close()
                    session = logger._get_session()

                await asyncio.sleep(2)
        finally:
            session.close()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ── Unified Dashboard Stream (SSE) ──────────────────────────


@router.get(
    "/api/dashboard/stream",
    tags=["Streaming"],
    summary="Unified dashboard stream (SSE)",
    description=(
        "Single SSE stream that combines stats updates and activity events. "
        "Stats are sent every 5 seconds (only when changed). Activity events "
        "(new commands, incidents, scans) are checked every 2 seconds and sent "
        "immediately. Token is passed as a query parameter for EventSource "
        "compatibility."
    ),
    response_description="Server-Sent Events stream with unified stats and activity data",
)
async def dashboard_stream(
    request: Request,
    hours: int = Query(24, ge=1, le=720),
    token: Optional[str] = Query(None),
    config: SentinelConfig = Depends(get_config),
    logger: BlackboxLogger = Depends(get_logger),
):
    """Unified SSE stream combining stats and activity for the dashboard.

    Emits two event types:
      - {"type": "stats", "data": {...}}   every 5s (only on change)
      - {"type": "activity", "data": {...}} immediately on new events (polled every 2s)

    Token via query param for EventSource compatibility.
    """
    if not token:
        raise HTTPException(status_code=401, detail={"error": "Token required"})
    user = decode_token(token, config.auth)
    if not user:
        raise HTTPException(status_code=401, detail={"error": "Invalid token"})

    is_admin_user = user.role == "admin" or is_super_admin(user, config)

    async def unified_event_generator():
        last_stats_hash: Optional[int] = None
        last_cmd_id = 0
        last_inc_id = 0
        last_scan_id = 0
        first_run = True
        tick = 0
        stats_interval_ticks = 3  # 3 * 2s = 6s (close to 5s target)

        session = logger._get_session()

        try:
            while True:
                if await request.is_disconnected():
                    break

                try:
                    # ── Stats (every ~6 seconds, only on change) ─────
                    if first_run or tick % stats_interval_ticks == 0:
                        stats = logger.get_stats(hours=hours, session=session)
                        stats_dict = stats.model_dump()

                        # Redact all-time data for non-admin
                        if not is_admin_user:
                            stats_dict["all_time_blocked"] = None
                            stats_dict["all_time_warned"] = None
                            stats_dict["all_time_allowed"] = None
                            stats_dict["all_time_incidents"] = None
                            stats_dict["all_time_scans"] = None
                            stats_dict["all_time_total"] = None
                            stats_dict["all_time_blocked_available"] = False
                        else:
                            stats_dict["all_time_blocked_available"] = True

                        # Include usage data
                        try:
                            from sentinelai.api.deps import (
                                UsageInfo,
                                _get_daily_usage_internal,
                                get_user_tier_limits,
                            )

                            if is_super_admin(user, config):
                                usage_info = UsageInfo(
                                    tier="unlimited",
                                    commands_used=0,
                                    commands_limit=-1,
                                    scans_used=0,
                                    scans_limit=-1,
                                    commands_remaining=-1,
                                    scans_remaining=-1,
                                    limit_reached=False,
                                    upgrade_url="",
                                    is_admin=True,
                                )
                            else:
                                user_tier, user_limits = get_user_tier_limits(
                                    user, config, logger, session=session,
                                )
                                usage_info = _get_daily_usage_internal(
                                    logger, config,
                                    user_tier=user_tier,
                                    user_limits=user_limits,
                                    is_admin=is_admin_user,
                                    session=session,
                                    user_email=user.email,
                                )
                            stats_dict["usage"] = usage_info.model_dump()
                        except Exception:
                            stats_dict["usage"] = None

                        current_hash = hash(
                            json.dumps(stats_dict, sort_keys=True, default=str)
                        )
                        if current_hash != last_stats_hash:
                            envelope = {"type": "stats", "data": stats_dict}
                            yield f"data: {json.dumps(envelope, default=str)}\n\n"
                            last_stats_hash = current_hash

                    # ── Activity (every 2 seconds) ───────────────────
                    activity_events: List[Dict[str, Any]] = []

                    if first_run:
                        cmds = (
                            session.query(CommandLog)
                            .order_by(CommandLog.id.desc())
                            .limit(20)
                            .all()
                        )
                        incs = (
                            session.query(IncidentLog)
                            .order_by(IncidentLog.id.desc())
                            .limit(10)
                            .all()
                        )
                        scans = (
                            session.query(PromptScanLog)
                            .order_by(PromptScanLog.id.desc())
                            .limit(10)
                            .all()
                        )
                        first_run = False
                    else:
                        cmds = (
                            session.query(CommandLog)
                            .filter(CommandLog.id > last_cmd_id)
                            .order_by(CommandLog.id.desc())
                            .all()
                        )
                        incs = (
                            session.query(IncidentLog)
                            .filter(IncidentLog.id > last_inc_id)
                            .order_by(IncidentLog.id.desc())
                            .all()
                        )
                        scans = (
                            session.query(PromptScanLog)
                            .filter(PromptScanLog.id > last_scan_id)
                            .order_by(PromptScanLog.id.desc())
                            .all()
                        )

                    for cmd in cmds:
                        activity_events.append({
                            "type": "CMD",
                            "timestamp": cmd.timestamp.isoformat() if cmd.timestamp else None,
                            "summary": cmd.command[:60] if cmd.command else "",
                            "score": cmd.risk_score,
                            "action": cmd.action_taken,
                            "id": cmd.id,
                        })
                        last_cmd_id = max(last_cmd_id, cmd.id)

                    for inc in incs:
                        activity_events.append({
                            "type": "INC",
                            "timestamp": inc.timestamp.isoformat() if inc.timestamp else None,
                            "summary": f"#{inc.id} {inc.title[:50] if inc.title else ''}",
                            "severity": inc.severity,
                            "id": inc.id,
                        })
                        last_inc_id = max(last_inc_id, inc.id)

                    for scan in scans:
                        activity_events.append({
                            "type": "SCAN",
                            "timestamp": scan.timestamp.isoformat() if scan.timestamp else None,
                            "summary": f"Risk: {scan.overall_score}",
                            "score": scan.overall_score,
                            "id": scan.id,
                        })
                        last_scan_id = max(last_scan_id, scan.id)

                    # Send each activity event wrapped in the unified envelope
                    activity_events.sort(
                        key=lambda x: x.get("timestamp") or "", reverse=True,
                    )
                    for event in activity_events:
                        envelope = {"type": "activity", "data": event}
                        yield f"data: {json.dumps(envelope)}\n\n"

                    # Expire cached objects so next iteration sees fresh data
                    session.expire_all()

                except Exception:
                    # Session broken -- recreate it
                    session.close()
                    session = logger._get_session()

                tick += 1
                await asyncio.sleep(2)
        finally:
            session.close()

    return StreamingResponse(
        unified_event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ── Command Center APIs (Wave 7 / Lane U) ───────────────────


class SecurityStatusResponse(BaseModel):
    """System-level security posture at a glance."""
    state: str = Field(description="secure | warning | critical")
    state_label: str = Field(description="Human-readable status label")
    state_detail: str = Field(description="Short explanation of current state")
    threats_blocked_today: int = 0
    threats_blocked_7d: int = 0
    threats_blocked_30d: int = 0
    blocked_trend_pct: float = Field(0.0, description="% change vs previous period")
    suspicious_today: int = 0
    unresolved_incidents: int = 0
    last_threat_at: Optional[str] = Field(None, description="ISO timestamp of last blocked threat")
    security_score: int = Field(100, ge=0, le=100)
    scanner_active: bool = True
    protection_mode: str = "enforce"


@router.get(
    "/api/dashboard/security-status",
    tags=["Command Center"],
    summary="Get system security posture",
    response_model=SecurityStatusResponse,
)
def get_security_status(
    user: TokenData = Depends(require_verified_email),
    config: SentinelConfig = Depends(get_config),
    logger: BlackboxLogger = Depends(get_logger),
):
    """Return the current security posture: state, score, threat counts, last threat time."""
    session = logger._get_session()
    try:
        now = datetime.utcnow()
        cutoff_24h = now - timedelta(hours=24)
        cutoff_7d = now - timedelta(days=7)
        cutoff_30d = now - timedelta(days=30)
        cutoff_prev_7d = cutoff_7d - timedelta(days=7)

        # Threat counts (blocked commands)
        blocked_24h = session.query(func.count()).select_from(CommandLog).filter(
            CommandLog.timestamp >= cutoff_24h, CommandLog.action_taken == "block",
        ).scalar() or 0

        blocked_7d = session.query(func.count()).select_from(CommandLog).filter(
            CommandLog.timestamp >= cutoff_7d, CommandLog.action_taken == "block",
        ).scalar() or 0

        blocked_30d = session.query(func.count()).select_from(CommandLog).filter(
            CommandLog.timestamp >= cutoff_30d, CommandLog.action_taken == "block",
        ).scalar() or 0

        # Previous 7d for trend calculation
        blocked_prev_7d = session.query(func.count()).select_from(CommandLog).filter(
            CommandLog.timestamp >= cutoff_prev_7d,
            CommandLog.timestamp < cutoff_7d,
            CommandLog.action_taken == "block",
        ).scalar() or 0

        # Suspicious commands (warned, or score 40-79)
        suspicious_24h = session.query(func.count()).select_from(CommandLog).filter(
            CommandLog.timestamp >= cutoff_24h,
            CommandLog.action_taken == "warn",
        ).scalar() or 0

        # Unresolved incidents
        unresolved = session.query(func.count()).select_from(IncidentLog).filter(
            IncidentLog.resolved == False,
        ).scalar() or 0

        # Unresolved CRITICAL incidents
        unresolved_critical = session.query(func.count()).select_from(IncidentLog).filter(
            IncidentLog.resolved == False,
            IncidentLog.severity == "CRITICAL",
        ).scalar() or 0

        # Last blocked threat timestamp
        last_blocked = session.query(CommandLog.timestamp).filter(
            CommandLog.action_taken == "block",
        ).order_by(CommandLog.timestamp.desc()).first()
        last_threat_at = last_blocked[0].isoformat() + "Z" if last_blocked else None

        # Security score: 100 - penalties
        score = 100
        score -= min(blocked_24h * 3, 30)       # Up to -30 for blocks today
        score -= min(unresolved * 5, 25)         # Up to -25 for unresolved incidents
        score -= min(unresolved_critical * 10, 20)  # Up to -20 for critical unresolved
        score -= min(suspicious_24h, 15)         # Up to -15 for suspicious
        score = max(0, min(100, score))

        # State determination
        if unresolved_critical > 0 or blocked_24h > 5:
            state = "critical"
            state_label = "ACTIVE THREAT"
            state_detail = (
                f"{unresolved_critical} critical incidents unresolved"
                if unresolved_critical > 0
                else f"{blocked_24h} threats blocked in last 24h"
            )
        elif blocked_24h > 0 or unresolved > 0:
            state = "warning"
            state_label = "ELEVATED RISK"
            parts = []
            if blocked_24h > 0:
                parts.append(f"{blocked_24h} threat{'s' if blocked_24h != 1 else ''} blocked today")
            if unresolved > 0:
                parts.append(f"{unresolved} incident{'s' if unresolved != 1 else ''} pending review")
            state_detail = ". ".join(parts)
        else:
            state = "secure"
            state_label = "SYSTEM SECURE"
            state_detail = "No threats detected. ShieldPilot actively protecting your agents."

        trend = _compute_trend(blocked_7d, blocked_prev_7d)

        return SecurityStatusResponse(
            state=state,
            state_label=state_label,
            state_detail=state_detail,
            threats_blocked_today=blocked_24h,
            threats_blocked_7d=blocked_7d,
            threats_blocked_30d=blocked_30d,
            blocked_trend_pct=trend,
            suspicious_today=suspicious_24h,
            unresolved_incidents=unresolved,
            last_threat_at=last_threat_at,
            security_score=score,
            scanner_active=config.mode != "disabled",
            protection_mode=config.mode,
        )
    finally:
        session.close()


# ── U2: Threat Intelligence ──────────────────────────────────


class ThreatTimelineDay(BaseModel):
    """Daily threat counts for the stacked timeline chart."""
    date: str
    blocked: int = 0
    warned: int = 0
    safe: int = 0


class ThreatTypeCount(BaseModel):
    """Single threat type with occurrence count."""
    type: str
    count: int


class ThreatIntelResponse(BaseModel):
    """Threat intelligence data for the Command Center."""
    timeline: List[ThreatTimelineDay]
    top_threat_types: List[ThreatTypeCount]
    period: str


@router.get(
    "/api/dashboard/threat-intel",
    tags=["Command Center"],
    summary="Get threat intelligence data",
    response_model=ThreatIntelResponse,
)
def get_threat_intel(
    period: str = Query("7d", pattern="^(24h|7d|30d)$"),
    user: TokenData = Depends(require_verified_email),
    config: SentinelConfig = Depends(get_config),
    logger: BlackboxLogger = Depends(get_logger),
):
    """Return threat timeline (daily blocked/warned/safe) and top threat types."""
    hours = _period_to_hours(period)
    session = logger._get_session()
    try:
        now = datetime.utcnow()
        cutoff = now - timedelta(hours=hours)
        days = max(1, hours // 24)

        # ── Daily command breakdown for timeline ──────────────────
        cmd_daily = (
            session.query(
                func.date(CommandLog.timestamp).label("day"),
                func.sum(func.iif(CommandLog.action_taken == "block", 1, 0)).label("blocked"),
                func.sum(func.iif(CommandLog.action_taken == "warn", 1, 0)).label("warned"),
                func.sum(func.iif(CommandLog.action_taken == "allow", 1, 0)).label("safe"),
            )
            .filter(CommandLog.timestamp >= cutoff)
            .group_by(func.date(CommandLog.timestamp))
            .all()
        )
        by_date = {
            row.day: {"blocked": row.blocked or 0, "warned": row.warned or 0, "safe": row.safe or 0}
            for row in cmd_daily
        }

        timeline = []
        for offset in range(days - 1, -1, -1):
            day_str = (now - timedelta(days=offset)).strftime("%Y-%m-%d")
            data = by_date.get(day_str, {})
            timeline.append(ThreatTimelineDay(
                date=day_str,
                blocked=data.get("blocked", 0),
                warned=data.get("warned", 0),
                safe=data.get("safe", 0),
            ))

        # ── Top threat types from incident categories ─────────────
        cat_rows = (
            session.query(
                IncidentLog.category,
                func.count().label("cnt"),
            )
            .filter(IncidentLog.timestamp >= cutoff)
            .group_by(IncidentLog.category)
            .order_by(func.count().desc())
            .limit(10)
            .all()
        )

        # Also augment with signal categories from blocked commands
        signal_counter: Counter = Counter()
        blocked_signals = (
            session.query(CommandLog.signals_json)
            .filter(
                CommandLog.timestamp >= cutoff,
                CommandLog.action_taken == "block",
            )
            .all()
        )
        for (signals_json_str,) in blocked_signals:
            if not signals_json_str:
                continue
            try:
                signals = json.loads(signals_json_str)
                for signal in signals:
                    name = signal.get("name", "")
                    if name:
                        signal_counter[_extract_signal_category(name)] += 1
            except (json.JSONDecodeError, TypeError):
                continue

        # Merge incident categories with signal categories
        merged: Counter = Counter()
        for row in cat_rows:
            merged[row.category] += row.cnt
        for cat, cnt in signal_counter.items():
            merged[cat] += cnt

        top_threat_types = [
            ThreatTypeCount(type=cat, count=cnt)
            for cat, cnt in merged.most_common(10)
        ]

        return ThreatIntelResponse(
            timeline=timeline,
            top_threat_types=top_threat_types,
            period=period,
        )
    finally:
        session.close()


# ── U3: Attack Summary ───────────────────────────────────────


class AttackCategoryCount(BaseModel):
    """Single attack category with counts."""
    category: str
    label: str
    count_24h: int = 0
    count_7d: int = 0
    count_30d: int = 0


class AttackSummaryResponse(BaseModel):
    """Attack breakdown by category for the Command Center."""
    categories: List[AttackCategoryCount]
    total_blocked_24h: int = 0
    total_blocked_7d: int = 0
    total_blocked_30d: int = 0


# Map raw signal categories to human-readable labels
_CATEGORY_LABELS = {
    "prompt_injection": "Prompt Injection",
    "injection": "Prompt Injection",
    "system_prompt": "System Prompt Access",
    "data_exfiltration": "Data Exfiltration",
    "network_exfil": "Network Exfiltration",
    "credential_access": "Credential Access",
    "filesystem_access": "Filesystem Access",
    "tool_abuse": "Tool Abuse",
    "supply_chain": "Supply Chain",
    "privilege_escalation": "Privilege Escalation",
    "obfuscation": "Obfuscation",
}


def _normalize_category(raw: str) -> str:
    """Normalize a raw signal category to a canonical key."""
    lower = raw.lower().strip().replace(" ", "_").replace("-", "_")
    # Map known aliases
    if "injection" in lower or "inject" in lower:
        return "prompt_injection"
    if "exfil" in lower or "exfiltration" in lower:
        return "data_exfiltration"
    if "credential" in lower or "password" in lower or "secret" in lower:
        return "credential_access"
    if "system_prompt" in lower or "systemprompt" in lower:
        return "system_prompt"
    if "supply" in lower:
        return "supply_chain"
    if "network" in lower:
        return "network_exfil"
    if "filesystem" in lower or "file_" in lower:
        return "filesystem_access"
    if "privilege" in lower or "escalat" in lower:
        return "privilege_escalation"
    if "obfuscat" in lower or "encod" in lower:
        return "obfuscation"
    return lower


@router.get(
    "/api/dashboard/attack-summary",
    tags=["Command Center"],
    summary="Get attack breakdown by category",
    response_model=AttackSummaryResponse,
)
def get_attack_summary(
    user: TokenData = Depends(require_verified_email),
    config: SentinelConfig = Depends(get_config),
    logger: BlackboxLogger = Depends(get_logger),
):
    """Return attack counts broken down by category across 24h/7d/30d windows."""
    session = logger._get_session()
    try:
        now = datetime.utcnow()
        cutoff_24h = now - timedelta(hours=24)
        cutoff_7d = now - timedelta(days=7)
        cutoff_30d = now - timedelta(days=30)

        def _count_by_category(cutoff: datetime) -> Counter:
            """Count signal categories from blocked commands since cutoff."""
            counter: Counter = Counter()
            rows = (
                session.query(CommandLog.signals_json)
                .filter(
                    CommandLog.timestamp >= cutoff,
                    CommandLog.action_taken == "block",
                )
                .all()
            )
            for (signals_json_str,) in rows:
                if not signals_json_str:
                    continue
                try:
                    signals = json.loads(signals_json_str)
                    seen = set()  # Count each category once per command
                    for signal in signals:
                        name = signal.get("name", "")
                        if name:
                            cat = _normalize_category(_extract_signal_category(name))
                            if cat not in seen:
                                counter[cat] += 1
                                seen.add(cat)
                except (json.JSONDecodeError, TypeError):
                    continue

            # Also count incidents
            inc_rows = (
                session.query(IncidentLog.category, func.count().label("cnt"))
                .filter(IncidentLog.timestamp >= cutoff)
                .group_by(IncidentLog.category)
                .all()
            )
            for row in inc_rows:
                cat = _normalize_category(row.category)
                counter[cat] += row.cnt

            return counter

        cats_24h = _count_by_category(cutoff_24h)
        cats_7d = _count_by_category(cutoff_7d)
        cats_30d = _count_by_category(cutoff_30d)

        # Collect all seen categories
        all_cats = set(cats_24h.keys()) | set(cats_7d.keys()) | set(cats_30d.keys())

        categories = []
        for cat in sorted(all_cats):
            label = _CATEGORY_LABELS.get(cat, cat.replace("_", " ").title())
            categories.append(AttackCategoryCount(
                category=cat,
                label=label,
                count_24h=cats_24h.get(cat, 0),
                count_7d=cats_7d.get(cat, 0),
                count_30d=cats_30d.get(cat, 0),
            ))

        # Sort by 30d count descending
        categories.sort(key=lambda c: c.count_30d, reverse=True)

        # Totals
        total_24h = session.query(func.count()).select_from(CommandLog).filter(
            CommandLog.timestamp >= cutoff_24h, CommandLog.action_taken == "block",
        ).scalar() or 0
        total_7d = session.query(func.count()).select_from(CommandLog).filter(
            CommandLog.timestamp >= cutoff_7d, CommandLog.action_taken == "block",
        ).scalar() or 0
        total_30d = session.query(func.count()).select_from(CommandLog).filter(
            CommandLog.timestamp >= cutoff_30d, CommandLog.action_taken == "block",
        ).scalar() or 0

        return AttackSummaryResponse(
            categories=categories,
            total_blocked_24h=total_24h,
            total_blocked_7d=total_7d,
            total_blocked_30d=total_30d,
        )
    finally:
        session.close()
