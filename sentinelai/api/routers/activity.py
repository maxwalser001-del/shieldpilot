"""Activity feed endpoint."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.orm import Session

from sentinelai.api.auth import TokenData
from sentinelai.api.deps import (
    get_db_session,
    require_verified_email,
)
from sentinelai.api.routers._shared import _sanitize_text

router = APIRouter()


# ── Sub-select templates for each event type ────────────────────

_CMD_SELECT = """
    SELECT 'CMD'  AS type, timestamp, SUBSTR(command, 1, 60) AS summary,
           risk_score AS score, action_taken AS action, id,
           NULL AS severity, NULL AS blocked
    FROM commands ORDER BY id DESC LIMIT :lim
"""

_INC_SELECT = """
    SELECT 'INC'  AS type, timestamp, '#' || CAST(id AS TEXT) || ' ' || SUBSTR(title, 1, 50) AS summary,
           NULL AS score, NULL AS action, id,
           severity, NULL AS blocked
    FROM incidents {severity_filter} ORDER BY id DESC LIMIT :lim
"""

_NET_SELECT = """
    SELECT 'NET'  AS type, timestamp, '-> ' || destination || ':' || COALESCE(CAST(port AS TEXT), '') AS summary,
           NULL AS score, NULL AS action, id,
           NULL AS severity, blocked
    FROM network_access ORDER BY id DESC LIMIT :lim
"""

_FILE_SELECT = """
    SELECT 'FILE' AS type, timestamp, file_path || ' (' || change_type || ')' AS summary,
           NULL AS score, NULL AS action, id,
           NULL AS severity, NULL AS blocked
    FROM file_changes ORDER BY id DESC LIMIT :lim
"""

_SCAN_SELECT = """
    SELECT 'SCAN' AS type, timestamp, source || ' (' || CAST(threat_count AS TEXT) || ' threats)' AS summary,
           overall_score AS score, NULL AS action, id,
           NULL AS severity, NULL AS blocked
    FROM prompt_scans ORDER BY id DESC LIMIT :lim
"""

# Map of type code -> sub-select template
_TYPE_SELECTS = {
    "CMD": _CMD_SELECT,
    "INC": _INC_SELECT,
    "NET": _NET_SELECT,
    "FILE": _FILE_SELECT,
    "SCAN": _SCAN_SELECT,
}


def _build_union_query(
    event_type: Optional[str],
    severity: Optional[str],
) -> tuple[str, dict]:
    """Build a dynamic UNION ALL query based on filters.

    Returns (sql_string, params_dict).
    """
    params: dict = {}

    # Determine which sub-selects to include
    if event_type and event_type.upper() in _TYPE_SELECTS:
        type_keys = [event_type.upper()]
    else:
        type_keys = list(_TYPE_SELECTS.keys())

    # Build severity filter for INC sub-select
    severity_filter = ""
    if severity and "INC" in type_keys:
        severity_filter = "WHERE severity = :severity"
        params["severity"] = severity

    # Assemble sub-selects
    sub_selects = []
    for key in type_keys:
        tpl = _TYPE_SELECTS[key]
        if key == "INC":
            tpl = tpl.format(severity_filter=severity_filter)
        sub_selects.append(f"SELECT * FROM ({tpl})")

    union_body = "\nUNION ALL\n".join(sub_selects)
    return union_body, params


# ── Activity Feed ─────────────────────────────────────────────


@router.get(
    "/api/activity/feed",
    tags=["Activity"],
    summary="Get unified activity feed",
    description=(
        "Return a merged, chronologically sorted feed of recent events across "
        "all log types (commands, incidents, scans, file changes, network access). "
        "Supports pagination via limit/offset and filtering by event_type and severity."
    ),
    response_description="Paginated, filterable timeline of security events",
)
def activity_feed(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    event_type: Optional[str] = Query(
        None, description="Filter by event type: CMD, INC, SCAN, NET, FILE"
    ),
    severity: Optional[str] = Query(
        None, description="Filter incidents by severity (e.g. critical, high, medium, low)"
    ),
    user: TokenData = Depends(require_verified_email),
    session: Session = Depends(get_db_session),
):
    """Unified activity feed across all log types.

    Uses a dynamic UNION ALL query built from the requested filters.
    Each sub-select fetches a pre-sorted slice so the database does minimal
    work.  The outer query sorts the merged result by timestamp and applies
    LIMIT + OFFSET for pagination.

    Returns ``total`` alongside ``events`` so the frontend can compute page
    count without a separate request.
    """
    union_body, params = _build_union_query(event_type, severity)

    # ── Count query (total matching events) ────────────────────
    count_sql = text("SELECT COUNT(*) FROM (" + union_body + " ORDER BY timestamp DESC)")
    # For the count query, use a large internal limit so sub-selects aren't
    # artificially capped at the page size.  10 000 is plenty for counting.
    count_params = {**params, "lim": 10_000}
    total: int = session.execute(count_sql, count_params).scalar() or 0

    # ── Data query (paginated) ─────────────────────────────────
    data_sql = text(
        union_body + "\n"
        "ORDER BY timestamp DESC\n"
        "LIMIT :lim OFFSET :off"
    )
    data_params = {**params, "lim": limit, "off": offset}
    rows = session.execute(data_sql, data_params).fetchall()

    events = []
    for row in rows:
        event: dict = {
            "type": row[0],
            "timestamp": (row[1].isoformat() if hasattr(row[1], "isoformat") else row[1]) if row[1] else None,
            "summary": _sanitize_text(row[2]),
            "id": row[5],
        }
        if row[3] is not None:
            event["score"] = row[3]
        if row[4] is not None:
            event["action"] = row[4]
        if row[6] is not None:
            event["severity"] = row[6]
        if row[7] is not None:
            event["blocked"] = bool(row[7])
        events.append(event)

    return {
        "events": events,
        "total": total,
        "limit": limit,
        "offset": offset,
    }
