"""Tests for dashboard, analytics, activity, export, and health endpoints.

Covers:
- GET /api/stats — Dashboard statistics
- GET /api/stats/analytics — Daily analytics with trends
- GET /api/activity/feed — Activity feed with filters + pagination
- GET /api/export/commands — CSV/JSON export
- GET /api/export/incidents — CSV/JSON export
- GET /api/export/scans — CSV/JSON export
- GET /api/health — Health check (no auth required)
- GET /api/health/chain — Chain integrity (admin only)
"""

from __future__ import annotations

import csv
import io
import json

import pytest
from fastapi.testclient import TestClient

from sentinelai.api import deps
from sentinelai.api.app import create_app
from sentinelai.api.auth import TokenData, create_access_token
from sentinelai.core.config import SentinelConfig
from sentinelai.core.constants import Action, IncidentSeverity, RiskLevel
from sentinelai.core.models import RiskAssessment, ScanResult, ThreatDetail
from sentinelai.core.secrets import SecretsMasker
from sentinelai.logger import BlackboxLogger


# ── Fixtures ──────────────────────────────────────────────────


@pytest.fixture
def app(test_config, db_path):
    """Create a test FastAPI app with test config."""
    deps.reset_singletons()

    masker = SecretsMasker(test_config.secrets_patterns)
    logger = BlackboxLogger(config=test_config.logging, masker=masker, db_path=db_path)

    deps._config = test_config
    deps._logger = logger

    application = create_app()
    yield application

    deps.reset_singletons()


@pytest.fixture
def client(app):
    """FastAPI test client."""
    return TestClient(app)


@pytest.fixture
def auth_headers(client, test_config):
    """Get admin auth headers by logging in."""
    response = client.post("/api/auth/login", json={
        "username": test_config.auth.default_admin_user,
        "password": test_config.auth.default_admin_password,
    })
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def non_admin_headers(app, test_config):
    """Get non-admin (viewer role) auth headers via direct token creation."""
    token_data = TokenData(
        username="viewer@test.com",
        email="viewer@test.com",
        role="viewer",
        tier="free",
        is_super_admin=False,
        email_verified=True,
    )
    token = create_access_token(data=token_data, auth_config=test_config.auth)
    return {"Authorization": f"Bearer {token.access_token}"}


def _seed_commands(logger: BlackboxLogger, count: int = 3) -> list[int]:
    """Seed command log entries and return their IDs."""
    ids = []

    # Low-risk allowed command
    assessment_allow = RiskAssessment(
        command="echo hello",
        final_score=5,
        risk_level=RiskLevel.NONE,
        action=Action.ALLOW,
        signals=[],
    )
    ids.append(logger.log_command(assessment_allow, executed=True))

    # Medium-risk warned command
    assessment_warn = RiskAssessment(
        command="curl http://example.com/data",
        final_score=50,
        risk_level=RiskLevel.MEDIUM,
        action=Action.WARN,
        signals=[],
    )
    ids.append(logger.log_command(assessment_warn, executed=True))

    if count >= 3:
        # High-risk blocked command
        assessment_block = RiskAssessment(
            command="rm -rf /important",
            final_score=95,
            risk_level=RiskLevel.CRITICAL,
            action=Action.BLOCK,
            signals=[],
        )
        ids.append(logger.log_command(assessment_block, executed=False))

    return ids


def _seed_incidents(logger: BlackboxLogger) -> list[int]:
    """Seed incident log entries and return their IDs."""
    ids = []
    ids.append(logger.log_incident(
        severity="critical",
        category="filesystem",
        title="High risk command detected",
        description="rm -rf / attempted",
        evidence="rm -rf / in command log",
    ))
    ids.append(logger.log_incident(
        severity="medium",
        category="network",
        title="Suspicious network access",
        description="Connection to unknown host",
        evidence="curl to 10.0.0.1",
    ))
    return ids


def _seed_scans(logger: BlackboxLogger) -> list[int]:
    """Seed prompt scan log entries and return their IDs."""
    ids = []
    scan_result = ScanResult(
        source="test-prompt",
        overall_score=85,
        threats=[
            ThreatDetail(
                category="injection",
                pattern_name="ignore_instructions",
                matched_text="ignore previous instructions",
                severity=IncidentSeverity.HIGH,
                description="Prompt injection detected",
                mitigation="Block the prompt",
            ),
        ],
        recommendation="Block",
    )
    ids.append(logger.log_prompt_scan(scan_result))

    clean_scan = ScanResult(
        source="clean-prompt",
        overall_score=0,
        threats=[],
        recommendation="Allow",
    )
    ids.append(logger.log_prompt_scan(clean_scan))
    return ids


@pytest.fixture
def seeded_app(app):
    """App with seeded test data (commands, incidents, scans)."""
    logger = deps.get_logger()
    _seed_commands(logger)
    _seed_incidents(logger)
    _seed_scans(logger)
    return app


@pytest.fixture
def seeded_client(seeded_app):
    """Test client with seeded data."""
    return TestClient(seeded_app)


# ── Stats Tests ───────────────────────────────────────────────


class TestStats:
    """GET /api/stats — Dashboard statistics."""

    def test_get_stats_returns_200_with_auth(self, client, auth_headers):
        response = client.get("/api/stats", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "total_commands" in data
        assert "blocked_commands" in data
        assert "warned_commands" in data
        assert "allowed_commands" in data
        assert "average_risk_score" in data
        assert "total_incidents" in data
        assert "total_scans" in data

    def test_get_stats_returns_401_without_auth(self, client):
        response = client.get("/api/stats")
        assert response.status_code == 401

    def test_get_stats_default_hours_24(self, client, auth_headers):
        response = client.get("/api/stats", headers=auth_headers)
        assert response.status_code == 200
        # Should work without explicit hours param (defaults to 24)

    def test_get_stats_custom_hours(self, client, auth_headers):
        response = client.get("/api/stats?hours=48", headers=auth_headers)
        assert response.status_code == 200

    def test_get_stats_shows_all_time_for_admin(self, client, auth_headers):
        response = client.get("/api/stats", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        # Admin should see all-time stats
        assert data.get("all_time_blocked_available") is True
        assert data.get("all_time_total") is not None

    def test_get_stats_redacts_all_time_for_non_admin(self, client, non_admin_headers):
        response = client.get("/api/stats", headers=non_admin_headers)
        assert response.status_code == 200
        data = response.json()
        # Non-admin should NOT see all-time stats
        assert data.get("all_time_blocked_available") is False
        assert data.get("all_time_total") is None
        assert data.get("all_time_blocked") is None
        assert data.get("all_time_warned") is None
        assert data.get("all_time_allowed") is None
        assert data.get("all_time_incidents") is None
        assert data.get("all_time_scans") is None

    def test_get_stats_with_data(self, seeded_client, auth_headers):
        response = seeded_client.get("/api/stats?hours=24", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        # We seeded 3 commands (1 allow, 1 warn, 1 block)
        assert data["total_commands"] == 3
        assert data["blocked_commands"] == 1
        assert data["warned_commands"] == 1
        assert data["allowed_commands"] == 1
        # Average risk score: (5 + 50 + 95) / 3 = 50.0
        assert data["average_risk_score"] == 50.0
        # We seeded 2 incidents
        assert data["total_incidents"] == 2
        assert data["unresolved_incidents"] == 2
        # We seeded 2 scans
        assert data["total_scans"] == 2

    def test_get_stats_hours_validation_too_low(self, client, auth_headers):
        response = client.get("/api/stats?hours=0", headers=auth_headers)
        assert response.status_code == 422  # ge=1 validation

    def test_get_stats_hours_validation_too_high(self, client, auth_headers):
        response = client.get("/api/stats?hours=721", headers=auth_headers)
        assert response.status_code == 422  # le=720 validation

    def test_get_stats_includes_top_blocked_commands(self, seeded_client, auth_headers):
        response = seeded_client.get("/api/stats", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "top_blocked_commands" in data
        assert isinstance(data["top_blocked_commands"], list)
        # We seeded 1 blocked command
        assert len(data["top_blocked_commands"]) == 1
        assert data["top_blocked_commands"][0]["count"] == 1

    def test_get_stats_includes_score_distribution(self, seeded_client, auth_headers):
        response = seeded_client.get("/api/stats", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "score_distribution" in data
        assert isinstance(data["score_distribution"], list)
        assert len(data["score_distribution"]) == 5  # 5 buckets
        # Check bucket labels
        labels = [b["range"] for b in data["score_distribution"]]
        assert labels == ["0-19", "20-39", "40-59", "60-79", "80-100"]


# ── Analytics Tests ───────────────────────────────────────────


class TestAnalytics:
    """GET /api/stats/analytics — Daily usage analytics."""

    def test_analytics_returns_daily_entries(self, client, auth_headers):
        response = client.get("/api/stats/analytics", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "daily" in data
        assert isinstance(data["daily"], list)
        # Default is 7 days
        assert len(data["daily"]) == 7

    def test_analytics_days_parameter(self, client, auth_headers):
        response = client.get("/api/stats/analytics?days=3", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data["daily"]) == 3

    def test_analytics_non_admin_limited_to_7_days(self, client, non_admin_headers):
        # Non-admin requests 30 days but should only get 7
        response = client.get("/api/stats/analytics?days=30", headers=non_admin_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data["daily"]) == 7

    def test_analytics_admin_gets_full_range(self, client, auth_headers):
        # Admin can request the full 30 days
        response = client.get("/api/stats/analytics?days=14", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data["daily"]) == 14

    def test_analytics_includes_trends(self, client, auth_headers):
        response = client.get("/api/stats/analytics", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "trends" in data
        trends = data["trends"]
        assert "commands_trend" in trends
        assert "blocked_trend" in trends
        assert "scans_trend" in trends

    def test_analytics_includes_top_categories(self, client, auth_headers):
        response = client.get("/api/stats/analytics", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "top_categories" in data
        assert isinstance(data["top_categories"], list)

    def test_analytics_empty_database(self, client, auth_headers):
        response = client.get("/api/stats/analytics?days=1", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        # Should return valid structure even with no data
        assert len(data["daily"]) == 1
        entry = data["daily"][0]
        assert entry["commands"] == 0
        assert entry["blocked"] == 0
        assert entry["warned"] == 0
        assert entry["scans"] == 0
        assert entry["incidents"] == 0

    def test_analytics_with_seeded_data(self, seeded_client, auth_headers):
        response = seeded_client.get("/api/stats/analytics?days=1", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        today_entry = data["daily"][0]
        # We seeded 3 commands, 2 scans, 2 incidents today
        assert today_entry["commands"] == 3
        assert today_entry["blocked"] == 1
        assert today_entry["warned"] == 1
        assert today_entry["scans"] == 2
        assert today_entry["incidents"] == 2

    def test_analytics_daily_entry_has_date_field(self, client, auth_headers):
        response = client.get("/api/stats/analytics?days=1", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        entry = data["daily"][0]
        assert "date" in entry
        # Should be YYYY-MM-DD format
        assert len(entry["date"]) == 10
        assert entry["date"][4] == "-"

    def test_analytics_days_validation_too_low(self, client, auth_headers):
        response = client.get("/api/stats/analytics?days=0", headers=auth_headers)
        assert response.status_code == 422

    def test_analytics_days_validation_too_high(self, client, auth_headers):
        response = client.get("/api/stats/analytics?days=31", headers=auth_headers)
        assert response.status_code == 422

    def test_analytics_requires_auth(self, client):
        response = client.get("/api/stats/analytics")
        assert response.status_code == 401


# ── Activity Feed Tests ───────────────────────────────────────


class TestActivityFeed:
    """GET /api/activity/feed — Unified activity feed."""

    def test_activity_feed_returns_events(self, seeded_client, auth_headers):
        response = seeded_client.get("/api/activity/feed", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "events" in data
        assert "total" in data
        assert len(data["events"]) > 0

    def test_activity_feed_pagination_limit_offset(self, seeded_client, auth_headers):
        # Get only 2 events
        response = seeded_client.get(
            "/api/activity/feed?limit=2&offset=0", headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data["events"]) <= 2
        assert data["limit"] == 2
        assert data["offset"] == 0

        # Offset to next page
        total = data["total"]
        if total > 2:
            response2 = seeded_client.get(
                "/api/activity/feed?limit=2&offset=2", headers=auth_headers,
            )
            assert response2.status_code == 200
            data2 = response2.json()
            assert data2["offset"] == 2

    def test_activity_feed_filter_by_event_type_cmd(self, seeded_client, auth_headers):
        response = seeded_client.get(
            "/api/activity/feed?event_type=CMD", headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        # All returned events should be CMD type
        for event in data["events"]:
            assert event["type"] == "CMD"

    def test_activity_feed_filter_by_event_type_inc(self, seeded_client, auth_headers):
        response = seeded_client.get(
            "/api/activity/feed?event_type=INC", headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        for event in data["events"]:
            assert event["type"] == "INC"
        # We seeded 2 incidents
        assert data["total"] == 2

    def test_activity_feed_filter_by_event_type_scan(self, seeded_client, auth_headers):
        response = seeded_client.get(
            "/api/activity/feed?event_type=SCAN", headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        for event in data["events"]:
            assert event["type"] == "SCAN"
        # We seeded 2 scans
        assert data["total"] == 2

    def test_activity_feed_filter_by_severity(self, seeded_client, auth_headers):
        response = seeded_client.get(
            "/api/activity/feed?event_type=INC&severity=critical",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        for event in data["events"]:
            assert event["severity"] == "critical"
        # We seeded 1 critical incident
        assert data["total"] == 1

    def test_activity_feed_combined_filters(self, seeded_client, auth_headers):
        response = seeded_client.get(
            "/api/activity/feed?event_type=INC&severity=medium",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        # We seeded 1 medium incident
        assert data["total"] == 1
        assert data["events"][0]["severity"] == "medium"

    def test_activity_feed_returns_total_count(self, seeded_client, auth_headers):
        response = seeded_client.get("/api/activity/feed?limit=1", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        # Total should be greater than limit returned
        assert "total" in data
        assert data["total"] >= len(data["events"])

    def test_activity_feed_empty_database(self, client, auth_headers):
        response = client.get("/api/activity/feed", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["events"] == []
        assert data["total"] == 0

    def test_activity_feed_requires_auth(self, client):
        response = client.get("/api/activity/feed")
        assert response.status_code == 401

    def test_activity_feed_events_have_timestamp(self, seeded_client, auth_headers):
        response = seeded_client.get("/api/activity/feed", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        for event in data["events"]:
            assert "timestamp" in event
            assert "type" in event
            assert "summary" in event
            assert "id" in event

    def test_activity_feed_events_sorted_by_timestamp(self, seeded_client, auth_headers):
        response = seeded_client.get("/api/activity/feed", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        timestamps = [e["timestamp"] for e in data["events"] if e["timestamp"]]
        # Should be in descending order (newest first)
        assert timestamps == sorted(timestamps, reverse=True)


# ── Export Tests ──────────────────────────────────────────────


class TestExportCommands:
    """GET /api/export/commands — CSV/JSON export."""

    def test_export_commands_csv(self, seeded_client, auth_headers):
        response = seeded_client.get(
            "/api/export/commands?format=csv", headers=auth_headers,
        )
        assert response.status_code == 200
        assert "text/csv" in response.headers["content-type"]
        assert "Content-Disposition" in response.headers
        assert "sentinel-commands.csv" in response.headers["Content-Disposition"]

        # Parse CSV and verify structure
        reader = csv.reader(io.StringIO(response.text))
        rows = list(reader)
        header = rows[0]
        assert "id" in header
        assert "command" in header
        assert "risk_score" in header
        # We seeded 3 commands
        assert len(rows) == 4  # header + 3 data rows

    def test_export_commands_json(self, seeded_client, auth_headers):
        response = seeded_client.get(
            "/api/export/commands?format=json", headers=auth_headers,
        )
        assert response.status_code == 200
        assert "Content-Disposition" in response.headers
        assert "sentinel-commands.json" in response.headers["Content-Disposition"]

        data = json.loads(response.text)
        assert isinstance(data, list)
        assert len(data) == 3
        # Verify fields present
        for item in data:
            assert "id" in item
            assert "timestamp" in item
            assert "command" in item
            assert "risk_score" in item
            assert "action" in item
            assert "executed" in item

    def test_export_commands_csv_empty(self, client, auth_headers):
        response = client.get(
            "/api/export/commands?format=csv", headers=auth_headers,
        )
        assert response.status_code == 200
        reader = csv.reader(io.StringIO(response.text))
        rows = list(reader)
        assert len(rows) == 1  # header only

    def test_export_commands_requires_auth(self, client):
        response = client.get("/api/export/commands?format=csv")
        assert response.status_code == 401

    def test_export_commands_invalid_format(self, client, auth_headers):
        response = client.get(
            "/api/export/commands?format=xml", headers=auth_headers,
        )
        assert response.status_code == 422  # pattern validation


class TestExportIncidents:
    """GET /api/export/incidents — CSV/JSON export."""

    def test_export_incidents_csv(self, seeded_client, auth_headers):
        response = seeded_client.get(
            "/api/export/incidents?format=csv", headers=auth_headers,
        )
        assert response.status_code == 200
        assert "text/csv" in response.headers["content-type"]
        assert "sentinel-incidents.csv" in response.headers["Content-Disposition"]

        reader = csv.reader(io.StringIO(response.text))
        rows = list(reader)
        header = rows[0]
        assert "severity" in header
        assert "category" in header
        assert "title" in header
        # 2 seeded incidents
        assert len(rows) == 3  # header + 2 data rows

    def test_export_incidents_json(self, seeded_client, auth_headers):
        response = seeded_client.get(
            "/api/export/incidents?format=json", headers=auth_headers,
        )
        assert response.status_code == 200
        assert "sentinel-incidents.json" in response.headers["Content-Disposition"]

        data = json.loads(response.text)
        assert isinstance(data, list)
        assert len(data) == 2
        for item in data:
            assert "severity" in item
            assert "category" in item
            assert "title" in item
            assert "resolved" in item

    def test_export_incidents_filter_severity(self, seeded_client, auth_headers):
        response = seeded_client.get(
            "/api/export/incidents?format=json&severity=critical",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = json.loads(response.text)
        assert len(data) == 1
        assert data[0]["severity"] == "critical"

    def test_export_incidents_requires_auth(self, client):
        response = client.get("/api/export/incidents?format=csv")
        assert response.status_code == 401


class TestExportScans:
    """GET /api/export/scans — CSV/JSON export."""

    def test_export_scans_csv(self, seeded_client, auth_headers):
        response = seeded_client.get(
            "/api/export/scans?format=csv", headers=auth_headers,
        )
        assert response.status_code == 200
        assert "text/csv" in response.headers["content-type"]
        assert "sentinel-scans.csv" in response.headers["Content-Disposition"]

        reader = csv.reader(io.StringIO(response.text))
        rows = list(reader)
        header = rows[0]
        assert "source" in header
        assert "overall_score" in header
        assert "threat_count" in header
        # 2 seeded scans
        assert len(rows) == 3  # header + 2 data rows

    def test_export_scans_json(self, seeded_client, auth_headers):
        response = seeded_client.get(
            "/api/export/scans?format=json", headers=auth_headers,
        )
        assert response.status_code == 200
        assert "sentinel-scans.json" in response.headers["Content-Disposition"]

        data = json.loads(response.text)
        assert isinstance(data, list)
        assert len(data) == 2
        for item in data:
            assert "source" in item
            assert "overall_score" in item
            assert "threat_count" in item
            assert "recommendation" in item

    def test_export_scans_filter_score_min(self, seeded_client, auth_headers):
        response = seeded_client.get(
            "/api/export/scans?format=json&score_min=50",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = json.loads(response.text)
        # Only the scan with score 85 should pass
        assert len(data) == 1
        assert data[0]["overall_score"] >= 50

    def test_export_scans_requires_auth(self, client):
        response = client.get("/api/export/scans?format=csv")
        assert response.status_code == 401


# ── Health Tests ──────────────────────────────────────────────


class TestHealth:
    """GET /api/health — Health check (no auth)."""

    def test_health_no_auth_required(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200

    def test_health_returns_status(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
        assert data["status"] in ("ok", "degraded", "error")

    def test_health_returns_version(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert "version" in data
        assert isinstance(data["version"], str)

    def test_health_returns_uptime(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert "uptime_seconds" in data
        assert isinstance(data["uptime_seconds"], int)
        assert data["uptime_seconds"] >= 0

    def test_health_returns_components(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert "components" in data
        components = data["components"]
        # Should have database, disk, chain_integrity, smtp, stripe, google_oauth
        assert "database" in components
        assert "disk" in components
        assert "chain_integrity" in components
        assert "smtp" in components
        assert "stripe" in components
        assert "google_oauth" in components

    def test_health_database_component(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        db = response.json()["components"]["database"]
        assert db["status"] == "ok"
        assert "response_ms" in db

    def test_health_chain_integrity_component(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        chain = response.json()["components"]["chain_integrity"]
        assert chain["status"] in ("ok", "degraded")
        assert "tables" in chain


class TestHealthChain:
    """GET /api/health/chain — Chain integrity (admin only)."""

    def test_health_chain_requires_admin(self, client, non_admin_headers):
        response = client.get("/api/health/chain", headers=non_admin_headers)
        assert response.status_code == 403

    def test_health_chain_requires_auth(self, client):
        response = client.get("/api/health/chain")
        assert response.status_code == 401

    def test_health_chain_returns_table_results(self, client, auth_headers):
        response = client.get("/api/health/chain", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "healthy" in data
        assert "chains" in data
        # All 5 tables should be present
        expected_tables = [
            "commands", "incidents", "prompt_scans",
            "file_changes", "network_access",
        ]
        for table in expected_tables:
            assert table in data["chains"]
            result = data["chains"][table]
            assert "valid" in result
            assert "total_entries" in result
            assert "verified_entries" in result
            assert "message" in result

    def test_health_chain_empty_database_is_valid(self, client, auth_headers):
        response = client.get("/api/health/chain", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        # Empty chains should be valid
        assert data["healthy"] is True
        for table_result in data["chains"].values():
            assert table_result["valid"] is True

    def test_health_chain_with_data_is_valid(self, seeded_client, auth_headers):
        response = seeded_client.get("/api/health/chain", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["healthy"] is True
        # Commands, incidents, prompt_scans should have entries
        assert data["chains"]["commands"]["total_entries"] == 3
        assert data["chains"]["incidents"]["total_entries"] == 2
        assert data["chains"]["prompt_scans"]["total_entries"] == 2
