"""Tests for Command Center API endpoints.

Covers:
- GET /api/dashboard/security-status — Security posture overview
- GET /api/dashboard/threat-intel — Threat timeline + top types
- GET /api/dashboard/attack-summary — Attack breakdown by category
"""

from __future__ import annotations

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


# ── Security Status Tests ─────────────────────────────────────


class TestSecurityStatus:
    """GET /api/dashboard/security-status -- Security posture overview."""

    def test_returns_200_with_auth(self, client, auth_headers):
        response = client.get("/api/dashboard/security-status", headers=auth_headers)
        assert response.status_code == 200

    def test_returns_401_without_auth(self, client):
        response = client.get("/api/dashboard/security-status")
        assert response.status_code == 401

    def test_response_has_all_required_fields(self, client, auth_headers):
        response = client.get("/api/dashboard/security-status", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        required_fields = [
            "state", "state_label", "state_detail",
            "threats_blocked_today", "threats_blocked_7d", "threats_blocked_30d",
            "blocked_trend_pct", "suspicious_today", "unresolved_incidents",
            "last_threat_at", "security_score", "scanner_active", "protection_mode",
        ]
        for field in required_fields:
            assert field in data, f"Missing field: {field}"

    def test_state_is_valid_enum(self, client, auth_headers):
        response = client.get("/api/dashboard/security-status", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["state"] in ("secure", "warning", "critical")

    def test_security_score_range_0_100(self, client, auth_headers):
        response = client.get("/api/dashboard/security-status", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["security_score"], int)
        assert 0 <= data["security_score"] <= 100

    def test_empty_db_state_is_secure(self, client, auth_headers):
        """With no data, the system should report 'secure' state."""
        response = client.get("/api/dashboard/security-status", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["state"] == "secure"
        assert data["threats_blocked_today"] == 0
        assert data["threats_blocked_7d"] == 0
        assert data["threats_blocked_30d"] == 0
        assert data["suspicious_today"] == 0
        assert data["unresolved_incidents"] == 0
        assert data["last_threat_at"] is None
        assert data["security_score"] == 100

    def test_seeded_data_reflects_threats(self, seeded_client, auth_headers):
        """With seeded data (1 block, 1 warn, 2 incidents), state should not be 'secure'."""
        response = seeded_client.get("/api/dashboard/security-status", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        # We seeded 1 blocked command and 2 unresolved incidents
        assert data["threats_blocked_today"] == 1
        assert data["suspicious_today"] == 1  # 1 warned command
        assert data["unresolved_incidents"] == 2
        assert data["state"] in ("warning", "critical")
        assert data["security_score"] < 100

    def test_last_threat_at_present_with_blocked(self, seeded_client, auth_headers):
        """When blocked commands exist, last_threat_at should be a non-None ISO timestamp."""
        response = seeded_client.get("/api/dashboard/security-status", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["last_threat_at"] is not None
        assert "T" in data["last_threat_at"]  # ISO format contains 'T'

    def test_scanner_active_matches_config(self, client, auth_headers):
        """scanner_active should be True when mode is not 'disabled'."""
        response = client.get("/api/dashboard/security-status", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["scanner_active"] is True

    def test_protection_mode_matches_config(self, client, auth_headers):
        """protection_mode should match the config mode ('enforce' in test config)."""
        response = client.get("/api/dashboard/security-status", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["protection_mode"] == "enforce"

    def test_blocked_trend_pct_is_float(self, client, auth_headers):
        """blocked_trend_pct should always be a float."""
        response = client.get("/api/dashboard/security-status", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["blocked_trend_pct"], (int, float))

    def test_threat_count_fields_are_non_negative(self, seeded_client, auth_headers):
        """All threat count fields must be non-negative integers."""
        response = seeded_client.get("/api/dashboard/security-status", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        for field in [
            "threats_blocked_today", "threats_blocked_7d", "threats_blocked_30d",
            "suspicious_today", "unresolved_incidents",
        ]:
            assert isinstance(data[field], int), f"{field} is not int"
            assert data[field] >= 0, f"{field} is negative"


# ── Threat Intel Tests ────────────────────────────────────────


class TestThreatIntel:
    """GET /api/dashboard/threat-intel -- Threat timeline + top types."""

    def test_returns_200_with_auth(self, client, auth_headers):
        response = client.get("/api/dashboard/threat-intel", headers=auth_headers)
        assert response.status_code == 200

    def test_returns_401_without_auth(self, client):
        response = client.get("/api/dashboard/threat-intel")
        assert response.status_code == 401

    def test_response_has_all_required_fields(self, client, auth_headers):
        response = client.get("/api/dashboard/threat-intel", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "timeline" in data
        assert "top_threat_types" in data
        assert "period" in data

    def test_default_period_is_7d(self, client, auth_headers):
        response = client.get("/api/dashboard/threat-intel", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["period"] == "7d"

    def test_period_24h(self, client, auth_headers):
        response = client.get("/api/dashboard/threat-intel?period=24h", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["period"] == "24h"
        # 24h = 1 day in the timeline
        assert len(data["timeline"]) == 1

    def test_period_7d(self, client, auth_headers):
        response = client.get("/api/dashboard/threat-intel?period=7d", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["period"] == "7d"
        assert len(data["timeline"]) == 7

    def test_period_30d(self, client, auth_headers):
        response = client.get("/api/dashboard/threat-intel?period=30d", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["period"] == "30d"
        assert len(data["timeline"]) == 30

    def test_invalid_period_returns_422(self, client, auth_headers):
        response = client.get("/api/dashboard/threat-intel?period=48h", headers=auth_headers)
        assert response.status_code == 422

    def test_invalid_period_nonsense_returns_422(self, client, auth_headers):
        response = client.get("/api/dashboard/threat-intel?period=invalid", headers=auth_headers)
        assert response.status_code == 422

    def test_timeline_entries_have_required_fields(self, client, auth_headers):
        response = client.get("/api/dashboard/threat-intel?period=7d", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        for entry in data["timeline"]:
            assert "date" in entry
            assert "blocked" in entry
            assert "warned" in entry
            assert "safe" in entry

    def test_timeline_dates_are_formatted(self, client, auth_headers):
        response = client.get("/api/dashboard/threat-intel?period=7d", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        for entry in data["timeline"]:
            # YYYY-MM-DD format
            assert len(entry["date"]) == 10
            assert entry["date"][4] == "-"
            assert entry["date"][7] == "-"

    def test_timeline_counts_non_negative(self, client, auth_headers):
        response = client.get("/api/dashboard/threat-intel?period=7d", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        for entry in data["timeline"]:
            assert entry["blocked"] >= 0
            assert entry["warned"] >= 0
            assert entry["safe"] >= 0

    def test_top_threat_types_is_list(self, client, auth_headers):
        response = client.get("/api/dashboard/threat-intel", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["top_threat_types"], list)

    def test_top_threat_types_entry_fields(self, seeded_client, auth_headers):
        """With seeded incidents, top_threat_types should contain entries with type+count."""
        response = seeded_client.get("/api/dashboard/threat-intel?period=7d", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        # We seeded 2 incidents with categories 'filesystem' and 'network'
        if data["top_threat_types"]:
            for entry in data["top_threat_types"]:
                assert "type" in entry
                assert "count" in entry
                assert isinstance(entry["count"], int)
                assert entry["count"] > 0

    def test_empty_db_returns_valid_structure(self, client, auth_headers):
        """With no data, should still return valid timeline + empty threat types."""
        response = client.get("/api/dashboard/threat-intel?period=24h", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data["timeline"]) == 1
        assert data["timeline"][0]["blocked"] == 0
        assert data["timeline"][0]["warned"] == 0
        assert data["timeline"][0]["safe"] == 0
        assert data["top_threat_types"] == []

    def test_seeded_data_reflected_in_timeline(self, seeded_client, auth_headers):
        """Seeded data should appear in the timeline for today."""
        response = seeded_client.get("/api/dashboard/threat-intel?period=24h", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        # We seeded 1 block, 1 warn, 1 allow today
        today = data["timeline"][0]
        assert today["blocked"] == 1
        assert today["warned"] == 1
        assert today["safe"] == 1

    def test_timeline_ordered_chronologically(self, client, auth_headers):
        """Timeline entries should be in ascending date order (oldest first)."""
        response = client.get("/api/dashboard/threat-intel?period=7d", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        dates = [e["date"] for e in data["timeline"]]
        assert dates == sorted(dates)


# ── Attack Summary Tests ──────────────────────────────────────


class TestAttackSummary:
    """GET /api/dashboard/attack-summary -- Attack breakdown by category."""

    def test_returns_200_with_auth(self, client, auth_headers):
        response = client.get("/api/dashboard/attack-summary", headers=auth_headers)
        assert response.status_code == 200

    def test_returns_401_without_auth(self, client):
        response = client.get("/api/dashboard/attack-summary")
        assert response.status_code == 401

    def test_response_has_all_required_fields(self, client, auth_headers):
        response = client.get("/api/dashboard/attack-summary", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "categories" in data
        assert "total_blocked_24h" in data
        assert "total_blocked_7d" in data
        assert "total_blocked_30d" in data

    def test_total_blocked_fields_are_non_negative_integers(self, client, auth_headers):
        response = client.get("/api/dashboard/attack-summary", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        for field in ["total_blocked_24h", "total_blocked_7d", "total_blocked_30d"]:
            assert isinstance(data[field], int), f"{field} is not int"
            assert data[field] >= 0, f"{field} is negative"

    def test_categories_is_list(self, client, auth_headers):
        response = client.get("/api/dashboard/attack-summary", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["categories"], list)

    def test_category_entry_has_required_fields(self, seeded_client, auth_headers):
        """With seeded incidents, category entries should have all required fields."""
        response = seeded_client.get("/api/dashboard/attack-summary", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        # Seeded incidents provide categories (filesystem, network)
        if data["categories"]:
            for cat in data["categories"]:
                assert "category" in cat
                assert "label" in cat
                assert "count_24h" in cat
                assert "count_7d" in cat
                assert "count_30d" in cat

    def test_category_counts_are_non_negative(self, seeded_client, auth_headers):
        """All count fields in categories must be non-negative."""
        response = seeded_client.get("/api/dashboard/attack-summary", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        for cat in data["categories"]:
            assert cat["count_24h"] >= 0
            assert cat["count_7d"] >= 0
            assert cat["count_30d"] >= 0

    def test_empty_db_returns_valid_structure(self, client, auth_headers):
        """With no data, should return empty categories and zero totals."""
        response = client.get("/api/dashboard/attack-summary", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["categories"] == []
        assert data["total_blocked_24h"] == 0
        assert data["total_blocked_7d"] == 0
        assert data["total_blocked_30d"] == 0

    def test_seeded_data_reflected_in_totals(self, seeded_client, auth_headers):
        """Seeded blocked commands should appear in total counts."""
        response = seeded_client.get("/api/dashboard/attack-summary", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        # We seeded 1 blocked command
        assert data["total_blocked_24h"] == 1
        assert data["total_blocked_7d"] == 1
        assert data["total_blocked_30d"] == 1

    def test_seeded_incidents_appear_in_categories(self, seeded_client, auth_headers):
        """Seeded incidents with filesystem/network categories should appear."""
        response = seeded_client.get("/api/dashboard/attack-summary", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        category_names = [c["category"] for c in data["categories"]]
        # Incidents seeded with 'filesystem' and 'network' categories
        # These get normalized by _normalize_category
        assert len(data["categories"]) > 0
        # Check that label is a non-empty string for each category
        for cat in data["categories"]:
            assert isinstance(cat["label"], str)
            assert len(cat["label"]) > 0

    def test_total_blocked_consistency(self, seeded_client, auth_headers):
        """total_blocked_24h <= total_blocked_7d <= total_blocked_30d (cumulative)."""
        response = seeded_client.get("/api/dashboard/attack-summary", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["total_blocked_24h"] <= data["total_blocked_7d"]
        assert data["total_blocked_7d"] <= data["total_blocked_30d"]
