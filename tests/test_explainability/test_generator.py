"""Unit tests for the non-technical incident explanation generator.

Tests cover:
- All 9 risk categories produce category-specific text
- Score boundary thresholds for severity mapping
- Safe vs dangerous user_impact based on score threshold
- Dominant signal selection with multiple signals
- Empty/malformed signal handling
- Fallback template for unknown categories
"""

import json

import pytest

from sentinelai.explainability.generator import (
    IncidentExplanation,
    _find_dominant_signal,
    _parse_signals,
    _pick_severity_text,
    generate_explanation,
)
from sentinelai.explainability.templates import (
    CATEGORY_TEMPLATES,
    FALLBACK_TEMPLATE,
)


# ---------------------------------------------------------------------------
# Helper: build a signals_json string for a single signal
# ---------------------------------------------------------------------------

def _make_signals_json(
    category: str = "destructive_filesystem",
    score: int = 100,
    weight: float = 1.0,
    description: str = "Test signal",
    analyzer: str = "test_analyzer",
) -> str:
    return json.dumps([{
        "category": category,
        "score": score,
        "weight": weight,
        "description": description,
        "evidence": "test evidence",
        "analyzer": analyzer,
    }])


# ---------------------------------------------------------------------------
# Tests: All 9 categories have templates
# ---------------------------------------------------------------------------

class TestCategoryTemplates:
    """Every RiskCategory value must have a corresponding template."""

    EXPECTED_CATEGORIES = [
        "destructive_filesystem",
        "privilege_escalation",
        "network_exfiltration",
        "credential_access",
        "persistence",
        "obfuscation",
        "malware_pattern",
        "supply_chain",
        "injection",
    ]

    def test_all_categories_have_templates(self):
        for cat in self.EXPECTED_CATEGORIES:
            assert cat in CATEGORY_TEMPLATES, f"Missing template for {cat}"

    @pytest.mark.parametrize("category", EXPECTED_CATEGORIES)
    def test_each_category_produces_explanation(self, category):
        """Each category generates a valid IncidentExplanation."""
        result = generate_explanation(
            signals_json=_make_signals_json(category=category, score=80),
            risk_score=80,
            severity="high",
            category=category,
        )
        assert isinstance(result, IncidentExplanation)
        assert len(result.what_happened) > 10
        assert len(result.why_blocked) > 10
        assert len(result.severity_explanation) > 10
        assert len(result.user_impact) > 10
        assert len(result.hypothetical) > 10

    @pytest.mark.parametrize("category", EXPECTED_CATEGORIES)
    def test_each_category_has_display_title(self, category):
        """Each category produces a non-empty display_title containing 'Blocked'."""
        result = generate_explanation(
            signals_json=_make_signals_json(category=category, score=80),
            risk_score=80,
            severity="high",
            category=category,
        )
        assert len(result.display_title) > 5
        assert "Blocked" in result.display_title

    @pytest.mark.parametrize("category", EXPECTED_CATEGORIES)
    def test_each_category_has_action_guidance(self, category):
        """Each category produces non-empty action_guidance."""
        result = generate_explanation(
            signals_json=_make_signals_json(category=category, score=80),
            risk_score=80,
            severity="high",
            category=category,
        )
        assert len(result.action_guidance) > 10

    @pytest.mark.parametrize("category", EXPECTED_CATEGORIES)
    def test_category_text_is_specific(self, category):
        """Each category produces different text (not all using fallback)."""
        result = generate_explanation(
            signals_json=_make_signals_json(category=category, score=80),
            risk_score=80,
            severity="high",
            category=category,
        )
        # Should NOT match fallback text
        assert result.what_happened != FALLBACK_TEMPLATE.what_happened


# ---------------------------------------------------------------------------
# Tests: Severity threshold boundaries
# ---------------------------------------------------------------------------

class TestSeverityThresholds:
    """Score → severity_explanation mapping at exact boundaries."""

    def test_score_39_is_low(self):
        result = generate_explanation(
            signals_json=_make_signals_json(score=39),
            risk_score=39,
            severity="low",
            category="destructive_filesystem",
        )
        template = CATEGORY_TEMPLATES["destructive_filesystem"]
        assert result.severity_explanation == template.severity_low

    def test_score_40_is_medium(self):
        result = generate_explanation(
            signals_json=_make_signals_json(score=40),
            risk_score=40,
            severity="medium",
            category="destructive_filesystem",
        )
        template = CATEGORY_TEMPLATES["destructive_filesystem"]
        assert result.severity_explanation == template.severity_medium

    def test_score_69_is_medium(self):
        result = generate_explanation(
            signals_json=_make_signals_json(score=69),
            risk_score=69,
            severity="medium",
            category="destructive_filesystem",
        )
        template = CATEGORY_TEMPLATES["destructive_filesystem"]
        assert result.severity_explanation == template.severity_medium

    def test_score_70_is_high(self):
        result = generate_explanation(
            signals_json=_make_signals_json(score=70),
            risk_score=70,
            severity="high",
            category="destructive_filesystem",
        )
        template = CATEGORY_TEMPLATES["destructive_filesystem"]
        assert result.severity_explanation == template.severity_high

    def test_score_89_is_high(self):
        result = generate_explanation(
            signals_json=_make_signals_json(score=89),
            risk_score=89,
            severity="high",
            category="destructive_filesystem",
        )
        template = CATEGORY_TEMPLATES["destructive_filesystem"]
        assert result.severity_explanation == template.severity_high

    def test_score_90_is_critical(self):
        result = generate_explanation(
            signals_json=_make_signals_json(score=90),
            risk_score=90,
            severity="critical",
            category="destructive_filesystem",
        )
        template = CATEGORY_TEMPLATES["destructive_filesystem"]
        assert result.severity_explanation == template.severity_critical

    def test_score_100_is_critical(self):
        result = generate_explanation(
            signals_json=_make_signals_json(score=100),
            risk_score=100,
            severity="critical",
            category="destructive_filesystem",
        )
        template = CATEGORY_TEMPLATES["destructive_filesystem"]
        assert result.severity_explanation == template.severity_critical


# ---------------------------------------------------------------------------
# Tests: User impact (safe vs dangerous)
# ---------------------------------------------------------------------------

class TestUserImpact:
    """Score < 70 → safe text, >= 70 → dangerous text."""

    def test_low_score_gives_safe_impact(self):
        result = generate_explanation(
            signals_json=_make_signals_json(score=50),
            risk_score=50,
            severity="medium",
            category="destructive_filesystem",
        )
        template = CATEGORY_TEMPLATES["destructive_filesystem"]
        assert result.user_impact == template.user_impact_safe

    def test_score_69_gives_safe_impact(self):
        result = generate_explanation(
            signals_json=_make_signals_json(score=69),
            risk_score=69,
            severity="medium",
            category="destructive_filesystem",
        )
        template = CATEGORY_TEMPLATES["destructive_filesystem"]
        assert result.user_impact == template.user_impact_safe

    def test_score_70_gives_dangerous_impact(self):
        result = generate_explanation(
            signals_json=_make_signals_json(score=70),
            risk_score=70,
            severity="high",
            category="destructive_filesystem",
        )
        template = CATEGORY_TEMPLATES["destructive_filesystem"]
        assert result.user_impact == template.user_impact_dangerous

    def test_score_100_gives_dangerous_impact(self):
        result = generate_explanation(
            signals_json=_make_signals_json(score=100),
            risk_score=100,
            severity="critical",
            category="destructive_filesystem",
        )
        template = CATEGORY_TEMPLATES["destructive_filesystem"]
        assert result.user_impact == template.user_impact_dangerous


# ---------------------------------------------------------------------------
# Tests: Action guidance (safe vs dangerous)
# ---------------------------------------------------------------------------

class TestActionGuidance:
    """Score < 70 → safe guidance, >= 70 → dangerous guidance."""

    def test_low_score_gives_safe_guidance(self):
        result = generate_explanation(
            signals_json=_make_signals_json(score=50),
            risk_score=50,
            severity="medium",
            category="destructive_filesystem",
        )
        template = CATEGORY_TEMPLATES["destructive_filesystem"]
        assert result.action_guidance == template.action_guidance_safe

    def test_high_score_gives_dangerous_guidance(self):
        result = generate_explanation(
            signals_json=_make_signals_json(score=80),
            risk_score=80,
            severity="high",
            category="destructive_filesystem",
        )
        template = CATEGORY_TEMPLATES["destructive_filesystem"]
        assert result.action_guidance == template.action_guidance_dangerous

    def test_score_69_gives_safe_guidance(self):
        result = generate_explanation(
            signals_json=_make_signals_json(score=69),
            risk_score=69,
            severity="medium",
            category="destructive_filesystem",
        )
        template = CATEGORY_TEMPLATES["destructive_filesystem"]
        assert result.action_guidance == template.action_guidance_safe

    def test_score_70_gives_dangerous_guidance(self):
        result = generate_explanation(
            signals_json=_make_signals_json(score=70),
            risk_score=70,
            severity="high",
            category="destructive_filesystem",
        )
        template = CATEGORY_TEMPLATES["destructive_filesystem"]
        assert result.action_guidance == template.action_guidance_dangerous


# ---------------------------------------------------------------------------
# Tests: Dominant signal selection
# ---------------------------------------------------------------------------

class TestDominantSignal:
    """Generator uses the highest weighted signal's category for template."""

    def test_highest_weighted_score_wins(self):
        signals = json.dumps([
            {
                "category": "credential_access",
                "score": 30,
                "weight": 0.5,
                "description": "Low signal",
                "evidence": "test",
                "analyzer": "credential_access",
            },
            {
                "category": "network_exfiltration",
                "score": 80,
                "weight": 1.0,
                "description": "High signal",
                "evidence": "test",
                "analyzer": "network_exfil",
            },
        ])
        result = generate_explanation(
            signals_json=signals,
            risk_score=80,
            severity="high",
            category="credential_access",
        )
        # Should use network_exfiltration template (dominant signal)
        net_template = CATEGORY_TEMPLATES["network_exfiltration"]
        assert result.what_happened == net_template.what_happened

    def test_weight_matters_in_selection(self):
        signals = json.dumps([
            {
                "category": "malware_pattern",
                "score": 90,
                "weight": 0.3,
                "description": "High score low weight",
                "evidence": "test",
                "analyzer": "malware",
            },
            {
                "category": "persistence",
                "score": 60,
                "weight": 0.9,
                "description": "Medium score high weight",
                "evidence": "test",
                "analyzer": "persistence",
            },
        ])
        # malware: 90*0.3=27, persistence: 60*0.9=54 → persistence wins
        result = generate_explanation(
            signals_json=signals,
            risk_score=60,
            severity="medium",
            category="malware_pattern",
        )
        persist_template = CATEGORY_TEMPLATES["persistence"]
        assert result.what_happened == persist_template.what_happened

    def test_technical_details_includes_all_signals(self):
        signals = json.dumps([
            {
                "category": "credential_access",
                "score": 30,
                "weight": 0.5,
                "description": "Signal 1",
                "evidence": "test",
                "analyzer": "cred",
            },
            {
                "category": "network_exfiltration",
                "score": 80,
                "weight": 1.0,
                "description": "Signal 2",
                "evidence": "test",
                "analyzer": "net",
            },
        ])
        result = generate_explanation(
            signals_json=signals,
            risk_score=80,
            severity="high",
            category="credential_access",
        )
        assert result.technical_details["signals_count"] == 2
        assert len(result.technical_details["signals"]) == 2
        assert sorted(result.technical_details["analyzers_triggered"]) == ["cred", "net"]


# ---------------------------------------------------------------------------
# Tests: Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Empty signals, malformed JSON, unknown categories."""

    def test_empty_signals_uses_category_template(self):
        result = generate_explanation(
            signals_json="[]",
            risk_score=50,
            severity="medium",
            category="credential_access",
        )
        cred_template = CATEGORY_TEMPLATES["credential_access"]
        assert result.what_happened == cred_template.what_happened

    def test_empty_signals_json_string(self):
        result = generate_explanation(
            signals_json="",
            risk_score=50,
            severity="medium",
            category="credential_access",
        )
        assert isinstance(result, IncidentExplanation)
        assert result.technical_details["signals_count"] == 0

    def test_malformed_json_degrades_gracefully(self):
        result = generate_explanation(
            signals_json="not valid json {{{",
            risk_score=50,
            severity="medium",
            category="credential_access",
        )
        assert isinstance(result, IncidentExplanation)
        assert result.technical_details["signals_count"] == 0

    def test_none_signals_json(self):
        result = generate_explanation(
            signals_json=None,
            risk_score=0,
            severity="low",
            category="unknown",
        )
        assert isinstance(result, IncidentExplanation)

    def test_unknown_category_uses_fallback(self):
        result = generate_explanation(
            signals_json="[]",
            risk_score=50,
            severity="medium",
            category="totally_unknown_category",
        )
        assert result.what_happened == FALLBACK_TEMPLATE.what_happened
        assert result.why_blocked == FALLBACK_TEMPLATE.why_blocked

    def test_technical_details_structure(self):
        result = generate_explanation(
            signals_json=_make_signals_json(score=85, analyzer="destructive_fs"),
            risk_score=85,
            severity="high",
            category="destructive_filesystem",
        )
        td = result.technical_details
        assert td["risk_score"] == 85
        assert td["severity"] == "high"
        assert td["category"] == "destructive_filesystem"
        assert td["signals_count"] == 1
        assert "destructive_fs" in td["analyzers_triggered"]
        assert len(td["signals"]) == 1
        assert td["signals"][0]["score"] == 85


# ---------------------------------------------------------------------------
# Tests: Internal helpers
# ---------------------------------------------------------------------------

class TestHelpers:
    """Test _parse_signals, _find_dominant_signal, _pick_severity_text."""

    def test_parse_signals_valid(self):
        data = [{"score": 10}]
        assert _parse_signals(json.dumps(data)) == data

    def test_parse_signals_empty_string(self):
        assert _parse_signals("") == []

    def test_parse_signals_none(self):
        assert _parse_signals(None) == []

    def test_parse_signals_invalid_json(self):
        assert _parse_signals("{{invalid") == []

    def test_parse_signals_non_list(self):
        assert _parse_signals(json.dumps({"key": "value"})) == []

    def test_find_dominant_empty(self):
        assert _find_dominant_signal([]) is None

    def test_find_dominant_single(self):
        signals = [{"score": 50, "weight": 1.0, "category": "test"}]
        assert _find_dominant_signal(signals) == signals[0]

    def test_find_dominant_multi(self):
        signals = [
            {"score": 30, "weight": 1.0},
            {"score": 80, "weight": 0.5},
            {"score": 50, "weight": 0.9},
        ]
        # 30*1.0=30, 80*0.5=40, 50*0.9=45 → third wins
        assert _find_dominant_signal(signals) == signals[2]

    def test_pick_severity_boundaries(self):
        t = FALLBACK_TEMPLATE
        assert _pick_severity_text(t, 0) == t.severity_low
        assert _pick_severity_text(t, 39) == t.severity_low
        assert _pick_severity_text(t, 40) == t.severity_medium
        assert _pick_severity_text(t, 69) == t.severity_medium
        assert _pick_severity_text(t, 70) == t.severity_high
        assert _pick_severity_text(t, 89) == t.severity_high
        assert _pick_severity_text(t, 90) == t.severity_critical
        assert _pick_severity_text(t, 100) == t.severity_critical
