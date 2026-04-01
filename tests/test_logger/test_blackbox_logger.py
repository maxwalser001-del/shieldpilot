"""Tests for the BlackboxLogger and chain integrity."""

from __future__ import annotations

import pytest

from sentinelai.core.constants import Action, IncidentSeverity, RiskCategory, RiskLevel
from sentinelai.core.models import (
    RiskAssessment,
    RiskSignal,
    ScanResult,
    ThreatDetail,
)


class TestBlackboxLogger:
    """Test logging operations."""

    def test_log_command(self, logger):
        assessment = RiskAssessment(
            command="ls -la",
            final_score=5,
            risk_level=RiskLevel.NONE,
            action=Action.ALLOW,
            signals=[],
        )
        entry_id = logger.log_command(assessment, executed=True, exit_code=0)
        assert entry_id > 0

    def test_log_command_with_signals(self, logger):
        assessment = RiskAssessment(
            command="rm -rf /tmp",
            final_score=60,
            risk_level=RiskLevel.MEDIUM,
            action=Action.WARN,
            signals=[
                RiskSignal(
                    category=RiskCategory.DESTRUCTIVE_FS,
                    score=60,
                    weight=0.8,
                    description="Recursive deletion",
                    evidence="rm -rf",
                    analyzer="destructive_fs",
                )
            ],
        )
        entry_id = logger.log_command(assessment)
        assert entry_id > 0

    def test_log_incident(self, logger):
        entry_id = logger.log_incident(
            severity="critical",
            category="destructive_filesystem",
            title="rm -rf / attempt",
            description="User attempted to delete root filesystem",
            evidence="rm -rf /",
        )
        assert entry_id > 0

    def test_query_commands(self, logger):
        # Log a few commands
        for cmd in ["ls", "cat file.txt", "rm temp"]:
            assessment = RiskAssessment(
                command=cmd, final_score=5,
                risk_level=RiskLevel.NONE, action=Action.ALLOW, signals=[],
            )
            logger.log_command(assessment)

        commands, total = logger.query_commands()
        assert total == 3
        assert len(commands) == 3

    def test_query_commands_with_filter(self, logger):
        # Log allowed and blocked
        allow = RiskAssessment(
            command="ls", final_score=5,
            risk_level=RiskLevel.NONE, action=Action.ALLOW, signals=[],
        )
        block = RiskAssessment(
            command="rm -rf /", final_score=100,
            risk_level=RiskLevel.CRITICAL, action=Action.BLOCK, signals=[],
        )
        logger.log_command(allow)
        logger.log_command(block)

        commands, total = logger.query_commands(action="block")
        assert total == 1
        assert commands[0].command == "rm -rf /"

    def test_query_commands_search(self, logger):
        for cmd in ["ls -la", "cat readme.md", "grep pattern"]:
            assessment = RiskAssessment(
                command=cmd, final_score=5,
                risk_level=RiskLevel.NONE, action=Action.ALLOW, signals=[],
            )
            logger.log_command(assessment)

        commands, total = logger.query_commands(search="cat")
        assert total == 1

    def test_log_prompt_scan(self, logger):
        result = ScanResult(
            source="test.txt",
            threats=[
                ThreatDetail(
                    category="jailbreak",
                    pattern_name="instruction_override",
                    matched_text="ignore previous instructions",
                    line_number=5,
                    severity=IncidentSeverity.HIGH,
                    description="Jailbreak attempt",
                    mitigation="Remove override patterns",
                )
            ],
            overall_score=70,
            recommendation="Review before use",
        )
        entry_id = logger.log_prompt_scan(result)
        assert entry_id > 0

    def test_resolve_incident(self, logger):
        inc_id = logger.log_incident(
            severity="high", category="test",
            title="Test incident", description="Test", evidence="test",
        )
        success = logger.resolve_incident(inc_id, "Fixed")
        assert success is True

    def test_resolve_nonexistent_incident(self, logger):
        success = logger.resolve_incident(9999, "notes")
        assert success is False

    def test_get_stats(self, logger):
        assessment = RiskAssessment(
            command="ls", final_score=10,
            risk_level=RiskLevel.LOW, action=Action.ALLOW, signals=[],
        )
        logger.log_command(assessment)
        stats = logger.get_stats(hours=24)
        assert stats.total_commands == 1
        assert stats.allowed_commands == 1


class TestChainIntegrity:
    """Test tamper-evident chain hashing."""

    def test_chain_valid_after_writes(self, logger):
        for i in range(5):
            assessment = RiskAssessment(
                command=f"command_{i}", final_score=i * 10,
                risk_level=RiskLevel.NONE, action=Action.ALLOW, signals=[],
            )
            logger.log_command(assessment)

        result = logger.verify_chain("commands")
        assert result.valid is True
        assert result.verified_entries == 5

    def test_chain_empty_table_valid(self, logger):
        result = logger.verify_chain("commands")
        assert result.valid is True
        assert result.total_entries == 0

    def test_chain_unknown_table(self, logger):
        result = logger.verify_chain("nonexistent")
        assert result.valid is False

    def test_secrets_masked_in_log(self, logger):
        assessment = RiskAssessment(
            command="export API_KEY=AKIAIOSFODNN7EXAMPLE",
            final_score=40,
            risk_level=RiskLevel.MEDIUM,
            action=Action.WARN,
            signals=[],
        )
        logger.log_command(assessment)
        commands, _ = logger.query_commands()
        # The AWS key should be masked
        assert "AKIAIOSFODNN7EXAMPLE" not in commands[0].command
