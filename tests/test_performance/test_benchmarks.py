"""I8: Performance Benchmarks.

Validates latency requirements:
- Hook allow-path: < 200ms
- Scanner clean input: < 50ms
- Risk Engine assessment: < 100ms
- DB single row lookup: < 10ms
"""

from __future__ import annotations

import os
import tempfile
import time

import pytest


class TestHookLatency:
    """Hook should respond in < 200ms for the allow fast-path."""

    def test_read_tool_allow_under_200ms(self):
        """Read-only tools hit the fast path — should be very fast."""
        import json
        from unittest.mock import patch, MagicMock

        hook_input = json.dumps({"tool_name": "Read", "tool_input": {"file_path": "test.txt"}})

        captured = {}
        def mock_print(text, **kwargs):
            if "file" not in kwargs:
                captured["out"] = text

        mock_stdin = MagicMock()
        mock_stdin.read.return_value = hook_input

        with patch("sentinelai.hooks.sentinel_hook.sys") as mock_sys, \
             patch("builtins.print", side_effect=mock_print):
            mock_sys.stdin = mock_stdin
            mock_sys.stderr = MagicMock()
            mock_sys.exit = MagicMock(side_effect=SystemExit(0))

            from sentinelai.hooks.sentinel_hook import main

            start = time.perf_counter()
            try:
                main()
            except SystemExit:
                pass
            elapsed_ms = (time.perf_counter() - start) * 1000

        assert elapsed_ms < 200, f"Hook allow-path took {elapsed_ms:.1f}ms (limit: 200ms)"
        assert "out" in captured


class TestScannerLatency:
    """Scanner should process clean input in < 50ms."""

    def test_clean_input_under_50ms(self):
        from sentinelai.scanner.scanner import PromptScanner

        scanner = PromptScanner()
        clean_text = "ls -la /tmp"

        start = time.perf_counter()
        result = scanner.scan(clean_text, source="benchmark")
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert elapsed_ms < 50, f"Scanner took {elapsed_ms:.1f}ms (limit: 50ms)"
        assert result.overall_score < 20  # Clean input should score low


class TestRiskEngineLatency:
    """Risk engine should assess a Bash command in < 100ms."""

    def test_bash_assessment_under_100ms(self, test_config, mock_context):
        from sentinelai.engine import RiskEngine

        engine = RiskEngine(test_config)

        start = time.perf_counter()
        assessment = engine.assess("ls -la /tmp", mock_context)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert elapsed_ms < 100, f"Risk engine took {elapsed_ms:.1f}ms (limit: 100ms)"


class TestDbLatency:
    """DB single row lookup should complete in < 10ms."""

    def test_single_row_lookup_under_10ms(self, test_config, masker):
        from sentinelai.logger import BlackboxLogger
        from sentinelai.logger.database import UsageRecord

        fd, db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)

        logger = BlackboxLogger(config=test_config.logging, masker=masker, db_path=db_path)
        session = logger._get_session()

        # Insert a row to query
        session.add(UsageRecord(
            tenant_id=None, date="2026-01-01",
            commands_evaluated=42, scans_performed=10,
            llm_calls=0, api_requests=0,
        ))
        session.commit()

        start = time.perf_counter()
        result = session.query(UsageRecord).filter(UsageRecord.date == "2026-01-01").first()
        elapsed_ms = (time.perf_counter() - start) * 1000

        session.close()
        os.unlink(db_path)

        assert elapsed_ms < 10, f"DB lookup took {elapsed_ms:.1f}ms (limit: 10ms)"
        assert result.commands_evaluated == 42
