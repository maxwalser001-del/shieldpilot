"""Tests for ML telemetry counters in sentinel_hook.py.

Verifies:
- Telemetry emits one stderr line after every 100 ticks
- Telemetry is silent when SENTINEL_ML_TELEMETRY is not "1"
- No raw text appears in telemetry output
- Counter values are correct
"""

from __future__ import annotations

import json
import sys
from io import StringIO
from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def _reset_telemetry():
    """Reset telemetry counters before each test."""
    from sentinelai.hooks.sentinel_hook import _telemetry
    original = dict(_telemetry)
    _telemetry["count_total"] = 0
    _telemetry["count_ml_scored"] = 0
    _telemetry["count_ml_rec_block"] = 0
    _telemetry["count_ml_rec_review"] = 0
    _telemetry["count_ml_denies"] = 0
    yield
    # Restore (in case other tests depend on state)
    _telemetry.update(original)


class TestTelemetryEmission:
    """When SENTINEL_ML_TELEMETRY=1, a JSON line should appear on stderr every 100 ticks."""

    def test_emits_after_100_ticks(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_ML_TELEMETRY", "1")
        from sentinelai.hooks.sentinel_hook import _telemetry_tick

        stderr_capture = StringIO()
        with patch("sys.stderr", stderr_capture):
            for i in range(101):
                _telemetry_tick(ml_scored=(i % 3 == 0), ml_recommendation="allow")

        output = stderr_capture.getvalue().strip()
        lines = [l for l in output.splitlines() if l.strip()]
        assert len(lines) == 1, f"Expected 1 telemetry line, got {len(lines)}: {output}"

        record = json.loads(lines[0])
        assert record["count_total"] == 100
        assert "ml_mode" in record

    def test_emits_at_200(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_ML_TELEMETRY", "1")
        from sentinelai.hooks.sentinel_hook import _telemetry_tick

        stderr_capture = StringIO()
        with patch("sys.stderr", stderr_capture):
            for _ in range(200):
                _telemetry_tick(ml_scored=True, ml_recommendation="allow")

        output = stderr_capture.getvalue().strip()
        lines = [l for l in output.splitlines() if l.strip()]
        assert len(lines) == 2, f"Expected 2 telemetry lines at 200 ticks, got {len(lines)}"

    def test_counter_values_correct(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_ML_TELEMETRY", "1")
        from sentinelai.hooks.sentinel_hook import _telemetry_tick

        stderr_capture = StringIO()
        with patch("sys.stderr", stderr_capture):
            # 50 scored, 10 block rec, 15 review rec, 5 denies
            for i in range(100):
                _telemetry_tick(
                    ml_scored=(i < 50),
                    ml_recommendation="block" if i < 10 else ("review" if i < 25 else "allow"),
                    ml_denied=(i < 5),
                )

        record = json.loads(stderr_capture.getvalue().strip())
        assert record["count_total"] == 100
        assert record["count_ml_scored"] == 50
        assert record["count_ml_rec_block"] == 10
        assert record["count_ml_rec_review"] == 15
        assert record["count_ml_denies"] == 5


class TestTelemetryOff:
    """When SENTINEL_ML_TELEMETRY is not set or != "1", no output."""

    def test_no_output_when_unset(self, monkeypatch):
        monkeypatch.delenv("SENTINEL_ML_TELEMETRY", raising=False)
        from sentinelai.hooks.sentinel_hook import _telemetry_tick

        stderr_capture = StringIO()
        with patch("sys.stderr", stderr_capture):
            for _ in range(200):
                _telemetry_tick(ml_scored=True, ml_recommendation="block")

        assert stderr_capture.getvalue() == ""

    def test_no_output_when_zero(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_ML_TELEMETRY", "0")
        from sentinelai.hooks.sentinel_hook import _telemetry_tick

        stderr_capture = StringIO()
        with patch("sys.stderr", stderr_capture):
            for _ in range(200):
                _telemetry_tick(ml_scored=True, ml_recommendation="block")

        assert stderr_capture.getvalue() == ""


class TestTelemetryNoRawText:
    """Telemetry output must never contain raw command text."""

    def test_no_raw_text_in_output(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_ML_TELEMETRY", "1")
        from sentinelai.hooks.sentinel_hook import _telemetry_tick

        stderr_capture = StringIO()
        with patch("sys.stderr", stderr_capture):
            for _ in range(100):
                # These args don't accept text, but verify the output anyway
                _telemetry_tick(ml_scored=True, ml_recommendation="block", ml_denied=True)

        output = stderr_capture.getvalue()
        record = json.loads(output.strip())

        # Only expected keys
        allowed_keys = {
            "ml_mode", "count_total", "count_ml_scored",
            "count_ml_rec_block", "count_ml_rec_review", "count_ml_denies",
        }
        assert set(record.keys()) == allowed_keys, (
            f"Unexpected keys in telemetry: {set(record.keys()) - allowed_keys}"
        )

        # No string value longer than 20 chars (mode names are short)
        for k, v in record.items():
            if isinstance(v, str):
                assert len(v) < 20, f"Suspiciously long string in telemetry: {k}={v}"
