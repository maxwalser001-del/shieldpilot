"""Agent Behavior Monitor — baseline recording and anomaly detection.

Records tool calls during a baseline phase and then scores subsequent calls
against that baseline to detect anomalous agent behaviour.

Anomaly scoring heuristics:
- Unknown tool (never seen in baseline): +0.4
- Frequency anomaly (current rate > 3x baseline rate): +0.3
- New file path (not seen in baseline): +0.2 per new path
- New domain (not seen in baseline): +0.25 per new domain
- Total score capped at 1.0; is_anomaly when score >= anomaly_threshold
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# Regex for extracting file paths from string arguments.
_RE_FILE_PATH = re.compile(r'(?:/[\w./\-]+|~[\w./\-]+|\./[\w./\-]+)')

# Regex for extracting domains from URLs in string arguments.
_RE_DOMAIN = re.compile(r'https?://([^/\s]+)')

# Baseline serialisation version.
_BASELINE_VERSION = "1"


@dataclass
class AnomalyResult:
    """Result of a single anomaly scoring call.

    Attributes
    ----------
    score:
        Composite anomaly score in the range [0.0, 1.0].
    is_anomaly:
        ``True`` when *score* is >= the monitor's ``anomaly_threshold``.
    alerts:
        Human-readable descriptions of each anomaly signal that fired.
    details:
        Machine-readable breakdown keyed by signal name.
    """

    score: float
    is_anomaly: bool
    alerts: List[str] = field(default_factory=list)
    details: Dict[str, object] = field(default_factory=dict)


def _extract_file_paths(arguments: dict) -> Set[str]:
    """Return all file-path strings found inside *arguments* values."""
    paths: Set[str] = set()
    for value in arguments.values():
        if isinstance(value, str):
            paths.update(_RE_FILE_PATH.findall(value))
    return paths


def _extract_domains(arguments: dict) -> Set[str]:
    """Return all URL-domain strings found inside *arguments* values."""
    domains: Set[str] = set()
    for value in arguments.values():
        if isinstance(value, str):
            domains.update(_RE_DOMAIN.findall(value))
    return domains


class BehaviorMonitor:
    """Monitor agent tool-call behaviour against a recorded baseline.

    Usage::

        monitor = BehaviorMonitor(baseline_size=50, anomaly_threshold=0.6)

        # Phase 1 — build the baseline
        for tool_name, args in historical_calls:
            monitor.record(tool_name, args)

        # Phase 2 — score live calls
        result = monitor.score("Bash", {"command": "curl https://evil.example.com"})
        if result.is_anomaly:
            print("Anomalous call!", result.alerts)
    """

    def __init__(
        self,
        baseline_size: int = 50,
        anomaly_threshold: float = 0.6,
    ) -> None:
        self._baseline_size = baseline_size
        self._anomaly_threshold = anomaly_threshold
        self._reset_state()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(
        self,
        tool_name: str,
        arguments: dict,
        timestamp: Optional[float] = None,
    ) -> None:
        """Record a tool call.

        During the baseline phase (``is_baseline_complete() == False``) this
        call updates the baseline statistics.  Once the baseline is complete,
        calls are still stored so that frequency rates can be computed.

        Parameters
        ----------
        tool_name:
            Name of the tool that was invoked (e.g. ``"Bash"``, ``"Read"``).
        arguments:
            Mapping of argument names to values as passed to the tool.
        timestamp:
            Unix timestamp of the call.  Defaults to ``time.time()``.
        """
        ts = timestamp if timestamp is not None else time.time()

        # Determine whether this call falls within the baseline window
        # BEFORE appending, so that the Nth (completing) call is included.
        in_baseline = len(self._calls) < self._baseline_size

        entry = {
            "tool": tool_name,
            "args_keys": sorted(arguments.keys()),
            "timestamp": ts,
        }
        self._calls.append(entry)
        self._timestamps.append(ts)

        if in_baseline:
            # Still building the baseline — update counters.
            self._tool_counts[tool_name] = self._tool_counts.get(tool_name, 0) + 1
            self._file_paths.update(_extract_file_paths(arguments))
            self._domains.update(_extract_domains(arguments))
            logger.debug(
                "Baseline record %d/%d — tool=%s",
                len(self._calls),
                self._baseline_size,
                tool_name,
            )

    def is_baseline_complete(self) -> bool:
        """Return ``True`` when *baseline_size* calls have been recorded."""
        return len(self._calls) >= self._baseline_size

    def score(self, tool_name: str, arguments: dict) -> AnomalyResult:
        """Calculate an anomaly score for a tool call against the baseline.

        If the baseline is not yet complete, returns a zero-score result so
        that callers are never blocked before enough data has been collected.

        Parameters
        ----------
        tool_name:
            Name of the tool being evaluated.
        arguments:
            Arguments supplied to the tool.

        Returns
        -------
        AnomalyResult
            Composite score in [0.0, 1.0], ``is_anomaly`` flag, alert
            messages, and a machine-readable ``details`` dict.
        """
        if not self.is_baseline_complete():
            return AnomalyResult(
                score=0.0,
                is_anomaly=False,
                alerts=[],
                details={"reason": "baseline_incomplete"},
            )

        raw_score = 0.0
        alerts: List[str] = []
        details: Dict[str, object] = {}

        # --- Signal 1: Unknown tool ------------------------------------
        if tool_name not in self._tool_counts:
            raw_score += 0.4
            alerts.append(f"Unknown tool: {tool_name}")
            details["unknown_tool"] = tool_name
            logger.debug("Anomaly signal — unknown tool: %s", tool_name)

        # --- Signal 2: Frequency anomaly -------------------------------
        baseline_rate = self._baseline_rate(tool_name)
        current_rate = self._current_rate(tool_name)
        if baseline_rate > 0 and current_rate > 3.0 * baseline_rate:
            raw_score += 0.3
            alerts.append(
                f"Frequency anomaly: {tool_name} current rate {current_rate:.2f}/s"
                f" vs baseline {baseline_rate:.2f}/s"
            )
            details["frequency_anomaly"] = {
                "tool": tool_name,
                "current_rate": current_rate,
                "baseline_rate": baseline_rate,
            }
            logger.debug(
                "Anomaly signal — frequency: tool=%s current=%.4f baseline=%.4f",
                tool_name,
                current_rate,
                baseline_rate,
            )

        # --- Signal 3: New file paths ----------------------------------
        new_paths = _extract_file_paths(arguments) - self._file_paths
        if new_paths:
            increment = min(0.2 * len(new_paths), 0.6)  # cap contribution
            raw_score += increment
            for p in sorted(new_paths):
                alerts.append(f"New file path: {p}")
            details["new_file_paths"] = sorted(new_paths)
            logger.debug("Anomaly signal — new file paths: %s", new_paths)

        # --- Signal 4: New domains ------------------------------------
        new_domains = _extract_domains(arguments) - self._domains
        if new_domains:
            increment = min(0.25 * len(new_domains), 0.75)  # cap contribution
            raw_score += increment
            for d in sorted(new_domains):
                alerts.append(f"New domain: {d}")
            details["new_domains"] = sorted(new_domains)
            logger.debug("Anomaly signal — new domains: %s", new_domains)

        final_score = min(raw_score, 1.0)
        is_anomaly = final_score >= self._anomaly_threshold

        return AnomalyResult(
            score=final_score,
            is_anomaly=is_anomaly,
            alerts=alerts,
            details=details,
        )

    def save_baseline(self, path: str | Path) -> None:
        """Serialise the current baseline to a JSON file.

        Parameters
        ----------
        path:
            Destination file path.  Parent directories must already exist.
        """
        payload = {
            "version": _BASELINE_VERSION,
            "baseline_size": self._baseline_size,
            "calls": self._calls,
            "tool_counts": self._tool_counts,
            "file_paths": sorted(self._file_paths),
            "domains": sorted(self._domains),
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        destination = Path(path)
        destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger.info("Baseline saved to %s (%d calls)", destination, len(self._calls))

    def load_baseline(self, path: str | Path) -> None:
        """Load a previously saved baseline from a JSON file.

        This replaces all in-memory state.  The ``baseline_size`` stored in
        the file is used so that ``is_baseline_complete()`` returns the
        correct value immediately after loading.

        Parameters
        ----------
        path:
            Source file path previously created by :meth:`save_baseline`.
        """
        source = Path(path)
        payload = json.loads(source.read_text(encoding="utf-8"))

        self._baseline_size = int(payload.get("baseline_size", self._baseline_size))
        self._calls = list(payload.get("calls", []))
        self._tool_counts = dict(payload.get("tool_counts", {}))
        self._file_paths = set(payload.get("file_paths", []))
        self._domains = set(payload.get("domains", []))
        self._timestamps = [c["timestamp"] for c in self._calls if "timestamp" in c]

        logger.info(
            "Baseline loaded from %s — %d calls, %d tools",
            source,
            len(self._calls),
            len(self._tool_counts),
        )

    def reset(self) -> None:
        """Clear all recorded data and return to the baseline phase."""
        self._reset_state()
        logger.debug("BehaviorMonitor reset.")

    def get_stats(self) -> dict:
        """Return a statistics summary of the current monitor state.

        Returns
        -------
        dict
            Keys: ``total_recorded``, ``baseline_size``, ``is_complete``,
            ``top_tools``, ``unique_file_paths``, ``unique_domains``.
        """
        sorted_tools = sorted(
            self._tool_counts.items(), key=lambda kv: kv[1], reverse=True
        )
        return {
            "total_recorded": len(self._calls),
            "baseline_size": self._baseline_size,
            "is_complete": self.is_baseline_complete(),
            "top_tools": [{"tool": t, "count": c} for t, c in sorted_tools[:10]],
            "unique_file_paths": len(self._file_paths),
            "unique_domains": len(self._domains),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _reset_state(self) -> None:
        """Initialise (or re-initialise) all mutable state."""
        self._calls: List[dict] = []
        self._tool_counts: Dict[str, int] = {}
        self._file_paths: Set[str] = set()
        self._domains: Set[str] = set()
        self._timestamps: List[float] = []

    def _baseline_rate(self, tool_name: str) -> float:
        """Return average calls-per-second for *tool_name* in the baseline.

        Uses the first *baseline_size* calls and the time span they cover.
        Returns 0.0 if the tool was not seen or the time span is zero.
        """
        baseline_calls = self._calls[: self._baseline_size]
        tool_ts = [
            c["timestamp"] for c in baseline_calls if c["tool"] == tool_name
        ]
        if len(tool_ts) < 2:
            # Need at least two calls to determine a time span.
            return float(self._tool_counts.get(tool_name, 0)) / max(
                self._baseline_span(), 1.0
            )
        span = max(tool_ts) - min(tool_ts)
        if span <= 0:
            return 0.0
        return len(tool_ts) / span

    def _baseline_span(self) -> float:
        """Return wall-clock seconds covered by the baseline window."""
        baseline_ts = [
            c["timestamp"] for c in self._calls[: self._baseline_size]
        ]
        if len(baseline_ts) < 2:
            return 1.0
        return max(baseline_ts) - min(baseline_ts)

    def _current_rate(self, tool_name: str) -> float:
        """Return average calls-per-second for *tool_name* across ALL calls.

        Uses only post-baseline calls so that the baseline itself does not
        inflate the current rate.
        """
        post_baseline_calls = self._calls[self._baseline_size :]
        tool_ts = [
            c["timestamp"] for c in post_baseline_calls if c["tool"] == tool_name
        ]
        if not tool_ts:
            return 0.0
        if len(tool_ts) < 2:
            # Single post-baseline call — cannot compute rate from span alone;
            # compare against the full post-baseline window instead.
            all_post_ts = [c["timestamp"] for c in post_baseline_calls]
            if len(all_post_ts) < 2:
                return 0.0
            span = max(all_post_ts) - min(all_post_ts)
            return 1.0 / max(span, 1.0)
        span = max(tool_ts) - min(tool_ts)
        if span <= 0:
            return 0.0
        return len(tool_ts) / span
