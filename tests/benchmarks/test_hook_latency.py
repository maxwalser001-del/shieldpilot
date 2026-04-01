"""E2E latency benchmarks for the ShieldPilot hook -- Spec 5.

Measures the full hook decision path: stdin parse -> decision -> stdout.

Each test runs the hook main() 50 times with mocked stdin/stdout and
measures wall-clock time using time.perf_counter(). The hook calls
sys.exit(0) which we catch via a mocked sys module (same pattern as
the integration tests in test_hook_integration.py).

For Bash command tests, DB-touching helpers (_check_usage_limit, etc.)
are mocked out, but the risk engine itself is REAL so the blacklist
fast-path and analyzer pipeline are actually exercised.
"""

from __future__ import annotations

import contextlib
import json
import time
from unittest.mock import patch, MagicMock

import pytest

from sentinelai.core.config import (
    BlacklistConfig,
    LLMConfig,
    LoggingConfig,
    RiskThresholds,
    SentinelConfig,
    WhitelistConfig,
)
from sentinelai.core.performance import (
    FAST_PATH_MAX_MS,
    HOOK_LATENCY_TARGETS,
)
from sentinelai.engine import RiskEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_test_config() -> SentinelConfig:
    """Build a minimal SentinelConfig without touching disk."""
    return SentinelConfig(
        mode="enforce",
        risk_thresholds=RiskThresholds(block=80, warn=40, allow=0),
        llm=LLMConfig(enabled=False),
        whitelist=WhitelistConfig(commands=["ls", "cat", "echo", "pwd"]),
        blacklist=BlacklistConfig(
            commands=["rm -rf /", "mkfs", ":(){:|:&};:"],
            domains=["evil.com"],
        ),
        protected_paths=["/etc", "~/.ssh"],
        secrets_patterns=[],
        logging=LoggingConfig(database=":memory:", chain_hashing=False),
    )


# Pre-build config and engine once so that object construction cost is not
# measured on every iteration.  These are module-level singletons; each test
# still gets fresh stdin/stdout mocks per iteration.
_SHARED_CONFIG = _make_test_config()
_SHARED_ENGINE = RiskEngine(_SHARED_CONFIG)


def _time_hook(input_data: dict, extra_patches: dict | None = None) -> float:
    """Run the hook main() once and return elapsed time in milliseconds.

    Args:
        input_data: Hook input dict (JSON-serialised to stdin).
        extra_patches: Optional ``{target_string: return_value}`` for
            additional ``unittest.mock.patch`` calls that should be active
            while main() runs.

    Returns:
        Wall-clock elapsed time in milliseconds.
    """
    raw = json.dumps(input_data)

    mock_stdin = MagicMock()
    mock_stdin.read.return_value = raw

    start = time.perf_counter()

    with contextlib.ExitStack() as stack:
        # Core mocks -- same pattern as test_hook_integration.py
        mock_sys = stack.enter_context(
            patch("sentinelai.hooks.sentinel_hook.sys")
        )
        mock_sys.stdin = mock_stdin
        mock_sys.stderr = MagicMock()
        mock_sys.exit = MagicMock(side_effect=SystemExit(0))

        stack.enter_context(patch("builtins.print"))

        # Apply caller-supplied patches (DB helpers, _load_sentinel, etc.)
        if extra_patches:
            for target, return_value in extra_patches.items():
                stack.enter_context(
                    patch(target, return_value=return_value)
                )

        try:
            from sentinelai.hooks.sentinel_hook import main
            main()
        except SystemExit:
            pass

    elapsed_ms = (time.perf_counter() - start) * 1000
    return elapsed_ms


# ---------------------------------------------------------------------------
# Benchmark suite
# ---------------------------------------------------------------------------

class TestHookLatency:
    """Benchmark the full hook decision path."""

    ITERATIONS = 50

    # -- measurement helpers ------------------------------------------------

    def _measure(
        self,
        input_data: dict,
        extra_patches: dict | None = None,
    ) -> list[float]:
        """Run the hook ITERATIONS times and return sorted latencies (ms)."""
        latencies: list[float] = []
        for _ in range(self.ITERATIONS):
            latencies.append(_time_hook(input_data, extra_patches))
        return sorted(latencies)

    @staticmethod
    def _percentile(sorted_values: list[float], p: int) -> float:
        """Return the *p*-th percentile from pre-sorted values."""
        k = (len(sorted_values) - 1) * p / 100
        f = int(k)
        c = f + 1 if f + 1 < len(sorted_values) else f
        return sorted_values[f] + (k - f) * (sorted_values[c] - sorted_values[f])

    # -- 1. Read-only tools (fast path, no engine) --------------------------

    def test_readonly_tool_fast_path(self):
        """Read-only tools (Glob, Read, Grep) should return near-instantly.

        The hook recognises these tool names and calls _allow() before any
        config loading or engine invocation.  We allow a generous 3x
        multiplier over FAST_PATH_MAX_MS to account for CI jitter.
        """
        data = {"tool_name": "Glob", "tool_input": {"pattern": "*.py"}}
        latencies = self._measure(data)

        p50 = self._percentile(latencies, 50)
        p95 = self._percentile(latencies, 95)

        threshold = FAST_PATH_MAX_MS * 3  # 15 ms
        assert p95 < threshold, (
            f"Read-only fast path p95={p95:.1f}ms exceeds {threshold}ms "
            f"(p50={p50:.1f}ms)"
        )

    # -- 2. Write tool (path check, no full engine) -------------------------

    def test_write_tool_path_check_latency(self):
        """Write tool to a non-protected path should complete quickly.

        The hook loads config, checks the path against protected_paths,
        and calls _allow().  We mock _load_sentinel to skip disk I/O.
        """
        data = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/test.txt"},
        }
        extra = {
            "sentinelai.hooks.sentinel_hook._load_sentinel": (
                _SHARED_CONFIG,
                _SHARED_ENGINE,
                MagicMock(),
            ),
            "sentinelai.hooks.sentinel_hook._check_protected_path": False,
        }
        latencies = self._measure(data, extra)

        p95 = self._percentile(latencies, 95)
        assert p95 < HOOK_LATENCY_TARGETS["p95"], (
            f"Write tool p95={p95:.1f}ms exceeds "
            f"target {HOOK_LATENCY_TARGETS['p95']}ms"
        )

    # -- 3. Bash safe command (full engine, real analyzers) -----------------

    def test_bash_safe_command_latency(self):
        """Bash safe command through real engine should meet hook targets.

        DB helpers are mocked, but the risk engine (with all built-in
        analyzers) runs for real.  ``ls -la`` is whitelisted so the
        engine caps its score at 10 and returns ALLOW quickly.
        """
        from sentinelai.core.constants import Action

        data = {
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
        }
        extra = {
            "sentinelai.hooks.sentinel_hook._load_sentinel": (
                _SHARED_CONFIG,
                _SHARED_ENGINE,
                Action,
            ),
            "sentinelai.hooks.sentinel_hook._check_usage_limit": (False, ""),
            "sentinelai.hooks.sentinel_hook._check_injection_rate": (False, ""),
            "sentinelai.hooks.sentinel_hook._increment_usage": None,
            "sentinelai.hooks.sentinel_hook._log_assessment": None,
            "sentinelai.hooks.sentinel_hook._get_usage_warning": "",
        }
        latencies = self._measure(data, extra)

        p50 = self._percentile(latencies, 50)
        p95 = self._percentile(latencies, 95)
        assert p95 < HOOK_LATENCY_TARGETS["p95"], (
            f"Bash safe p95={p95:.1f}ms exceeds "
            f"target {HOOK_LATENCY_TARGETS['p95']}ms (p50={p50:.1f}ms)"
        )

    # -- 4. Bash blacklisted command (fast exit via blacklist) --------------

    def test_bash_blacklisted_command_fast_exit(self):
        """Blacklisted commands should hit the engine blacklist fast-path.

        ``rm -rf /`` matches the blacklist in _SHARED_CONFIG, so the
        engine returns BLOCK with score 100 before running any analyzers.
        The hook then calls _deny() and exits.
        """
        from sentinelai.core.constants import Action

        data = {
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
        }
        extra = {
            "sentinelai.hooks.sentinel_hook._load_sentinel": (
                _SHARED_CONFIG,
                _SHARED_ENGINE,
                Action,
            ),
            "sentinelai.hooks.sentinel_hook._check_usage_limit": (False, ""),
            "sentinelai.hooks.sentinel_hook._check_injection_rate": (False, ""),
            "sentinelai.hooks.sentinel_hook._increment_usage": None,
            "sentinelai.hooks.sentinel_hook._log_assessment": None,
            "sentinelai.hooks.sentinel_hook._get_usage_warning": "",
        }
        latencies = self._measure(data, extra)

        p50 = self._percentile(latencies, 50)
        p95 = self._percentile(latencies, 95)
        assert p95 < HOOK_LATENCY_TARGETS["p95"], (
            f"Blacklisted p95={p95:.1f}ms exceeds "
            f"target {HOOK_LATENCY_TARGETS['p95']}ms (p50={p50:.1f}ms)"
        )

    # -- 5. Latency distribution stability ----------------------------------

    def test_hook_latency_distribution_stable(self):
        """Verify the read-only fast path has reasonable variance.

        Uses trimmed statistics (drop top/bottom 10%) to remove OS
        scheduling outliers that are unavoidable on sub-millisecond paths.
        """
        import statistics

        data = {"tool_name": "Read", "tool_input": {"file_path": "/tmp/x"}}
        latencies = self._measure(data)

        # Trim top/bottom 10% to remove OS scheduling outliers
        trim = max(1, len(latencies) // 10)
        trimmed = sorted(latencies)[trim:-trim]

        mean = statistics.mean(trimmed)
        std_dev = statistics.stdev(trimmed) if len(trimmed) > 1 else 0
        cv = std_dev / mean if mean > 0 else 0

        assert cv < 3.0, (
            f"Latency too variable: mean={mean:.2f}ms, "
            f"std={std_dev:.2f}ms, CV={cv:.2f}"
        )
