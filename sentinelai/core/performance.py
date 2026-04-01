"""Performance targets for ShieldPilot components.

These targets define acceptable latency for various operations.
Benchmarks should verify these targets are met.
"""

# Hook latency targets (in milliseconds)
HOOK_LATENCY_TARGETS = {
    "p50": 20,     # 50th percentile: 20ms
    "p95": 50,     # 95th percentile: 50ms
    "p99": 100,    # 99th percentile: 100ms
    "max": 500,    # Absolute maximum: 500ms
}

# Risk engine targets (without LLM)
ENGINE_LATENCY_TARGETS = {
    "p50": 10,
    "p95": 30,
    "p99": 50,
}

# Prompt scanner targets (without LLM)
SCANNER_LATENCY_TARGETS = {
    "p50": 15,
    "p95": 50,
    "p99": 100,
}

# Read-only tool fast path should be near-instant
FAST_PATH_MAX_MS = 5
