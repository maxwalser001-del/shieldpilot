"""Policy-as-Code Engine for ShieldPilot.

Public API::

    from sentinelai.policy import PolicyEngine, PolicyDecision

    engine = PolicyEngine()
    engine.load_policy("sentinelai/policy/defaults/default_safe.yaml")
    decision = engine.evaluate("bash", "rm -rf /home")
    print(decision.action)  # "deny"
"""

from __future__ import annotations

from sentinelai.policy.engine import PolicyDecision, PolicyEngine, PolicyRule

__all__ = ["PolicyEngine", "PolicyDecision", "PolicyRule"]
