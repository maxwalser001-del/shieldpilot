"""Risk Engine — orchestrates all analyzers and computes final risk score.

Scoring algorithm:
1. Check whitelist (exact match → score=0, ALLOW)
2. Check blacklist (pattern match → score=100, BLOCK)
3. Run all analyzers, collect RiskSignals
4. Compute weighted score using maximum-weighted + diminishing tail
5. Optionally refine with LLM for ambiguous scores
6. Determine action based on thresholds
"""

from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import List, Optional

from sentinelai.core.config import SentinelConfig
from sentinelai.core.constants import Action, RiskLevel, score_to_risk_level
from sentinelai.core.models import RiskAssessment, RiskSignal
from sentinelai.engine.base import AnalysisContext, BaseAnalyzer
from sentinelai.engine.llm_evaluator import LLMEvaluator

logger = logging.getLogger(__name__)


class RiskEngine:
    """Central risk scoring engine.

    Coordinates all registered analyzers, computes a composite risk score,
    and determines the appropriate action (block/warn/allow).
    """

    def __init__(
        self,
        config: SentinelConfig,
        analyzers: Optional[List[BaseAnalyzer]] = None,
    ):
        self.config = config

        if analyzers is not None:
            self.analyzers = analyzers
        else:
            # Load all built-in analyzers
            from sentinelai.engine.analyzers import ALL_ANALYZERS
            self.analyzers = [cls() for cls in ALL_ANALYZERS]

        # Initialize LLM evaluator if enabled
        self.llm_evaluator: Optional[LLMEvaluator] = None
        if config.llm.enabled:
            self.llm_evaluator = LLMEvaluator(config.llm)

    def assess(self, command: str, context: Optional[AnalysisContext] = None) -> RiskAssessment:
        """Perform full risk assessment on a command.

        Args:
            command: Shell command string to evaluate.
            context: Analysis context. Created with defaults if not provided.

        Returns:
            Complete RiskAssessment with score, signals, and action.
        """
        start_time = time.time()

        if context is None:
            context = AnalysisContext(config=self.config)
        elif context.config is None:
            context.config = self.config

        # Step 1: Whitelist check — exact command match
        base_cmd = command.strip().split()[0] if command.strip() else ""
        if base_cmd in self.config.whitelist.commands:
            # Whitelisted commands still go through analysis but score is capped
            pass

        # Step 2: Blacklist check — pattern match
        cmd_lower = command.lower().strip()
        for blacklisted in self.config.blacklist.commands:
            if blacklisted.lower() in cmd_lower:
                elapsed = (time.time() - start_time) * 1000
                return RiskAssessment(
                    command=command,
                    final_score=100,
                    risk_level=RiskLevel.CRITICAL,
                    action=Action.BLOCK,
                    signals=[
                        RiskSignal(
                            category=self.analyzers[0].category if self.analyzers else "malware_pattern",
                            score=100,
                            weight=1.0,
                            description=f"Command matches blacklist pattern: {blacklisted}",
                            evidence=command,
                            analyzer="blacklist",
                        )
                    ],
                    timestamp=datetime.utcnow(),
                    execution_time_ms=elapsed,
                )

        # Step 3: Run all analyzers
        all_signals: List[RiskSignal] = []
        for analyzer in self.analyzers:
            try:
                signals = analyzer.analyze(command, context)
                all_signals.extend(signals)
            except Exception as e:
                logger.warning(f"Analyzer {analyzer.name} failed: {e}")

        # Step 4: Compute composite score
        raw_score = self._compute_score(all_signals)

        # Apply whitelist cap: if base command is whitelisted, cap at 10
        # UNLESS a credential-access signal was detected. Whitelisted commands
        # like `cat` or `grep` are safe for normal files but dangerous when
        # targeting secrets (e.g. `cat ~/.ssh/id_rsa`). Only credential_access
        # signals bypass the cap — other analyzers (e.g. destructive_fs
        # matching "/etc" in `ls /etc/passwd`) should remain capped.
        if base_cmd in self.config.whitelist.commands:
            has_credential_signal = any(
                s.analyzer == "credential_access" and s.score >= self.config.risk_thresholds.warn
                for s in all_signals
            )
            if not has_credential_signal:
                raw_score = min(raw_score, 10)

        # Step 5: LLM refinement for ambiguous scores
        llm_used = False
        llm_reasoning = None
        final_score = raw_score

        score_range = self.config.llm.score_range
        if (
            self.llm_evaluator is not None
            and len(score_range) == 2
            and score_range[0] <= raw_score <= score_range[1]
        ):
            llm_result = self.llm_evaluator.evaluate(
                command=command,
                current_score=raw_score,
                signals=all_signals,
                working_directory=context.working_directory,
            )
            if llm_result.error is None:
                llm_used = True
                llm_reasoning = llm_result.reasoning
                final_score = max(0, min(100, raw_score + llm_result.adjustment))

        # Step 6: Determine action
        action = self._determine_action(final_score)

        elapsed = (time.time() - start_time) * 1000

        return RiskAssessment(
            command=command,
            final_score=final_score,
            risk_level=score_to_risk_level(final_score),
            action=action,
            signals=all_signals,
            llm_used=llm_used,
            llm_reasoning=llm_reasoning,
            timestamp=datetime.utcnow(),
            execution_time_ms=elapsed,
        )

    def _compute_score(self, signals: List[RiskSignal]) -> int:
        """Compute composite score using maximum-weighted + diminishing tail.

        The highest weighted signal dominates. Additional signals add
        diminishing contributions (each subsequent signal adds 50% less
        than the previous one). This prevents false positives from benign
        commands that happen to match multiple low-risk patterns.
        """
        if not signals:
            return 0

        # Compute weighted scores
        weighted = [s.score * s.weight for s in signals]
        weighted.sort(reverse=True)

        # Maximum-weighted with diminishing tail
        score = weighted[0]
        for i, w in enumerate(weighted[1:], 1):
            score += w * (0.5 ** i)

        return min(100, int(score))

    def _determine_action(self, score: int) -> Action:
        """Map a risk score to an action based on configured thresholds."""
        if score >= self.config.risk_thresholds.block:
            return Action.BLOCK
        elif score >= self.config.risk_thresholds.warn:
            return Action.WARN
        else:
            return Action.ALLOW
