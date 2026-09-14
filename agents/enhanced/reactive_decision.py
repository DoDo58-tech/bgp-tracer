"""
Reactive decision engine for the enhanced workflow.

In enhanced mode, after each pipeline stage the engine inspects evidence
quality, debate signals, and budget limits, then returns one of:
  - "proceed"  : continue with the next stage / step
  - "debate"   : run LLMDebateAgent to settle contested claims
  - "retry"    : re-run an earlier stage with new parameters
  - "probe"    : dispatch ProbeAgent to collect more evidence
  - "escalate" : jump to multi-agent report generation
  - "stop"     : stop with insufficient evidence

Only the classes consumed by workflow_engine are exposed.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Optional


VALID_ACTIONS = {"proceed", "debate", "retry", "probe", "escalate", "stop"}
DEFAULT_BUDGETS = {"debate": 2, "retry": 1, "probe": 2, "escalate": 1}


@dataclass
class ReactiveDecision:
    action: str = "proceed"
    reasoning: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    stage: Optional[str] = None
    confidence: float = 0.0

    def to_dict(self):
        return asdict(self)


class ReactiveDecisionEngine:
    """
    Lightweight reactive decision engine.

    Uses the LLM to choose the next action when budgets allow; falls back to
    deterministic rules when the LLM is unavailable or no contested claims
    are present.
    """

    def __init__(self, llm=None):
        self.llm = llm
        self.budgets: Dict[str, int] = dict(DEFAULT_BUDGETS)

    def consume_budget(self, action: str):
        if action in self.budgets:
            self.budgets[action] = max(0, self.budgets[action] - 1)

    async def decide(self, stage, completed_stages=None, evidence=None, quality_metrics=None, **kwargs):
        claims = []
        if isinstance(evidence, dict):
            claims = (evidence.get("claims") or [])
            if isinstance(claims, dict):
                claims = list(claims.keys())
        # 用 confidence 离散度 + kind 多样性识别"高争议" claim
        if claims and isinstance(claims[0], dict):
            scored = [c.get("score", c.get("confidence", 0.5)) for c in claims]
            contested = [
                c for c, s in zip(claims, scored)
                if (
                    c.get("contested")
                    or 0.25 <= s <= 0.65  # 中等置信度意味着争议
                    or c.get("challenges")  # 已被挑战
                )
            ]
            # 多 kind 类型说明假设有分歧 → 也算 contested
            kinds = {c.get("kind") for c in claims}
            if len(kinds) >= 2:
                contested = contested or claims[:1]
        else:
            contested = []

        if contested and self.budgets.get("debate", 0) > 0:
            return ReactiveDecision(
                action="debate", stage=stage,
                reasoning=f"{len(contested)} contested claims; running debate",
                parameters={"focus_claims": [c.get("id", i) for i, c in enumerate(contested)], "rounds": 3},
            )

        qm_low = isinstance(quality_metrics, dict) and quality_metrics.get("overall_score", 1.0) < 0.4
        if qm_low and self.budgets.get("probe", 0) > 0:
            return ReactiveDecision(
                action="probe", stage=stage,
                reasoning="low quality score; probing for more evidence",
                parameters={"target": stage},
            )

        return ReactiveDecision(
            action="proceed", stage=stage,
            reasoning="quality acceptable; continuing",
            confidence=0.7,
        )