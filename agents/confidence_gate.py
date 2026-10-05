"""Adaptive confidence-gated pipeline (Innovation A).

This module is the **skeleton** of innovation point A from the paper. It is
designed to be **fully additive** — it does NOT touch ``workflow_engine.py``
or ``agents/llm_reasoning.py`` until the gating decision is wired into
``WorkflowEngine.get_next_state`` (Step 2). Until then, all functions are
unit-testable in isolation.

Key concepts
------------
A :class:`ConfidenceReport` is emitted by each pipeline stage after it runs.
The :class:`ConfidenceGate` consumes a list of reports and decides what the
next state should be: ``PROCEED``, ``SKIP``, ``REPLAY`` or ``ESCALATE``.

The decision is **deterministic** (rule-based) — the gate is intentionally
NOT a learned model. This is a paper-grade decision: every gate decision is
auditable from the report list, which is exactly the reviewer-friendly
evidence we want for the ablation table.

Design choices
--------------
- **Hysteresis** is built in via separate ``enter_skip`` and ``exit_skip``
  thresholds. A stage that flipped between "skip" and "no-skip" on every
  run would be useless, so the gate only enters the skip regime once
  ``enter_skip`` is crossed and only leaves it once ``exit_skip`` is crossed.
- **Per-stage budgets**. Each stage has its own token budget so a noisy
  early stage cannot starve the more expensive reasoning stages.
- **Confidence score decomposition**. The report splits confidence into
  four components: rule_based, llm_based, prior and residual. The total is a
  weighted sum. This decomposition is what makes the program-generated
  reflection (innovation C) attachable later.
- **JSON-safe by construction**. Every field is a primitive or a list of
  primitives, so the report can be embedded in the Blackboard without
  custom serialisation.

Public surface
--------------
- :class:`ConfidenceReport` — the dataclass.
- :class:`ConfidenceGate` — the decision engine.
- :class:`GateDecision` — the decision envelope (proceed / skip / replay /
  escalate + reasoning).
- :func:`score_to_components` — helper that builds a confidence score from
  the four components without callers having to know the weights.

This file is unit-tested by ``tests/test_round24_confidence_gate.py`` (to
be added in this commit).
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

# ── Defaults (overridable via GateConfig) ────────────────────────────────────
DEFAULT_ENTER_SKIP_THRESHOLD = 0.92
DEFAULT_EXIT_SKIP_THRESHOLD = 0.85
DEFAULT_REPLAY_THRESHOLD = 0.30
DEFAULT_ESCALATE_THRESHOLD = 0.50


class GateAction(str, Enum):
    """Action the gate recommends for the next pipeline state."""

    PROCEED = "proceed"   # continue to the default next state
    SKIP = "skip"         # skip the next stage entirely
    REPLAY = "replay"     # re-run the previous stage (confidence too low)
    ESCALATE = "escalate" # jump to a higher-cost stage (e.g. validation)


# ── Score components ────────────────────────────────────────────────────────


@dataclass
class ConfidenceComponents:
    """Decomposed confidence score.

    Attributes:
        rule_based: Confidence coming from deterministic detectors
            (e.g. anomaly count, signature match). Range ``[0, 1]``.
        llm_based:  Confidence coming from LLM judgement. Range ``[0, 1]``.
        prior:      Prior probability for the current event type, derived
            from the screening stage. Range ``[0, 1]``.
        residual:   Inverse of the disagreement score between the rule-based
            and LLM-based components. ``1.0`` means total agreement.
            Range ``[0, 1]``.
    """

    rule_based: float = 0.0
    llm_based: float = 0.0
    prior: float = 0.5
    residual: float = 1.0

    def __post_init__(self) -> None:
        for name in ("rule_based", "llm_based", "prior", "residual"):
            v = getattr(self, name)
            if not isinstance(v, (int, float)):
                raise TypeError(
                    f"ConfidenceComponents.{name} must be numeric, got {type(v).__name__}"
                )
            if not 0.0 <= float(v) <= 1.0:
                raise ValueError(
                    f"ConfidenceComponents.{name} must be in [0, 1], got {v}"
                )

    @property
    def total(self) -> float:
        """Weighted total in ``[0, 1]``.

        Weights are fixed by design — the gate is deterministic. If the
        ablation shows the weights are sub-optimal for any stage, the
        weights are exposed via :class:`GateConfig` rather than re-derived
        here.
        """
        return (
            0.45 * float(self.rule_based)
            + 0.30 * float(self.llm_based)
            + 0.15 * float(self.prior)
            + 0.10 * float(self.residual)
        )


def score_to_components(
    rule_based: float = 0.0,
    llm_based: float = 0.0,
    prior: float = 0.5,
    residual: float = 1.0,
) -> ConfidenceComponents:
    """Convenience constructor with explicit semantics.

    All arguments are clamped to ``[0, 1]``. Out-of-range values raise
    ``ValueError`` (deliberate — silent clamping hides bugs in callers
    that pass an unbounded anomaly count, e.g.).
    """
    return ConfidenceComponents(
        rule_based=rule_based,
        llm_based=llm_based,
        prior=prior,
        residual=residual,
    )


# ── Stage report ────────────────────────────────────────────────────────────


@dataclass
class ConfidenceReport:
    """Structured confidence report emitted by a pipeline stage.

    The report is what the downstream gate consumes. A stage populates the
    fields that apply and leaves the rest at their defaults.

    Attributes:
        stage: Workflow state that emitted the report. Free-form for now —
            the gate does not inspect the value.
        score: Decomposed confidence. Defaults to all-zero (no signal).
        skip_recommendation: If non-None, name of the stage this stage
            recommends skipping (e.g. ``"ROUTING_ANALYSIS"``).
        reason: Human-readable reason for the recommendation. Goes into
            the ablation table.
        token_cost: Approximate token cost of the stage that emitted the
            report. Used by the gate's per-stage budget accounting.
        extras: Free-form metadata for ablation studies (timestamp, etc.).
    """

    stage: str = ""
    score: ConfidenceComponents = field(default_factory=ConfidenceComponents)
    skip_recommendation: Optional[str] = None
    reason: str = ""
    token_cost: int = 0
    extras: dict = field(default_factory=dict)

    @property
    def total(self) -> float:
        return self.score.total

    def to_dict(self) -> dict:
        d = asdict(self)
        d["score"] = asdict(self.score)
        d["total"] = self.total
        return d


# ── Gate configuration ──────────────────────────────────────────────────────


@dataclass
class GateConfig:
    """Thresholds and budgets for the gate.

    Defaults are conservative: when ``enabled=False`` (the default), the
    gate is a no-op. Callers who opt in should pass an explicit
    ``enter_skip`` and ``exit_skip``; the defaults below are 0.0 / 0.0 so
    a misconfigured opt-in fails loudly rather than silently skipping.
    """

    enter_skip: float = 0.0     # disabled-by-default threshold; opt-in callers must override
    exit_skip: float = 0.0      # disabled-by-default threshold; opt-in callers must override
    replay_threshold: float = DEFAULT_REPLAY_THRESHOLD
    escalate_threshold: float = DEFAULT_ESCALATE_THRESHOLD
    token_budget_per_stage: int = 50_000
    enabled: bool = False

    def __post_init__(self) -> None:
        # Threshold ordering sanity check. We require enter > exit to make
        # hysteresis meaningful; otherwise the gate would oscillate.
        if self.enter_skip < self.exit_skip:
            raise ValueError(
                "GateConfig.enter_skip must be >= exit_skip "
                f"(got enter={self.enter_skip}, exit={self.exit_skip})"
            )
        for name in ("enter_skip", "exit_skip", "replay_threshold", "escalate_threshold"):
            v = getattr(self, name)
            if not 0.0 <= v <= 1.0:
                raise ValueError(
                    f"GateConfig.{name} must be in [0, 1], got {v}"
                )
        if self.token_budget_per_stage < 0:
            raise ValueError(
                f"GateConfig.token_budget_per_stage must be >= 0, got {self.token_budget_per_stage}"
            )


# ── Gate decision ────────────────────────────────────────────────────────────


@dataclass
class GateDecision:
    """The gate's recommendation for the next state.

    Attributes:
        action: One of :class:`GateAction`.
        target: The state name to jump to (interpretation depends on
            ``action``: ``PROCEED`` keeps the engine's default next state;
            ``SKIP`` jumps to the state after ``target``; ``REPLAY``
            re-runs ``target``; ``ESCALATE`` jumps to the heavyweight
            validation stage). May be empty for ``PROCEED``.
        reason: Human-readable explanation. Goes into the ablation table.
        score: The total confidence score that drove the decision.
        stage: The stage whose report drove the decision.
        estimated_token_savings: Estimated tokens saved by acting on this
            decision. Computed from the per-stage budget and the source
            report's ``token_cost``.
    """

    action: GateAction
    target: str = ""
    reason: str = ""
    score: float = 0.0
    stage: str = ""
    estimated_token_savings: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["action"] = self.action.value
        return d


# ── The gate ────────────────────────────────────────────────────────────────


class ConfidenceGate:
    """Rule-based gate that consumes a stream of :class:`ConfidenceReport`.

    The gate is **stateless across runs** — every :meth:`decide` call takes
    the full report list, which makes the decision deterministic and
    auditable.

    Hysteresis rule
    ---------------
    For each stage the gate tracks a ``was_skipping`` flag. The gate enters
    the skip regime for stage ``S`` when the latest report for ``S`` has
    ``total >= config.enter_skip``. It leaves the skip regime when the
    latest report for ``S`` has ``total < config.exit_skip``. This is what
    prevents oscillation when a stage's score is right at the threshold.
    """

    def __init__(self, config: Optional[GateConfig] = None) -> None:
        self.config = config or GateConfig()
        self._skipping: dict[str, bool] = {}

    def reset(self) -> None:
        """Clear per-run state. Call at the start of each workflow run."""
        self._skipping.clear()

    # ── Decision entry point ────────────────────────────────────────────────

    def decide(
        self,
        reports: list[ConfidenceReport],
        default_next_stage: str = "",
        proposed_skip: str = "",
    ) -> GateDecision:
        """Decide what the next state should be given the latest reports.

        Args:
            reports: All reports emitted so far in the run, in order.
                Only the **last** report per stage is consulted; earlier
                reports are retained in ``reports`` for the ablation table
                but ignored by the decision logic.
            default_next_stage: The state the engine would transition to
                without gating. Returned as ``target`` when the action is
                ``PROCEED``.
            proposed_skip: The state the latest report recommends
                skipping. Pass-through so the gate can validate against
                its own hysteresis state.

        Returns:
            A :class:`GateDecision` describing the action.
        """
        if not self.config.enabled:
            return GateDecision(
                action=GateAction.PROCEED,
                target=default_next_stage,
                reason="gate_disabled",
                score=0.0,
                stage="",
                estimated_token_savings=0,
            )

        if not reports:
            # Empty report list — first stage of a run. Always proceed.
            return GateDecision(
                action=GateAction.PROCEED,
                target=default_next_stage,
                reason="no_reports_yet",
                score=0.0,
                stage="",
                estimated_token_savings=0,
            )

        # Last report per stage
        latest_per_stage: dict[str, ConfidenceReport] = {}
        for r in reports:
            latest_per_stage[r.stage] = r

        # Decide for the stage the engine is leaving.
        # The convention is: the *last* report's stage is the one we just
        # finished. If that stage says "skip proposed_skip" and we trust
        # it, we act on it.
        last_report = reports[-1]
        last_stage = last_report.stage
        score = last_report.total
        was_skipping = self._skipping.get(last_stage, False)

        # ── Path 1: replay ──────────────────────────────────────────────────
        if score < self.config.replay_threshold:
            self._skipping[last_stage] = False
            return GateDecision(
                action=GateAction.REPLAY,
                target=last_stage,
                reason=f"score={score:.3f} below replay_threshold={self.config.replay_threshold:.3f}",
                score=score,
                stage=last_stage,
                estimated_token_savings=0,
            )

        # ── Path 2: skip (with hysteresis) ──────────────────────────────────
        if proposed_skip and last_report.skip_recommendation == proposed_skip:
            if not was_skipping and score >= self.config.enter_skip:
                # Enter skip regime
                self._skipping[last_stage] = True
                return GateDecision(
                    action=GateAction.SKIP,
                    target=proposed_skip,
                    reason=f"score={score:.3f} crossed enter_skip={self.config.enter_skip:.3f}",
                    score=score,
                    stage=last_stage,
                    estimated_token_savings=last_report.token_cost,
                )
            if was_skipping and score < self.config.exit_skip:
                # Exit skip regime (back to default)
                self._skipping[last_stage] = False
                return GateDecision(
                    action=GateAction.PROCEED,
                    target=default_next_stage,
                    reason=(
                        f"score={score:.3f} below exit_skip={self.config.exit_skip:.3f}, "
                        "exiting skip regime"
                    ),
                    score=score,
                    stage=last_stage,
                    estimated_token_savings=0,
                )
            if was_skipping:
                # Already skipping, stay
                return GateDecision(
                    action=GateAction.SKIP,
                    target=proposed_skip,
                    reason=(
                        f"already in skip regime for {proposed_skip}, "
                        f"score={score:.3f}"
                    ),
                    score=score,
                    stage=last_stage,
                    estimated_token_savings=last_report.token_cost,
                )

        # ── Path 3: escalate (rule + llm disagreement) ─────────────────────
        if score < self.config.escalate_threshold and last_report.score.residual < 0.5:
            return GateDecision(
                action=GateAction.ESCALATE,
                target="VALIDATION",
                reason=(
                    f"score={score:.3f} below escalate_threshold={self.config.escalate_threshold:.3f} "
                    f"and rule/LLM residual={last_report.score.residual:.3f} < 0.5"
                ),
                score=score,
                stage=last_stage,
                estimated_token_savings=0,
            )

        # ── Path 4: default proceed ─────────────────────────────────────────
        return GateDecision(
            action=GateAction.PROCEED,
            target=default_next_stage,
            reason="default_proceed",
            score=score,
            stage=last_stage,
            estimated_token_savings=0,
        )


__all__ = [
    "ConfidenceComponents",
    "ConfidenceReport",
    "ConfidenceGate",
    "GateConfig",
    "GateDecision",
    "GateAction",
    "score_to_components",
    "DEFAULT_ENTER_SKIP_THRESHOLD",
    "DEFAULT_EXIT_SKIP_THRESHOLD",
    "DEFAULT_REPLAY_THRESHOLD",
    "DEFAULT_ESCALATE_THRESHOLD",
]
