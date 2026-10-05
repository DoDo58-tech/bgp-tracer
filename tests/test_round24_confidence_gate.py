"""Round-24: tests for the confidence-gate skeleton (innovation point A).

These tests verify the :class:`ConfidenceGate` decision logic in
isolation. The skeleton is intentionally decoupled from
``workflow_engine.py`` so the gate can be validated before it is wired
into the state machine (Step 2 of the paper work plan).

Each test corresponds to one of the decision paths documented in
``agents/confidence_gate.py``. They all run in <50 ms and are tagged
``fast`` by ``tests/conftest.py``.
"""

from __future__ import annotations

import pytest

from agents.confidence_gate import (
    ConfidenceComponents,
    ConfidenceGate,
    ConfidenceReport,
    GateAction,
    GateConfig,
    GateDecision,
    score_to_components,
)


# ── BUG-24-1: ConfidenceComponents rejects out-of-range scores ─────────────


def test_confidence_components_rejects_out_of_range():
    """Components outside [0, 1] raise rather than silently clamping."""
    with pytest.raises(ValueError):
        ConfidenceComponents(rule_based=1.5)
    with pytest.raises(ValueError):
        ConfidenceComponents(prior=-0.01)
    with pytest.raises(ValueError):
        ConfidenceComponents(residual=2.0)


def test_confidence_components_rejects_non_numeric():
    """Non-numeric components raise TypeError immediately."""
    with pytest.raises(TypeError):
        ConfidenceComponents(rule_based="high")  # type: ignore[arg-type]


def test_confidence_components_total_is_weighted_sum():
    """Total follows the documented weights (0.45/0.30/0.15/0.10)."""
    c = ConfidenceComponents(rule_based=1.0, llm_based=1.0, prior=1.0, residual=1.0)
    assert c.total == pytest.approx(1.0)

    c2 = ConfidenceComponents(rule_based=0.0, llm_based=0.0, prior=0.0, residual=0.0)
    assert c2.total == pytest.approx(0.0)

    c3 = ConfidenceComponents(rule_based=0.5, llm_based=0.5, prior=0.5, residual=0.5)
    assert c3.total == pytest.approx(0.5)


# ── BUG-24-2: GateConfig enforces hysteresis ordering ──────────────────────


def test_gate_config_rejects_inverted_hysteresis():
    """enter_skip < exit_skip would make the gate oscillate."""
    with pytest.raises(ValueError):
        GateConfig(enter_skip=0.80, exit_skip=0.90)


def test_gate_config_accepts_equal_hysteresis():
    """enter_skip == exit_skip is allowed (no hysteresis, single threshold)."""
    cfg = GateConfig(enter_skip=0.90, exit_skip=0.90)
    assert cfg.enter_skip == cfg.exit_skip == 0.90


def test_gate_config_rejects_negative_budget():
    with pytest.raises(ValueError):
        GateConfig(token_budget_per_stage=-1)


# ── BUG-24-3: Gate defaults to disabled (no behaviour change) ─────────────


def test_gate_disabled_returns_proceed_regardless_of_reports():
    """Gate must be a no-op when ``enabled=False`` (default).

    This is the most important regression guard — the gate skeleton must
    not change any existing workflow behaviour until explicitly opted in.
    """
    cfg = GateConfig(enabled=False)
    gate = ConfidenceGate(cfg)

    # Even with a perfect score, a disabled gate proceeds.
    high_report = ConfidenceReport(
        stage="TRAFFIC_SCREENING",
        score=score_to_components(rule_based=1.0, llm_based=1.0, prior=1.0, residual=1.0),
        skip_recommendation="ROUTING_ANALYSIS",
    )
    decision = gate.decide([high_report], default_next_stage="JOINT_EVIDENCE", proposed_skip="ROUTING_ANALYSIS")
    assert decision.action == GateAction.PROCEED
    assert decision.reason == "gate_disabled"


# ── BUG-24-4: empty report list → PROCEED ──────────────────────────────────


def test_empty_reports_returns_proceed():
    """No reports yet (start of run) → PROCEED with no target change."""
    cfg = GateConfig(enabled=True, enter_skip=0.90, exit_skip=0.85)
    gate = ConfidenceGate(cfg)
    decision = gate.decide([], default_next_stage="PARSING_INPUT")
    assert decision.action == GateAction.PROCEED
    assert decision.reason == "no_reports_yet"
    assert decision.target == "PARSING_INPUT"


# ── BUG-24-5: low score → REPLAY ───────────────────────────────────────────


def test_low_score_triggers_replay():
    """Score below ``replay_threshold`` causes a REPLAY of the same stage."""
    cfg = GateConfig(
        enabled=True,
        enter_skip=0.95,
        exit_skip=0.85,
        replay_threshold=0.30,
        escalate_threshold=0.50,
    )
    gate = ConfidenceGate(cfg)
    low_report = ConfidenceReport(
        stage="REASONING",
        score=score_to_components(rule_based=0.1, llm_based=0.1, prior=0.1, residual=0.5),
    )
    decision = gate.decide([low_report], default_next_stage="VALIDATION")
    assert decision.action == GateAction.REPLAY
    assert decision.target == "REASONING"
    assert decision.stage == "REASONING"
    assert "replay_threshold" in decision.reason


# ── BUG-24-6: high score + skip recommendation → SKIP (with hysteresis) ────


def test_high_score_with_skip_recommendation_triggers_skip():
    cfg = GateConfig(
        enabled=True,
        enter_skip=0.90,
        exit_skip=0.85,
        replay_threshold=0.30,
        escalate_threshold=0.50,
    )
    gate = ConfidenceGate(cfg)
    report = ConfidenceReport(
        stage="TRAFFIC_SCREENING",
        score=score_to_components(rule_based=1.0, llm_based=1.0, prior=1.0, residual=1.0),
        skip_recommendation="ROUTING_ANALYSIS",
        token_cost=1234,
    )
    decision = gate.decide(
        [report],
        default_next_stage="TRAFFIC_ANALYSIS",
        proposed_skip="ROUTING_ANALYSIS",
    )
    assert decision.action == GateAction.SKIP
    assert decision.target == "ROUTING_ANALYSIS"
    assert decision.estimated_token_savings == 1234
    assert "enter_skip" in decision.reason


def test_hysteresis_keeps_skip_regime_active_across_calls():
    """Once in skip regime, subsequent calls stay in skip even if score dips
    between enter and exit thresholds."""
    cfg = GateConfig(
        enabled=True,
        enter_skip=0.90,
        exit_skip=0.85,
        replay_threshold=0.30,
        escalate_threshold=0.50,
    )
    gate = ConfidenceGate(cfg)

    # First call: enter skip regime (score=0.95)
    r1 = ConfidenceReport(
        stage="TRAFFIC_SCREENING",
        score=score_to_components(rule_based=1.0, llm_based=0.95, prior=1.0, residual=1.0),
        skip_recommendation="ROUTING_ANALYSIS",
        token_cost=500,
    )
    d1 = gate.decide([r1], default_next_stage="TRAFFIC_ANALYSIS", proposed_skip="ROUTING_ANALYSIS")
    assert d1.action == GateAction.SKIP

    # Second call: score=0.88 (between exit 0.85 and enter 0.90) → still skip
    r2 = ConfidenceReport(
        stage="TRAFFIC_SCREENING",
        score=score_to_components(rule_based=1.0, llm_based=0.6, prior=1.0, residual=1.0),
        skip_recommendation="ROUTING_ANALYSIS",
        token_cost=500,
    )
    d2 = gate.decide([r1, r2], default_next_stage="TRAFFIC_ANALYSIS", proposed_skip="ROUTING_ANALYSIS")
    assert d2.action == GateAction.SKIP, (
        "Score between enter and exit must not exit the skip regime"
    )
    assert "already in skip regime" in d2.reason


def test_hysteresis_exits_when_score_drops_below_exit_threshold():
    cfg = GateConfig(
        enabled=True,
        enter_skip=0.90,
        exit_skip=0.85,
        replay_threshold=0.30,
        escalate_threshold=0.50,
    )
    gate = ConfidenceGate(cfg)

    r1 = ConfidenceReport(
        stage="TRAFFIC_SCREENING",
        score=score_to_components(rule_based=1.0, llm_based=0.95, prior=1.0, residual=1.0),
        skip_recommendation="ROUTING_ANALYSIS",
    )
    gate.decide([r1], default_next_stage="TRAFFIC_ANALYSIS", proposed_skip="ROUTING_ANALYSIS")

    # Second report: score=0.50 (below exit_skip 0.85)
    r2 = ConfidenceReport(
        stage="TRAFFIC_SCREENING",
        score=score_to_components(rule_based=0.5, llm_based=0.5, prior=0.5, residual=0.5),
        skip_recommendation="ROUTING_ANALYSIS",
    )
    d2 = gate.decide([r1, r2], default_next_stage="TRAFFIC_ANALYSIS", proposed_skip="ROUTING_ANALYSIS")
    assert d2.action == GateAction.PROCEED
    assert "exiting skip regime" in d2.reason


# ── BUG-24-7: rule + llm disagreement → ESCALATE ───────────────────────────


def test_rule_llm_disagreement_triggers_escalate():
    """When score is moderate but rule/LLM disagree, escalate to VALIDATION."""
    cfg = GateConfig(
        enabled=True,
        enter_skip=0.95,
        exit_skip=0.85,
        replay_threshold=0.30,
        escalate_threshold=0.70,
    )
    gate = ConfidenceGate(cfg)
    report = ConfidenceReport(
        stage="JOINT_EVIDENCE",
        # Score lands between escalate (0.70) and replay (0.30)
        score=score_to_components(rule_based=0.9, llm_based=0.2, prior=0.5, residual=0.4),
    )
    decision = gate.decide([report], default_next_stage="REASONING")
    assert decision.action == GateAction.ESCALATE
    assert decision.target == "VALIDATION"


# ── BUG-24-8: default path returns PROCEED with stage metadata ──────────────


def test_default_path_returns_proceed_with_stage_metadata():
    cfg = GateConfig(enabled=True, enter_skip=0.95, exit_skip=0.85)
    gate = ConfidenceGate(cfg)
    report = ConfidenceReport(
        stage="REASONING",
        score=score_to_components(rule_based=0.6, llm_based=0.6, prior=0.5, residual=0.7),
    )
    decision = gate.decide([report], default_next_stage="VALIDATION")
    assert decision.action == GateAction.PROCEED
    assert decision.target == "VALIDATION"
    assert decision.stage == "REASONING"
    assert decision.score == pytest.approx(report.total)


# ── BUG-24-9: GateDecision is JSON-safe via to_dict ─────────────────────────


def test_gate_decision_is_json_safe():
    import json

    decision = GateDecision(
        action=GateAction.SKIP,
        target="ROUTING_ANALYSIS",
        reason="test",
        score=0.95,
        stage="TRAFFIC_SCREENING",
        estimated_token_savings=500,
    )
    # Round-trip through JSON without TypeError.
    serialised = json.dumps(decision.to_dict())
    deserialised = json.loads(serialised)
    assert deserialised["action"] == "skip"
    assert deserialised["target"] == "ROUTING_ANALYSIS"


def test_confidence_report_is_json_safe():
    import json

    report = ConfidenceReport(
        stage="TRAFFIC_SCREENING",
        score=score_to_components(rule_based=0.9, llm_based=0.8),
        skip_recommendation="ROUTING_ANALYSIS",
        reason="no events",
        token_cost=100,
        extras={"timestamp": "2026-10-01T00:00:00Z"},
    )
    serialised = json.dumps(report.to_dict())
    deserialised = json.loads(serialised)
    assert deserialised["stage"] == "TRAFFIC_SCREENING"
    assert deserialised["total"] == pytest.approx(report.total)
    assert deserialised["score"]["rule_based"] == pytest.approx(0.9)


# ── BUG-24-10: reset() clears per-run hysteresis state ──────────────────────


def test_reset_clears_skip_regime():
    """After reset(), the gate should treat a new run as cold-started."""
    cfg = GateConfig(enabled=True, enter_skip=0.90, exit_skip=0.85)
    gate = ConfidenceGate(cfg)
    r1 = ConfidenceReport(
        stage="TRAFFIC_SCREENING",
        score=score_to_components(rule_based=1.0, llm_based=1.0, prior=1.0, residual=1.0),
        skip_recommendation="ROUTING_ANALYSIS",
    )
    gate.decide([r1], default_next_stage="TRAFFIC_ANALYSIS", proposed_skip="ROUTING_ANALYSIS")

    gate.reset()
    # Without reset, an immediate second call with the same report would
    # return "already in skip regime". After reset, the gate is cold and
    # sees the report as the first call of a new run.
    decision = gate.decide([r1], default_next_stage="TRAFFIC_ANALYSIS", proposed_skip="ROUTING_ANALYSIS")
    assert decision.action == GateAction.SKIP
    assert "enter_skip" in decision.reason, (
        "After reset(), gate must enter the skip regime fresh (not 'already in skip')"
    )
