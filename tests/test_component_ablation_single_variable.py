"""The component ablation must stay single-variable.

Each arm of the ablation disables exactly one coordination stage, so
the delta against the full agent is attributable to that stage alone.
That property breaks whenever one stage's output is the *gate* for
another: disabling the gate also disables whatever it gates, and the
measured delta then belongs to two stages rather than one.

The joint-evidence tier is the gate for the reasoning stage.  Ablating
the joint evidence stage drops the tier to INSUFFICIENT, which used to
short-circuit the reasoning stage with it -- so the "no joint
evidence" arm measured the loss of *both* stages, and the "no
reasoning" arm was the only arm that measured reasoning alone.

These tests pin the property on the gate itself.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


class _FakeContext:
    """The parts of the workflow context the gate reads."""

    def __init__(self, **kwargs):
        self.anomalies_detected = False
        self.joint_tier = "INSUFFICIENT"
        self.joint_score = 0.0
        self.paddle_attribution = {}
        self.validation_notes = []
        for key, value in kwargs.items():
            setattr(self, key, value)


def make_engine():
    """A workflow engine with the ablation switches under test.

    The engine is built without running anything: the gate is a plain
    method, and constructing the engine does not touch the network.
    """
    from workflow_engine import WorkflowEngine
    return WorkflowEngine()


def test_joint_evidence_ablation_does_not_short_circuit_reasoning():
    """The whole point of the fix.

    With the joint evidence stage ablated, the tier is INSUFFICIENT and
    the score is 0.  The gate must not use either of them to skip the
    reasoning stage, because the tier is an *output* of the stage that
    was ablated -- using it would be using a stage's own absence as
    evidence against the next stage.
    """
    engine = make_engine()
    engine.ablate["joint_evidence"] = True
    engine.skip_unnecessary_analysis = True

    context = _FakeContext(
        joint_tier="INSUFFICIENT",
        joint_score=0.0,
    )

    assert engine.should_skip_reasoning(context) is False, (
        "ablation of the joint evidence stage short-circuited the "
        "reasoning stage with it -- the arm is no longer single-variable"
    )

    # The decision has to be recorded, so a run can be audited after
    # the fact rather than inferred from the absence of a note.
    cases = [n.get("case") for n in context.validation_notes]
    assert "reasoning_not_skipped" in cases, (
        "the reasoning stage proceeded but nothing recorded why, so the "
        "single-variable property cannot be verified from the run")


def test_joint_evidence_ablation_keeps_reasoning_even_without_anomalies():
    """The ablated arm must still do the work of the other stages.

    An event with no explicit anomalies is exactly the case where the
    gate would fire, so it is the case worth pinning.
    """
    engine = make_engine()
    engine.ablate["joint_evidence"] = True
    engine.skip_unnecessary_analysis = True

    context = _FakeContext(anomalies_detected=False)
    assert engine.should_skip_reasoning(context) is False


def test_the_gate_still_fires_for_a_normal_run():
    """The fix must not disable the gate itself.

    Without an ablation, a run with no anomalies and a tier below the
    threshold still skips reasoning.  That is the gate doing its job,
    and it is what makes the reasoning ablation arm comparable.
    """
    engine = make_engine()
    engine.ablate["joint_evidence"] = False
    engine.skip_unnecessary_analysis = True

    context = _FakeContext(
        anomalies_detected=False,
        joint_tier="INSUFFICIENT",
        joint_score=0.0,
    )

    assert engine.should_skip_reasoning(context) is True, (
        "the skip-reasoning gate stopped firing outside ablation runs; "
        "the reasoning arm would no longer be comparable to the others"
    )


def test_the_baseline_arm_suspends_the_gate_too():
    """The single-variable property belongs to the comparison.

    The "full" arm has nothing ablated, so on its own it would keep
    the cost gate and could skip reasoning on a no-anomaly event while
    an ablated arm -- which cannot use the joint tier to reach that
    decision -- does not.  The delta would then belong to the stage
    under test *and* to the gate.

    So the campaign switch suspends the gate for every arm, the
    baseline included.
    """
    from agents.ablation_switches import (
        ABLATION_CAMPAIGN_ENV_VAR,
        reset_ablation_switches,
    )
    try:
        reset_ablation_switches()
        engine = make_engine()
        engine.ablate["joint_evidence"] = False
        engine.skip_unnecessary_analysis = True

        context = _FakeContext(
            anomalies_detected=False,
            joint_tier="INSUFFICIENT",
            joint_score=0.0,
        )

        # Without the campaign switch the gate fires (as above).
        assert engine.should_skip_reasoning(context) is True

        # With it, the baseline runs reasoning like every other arm.
        os.environ[ABLATION_CAMPAIGN_ENV_VAR] = "1"
        context2 = _FakeContext(
            anomalies_detected=False,
            joint_tier="INSUFFICIENT",
            joint_score=0.0,
        )
        assert engine.should_skip_reasoning(context2) is False, (
            "the baseline arm skipped reasoning while an ablated arm did "
            "not; the delta now measures the gate as well as the stage"
        )
    finally:
        reset_ablation_switches()


def test_the_gate_still_fires_for_a_strong_tier_run():
    """A strong joint tier lets reasoning through, as before."""
    engine = make_engine()
    engine.ablate["joint_evidence"] = False
    engine.skip_unnecessary_analysis = True

    context = _FakeContext(
        anomalies_detected=False,
        joint_tier="C3",
        joint_score=0.9,
    )

    assert engine.should_skip_reasoning(context) is False


def test_each_ablation_switch_is_read_independently():
    """No ablation switch may imply another.

    The arms are compared against each other, so a switch that turned
    two stages off would make every comparison involving it wrong.
    """
    engine = make_engine()
    assert not any(engine.ablate.values()), (
        "the engine came up with an ablation already active")

    for stage in engine.ablate:
        engine.ablate[stage] = True
        others = [s for s in engine.ablate if s != stage and engine.ablate[s]]
        assert not others, (
            f"setting the {stage} switch also set {others}")
        engine.ablate[stage] = False


# ── The harness's own check ───────────────────────────────────────────


def test_harness_flags_an_arm_that_dropped_a_second_stage():
    """The check must catch the exact failure this fix prevents.

    A "no joint evidence" arm in which reasoning also did not run is
    the multi-variable case, and the harness has to report it rather
    than score it as a large delta for joint evidence.
    """
    from scripts.component_ablation_gt import check_single_variable

    records = [{
        "stage": "no_joint_evidence",
        "event_id": "ev-1",
        "stage_execution": {
            "joint_evidence": {"ran": False},
            "reasoning": {"ran": False},
            "paddle": {"ran": True},
            "hypothesis": {"ran": True},
        },
    }]
    result = check_single_variable(records)
    assert result["ok"] is False
    assert result["n_violations"] >= 1
    assert any("reasoning" in v for v in result["violations"])


def test_harness_accepts_a_clean_single_variable_arm():
    """A clean arm must pass the check."""
    from scripts.component_ablation_gt import check_single_variable

    records = [{
        "stage": "no_joint_evidence",
        "event_id": "ev-1",
        "stage_execution": {
            "joint_evidence": {"ran": False},
            "reasoning": {"ran": True},
            "paddle": {"ran": True},
            "hypothesis": {"ran": True},
        },
    }]
    result = check_single_variable(records)
    assert result["ok"] is True, result["violations"]
    assert result["checked"] == 1


def test_harness_flags_an_ablated_stage_that_actually_ran():
    """The switch must reach the stage, not just the engine's intent.

    If a stage recomputed its work inside a tool or a sub-agent, the
    engine would believe it was off while the run did the work anyway.
    The stage record is what exposes that.
    """
    from scripts.component_ablation_gt import check_single_variable

    records = [{
        "stage": "no_joint_evidence",
        "event_id": "ev-1",
        "stage_execution": {
            "joint_evidence": {"ran": True},
            "reasoning": {"ran": True},
        },
    }]
    result = check_single_variable(records)
    assert result["ok"] is False
    assert any("joint_evidence" in v for v in result["violations"])


# ── The shared switch module ──────────────────────────────────────────


def test_reset_clears_every_switch():
    """The harness runs the arms in one process.

    A switch left set by one arm would leak into the next and the arms
    would stop being comparable, so the reset has to reach every
    variable the module knows about.
    """
    from agents.ablation_switches import (
        ABLATION_CAMPAIGN_ENV_VAR,
        ABLATION_ENV_VARS,
        ablation_campaign_active,
        ablation_switches,
        reset_ablation_switches,
    )
    try:
        for var in ABLATION_ENV_VARS.values():
            os.environ[var] = "1"
        os.environ[ABLATION_CAMPAIGN_ENV_VAR] = "1"
        assert all(ablation_switches().values())
        assert ablation_campaign_active() is True

        reset_ablation_switches()
        assert not any(ablation_switches().values()), (
            "reset left an ablation switch set; the next arm would start "
            "with a stage already disabled")
        assert ablation_campaign_active() is False, (
            "reset left the campaign switch set; the next run outside the "
            "ablation would still have its cost gate suspended")
    finally:
        reset_ablation_switches()


def test_switches_are_read_fresh_not_cached_at_import():
    """The harness flips a switch around a single run.

    A switch read once at import time would never be seen, and the arm
    would measure nothing.
    """
    from agents.ablation_switches import (
        ABLATION_ENV_VARS,
        ablation_switches,
        reset_ablation_switches,
    )
    try:
        reset_ablation_switches()
        assert ablation_switches()["joint_evidence"] is False

        os.environ[ABLATION_ENV_VARS["joint_evidence"]] = "1"
        assert ablation_switches()["joint_evidence"] is True

        os.environ[ABLATION_ENV_VARS["joint_evidence"]] = "0"
        assert ablation_switches()["joint_evidence"] is False
    finally:
        reset_ablation_switches()


# ── End-to-end: the reasoning stage must actually execute ─────────────


def test_reasoning_stage_really_runs_when_joint_evidence_is_ablated(monkeypatch):
    """The gate returning False is necessary but not sufficient.

    The failure mode this fixes was a *short-circuit*: the reasoning
    stage never ran.  So the test has to drive the stage itself and
    observe the reasoning agent being called, rather than only checking
    the gate's return value.
    """
    import asyncio

    from workflow_engine import WorkflowContext, WorkflowEngine

    calls: list[dict] = []

    def fake_run_reasoning_agent(**kwargs):
        calls.append(kwargs)
        return {"success": True, "skipped": False, "rounds_performed": 2}

    class _FakeHypothesisAgent:
        def __init__(self, bb):
            self.bb = bb

        async def start(self):
            return None

        async def step(self):
            return {"claims": []}

    import agents.reasoning_agent as reasoning_module
    import agents.hypothesis_manager as hypothesis_module

    monkeypatch.setattr(reasoning_module, "run_reasoning_agent",
                        fake_run_reasoning_agent)
    monkeypatch.setattr(hypothesis_module, "HypothesisAgent", _FakeHypothesisAgent)

    engine = WorkflowEngine()
    engine.ablate["joint_evidence"] = True
    engine.skip_unnecessary_analysis = True

    context = WorkflowContext(
        asn="65001",
        start_time="2025-05-16T16:00:00",
        end_time="2025-05-16T23:59:00",
    )
    context.anomalies_detected = False
    context.joint_tier = "INSUFFICIENT"
    context.joint_score = 0.0

    asyncio.run(engine.handle_reasoning(context))

    assert calls, (
        "the reasoning agent was never called: ablating joint evidence "
        "still short-circuited the reasoning stage"
    )
    assert context.reasoning_result.get("skipped") is not True
    assert context.stage_execution.get("reasoning", {}).get("ran") is True, (
        "the run's own stage record does not show reasoning as having run")


def test_the_harness_puts_every_arm_in_the_same_campaign(monkeypatch, tmp_path):
    """The harness must suspend the cost gate for the baseline too.

    This is checked by running the harness's own cell runner for the
    "full" arm with the pipeline stubbed out, and observing what the
    environment looked like when the pipeline was entered.
    """
    import scripts.component_ablation_gt as harness

    from agents.ablation_switches import (
        ablation_campaign_active,
        ablation_switches,
        reset_ablation_switches,
    )

    seen: dict = {}

    def fake_run_one(quick):
        seen["campaign"] = ablation_campaign_active()
        seen["switches"] = dict(ablation_switches())
        return {"success": True, "cause": "outage", "cause_raw": "outage"}

    cache_file = tmp_path / "quick.json"
    cache_file.write_text("{}")

    class _Match:
        path = cache_file

    monkeypatch.setattr(harness, "resolve_cache", lambda *a, **k: _Match())
    monkeypatch.setattr(harness, "run_one", fake_run_one)

    try:
        reset_ablation_switches()
        ev = {"asn": "65001", "start": "a", "end": "b",
              "event_id": "ev-1", "gt_cause": "outage"}

        harness.run_cell("full", ev)
        assert seen.get("campaign") is True, (
            "the baseline arm ran outside the ablation campaign, so its "
            "cost gate was live while the ablated arms' was not")
        assert not any(seen.get("switches", {}).values()), (
            "the baseline arm had a stage ablated")

        harness.run_cell("no_joint_evidence", ev)
        assert seen.get("campaign") is True
        assert seen.get("switches", {}).get("joint_evidence") is True, (
            "the no_joint_evidence arm did not have joint evidence ablated")
        others = [k for k, v in seen.get("switches", {}).items()
                  if v and k != "joint_evidence"]
        assert not others, f"the arm also ablated {others}"
    finally:
        reset_ablation_switches()
