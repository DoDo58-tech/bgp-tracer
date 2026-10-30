"""Tests for the component-ablation scoring rule.

The ablation asks each arm to answer every event in the corpus.  A run
that failed on an event therefore has to be scored as a wrong answer: if
the failures were dropped from the denominator, an arm could raise its
accuracy by crashing on the events it could not handle, which is the
opposite of what the ablation is supposed to measure.

These tests pin that rule on the scorer itself, and on the aggregate that
the paper's ablation table is printed from.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, PROJECT_ROOT / relative)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_failed_run_counts_against_the_arm():
    mod = load_module("component_ablation_gt", "scripts/component_ablation_gt.py")
    records = [
        {"stage": "full", "event_id": "a", "gt_cause": "outage",
         "resolved": True, "success": True, "cause": "outage"},
        {"stage": "full", "event_id": "b", "gt_cause": "outage",
         "resolved": True, "success": True, "cause": "route_leak"},
        {"stage": "full", "event_id": "c", "gt_cause": "outage",
         "resolved": True, "success": False, "cause": None},
    ]
    scored = mod.score(records)
    assert scored["n_scored"] == 3
    assert scored["n_ran"] == 2
    assert scored["n_failed"] == 1
    # One correct answer out of three scored events, not one out of two.
    assert scored["accuracy"] == round(1 / 3, 4)
    assert scored["n_correct"] == 1


def test_unresolved_events_stay_out_of_the_denominator():
    mod = load_module("component_ablation_gt", "scripts/component_ablation_gt.py")
    records = [
        {"stage": "full", "event_id": "a", "gt_cause": "outage",
         "resolved": True, "success": True, "cause": "outage"},
        {"stage": "full", "event_id": "z", "gt_cause": "outage",
         "resolved": False, "success": False, "cause": None},
    ]
    scored = mod.score(records)
    assert scored["n_scored"] == 1
    assert scored["accuracy"] == 1.0


def test_aggregator_uses_the_same_denominator():
    mod = load_module(
        "aggregate_component_ablation", "scripts/aggregate_component_ablation.py")
    runs = [{
        "repeat": 0,
        "stage": "full",
        "records": [
            {"event_id": "a", "gt_cause": "outage", "resolved": True,
             "success": True, "cause": "outage"},
            {"event_id": "b", "gt_cause": "outage", "resolved": True,
             "success": False, "cause": None},
        ],
    }]
    table = mod.per_run_stats(runs)
    slot = table["full"][0]
    assert slot["n_scored"] == 2
    assert slot["n_ran"] == 1
    assert slot["accuracy"] == 0.5


def test_paper_ablation_table_matches_the_summary():
    """Every accuracy the paper prints must be the summary's value."""
    summary_path = (
        PROJECT_ROOT / "results" / "eval" / "component_ablation_summary.json")
    if not summary_path.exists():
        return
    summary = json.loads(summary_path.read_text())
    tex = (PROJECT_ROOT / "docs" / "paper" / "appendix.tex").read_text()
    labels = {
        "no_joint_evidence": "Joint evidence",
        "no_hcaf": "HCAF attribution",
        "no_hypothesis": "Hypothesis generation",
        "no_reasoning": "Multi-round reasoning",
        "no_evidence_board": "Evidence Blackboard",
        "no_enrichment": "External enrichment",
    }
    for stage, label in labels.items():
        mean = summary["summary"][stage]["accuracy_across_runs"]["mean"]
        printed = f"{mean:.3f}"
        rows = [ln for ln in tex.splitlines()
                if ln.strip().startswith(label + " ") and "&" in ln]
        assert rows, f"{label} row missing from the paper"
        assert printed in rows[0], (
            f"{label}: paper prints something other than {printed}")
