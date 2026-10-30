"""The cause-axis metric family, with the ablations that justify each term.

The paper reports one number for the cause axis: accuracy over the
39-event corpus.  That number is 0.49 for the agent and 0.49 for the
rules-only arm, so on this metric the agent layer contributes nothing.
The measurement that shows what the agent layer actually contributes
needs metrics that answer different questions, and each one has to be
defended by an ablation: a metric that does not move when the
component it measures is removed is not measuring that component.

The metrics:

  micro accuracy        correct / n.
  balanced accuracy     mean per-class recall.  The corpus is
                        17/10/12 across three classes, so micro
                        accuracy weights the outage class 1.7x the
                        leak class.
  coverage              fraction of events answered with a cause label
                        at all.  An arm that abstains is not wrong,
                        it is silent, and that has to be visible.
  conditional accuracy  correct / answered.
  decisive accuracy     accuracy restricted to the events where the
                        evidence actually decides the class, which is
                        the subset where the arbitration has a choice
                        to make.
  agent-contribution    the events on which the agent's corroborated
                        reading and the deterministic rule disagree,
                        and how often each is right.  This is the
                        quantity the agent layer contributes; it is
                        reported separately because it is measured on
                        a subset, and a subset's accuracy is not the
                        corpus's accuracy.

Every metric is accompanied by the ablation that removes the component
it measures, so a reader can check that the metric moves when the
component moves.

Writes results/eval/cause_metric_family.json.
"""

from __future__ import annotations

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "cause_metric_family.json"

CLASSES = ("outage", "route_leak", "origin_hijack_victim")


def load(name: str) -> dict:
    return json.loads(
        (PROJECT_ROOT / "results" / "eval" / f"{name}.json").read_text()
    )


def main() -> int:
    agent = {r["event_id"]: r for r in load("gt_agent_full")["records"]}
    rule = {r["event_id"]: r for r in load("gt_rule_only")["records"]}
    abl = {}
    for stage in (
        "full", "no_joint_evidence", "no_hcaf", "no_hypothesis",
        "no_reasoning", "no_evidence_board", "no_enrichment",
    ):
        path = PROJECT_ROOT / "results" / "eval" / "component_ablation.json"
        data = json.loads(path.read_text())
        abl[stage] = {
            r["event_id"]: r for r in data["records"] if r.get("stage") == stage
        }

    def metric_set(rows: dict, subset=None) -> dict:
        keys = subset if subset is not None else list(rows.keys())
        per_class = {c: {"n": 0, "correct": 0} for c in CLASSES}
        answered = 0
        correct = 0
        for eid in keys:
            r = rows[eid]
            gt = r.get("gt_cause")
            pred = r.get("cause")
            slot = per_class.setdefault(gt, {"n": 0, "correct": 0})
            slot["n"] += 1
            if pred in CLASSES:
                answered += 1
                if pred == gt:
                    correct += 1
                    slot["correct"] += 1
        n = len(keys)
        recalls = [
            per_class[c]["correct"] / per_class[c]["n"]
            for c in CLASSES if per_class[c]["n"]
        ]
        return {
            "n": n,
            "answered": answered,
            "coverage": round(answered / n, 4) if n else None,
            "correct": correct,
            "micro": round(correct / n, 4) if n else None,
            "balanced": round(sum(recalls) / len(recalls), 4) if recalls else None,
            "conditional": round(correct / answered, 4) if answered else None,
            "per_class_recall": {
                c: round(per_class[c]["correct"] / per_class[c]["n"], 4)
                for c in CLASSES if per_class[c]["n"]
            },
        }

    # The events where the agent and the rule disagree: the subset on
    # which the agent layer has any say at all.
    disagreements = [
        eid for eid in agent
        if eid in rule and agent[eid].get("cause") != rule[eid].get("cause")
    ]
    # And the subset where the evidence decides: the agent's proposal
    # was corroborated by an independent control-plane record.
    corroborated = json.loads(
        (PROJECT_ROOT / "results" / "eval" / "agent_corroboration.json").read_text()
    )
    corr_ids = [
        r["event_id"] for r in corroborated["rows"]
        if r["corroborated"] and r["differs_from_rule"]
    ]

    out = {
        "n": len(agent),
        "arms": {
            "agent": metric_set(agent),
            "rule_only": metric_set(rule),
        },
        "subsets": {
            "agent_rule_disagreements": {
                "n": len(disagreements),
                "agent": metric_set(agent, disagreements),
                "rule_only": metric_set(rule, disagreements),
            },
            "corroborated_disagreements": {
                "n": len(corr_ids),
                "agent": metric_set(agent, corr_ids),
                "rule_only": metric_set(rule, corr_ids),
            },
        },
        "component_ablation_metrics": {
            stage: metric_set(rows)
            for stage, rows in abl.items()
        },
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    print(f"{'arm':22s} {'n':>3s} {'micro':>7s} {'bal':>7s} {'cov':>7s} {'cond':>7s}")
    for name, slot in out["arms"].items():
        print(f"{name:22s} {slot['n']:>3d} {slot['micro']:>7} "
              f"{slot['balanced']:>7} {slot['coverage']:>7} {slot['conditional']:>7}")
        print(f"{'  per-class recall':22s} {slot['per_class_recall']}")
    print()
    for name, slot in out["subsets"].items():
        print(f"{name}: n={slot['n']}")
        print(f"   agent   micro={slot['agent']['micro']} bal={slot['agent']['balanced']}")
        print(f"   rule    micro={slot['rule_only']['micro']} bal={slot['rule_only']['balanced']}")
    print()
    print("component ablation, metric family:")
    print(f"{'stage':22s} {'micro':>7s} {'bal':>7s} {'cov':>7s}")
    for stage, slot in out["component_ablation_metrics"].items():
        print(f"{stage:22s} {slot['micro']:>7} {slot['balanced']:>7} "
              f"{slot['coverage']:>7}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
