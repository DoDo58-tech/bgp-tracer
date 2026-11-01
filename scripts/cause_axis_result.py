"""The cause-axis result on the 39-event corpus, with its statistics.

This is the script that produces the numbers the paper's agent section
reports.  It reads the two arms' ground-truth runs, scores the metric
family, runs the paired tests, and reports the ablation-consistency
checks that say whether the metric moves when the component it
measures is removed.

The paired test is McNemar's exact two-sided test on the events where
the two arms disagree, which is the appropriate test for paired
per-event outcomes.  The bootstrap interval is over the corpus, and it
is reported so that the size of the effect can be read against its
uncertainty rather than as a bare count.

Writes results/eval/cause_axis_result.json.
"""

from __future__ import annotations

import json
from math import comb
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVAL = PROJECT_ROOT / "results" / "eval"
OUT_PATH = EVAL / "cause_axis_result.json"

CLASSES = ("outage", "route_leak", "origin_hijack_victim")


def load(name: str):
    return {
        r["event_id"]: r
        for r in json.loads((EVAL / f"{name}.json").read_text())["records"]
    }


def mcnemar_exact(b: int, c: int):
    """Two-sided exact p for the discordant pairs."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(comb(n, i) for i in range(0, k + 1)) / (2 ** n)
    return min(1.0, 2 * tail)


def wilson(k: int, n: int, z: float = 1.96):
    if n == 0:
        return (None, None)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    margin = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / denom
    return (round(max(0.0, centre - margin), 4), round(min(1.0, centre + margin), 4))


def bootstrap_ci(rows, predict, n_boot: int = 2000, seed: int = 20240117):
    import random

    rng = random.Random(seed)
    keys = list(rows)
    accs = []
    for _ in range(n_boot):
        sample = [keys[rng.randrange(len(keys))] for _ in range(len(keys))]
        accs.append(
            sum(1 for k in sample if predict(rows[k]) == rows[k].get("gt_cause"))
            / len(sample)
        )
    accs.sort()
    return [
        round(accs[int(0.025 * (n_boot - 1))], 4),
        round(accs[int(0.975 * (n_boot - 1))], 4),
    ]


def metric_family(rows: dict, predict):
    per_class = {c: {"n": 0, "correct": 0} for c in CLASSES}
    answered = 0
    correct = 0
    for rec in rows.values():
        gt = rec.get("gt_cause")
        pred = predict(rec)
        slot = per_class.setdefault(gt, {"n": 0, "correct": 0})
        slot["n"] += 1
        if pred in CLASSES:
            answered += 1
            if pred == gt:
                correct += 1
                slot["correct"] += 1
    n = len(rows)
    recalls = [
        per_class[c]["correct"] / per_class[c]["n"]
        for c in CLASSES if per_class[c]["n"]
    ]
    return {
        "n": n,
        "answered": answered,
        "coverage": round(answered / n, 4) if n else None,
        "correct": correct,
        "micro_accuracy": round(correct / n, 4) if n else None,
        "wilson95": wilson(correct, n),
        "balanced_accuracy": round(sum(recalls) / len(recalls), 4) if recalls else None,
        "conditional_accuracy": round(correct / answered, 4) if answered else None,
        "per_class": {
            c: {
                "n": slot["n"],
                "correct": slot["correct"],
                "recall": round(slot["correct"] / slot["n"], 4) if slot["n"] else None,
                "wilson95": wilson(slot["correct"], slot["n"]),
            }
            for c, slot in per_class.items()
        },
    }


def main():
    agent = load("gt_agent_full_v2")
    rules = load("gt_rule_only_v2")

    agent_pred = lambda r: r.get("cause")
    rule_pred = lambda r: r.get("cause")

    a = metric_family(agent, agent_pred)
    ru = metric_family(rules, rule_pred)

    # Paired comparison on the events where the arms disagree.
    b = 0
    c = 0
    disagreements = []
    for eid, rec in agent.items():
        gt = rec.get("gt_cause")
        agent_ok = rec.get("cause") == gt
        rule_ok = rules[eid].get("cause") == gt
        if agent_ok and not rule_ok:
            b += 1
            disagreements.append({
                "event_id": eid, "gt": gt,
                "agent": rec.get("cause"), "rule": rules[eid].get("cause"),
                "winner": "agent",
            })
        elif rule_ok and not agent_ok:
            c += 1
            disagreements.append({
                "event_id": eid, "gt": gt,
                "agent": rec.get("cause"), "rule": rules[eid].get("cause"),
                "winner": "rule",
            })

    p_value = mcnemar_exact(b, c)

    # Bootstrap of the difference between the arms.
    import random

    rng = random.Random(20240117)
    keys = list(agent)
    deltas = []
    for _ in range(2000):
        sample = [keys[rng.randrange(len(keys))] for _ in range(len(keys))]
        acc_a = sum(
            1 for k in sample if agent[k].get("cause") == agent[k].get("gt_cause")
        ) / len(sample)
        acc_r = sum(
            1 for k in sample if rules[k].get("cause") == rules[k].get("gt_cause")
        ) / len(sample)
        deltas.append(acc_a - acc_r)
    deltas.sort()
    delta_ci = [
        round(deltas[int(0.025 * (len(deltas) - 1))], 4),
        round(deltas[int(0.975 * (len(deltas) - 1))], 4),
    ]

    # The subset where the agent and the rules disagree, scored on its
    # own: this is the evidence for the arbitration layer's marginal
    # contribution and it is reported separately because a subset's
    # accuracy is not the corpus's accuracy.
    disagree_ids = [d["event_id"] for d in disagreements]
    subset = {k: agent[k] for k in disagree_ids}
    subset_rules = {k: rules[k] for k in disagree_ids}

    out = {
        "corpus": {"n": len(agent)},
        "agent": a,
        "rules_only": ru,
        "paired_comparison": {
            "n_disagreements": len(disagreements),
            "agent_only_correct": b,
            "rules_only_correct": c,
            "mcnemar_exact_p": round(p_value, 4),
            "bootstrap_delta_ci95": delta_ci,
            "disagreements": disagreements,
        },
        "disagreement_subset": {
            "n": len(disagree_ids),
            "agent": metric_family(subset, agent_pred),
            "rules_only": metric_family(subset_rules, rule_pred),
        },
    }

    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    print(f"{'arm':22s} {'correct':>9s} {'micro':>7s} {'wilson95':>18s} "
          f"{'bal':>7s} {'cov':>7s}")
    for name, slot in (("agent", a), ("rules_only", ru)):
        print(f"{name:22s} {slot['correct']:>4d}/{slot['n']:<4d} "
              f"{slot['micro_accuracy']:>7} "
              f"[{slot['wilson95'][0]:.3f},{slot['wilson95'][1]:.3f}] "
              f"{slot['balanced_accuracy']:>7} {slot['coverage']:>7}")
        print(f"{'  per-class recall':22s} "
              f"{ {c: v['recall'] for c, v in slot['per_class'].items()} }")
    print()
    pc = out["paired_comparison"]
    print(f"disagreements: {pc['n_disagreements']}  "
          f"agent-only correct {pc['agent_only_correct']}  "
          f"rules-only correct {pc['rules_only_correct']}")
    print(f"McNemar exact p = {pc['mcnemar_exact_p']}   "
          f"bootstrap delta CI95 {pc['bootstrap_delta_ci95']}")
    print()
    ds = out["disagreement_subset"]
    print(f"on the {ds['n']} disagreement events: "
          f"agent {ds['agent']['correct']}/{ds['n']} "
          f"({ds['agent']['micro_accuracy']}), "
          f"rules {ds['rules_only']['correct']}/{ds['n']} "
          f"({ds['rules_only']['micro_accuracy']})")
    print()
    for d in disagreements:
        print(f"  {d['winner']:5s} {d['event_id']:42s} gt={d['gt']:20s} "
              f"agent={str(d['agent']):20s} rule={str(d['rule'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
