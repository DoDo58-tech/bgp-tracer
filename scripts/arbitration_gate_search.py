"""Search the arbitration gate space with leave-one-out validation.

The corroboration gate improves the cause axis from 19/39 to 22/39 on
the 39-event corpus.  That number is in-sample, so this script
searches a wider gate space and reports, for every candidate, the
leave-one-out estimate as well, and only recommends a candidate whose
cross-validated accuracy beats the incumbent's.

The space is described declaratively.  Each gate is a conjunction of
conditions over the physical features:

  ``corroborated``      the agent's proposal is backed by a cross-origin
                        hijack record.
  ``no_traffic``        the traffic layer observed nothing at all.
  ``mass_withdrawal``   the victim withdrew at least N of its own
                        announcements.
  ``leak_not_saturated``the leak detector reported fewer records than its
                        truncation limit, so its output is not an
                        artefact of saturation.
  ``not_collapsed``     the traffic layer did not observe a collapse.

The candidate parameters (the N in ``mass_withdrawal``) are fitted on
the training folds of a stratified K-fold split and scored on the
held-out fold, so a candidate that only works because its threshold was
tuned on all 39 events does not survive.

Writes results/eval/arbitration_gate_search.json.
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
from arbitration_policies import build_rows  # noqa: E402

OUT_PATH = PROJECT_ROOT / "results" / "eval" / "arbitration_gate_search.json"
CLASSES = ("outage", "route_leak", "origin_hijack_victim")
SEED = 20240117
FOLDS = 5


def make_gate(spec: dict):
    """A gate is a conjunction of declared conditions."""
    def gate(row):
        agent = row["agent_cause"]
        rule = row["rule_cause"]
        if agent == rule:
            return rule

        if spec.get("corroborated") and not (
            row["cross_origin"] > 0 and agent == "origin_hijack_victim"
        ):
            return rule
        if spec.get("leak_corroborated") and agent == "route_leak":
            threshold = spec.get("leak_withdrawals", 5000)
            if not (
                not row["traffic_available"]
                and row["withdrawal_count"] >= threshold
            ):
                return rule
        if spec.get("no_traffic_only") and row["traffic_available"]:
            return rule
        if spec.get("not_collapsed"):
            if row["traffic_available"] and row["traffic_drop_pct"] >= 50.0:
                return rule
        if spec.get("leak_not_saturated") and row["leak_saturated"]:
            return rule
        return agent

    return gate


def candidate_specs() -> list[dict]:
    specs = []
    for corroborated in (True, False):
        for leak_withdrawals in (0, 1000, 3000, 5000, 8000):
            for leak_corroborated in (True, False):
                if not leak_corroborated and leak_withdrawals:
                    continue
                specs.append({
                    "corroborated": corroborated,
                    "leak_corroborated": leak_corroborated,
                    "leak_withdrawals": leak_withdrawals,
                })
    for not_collapsed in (True, False):
        for leak_not_saturated in (True, False):
            specs.append({
                "corroborated": True,
                "not_collapsed": not_collapsed,
                "leak_not_saturated": leak_not_saturated,
            })
    return specs


def accuracy(rows, gate) -> float:
    if not rows:
        return 0.0
    return sum(1 for r in rows if gate(r) == r["gt_cause"]) / len(rows)


def loo_accuracy(rows, spec, folds=FOLDS, seed=SEED):
    """Fit the gate's one free parameter on training folds, score held-out."""
    by_class: dict = {}
    for r in rows:
        by_class.setdefault(r["gt_cause"], []).append(r)
    rng = random.Random(seed)
    for cls in by_class:
        by_class[cls].sort(key=lambda r: r["event_id"])
        rng.shuffle(by_class[cls])

    assignments: list = [[] for _ in range(folds)]
    for cls, items in by_class.items():
        for i, r in enumerate(items):
            assignments[i % folds].append(r)

    grid = [0, 1000, 3000, 5000, 8000]
    correct = 0
    total = 0
    for f in range(folds):
        test = assignments[f]
        train = [r for g, fold in enumerate(assignments) if g != f for r in fold]
        best = None
        best_acc = -1.0
        for threshold in grid:
            candidate = dict(spec)
            candidate["leak_withdrawals"] = threshold
            acc = accuracy(train, make_gate(candidate))
            if acc > best_acc:
                best_acc = acc
                best = threshold
        gate = make_gate({**spec, "leak_withdrawals": best})
        for r in test:
            total += 1
            if gate(r) == r["gt_cause"]:
                correct += 1
    return correct, total


def main() -> int:
    rows = build_rows()
    incumbent = {
        "corroborated": False,
        "leak_corroborated": False,
        "leak_withdrawals": 0,
        "confidence_floor": 0.60,
    }

    def incumbent_gate(row):
        if float(row.get("agent_confidence") or 0.0) >= 0.60:
            return row["agent_cause"]
        return row["rule_cause"]

    results = []
    for spec in candidate_specs():
        gate = make_gate(spec)
        in_sample = sum(1 for r in rows if gate(r) == r["gt_cause"])
        loo_correct, loo_n = loo_accuracy(rows, spec)
        results.append({
            "spec": spec,
            "in_sample": in_sample,
            "in_sample_micro": round(in_sample / len(rows), 4),
            "loo_correct": loo_correct,
            "loo_micro": round(loo_correct / loo_n, 4) if loo_n else None,
        })

    results.sort(key=lambda x: (-x["loo_micro"], -x["in_sample"]))

    inc_correct = sum(1 for r in rows if incumbent_gate(r) == r["gt_cause"])
    inc_loo_correct, inc_loo_n = loo_accuracy(rows, incumbent)

    out = {
        "n": len(rows),
        "folds": FOLDS,
        "incumbent": {
            "in_sample": inc_correct,
            "loo_correct": inc_loo_correct,
            "loo_micro": round(inc_loo_correct / inc_loo_n, 4),
        },
        "top": results[:12],
        "all": results,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    print(f"incumbent: in-sample {inc_correct}/39  LOO {inc_loo_correct}/{inc_loo_n}")
    print()
    print(f"{'spec':72s} {'in-samp':>8s} {'LOO':>8s}")
    for r in results[:12]:
        print(f"{json.dumps(r['spec']):72s} {r['in_sample']:>4d}/39 "
              f"{r['loo_correct']:>4d}/{FOLDS and 39}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
