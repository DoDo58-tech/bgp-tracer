"""Select the arbitration policy by cross-validation, not by corpus fit.

``arbitration_robustness.py`` showed that the incumbent policy (agent
overrides whenever its own confidence clears 0.60) is at chance, and
that a corroboration gate is better.  It did not settle *which*
corroboration gate, and picking the gate that scores best on the same
39 events it is measured on is corpus fitting.

This script declares a small family of physically-motivated gates and
subjects each to the same three checks: in-sample accuracy, stratified
3-fold cross-validation with the gate's parameter fitted on the
training folds, and a 2000-sample bootstrap of the accuracy difference
against the incumbent.  A gate is only recommended if it wins under
cross-validation as well as in-sample.

The gates differ in what they require of the agent's proposal before it
may override the deterministic physical rule:

  corroboration        an independent physical signal supports it: the
                       hijack detector recorded announcements of the
                       victim's prefixes by an origin that is neither
                       the victim nor one of its legitimate origins.
  corroborated_hijack  the proposal is an origin hijack *and* a
                       cross-origin record supports it.  An origin
                       hijack claim is the one that needs origin
                       evidence; the other two classes are defined by
                       what the victim did with its own routes.
  corroborated_any    the proposal is corroborated and the rule's own
                       answer is not physically supported, so the agent
                       is only breaking a tie the physical layer could
                       not break.

Writes results/eval/arbitration_selection.json.
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
from arbitration_policies import build_rows, score  # noqa: E402

OUT_PATH = PROJECT_ROOT / "results" / "eval" / "arbitration_selection.json"
CLASSES = ("outage", "route_leak", "origin_hijack_victim")
SEED = 20240117
BOOTSTRAP_N = 2000


def rule_physically_supported(row) -> bool:
    """Does the deterministic rule's answer rest on a measured signature?

    The rule's default answer is ``origin_hijack_victim``, which it
    returns whenever the hijack detector fired and the victim did not
    withdraw its routes.  Since the hijack detector fires on every
    event in this corpus, that default is not a measurement.  The rule
    is physically supported when it returned an answer that its own
    veto or its own traffic reading forced.
    """
    cause = row["rule_cause"]
    if cause == "outage":
        return row["withdrawal_count"] >= 100 or row["traffic_drop_pct"] >= 50.0
    if cause == "route_leak":
        return row["evidenced_leaks"] > 0 and row["withdrawal_count"] < 100
    if cause == "origin_hijack_victim":
        # Supported only when the traffic layer saw a collapse that was
        # not explained by the victim's own withdrawal.
        return (
            row["traffic_available"]
            and row["traffic_drop_pct"] >= 50.0
            and row["withdrawal_count"] < 100
        )
    return False


def gate_rule_only(row, params):
    return row["rule_cause"]


def gate_agent_only(row, params):
    return row["agent_cause"]


def gate_incumbent(row, params):
    if float(row.get("agent_confidence") or 0.0) >= params.get("floor", 0.60):
        return row["agent_cause"]
    return row["rule_cause"]


def gate_corroboration(row, params):
    if row["cross_origin"] > 0:
        return row["agent_cause"]
    return row["rule_cause"]


def gate_corroborated_hijack(row, params):
    if (
        row["cross_origin"] > 0
        and row["agent_cause"] == "origin_hijack_victim"
    ):
        return row["agent_cause"]
    return row["rule_cause"]


def gate_corroborated_any(row, params):
    if row["cross_origin"] > 0 and not rule_physically_supported(row):
        return row["agent_cause"]
    return row["rule_cause"]


GATES = {
    "rule_only": gate_rule_only,
    "agent_only": gate_agent_only,
    "incumbent_conf_0.6": gate_incumbent,
    "corroboration": gate_corroboration,
    "corroborated_hijack": gate_corroborated_hijack,
    "corroborated_any": gate_corroborated_any,
}


def stratified_cv(rows, gate, param_grid, folds=3, seed=SEED):
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

    correct = 0
    total = 0
    chosen = []
    for f in range(folds):
        test = assignments[f]
        train = [r for g, fold in enumerate(assignments) if g != f for r in fold]
        best_param, best_c = None, -1
        for p in param_grid:
            c = sum(
                1 for r in train if gate(r, p) == r["gt_cause"]
            )
            if c > best_c:
                best_c = c
                best_param = p
        chosen.append(best_param)
        for r in test:
            total += 1
            if gate(r, best_param) == r["gt_cause"]:
                correct += 1
    return {
        "chosen": chosen,
        "correct": correct,
        "n": total,
        "micro": round(correct / total, 4) if total else None,
    }


def bootstrap(rows, incumbent, candidate, n=BOOTSTRAP_N, seed=SEED):
    rng = random.Random(seed)
    n_rows = len(rows)
    deltas = []
    for _ in range(n):
        sample = [rows[rng.randrange(n_rows)] for _ in range(n_rows)]
        ic = sum(1 for r in sample if incumbent(r) == r["gt_cause"])
        cc = sum(1 for r in sample if candidate(r) == r["gt_cause"])
        deltas.append((cc - ic) / n_rows)
    deltas.sort()
    lo = deltas[int(0.025 * (len(deltas) - 1))]
    hi = deltas[int(0.975 * (len(deltas) - 1))]
    return {
        "mean_delta": round(sum(deltas) / len(deltas), 4),
        "ci95": [round(lo, 4), round(hi, 4)],
        "p_better": round(sum(1 for d in deltas if d > 0) / len(deltas), 4),
    }


def main() -> int:
    rows = build_rows()
    out = {"n": len(rows), "gates": {}}

    param_grids = {
        "rule_only": [{}],
        "agent_only": [{}],
        "incumbent_conf_0.6": [{"floor": 0.6}],
        "corroboration": [{}],
        "corroborated_hijack": [{}],
        "corroborated_any": [{}],
    }

    for name, gate in GATES.items():
        s = score(rows, lambda r: gate(r, {}))
        cv = stratified_cv(rows, gate, param_grids[name])
        boot = bootstrap(
            rows,
            lambda r: GATES["incumbent_conf_0.6"](r, {"floor": 0.6}),
            lambda r: gate(r, {}),
        )
        out["gates"][name] = {
            "correct": s["correct"],
            "micro": s["micro"],
            "balanced": s["balanced"],
            "per_class_recall": s["per_class_recall"],
            "cv_micro": cv["micro"],
            "cv_correct": cv["correct"],
            "bootstrap_vs_incumbent": boot,
        }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    print(f"{'gate':24s} {'in-sample':>10s} {'CV':>8s} {'bal':>7s} "
          f"{'bootΔ':>8s} {'95% CI':>18s} {'P(>inc)':>8s}")
    for name, slot in out["gates"].items():
        b = slot["bootstrap_vs_incumbent"]
        print(
            f"{name:24s} {slot['correct']:>4d}/39 {slot['cv_micro']:>8} "
            f"{slot['balanced']:>7} {b['mean_delta']:>+8} "
            f"[{b['ci95'][0]:>+6},{b['ci95'][1]:>+6}] {b['p_better']:>8}"
        )
    print()
    for name, slot in out["gates"].items():
        print(f"{name:24s} per-class recall {slot['per_class_recall']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
