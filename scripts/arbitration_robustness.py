"""Robustness of the arbitration policy: bootstrap, cross-validation,
and a leave-one-out comparison against the incumbent.

Choosing a policy because it scores best on the same 39 events it is
measured on is corpus fitting.  This script subjects the candidate
policies to three checks that a fitted policy does not survive:

  bootstrap        resample the corpus with replacement, 2000 times,
                   and report the distribution of the accuracy
                   difference against the incumbent policy.
  stratified CV    split the corpus by ground-truth class into K
                   folds, fit the policy's free parameter on the
                   training folds, and score on the held-out fold.
  paired sign test count the events on which each policy and the
                   incumbent disagree, and whether the disagreements
                   favour one or the other.

The policy that survives all three is the one to ship.
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
from arbitration_policies import (  # noqa: E402
    build_rows,
    policy_confidence_gate,
    policy_corroborated,
    policy_mechanism,
    policy_mechanism_corroborated,
    policy_rule_only,
    score,
)

OUT_PATH = PROJECT_ROOT / "results" / "eval" / "arbitration_robustness.json"

CANDIDATES = {
    "rule_only": lambda r: policy_rule_only(r, {}),
    "confidence_gate@0.6": lambda r: policy_confidence_gate(r, {"floor": 0.6}),
    "confidence_gate@0.8": lambda r: policy_confidence_gate(r, {"floor": 0.8}),
    "corroborated": lambda r: policy_corroborated(r, {}),
    "mechanism": lambda r: policy_mechanism(r, {}),
    "mechanism_corroborated": lambda r: policy_mechanism_corroborated(r, {}),
}

INCUMBENT = "confidence_gate@0.6"
BOOTSTRAP_N = 2000
SEED = 20240117


def bootstrap_delta(rows, incumbent, candidate, n=BOOTSTRAP_N, seed=SEED):
    rng = random.Random(seed)
    n_rows = len(rows)
    deltas = []
    incumbent_correct = []
    candidate_correct = []
    for _ in range(n):
        sample = [rows[rng.randrange(n_rows)] for _ in range(n_rows)]
        ic = sum(
            1 for r in sample if incumbent(r) == r["gt_cause"]
        )
        cc = sum(
            1 for r in sample if candidate(r) == r["gt_cause"]
        )
        incumbent_correct.append(ic / n_rows)
        candidate_correct.append(cc / n_rows)
        deltas.append((cc - ic) / n_rows)
    deltas.sort()

    def pct(values, q):
        idx = min(len(values) - 1, max(0, int(q * (len(values) - 1))))
        return values[idx]

    return {
        "mean_delta": round(sum(deltas) / len(deltas), 4),
        "median_delta": round(pct(deltas, 0.5), 4),
        "ci95_low": round(pct(deltas, 0.025), 4),
        "ci95_high": round(pct(deltas, 0.975), 4),
        "p_candidate_better": round(
            sum(1 for d in deltas if d > 0) / len(deltas), 4
        ),
        "p_tied": round(sum(1 for d in deltas if d == 0) / len(deltas), 4),
    }


def stratified_cv(rows, folds=3, seed=SEED):
    """Fit the confidence floor on training folds, score on the held-out fold."""
    by_class: dict = {}
    for r in rows:
        by_class.setdefault(r["gt_cause"], []).append(r)
    for cls in by_class:
        by_class[cls].sort(key=lambda r: r["event_id"])

    rng = random.Random(seed)
    for cls in by_class:
        rng.shuffle(by_class[cls])

    assignments: list = [[] for _ in range(folds)]
    for cls, items in by_class.items():
        for i, r in enumerate(items):
            assignments[i % folds].append(r)

    floor_grid = (0.0, 0.5, 0.6, 0.7, 0.8, 0.9)
    correct = 0
    total = 0
    chosen = []
    for f in range(folds):
        test = assignments[f]
        train = [r for g, fold in enumerate(assignments) if g != f for r in fold]
        best_floor, best_c = None, -1
        for fl in floor_grid:
            c = sum(
                1 for r in train
                if policy_confidence_gate(r, {"floor": fl}) == r["gt_cause"]
            )
            if c > best_c:
                best_c = c
                best_floor = fl
        chosen.append(best_floor)
        for r in test:
            total += 1
            if policy_confidence_gate(r, {"floor": best_floor}) == r["gt_cause"]:
                correct += 1
    return {
        "folds": folds,
        "chosen_floors": chosen,
        "correct": correct,
        "n": total,
        "micro": round(correct / total, 4) if total else None,
    }


def sign_test(rows, incumbent, candidate):
    """McNemar-style paired comparison on the events the two disagree on."""
    b = 0
    c = 0
    for r in rows:
        i_ok = incumbent(r) == r["gt_cause"]
        c_ok = candidate(r) == r["gt_cause"]
        if i_ok and not c_ok:
            b += 1
        elif c_ok and not i_ok:
            c += 1
    n = b + c
    if n == 0:
        return {"discordant": 0, "p_value": 1.0}
    # exact two-sided binomial test
    from math import comb

    k = min(b, c)
    tail = sum(comb(n, i) for i in range(0, k + 1)) / (2 ** n)
    p = min(1.0, 2 * tail)
    return {
        "incumbent_only_correct": b,
        "candidate_only_correct": c,
        "discordant": n,
        "p_value": round(p, 4),
    }


def main() -> int:
    rows = build_rows()
    out = {"n": len(rows), "bootstrap_n": BOOTSTRAP_N, "seed": SEED, "policies": {}}

    for name, fn in CANDIDATES.items():
        s = score(rows, fn)
        entry = {
            "correct": s["correct"],
            "micro": s["micro"],
            "balanced": s["balanced"],
            "per_class_recall": s["per_class_recall"],
            "bootstrap_vs_incumbent": bootstrap_delta(
                rows, CANDIDATES[INCUMBENT], fn
            ),
            "sign_test_vs_incumbent": sign_test(
                rows, CANDIDATES[INCUMBENT], fn
            ),
        }
        out["policies"][name] = entry

    out["stratified_cv_confidence_gate"] = stratified_cv(rows)
    out["incumbent"] = INCUMBENT

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    print(f"{'policy':26s} {'corr':>7s} {'micro':>7s} {'bal':>7s} "
          f"{'bootΔ':>8s} {'95% CI':>18s} {'P(>inc)':>8s} {'sign p':>8s}")
    for name, slot in out["policies"].items():
        b = slot["bootstrap_vs_incumbent"]
        st = slot["sign_test_vs_incumbent"]
        print(
            f"{name:26s} {slot['correct']:>3d}/39 {slot['micro']:>7} "
            f"{slot['balanced']:>7} {b['mean_delta']:>+8} "
            f"[{b['ci95_low']:>+6},{b['ci95_high']:>+6}] {b['p_candidate_better']:>8} "
            f"{st['p_value']:>8}"
        )
    print()
    print("stratified 3-fold CV (confidence floor):", json.dumps(out["stratified_cv_confidence_gate"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
