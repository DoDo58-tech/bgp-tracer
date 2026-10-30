"""Discriminability search over physical cause features.

Answers one question: which physical feature set separates the three
ground-truth cause classes on the 39-event corpus, and how much of the
agent pipeline's remaining error each candidate leaves?

The search is exhaustive over a small, declared feature space (thresholds
and boolean combinations of the physical signals the detectors actually
produce).  It is *not* a model fit: every candidate is a hand-written
rule in the same shape as the one the production code uses, so the
winner can be read directly as a rule and checked by a reviewer.

Outputs, for the best candidate per class:
  * the rule's accuracy on the corpus,
  * the confusion matrix against the ground truth,
  * the events it still gets wrong, with their physical feature values.

Writes results/eval/cause_discriminability.json.
"""

from __future__ import annotations

import itertools
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

FEATURE_TABLE = PROJECT_ROOT / "results" / "eval" / "cause_feature_table.json"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "cause_discriminability.json"

CLASSES = ("outage", "route_leak", "origin_hijack_victim")


def load_rows() -> list[dict]:
    return json.loads(FEATURE_TABLE.read_text())["rows"]


def features(r: dict) -> dict:
    """Normalise the raw row into the feature dict the search ranges over."""
    drop = float(r.get("traffic_drop_pct") or 0.0)
    ratio = float(r.get("withdrawal_ratio") or 0.0)
    return {
        "drop": drop,
        "ratio": ratio,
        "withdrawals": int(r.get("withdrawal_count") or 0),
        "announcements": int(r.get("announcement_count") or 0),
        "opa": int(r.get("outage_period_anomalies") or 0),
        "anomalies": 1 if r.get("traffic_signal") else 0,
        "available": 1 if r.get("traffic_available") else 0,
        "origin_hijack": 1 if r.get("has_origin_hijack") else 0,
        "forge_hijack": 1 if r.get("has_forge_hijack") else 0,
        "victim_withdrew": 1 if r.get("victim_withdrew") else 0,
        "victim_withdrew_hard": 1 if r.get("victim_withdrew_hard") else 0,
        "leak_evidence": 1 if int(r.get("evidenced_leaks") or 0) > 0 else 0,
        "leak_saturated": 1 if (
            r.get("leak_truncated") or r.get("leak_skipped")
            or int(r.get("leak_count") or 0) >= 5000
        ) else 0,
        "baseline_missing": 1 if not r.get("baseline_weeks") else 0,
    }


DROP_THRESHOLDS = (0.0, 30.0, 50.0, 60.0, 70.0, 80.0)
RATIO_THRESHOLDS = (0.0, 0.005, 0.01, 0.02, 0.03, 0.05)
OPA_THRESHOLDS = (0, 1, 2, 3)


def candidate_rules() -> list[tuple[str, callable]]:
    """Every candidate is (name, fn(features) -> label)."""
    rules = []

    for drop_t in DROP_THRESHOLDS:
        for ratio_t in RATIO_THRESHOLDS:
            for opa_t in OPA_THRESHOLDS:

                def make(drop_t=drop_t, ratio_t=ratio_t, opa_t=opa_t):
                    def rule(f):
                        collapsed = f["available"] and f["drop"] >= drop_t
                        withdrew = f["ratio"] >= ratio_t and f["withdrawals"] >= 100
                        if collapsed and f["opa"] >= opa_t and withdrew:
                            return "outage"
                        if collapsed:
                            return "origin_hijack_victim"
                        if f["leak_evidence"] and not withdrew:
                            return "route_leak"
                        if f["victim_withdrew_hard"]:
                            return "outage"
                        return "route_leak"
                    return rule

                rules.append((
                    f"drop>={drop_t},ratio>={ratio_t},opa>={opa_t}",
                    make(),
                ))

    # Variants that consult the hijack detector directly.
    for drop_t in (0.0, 50.0, 70.0):
        for ratio_t in (0.01, 0.02, 0.03):
            for opa_t in (0, 2):

                def make2(drop_t=drop_t, ratio_t=ratio_t, opa_t=opa_t):
                    def rule(f):
                        collapsed = f["available"] and f["drop"] >= drop_t
                        withdrew = f["ratio"] >= ratio_t and f["withdrawals"] >= 100
                        if collapsed and f["opa"] >= opa_t:
                            return "outage"
                        if f["origin_hijack"] and not withdrew:
                            return "origin_hijack_victim"
                        if collapsed:
                            return "origin_hijack_victim"
                        if f["leak_evidence"] and not withdrew:
                            return "route_leak"
                        if f["victim_withdrew_hard"]:
                            return "outage"
                        return "route_leak"
                    return rule

                rules.append((
                    f"hijack-aware:drop>={drop_t},ratio>={ratio_t},opa>={opa_t}",
                    make2(),
                ))

    # Variants that use the leak detector's saturation as a signal.
    for drop_t in (0.0, 50.0, 70.0):
        for ratio_t in (0.01, 0.02, 0.03):
            for opa_t in (0, 2):

                def make3(drop_t=drop_t, ratio_t=ratio_t, opa_t=opa_t):
                    def rule(f):
                        collapsed = f["available"] and f["drop"] >= drop_t
                        withdrew = f["ratio"] >= ratio_t and f["withdrawals"] >= 100
                        if collapsed and f["opa"] >= opa_t:
                            return "outage"
                        if collapsed and not f["origin_hijack"] and not f["leak_saturated"]:
                            return "outage"
                        if f["origin_hijack"] and not withdrew:
                            return "origin_hijack_victim"
                        if collapsed:
                            return "origin_hijack_victim"
                        if f["leak_evidence"] and not withdrew:
                            return "route_leak"
                        if f["victim_withdrew_hard"]:
                            return "outage"
                        return "route_leak"
                    return rule

                rules.append((
                    f"saturation-aware:drop>={drop_t},ratio>={ratio_t},opa>={opa_t}",
                    make3(),
                ))

    return rules


def evaluate(rule: callable, rows: list[dict]) -> dict:
    correct = 0
    per_class = {c: {"n": 0, "correct": 0} for c in CLASSES}
    errors = []
    for r in rows:
        f = features(r)
        pred = rule(f)
        gt = r["gt_cause"]
        slot = per_class.setdefault(gt, {"n": 0, "correct": 0})
        slot["n"] += 1
        if pred == gt:
            correct += 1
            slot["correct"] += 1
        else:
            errors.append({
                "event_id": r["event_id"],
                "gt": gt,
                "pred": pred,
                "agent_cause": r.get("agent_cause"),
                "rule_cause": r.get("rule_cause"),
                "features": f,
            })
    for c, slot in per_class.items():
        slot["accuracy"] = round(slot["correct"] / slot["n"], 4) if slot["n"] else None
    return {
        "n": len(rows),
        "correct": correct,
        "accuracy": round(correct / len(rows), 4),
        "per_class": per_class,
        "errors": errors,
    }


def main() -> int:
    rows = load_rows()
    results = []
    for name, rule in candidate_rules():
        res = evaluate(rule, rows)
        res["rule"] = name
        results.append(res)

    results.sort(key=lambda x: (-x["correct"], x["rule"]))
    best = results[0]

    # The deterministic production rule, for reference.
    agent_correct = sum(
        1 for r in rows if r.get("agent_cause") == r["gt_cause"]
    )
    rule_correct = sum(
        1 for r in rows if r.get("rule_cause") == r["gt_cause"]
    )

    out = {
        "n_rows": len(rows),
        "reference": {
            "agent_pipeline_correct": agent_correct,
            "agent_pipeline_accuracy": round(agent_correct / len(rows), 4),
            "production_rule_correct": rule_correct,
            "production_rule_accuracy": round(rule_correct / len(rows), 4),
        },
        "best_rule": {
            "rule": best["rule"],
            "correct": best["correct"],
            "accuracy": best["accuracy"],
            "per_class": best["per_class"],
            "errors": best["errors"],
        },
        "top_rules": [
            {k: v for k, v in r.items() if k != "errors"} | {"n_errors": len(r["errors"])}
            for r in results[:15]
        ],
        "all_rules": [
            {k: v for k, v in r.items() if k != "errors"} for r in results
        ],
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    print(f"agent pipeline : {agent_correct}/{len(rows)}")
    print(f"production rule: {rule_correct}/{len(rows)}")
    print(f"best searched  : {best['correct']}/{len(rows)}  [{best['rule']}]")
    print(f"per class      : {json.dumps(best['per_class'])}")
    print()
    for err in best["errors"]:
        print(f"  MISS {err['event_id']:42s} gt={err['gt']:22s} pred={err['pred']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
