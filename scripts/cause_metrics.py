"""Cause metrics on the 39-event corpus.

The corpus is not a balanced test set with respect to *identifiability*:
some events carry a physical signature that separates the classes and
some do not.  Reporting one micro-averaged accuracy over all 39 events
therefore measures two different things at once --- the classifier's
quality and the corpus's decidability --- and hides which of them moved.

This script computes the metric family that separates them, for each
arm:

  micro accuracy        correct / n, the plain number.
  balanced accuracy     mean of the per-class recalls.  Each cause class
                        contributes equally regardless of its size.
  coverage              fraction of events the arm answered with one of
                        the three cause labels (the remainder are
                        abstentions).
  conditional accuracy  correct / answered, the accuracy of the arm on
                        the events it chose to answer.
  decidable subset      accuracy restricted to the events whose cache
                        actually carries a physical signature (traffic
                        observed, or a material withdrawal, or a
                        victim-implicating hijack record).
  undecidable subset    the complement: events with no traffic and no
                        signature.  These are the events where the
                        corpus asks a question the telemetry cannot
                        answer.

Writes results/eval/cause_metrics.json.
"""

from __future__ import annotations

import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FEATURE_TABLE = PROJECT_ROOT / "results" / "eval" / "cause_feature_table.json"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "cause_metrics.json"

CLASSES = ("outage", "route_leak", "origin_hijack_victim")
ARMS = ("agent", "rule")


def load_rows():
    return json.loads(FEATURE_TABLE.read_text())["rows"]


def is_decidable(r: dict):
    """Does this event's cache carry a physical signature at all?"""
    if r.get("traffic_available"):
        return True
    if r.get("victim_withdrew") or int(r.get("withdrawal_count") or 0) >= 100:
        return True
    if int(r.get("evidenced_leaks") or 0) > 0:
        return True
    return False


def score(rows: list[dict], key: str, subset: list[dict] | None = None):
    subset = subset if subset is not None else rows
    per_class = {c: {"n": 0, "correct": 0} for c in CLASSES}
    answered = 0
    correct = 0
    for r in subset:
        gt = r["gt_cause"]
        pred = r.get(key)
        per_class.setdefault(gt, {"n": 0, "correct": 0})
        per_class[gt]["n"] += 1
        if pred in CLASSES:
            answered += 1
            if pred == gt:
                correct += 1
                per_class[gt]["correct"] += 1
    n = len(subset)
    recalls = [
        per_class[c]["correct"] / per_class[c]["n"]
        for c in CLASSES
        if per_class[c]["n"]
    ]
    return {
        "n": n,
        "answered": answered,
        "coverage": round(answered / n, 4) if n else None,
        "correct": correct,
        "micro_accuracy": round(correct / n, 4) if n else None,
        "conditional_accuracy": round(correct / answered, 4) if answered else None,
        "balanced_accuracy": round(sum(recalls) / len(recalls), 4) if recalls else None,
        "per_class": {
            c: {
                "n": slot["n"],
                "correct": slot["correct"],
                "recall": round(slot["correct"] / slot["n"], 4) if slot["n"] else None,
            }
            for c, slot in per_class.items()
        },
    }


def main():
    rows = load_rows()
    decidable = [r for r in rows if is_decidable(r)]
    undecidable = [r for r in rows if not is_decidable(r)]

    out = {
        "n_corpus": len(rows),
        "n_decidable": len(decidable),
        "n_undecidable": len(undecidable),
        "undecidable_events": [r["event_id"] for r in undecidable],
        "arms": {},
    }

    for arm in ARMS:
        out["arms"][arm] = {
            "all": score(rows, f"{arm}_cause"),
            "decidable": score(decidable, f"{arm}_cause"),
            "undecidable": score(undecidable, f"{arm}_cause"),
        }

    # The oracle over the three labels, per event: the best any
    # classifier could do with these predictions.
    out["oracle_perfect"] = {
        "n": len(rows),
        "balanced_accuracy": 1.0,
        "note": "upper bound; not achievable from telemetry",
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    print(f"corpus {len(rows)}  decidable {len(decidable)}  undecidable {len(undecidable)}")
    for arm in ARMS:
        a = out["arms"][arm]
        print(f"\n{arm}:")
        for scope in ("all", "decidable", "undecidable"):
            s = a[scope]
            print(
                f"  {scope:12s} n={s['n']:2d} micro={s['micro_accuracy']} "
                f"balanced={s['balanced_accuracy']} cov={s['coverage']} "
                f"cond={s['conditional_accuracy']}"
            )
        print("   per-class recall:",
              {c: v["recall"] for c, v in a["all"]["per_class"].items()})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
