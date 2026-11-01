"""The single-detector and single-signal baselines, on the canonical corpus.

The paper's system-level comparison needs a row for each alternative
that does *not* use the coordination layer:

  pick_max        the highest-confidence single detector, no arbitration.
  routing_only    the routing detector's verdict, no traffic signal.
  traffic_only    the traffic detector's verdict, no routing signal.

Each is scored with the paper's strict protocol: an abstention is never
counted as correct, and a method is scored only on the events where it
commits, so coverage is reported next to accuracy.

Writes results/eval/baseline_comparison.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from agents.cache_resolution import resolve_cache  # noqa: E402

EVAL = PROJECT_ROOT / "results" / "eval"
QUICK_DIR = PROJECT_ROOT / "results" / "quick"
OUT_PATH = EVAL / "baseline_comparison.json"
CLASSES = ("outage", "route_leak", "origin_hijack_victim")


def load_events():
    from component_ablation_gt import load_gt

    return load_gt()


def load_records(name):
    return {
        r["event_id"]: r
        for r in json.loads((EVAL / f"{name}.json").read_text())["records"]
    }


def score(rows, predict):
    """Strict Top-1 with coverage, plus the per-class breakdown."""
    per_class = {c: {"n": 0, "correct": 0} for c in CLASSES}
    answered = 0
    correct = 0
    for r in rows:
        gt = r["gt_cause"]
        pred = predict(r)
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
        "top1": round(correct / n, 4) if n else None,
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


def build_rows():
    events = {e["event_id"]: e for e in load_events()}
    agent = load_records("gt_agent_full")
    rules = load_records("gt_rule_only")
    feat = {
        r["event_id"]: r
        for r in json.loads((EVAL / "cause_feature_table.json").read_text())["rows"]
    }

    rows = []
    for eid, arec in agent.items():
        ev = events.get(eid)
        if not ev:
            continue
        f = feat.get(eid, {})
        match = resolve_cache(
            ev["asn"], ev["start"], ev["end"], QUICK_DIR,
            event_id=eid, allow_same_date=False,
        )
        traffic_ok = bool(f.get("traffic_available")) and bool(f.get("traffic_signal"))
        routing_ok = bool(
            f.get("has_origin_hijack")
            or float(f.get("withdrawal_ratio") or 0.0) >= 0.01
            or int(f.get("withdrawal_count") or 0) >= 100
            or int(f.get("evidenced_leaks") or 0) > 0
        )
        rows.append({
            "event_id": eid,
            "gt_cause": arec.get("gt_cause"),
            "agent_cause": arec.get("cause"),
            "rule_cause": (rules.get(eid) or {}).get("cause"),
            "agent_confidence": float(arec.get("agent_confidence") or 0.0),
            "traffic_signal": traffic_ok,
            "routing_signal": routing_ok,
            "has_origin_hijack": bool(f.get("has_origin_hijack")),
            "withdrawal_count": int(f.get("withdrawal_count") or 0),
            "evidenced_leaks": int(f.get("evidenced_leaks") or 0),
        })
    return rows


def pick_max(r):
    """The highest-confidence single detector's verdict."""
    if r["has_origin_hijack"]:
        return "origin_hijack_victim"
    if r["withdrawal_count"] >= 100:
        return "outage"
    if r["evidenced_leaks"] > 0:
        return "route_leak"
    return ""


def routing_only(r):
    if not r["routing_signal"]:
        return ""
    return pick_max(r)


def traffic_only(r):
    if not r["traffic_signal"]:
        return ""
    return "outage"


def main():
    rows = build_rows()
    arms = {
        "pick_max": score(rows, pick_max),
        "routing_only": score(rows, routing_only),
        "traffic_only": score(rows, traffic_only),
        "rule_only": score(rows, lambda r: r["rule_cause"]),
        "agent_full": score(rows, lambda r: r["agent_cause"]),
    }

    out = {"n": len(rows), "arms": arms}
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    print(f"{'arm':16s} {'correct':>9s} {'top1':>7s} {'cov':>7s} {'bal':>7s}")
    for name, slot in arms.items():
        print(f"{name:16s} {slot['correct']:>4d}/{slot['n']:<4d} "
              f"{slot['top1']:>7} {slot['coverage']:>7} "
              f"{slot['balanced_accuracy']:>7}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
