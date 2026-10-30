"""Which simple, physically-stated gate should decide the cause?

The gate search in ``arbitration_gate_search.py`` left several
candidates tied on the cross-validated estimate, so the tie must be
broken on grounds other than the corpus.  This script states each
candidate as a sentence a reader can check against the physics, and
reports what each one does on the events where it differs from the
incumbent.

The candidates:

  corroboration
      The agent may assert an origin hijack when the routing collector
      recorded announcements of the victim's prefixes by an origin that
      is neither the victim nor one of its legitimate origins.

  blind_data_plane
      When the traffic layer observed nothing at all, the physical
      layer cannot distinguish the classes, so the agent's contextual
      reading decides.  When traffic *was* observed, the physical
      layer's reading stands.

  blind_and_leak
      ``blind_data_plane`` restricted to the agent's leak proposal.

Writes results/eval/arbitration_gate_reading.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
from arbitration_policies import build_rows  # noqa: E402

OUT_PATH = PROJECT_ROOT / "results" / "eval" / "arbitration_gate_reading.json"
CLASSES = ("outage", "route_leak", "origin_hijack_victim")


def gate_incumbent(row):
    if float(row.get("agent_confidence") or 0.0) >= 0.60:
        return row["agent_cause"]
    return row["rule_cause"]


def gate_corroboration(row):
    if (
        row["agent_cause"] != row["rule_cause"]
        and row["agent_cause"] == "origin_hijack_victim"
        and row["cross_origin"] > 0
    ):
        return row["agent_cause"]
    return row["rule_cause"]


def gate_blind_data_plane(row):
    if (
        row["agent_cause"] != row["rule_cause"]
        and not row["traffic_available"]
    ):
        return row["agent_cause"]
    return row["rule_cause"]


def gate_blind_and_leak(row):
    if (
        row["agent_cause"] != row["rule_cause"]
        and row["agent_cause"] == "route_leak"
        and not row["traffic_available"]
    ):
        return row["agent_cause"]
    return row["rule_cause"]


def gate_corroboration_or_blind_leak(row):
    if row["agent_cause"] == row["rule_cause"]:
        return row["rule_cause"]
    if (
        row["agent_cause"] == "origin_hijack_victim"
        and row["cross_origin"] > 0
    ):
        return row["agent_cause"]
    if (
        row["agent_cause"] == "route_leak"
        and not row["traffic_available"]
    ):
        return row["agent_cause"]
    return row["rule_cause"]


GATES = {
    "incumbent_conf_0.6": gate_incumbent,
    "corroboration": gate_corroboration,
    "blind_data_plane": gate_blind_data_plane,
    "blind_and_leak": gate_blind_and_leak,
    "corroboration_or_blind_leak": gate_corroboration_or_blind_leak,
}


def score(rows, gate):
    per_class = {c: {"n": 0, "correct": 0} for c in CLASSES}
    correct = 0
    for r in rows:
        gt = r["gt_cause"]
        per_class.setdefault(gt, {"n": 0, "correct": 0})
        per_class[gt]["n"] += 1
        if gate(r) == gt:
            correct += 1
            per_class[gt]["correct"] += 1
    recalls = [
        per_class[c]["correct"] / per_class[c]["n"]
        for c in CLASSES if per_class[c]["n"]
    ]
    return {
        "correct": correct,
        "micro": round(correct / len(rows), 4),
        "balanced": round(sum(recalls) / len(recalls), 4),
        "per_class_recall": {
            c: round(per_class[c]["correct"] / per_class[c]["n"], 4)
            for c in CLASSES if per_class[c]["n"]
        },
    }


def main() -> int:
    rows = build_rows()
    out = {"n": len(rows), "gates": {}}
    for name, gate in GATES.items():
        out["gates"][name] = score(rows, gate)

    print(f"{'gate':30s} {'correct':>9s} {'micro':>7s} {'bal':>7s}  per-class recall")
    for name, slot in out["gates"].items():
        print(f"{name:30s} {slot['correct']:>4d}/39 {slot['micro']:>7} "
              f"{slot['balanced']:>7}  {slot['per_class_recall']}")

    # What each candidate changes relative to the incumbent.
    out["deltas"] = {}
    for name, gate in GATES.items():
        if name == "incumbent_conf_0.6":
            continue
        changed = []
        for r in rows:
            a = gate_incumbent(r)
            b = gate(r)
            if a == b:
                continue
            changed.append({
                "event_id": r["event_id"],
                "gt_cause": r["gt_cause"],
                "incumbent": a,
                "gate": b,
                "incumbent_correct": a == r["gt_cause"],
                "gate_correct": b == r["gt_cause"],
                "traffic_available": r["traffic_available"],
                "cross_origin": r["cross_origin"],
            })
        gained = sum(1 for c in changed if c["gate_correct"] and not c["incumbent_correct"])
        lost = sum(1 for c in changed if c["incumbent_correct"] and not c["gate_correct"])
        out["deltas"][name] = {
            "n_changed": len(changed),
            "gained": gained,
            "lost": lost,
            "net": gained - lost,
            "events": changed,
        }
        print()
        print(f"{name}: changed {len(changed)} events, gained {gained}, lost {lost}")
        for c in changed:
            mark = "FIX" if (c["gate_correct"] and not c["incumbent_correct"]) else (
                "BREAK" if (c["incumbent_correct"] and not c["gate_correct"]) else "same"
            )
            print(f"   {mark:5s} {c['event_id']:42s} gt={c['gt_cause']:20s} "
                  f"inc={str(c['incumbent']):20s} -> {str(c['gate']):20s}")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
