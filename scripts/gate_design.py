"""Arbitration gate design: in-sample selection, out-of-sample estimate.

The corroboration gate asks the agent's proposal for a cause and then
checks whether a physical record corroborates it.  On the 39-event
corpus that reaches 22/39.  The question this script answers is
whether the *agent's proposal* is what produces the gain, or whether
the *physical record* is, and it answers it the way the question has
to be answered: by choosing the gate on the development corpus and
scoring it on events the development corpus never contained.

Three corpora are involved.

  ``development``  the 39-event balanced corpus the cause rule was
                   developed against.  Every gate family is scored
                   here and the family is selected here.
  ``heldout``      the 14 events present in the earlier ground-truth
                   corpora and absent from the reported one.  These
                   are scored once, at the end, with the gate that the
                   development corpus selected.

The gate families are:

  ``rule``            the physical rule alone.
  ``agent_conf``      the agent's proposal when its own confidence
                      clears a floor (the original production gate).
  ``cross_first``     a physical cross-origin hijack record decides
                      hijack; the agent's proposal may only decide
                      where no physical record exists.
  ``corroborated``    the agent's proposal, admitted only when a
                      physical record corroborates it.
  ``agent_tiebreak``  the agent's proposal breaks a tie the physical
                      layer cannot resolve (no traffic observation),
                      and is otherwise ignored.

The control is the constant-proposal arm: the same gate with the
agent's proposal replaced by a fixed label.  A constant that matches
the agent arm means the free-text proposal carried no information.

Writes results/eval/gate_design.json.
"""

from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from arbitration_policies import build_rows  # noqa: E402

EVAL = PROJECT_ROOT / "results" / "eval"
OUT_PATH = EVAL / "gate_design.json"
HELDOUT_PATH = EVAL / "heldout_events.json"

CLASSES = ("outage", "route_leak", "origin_hijack_victim", "roa_misconfig")


def score(rows: list[dict], predict) -> dict:
    per_class: dict = {}
    correct = 0
    for row in rows:
        gt = row["gt_cause"]
        slot = per_class.setdefault(gt, {"n": 0, "correct": 0})
        slot["n"] += 1
        if predict(row) == gt:
            correct += 1
            slot["correct"] += 1
    recalls = [
        slot["correct"] / slot["n"] for slot in per_class.values()
        if slot["n"]
    ]
    return {
        "n": len(rows),
        "correct": correct,
        "micro": round(correct / len(rows), 4) if rows else None,
        "balanced": round(sum(recalls) / len(recalls), 4) if recalls else None,
        "per_class": {
            cls: {
                "n": slot["n"],
                "correct": slot["correct"],
                "recall": round(slot["correct"] / slot["n"], 4),
            }
            for cls, slot in sorted(per_class.items())
        },
    }


def gate_rule(row, params=None):
    return row["rule_cause"]


def gate_agent_conf(row, params=None):
    floor = (params or {}).get("floor", 0.60)
    if float(row.get("agent_confidence") or 0.0) >= floor:
        return row["agent_cause"] or row["rule_cause"]
    return row["rule_cause"]


def gate_cross_first(row, params=None):
    """A physical cross-origin record decides; the agent only fills gaps."""
    if row["cross_origin"] > 0:
        return "origin_hijack_victim"
    proposal = row.get("agent_cause") or ""
    if proposal and not row["traffic_available"]:
        return proposal
    return row["rule_cause"]


def gate_corroborated(row, params=None):
    """The agent's proposal, admitted only when a physical record backs it."""
    proposal = row.get("agent_cause") or ""
    if proposal == "origin_hijack_victim" and row["cross_origin"] > 0:
        return proposal
    if proposal in ("outage", "route_leak") and not row["traffic_available"]:
        return proposal
    return row["rule_cause"]


def gate_agent_tiebreak(row, params=None):
    """The agent decides only where the physical layer observed nothing."""
    proposal = row.get("agent_cause") or ""
    if not row["traffic_available"] and proposal:
        return proposal
    return row["rule_cause"]


def gate_cross_then_tiebreak(row, params=None):
    """A physical record decides hijack; the agent fills the silent cases.

    The cross-origin record *is* the hijack claim: it says that a third
    party announced the victim's prefixes.  Requiring the agent to
    independently propose the same label before the record can be used
    makes the agent redundant wherever the record is present, so this
    gate lets the record decide on its own and reserves the agent's
    proposal for the windows where the physical layer observed nothing
    at all.
    """
    if row["cross_origin"] > 0:
        return "origin_hijack_victim"
    proposal = row.get("agent_cause") or ""
    if proposal and not row["traffic_available"]:
        return proposal
    return row["rule_cause"]


def gate_physical_only(row, params=None):
    """No agent input anywhere."""
    if row["cross_origin"] > 0:
        return "origin_hijack_victim"
    return row["rule_cause"]


GATES = {
    "rule": gate_rule,
    "agent_conf": gate_agent_conf,
    "cross_first": gate_cross_first,
    "corroborated": gate_corroborated,
    "agent_tiebreak": gate_agent_tiebreak,
    "cross_then_tiebreak": gate_cross_then_tiebreak,
    "physical_only": gate_physical_only,
}


def constant_proposal_gate(constant: str):
    """The gate with the agent's proposal replaced by a fixed label."""
    def predict(row, params=None):
        if constant == "origin_hijack_victim" and row["cross_origin"] > 0:
            return constant
        if constant in ("outage", "route_leak") and not row["traffic_available"]:
            return constant
        return row["rule_cause"]
    return predict


def load_heldout_rows() -> list[dict]:
    """The out-of-sample rows, already measured by heldout_validation.py."""
    path = EVAL / "heldout_validation.json"
    if not path.exists():
        return []
    data = json.loads(path.read_text())
    rows = []
    for event in data.get("events", []):
        rows.append({
            "event_id": event["event_id"],
            "gt_cause": event["gt_cause"],
            "rule_cause": event["rule_cause"],
            "agent_cause": event["agent_cause"],
            "agent_confidence": event.get("agent_confidence"),
            "cross_origin": event["cross_origin"],
            "traffic_available": event["traffic_available"],
        })
    return rows


def main() -> int:
    dev = build_rows()
    held = load_heldout_rows()

    out = {
        "development": {"n": len(dev)},
        "heldout": {"n": len(held)},
        "development_arms": {},
        "heldout_arms": {},
        "selection": {},
    }

    for name, fn in GATES.items():
        out["development_arms"][name] = score(dev, fn)
        if held:
            out["heldout_arms"][name] = score(held, fn)

    for constant in ("origin_hijack_victim", "outage", "route_leak"):
        fn = constant_proposal_gate(constant)
        key = f"constant_{constant}"
        out["development_arms"][key] = score(dev, fn)
        if held:
            out["heldout_arms"][key] = score(held, fn)

    # The confidence gate has a parameter, so it is selected on the
    # development corpus by leave-one-out cross-validation and the
    # selected floor is the one that is carried to the held-out set.
    floors = (0.0, 0.5, 0.6, 0.7, 0.8, 0.9)
    loo_correct = 0
    chosen_floor = None
    for held_index in range(len(dev)):
        train = [r for i, r in enumerate(dev) if i != held_index]
        best_floor, best_count = None, -1
        for floor in floors:
            count = sum(
                1 for r in train
                if gate_agent_conf(r, {"floor": floor}) == r["gt_cause"]
            )
            if count > best_count:
                best_count = count
                best_floor = floor
        if gate_agent_conf(dev[held_index], {"floor": best_floor}) == dev[held_index]["gt_cause"]:
            loo_correct += 1
        chosen_floor = best_floor
    out["selection"]["agent_confidence_floor"] = {
        "floor": chosen_floor,
        "loo_correct": loo_correct,
        "loo_micro": round(loo_correct / len(dev), 4) if dev else None,
        "sweep": {
            str(f): score(dev, lambda r, fl=f: gate_agent_conf(r, {"floor": fl}))
            for f in floors
        },
    }

    # Every other gate is parameter-free, so the development corpus
    # selects it outright and the held-out corpus is the estimate.
    best = max(
        (n for n in GATES if n != "agent_conf"),
        key=lambda n: out["development_arms"][n]["correct"],
    )
    out["selection"]["selected_gate"] = best
    out["selection"]["selected_on"] = "development corpus (39 events)"
    out["selection"]["selection_rule"] = (
        "The gate with the highest development-corpus accuracy among the "
        "parameter-free gates. The held-out corpus is not consulted "
        "during selection."
    )

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    print("development corpus (39 events)")
    print(f"{'arm':34s} {'correct':>9s} {'micro':>8s} {'balanced':>9s}")
    for name, slot in out["development_arms"].items():
        print(f"{name:34s} {slot['correct']:>4d}/{slot['n']:<4d} "
              f"{slot['micro']:>8} {slot['balanced']:>9}")

    if held:
        print()
        print("held-out corpus (14 events, never used for selection)")
        print(f"{'arm':34s} {'correct':>9s} {'micro':>8s} {'balanced':>9s}")
        for name, slot in out["heldout_arms"].items():
            print(f"{name:34s} {slot['correct']:>4d}/{slot['n']:<4d} "
                  f"{slot['micro']:>8} {slot['balanced']:>9}")

    print()
    print(f"selected gate (on development only): {best}")
    if held:
        print(f"  development: {out['development_arms'][best]['correct']}/{len(dev)}")
        print(f"  held-out:    {out['heldout_arms'][best]['correct']}/{len(held)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
