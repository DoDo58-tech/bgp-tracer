"""Where, if anywhere, does the agent's cause proposal change an outcome?

This script is the honest audit of the agent's contribution.  It takes
the production arbitration, replaces the agent's free-text proposal
with a label, and checks whether the outcome ever changes.

Three questions:

1. *Reach.*  How many events does the agent's proposal actually get to
   decide?  A proposal that is consulted on three events of thirty-nine
   cannot be a load-bearing component, whatever its measured accuracy.

2. *Direction.*  On the events the proposal does reach, is it right more
   often than the physical rule it would displace?  A proposal that
   ties the rule is adding nothing.

3. *Substitution.*  Does replacing the proposal with a fixed label
   change any outcome?  A gate whose output is invariant to its agent
   input is a deterministic gate with an LLM in front of it.

The development corpus is the 39-event corpus the cause rule was
developed against.  The held-out corpus is the 14 events absent from
it.  Both are scored with the same code.

Writes results/eval/agent_reach.py.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from agent_contribution import (  # noqa: E402
    load_development,
    load_heldout,
    policy_corroborated,
    policy_record_first,
)

EVAL = PROJECT_ROOT / "results" / "eval"
OUT_PATH = EVAL / "agent_reach.json"


def reach_analysis(rows: list[dict], label: str) -> dict:
    """How often does the agent's proposal reach the decision?"""
    reached = []
    for row in rows:
        proposal = row.get("proposal") or ""
        if not proposal:
            continue
        # The proposal reaches the decision only when the gate would
        # actually consult it.
        consulted = (
            (proposal == "origin_hijack_victim" and row["cross_origin"] > 0)
            or (proposal in ("outage", "route_leak")
                and not row["traffic_available"])
        )
        if consulted:
            reached.append(row)

    right = sum(1 for r in reached if r["proposal"] == r["gt_cause"])
    rule_right = sum(1 for r in reached if r["rule_cause"] == r["gt_cause"])
    return {
        "corpus": label,
        "n_events": len(rows),
        "n_with_a_proposal": sum(1 for r in rows if r.get("proposal")),
        "n_consulted": len(reached),
        "consult_rate": round(len(reached) / len(rows), 4) if rows else None,
        "proposal_correct": right,
        "rule_correct_on_those": rule_right,
        "proposal_accuracy": round(right / len(reached), 4) if reached else None,
        "rule_accuracy_on_those": (
            round(rule_right / len(reached), 4) if reached else None
        ),
        "consulted_events": [
            {
                "event_id": r["event_id"],
                "gt": r["gt_cause"],
                "proposal": r["proposal"],
                "rule": r["rule_cause"],
                "cross_origin": r["cross_origin"],
                "traffic_available": r["traffic_available"],
                "proposal_right": r["proposal"] == r["gt_cause"],
            }
            for r in reached
        ],
    }


def substitution_analysis(rows: list[dict], label: str) -> dict:
    """Is the gate's output invariant to the agent's proposal?"""
    outcomes = {}
    for row in rows:
        for proposal in ("", "origin_hijack_victim", "outage", "route_leak"):
            probe = dict(row)
            probe["proposal"] = proposal
            outcomes.setdefault(row["event_id"], set()).add(
                policy_record_first(probe)
            )
    changed = [
        eid for eid, outs in outcomes.items() if len(outs) > 1
    ]
    return {
        "corpus": label,
        "n_events": len(rows),
        "n_outcomes_dependent_on_proposal": len(changed),
        "events": changed,
    }


def main() -> int:
    dev = load_development()
    held = load_heldout()

    out = {
        "development": reach_analysis(dev, "development (39 events)"),
        "heldout": reach_analysis(held, "held-out (14 events)"),
        "substitution": {
            "development": substitution_analysis(dev, "development"),
            "heldout": substitution_analysis(held, "held-out"),
        },
    }

    # The corroborated gate's own reach, which is the production gate.
    prod = {
        "development": reach_analysis(dev, "development"),
        "heldout": reach_analysis(held, "held-out"),
    }
    out["production_gate_reach"] = {
        "development": {
            "n_events": len(dev),
            "n_consulted": out["development"]["n_consulted"],
            "consult_rate": out["development"]["consult_rate"],
        },
        "heldout": {
            "n_events": len(held),
            "n_consulted": out["heldout"]["n_consulted"],
            "consult_rate": out["heldout"]["consult_rate"],
        },
    }

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    for key in ("development", "heldout"):
        slot = out[key]
        print(f"{slot['corpus']}")
        print(f"  events with an agent proposal : {slot['n_with_a_proposal']}"
              f"/{slot['n_events']}")
        print(f"  events the proposal decides   : {slot['n_consulted']}"
              f" ({slot['consult_rate']})")
        print(f"  proposal correct there        : {slot['proposal_correct']}"
              f"/{slot['n_consulted']}")
        print(f"  rule correct on the same      : {slot['rule_correct_on_those']}"
              f"/{slot['n_consulted']}")
        print()

    for key, slot in out["substitution"].items():
        print(f"substitution ({key}): "
              f"{slot['n_outcomes_dependent_on_proposal']}"
              f"/{slot['n_events']} outcomes depend on the proposal")
        for eid in slot["events"]:
            print(f"    {eid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
