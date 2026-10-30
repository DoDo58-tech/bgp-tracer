"""Does the agent's proposal add anything over a deterministic rule?

The paper's claim is that the agent layer earns its cost.  That claim
only holds if the agent's *proposal* carries information that the
physical layer does not.  A gate that consults the agent's proposal and
a gate that replaces the agent's proposal with a fixed label can look
identical on the corpus while having completely different meanings.

This script therefore compares three families on the same events:

  * the agent's proposal, used as the arbitration input;
  * a deterministic stand-in that makes the *same* proposal the agent
    makes on every event where the agent proposes it, so the two can be
    separated;
  * the pure physical rule, with no agent input at all.

The comparison that matters is the "agent proposal replaced by a
constant" control: if the control reaches the same accuracy, the
agent's free-text cause is contributing nothing and the reported gain
is the gate's, not the agent's.

Writes results/eval/agent_value_under_control.json.
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

EVAL = PROJECT_ROOT / "results" / "eval"
OUT_PATH = EVAL / "agent_value_under_control.json"
CLASSES = ("outage", "route_leak", "origin_hijack_victim")


def score(rows, predict) -> dict:
    per_class = {c: {"n": 0, "correct": 0} for c in CLASSES}
    correct = 0
    for r in rows:
        gt = r["gt_cause"]
        per_class.setdefault(gt, {"n": 0, "correct": 0})
        per_class[gt]["n"] += 1
        if predict(r) == gt:
            correct += 1
            per_class[gt]["correct"] += 1
    recalls = [
        per_class[c]["correct"] / per_class[c]["n"]
        for c in CLASSES if per_class[c]["n"]
    ]
    return {
        "correct": correct,
        "n": len(rows),
        "micro": round(correct / len(rows), 4) if rows else None,
        "balanced": round(sum(recalls) / len(recalls), 4) if recalls else None,
        "per_class_recall": {
            c: round(per_class[c]["correct"] / per_class[c]["n"], 4)
            for c in CLASSES if per_class[c]["n"]
        },
    }


def gate_corroboration(row, proposal) -> dict:
    """The production gate, with the proposal supplied by the caller."""
    if (
        row["agent_cause"] != row["rule_cause"]
        and proposal == "origin_hijack_victim"
        and row["cross_origin"] > 0
    ):
        return proposal
    if (
        row["agent_cause"] != row["rule_cause"]
        and proposal == "route_leak"
        and not row["traffic_available"]
    ):
        return proposal
    return row["rule_cause"]


def main() -> int:
    rows = build_rows()
    out = {"n": len(rows), "arms": {}}

    out["arms"]["rule_only"] = score(rows, lambda r: r["rule_cause"])
    out["arms"]["agent_only"] = score(rows, lambda r: r["agent_cause"])
    out["arms"]["corroboration_with_agent_proposal"] = score(
        rows, lambda r: gate_corroboration(r, r["agent_cause"])
    )

    # The control: the gate is unchanged, but the proposal is replaced by
    # a fixed label.  A constant that reproduces the agent arm's accuracy
    # means the agent's free-text cause carried no information.
    for constant in CLASSES:
        out["arms"][f"corroboration_constant_{constant}"] = score(
            rows, lambda r, c=constant: gate_corroboration(r, c)
        )

    # A second control: the gate is allowed to override only towards a
    # fixed label, with no agent input, which is the strongest purely
    # deterministic alternative.
    def deterministic_cross_origin(row):
        if row["cross_origin"] > 0 and row["rule_cause"] != "origin_hijack_victim":
            return "origin_hijack_victim"
        return row["rule_cause"]

    out["arms"]["deterministic_cross_origin"] = score(rows, deterministic_cross_origin)

    print(f"{'arm':44s} {'correct':>9s} {'micro':>7s} {'bal':>7s}  per-class recall")
    for name, slot in out["arms"].items():
        print(
            f"{name:44s} {slot['correct']:>4d}/{slot['n']:<4d} "
            f"{slot['micro']:>7} {slot['balanced']:>7}  "
            f"{slot['per_class_recall']}"
        )

    agent_arm = out["arms"]["corroboration_with_agent_proposal"]
    best_control = max(
        (name for name in out["arms"] if name.startswith("corroboration_constant_")),
        key=lambda n: out["arms"][n]["correct"],
    )
    print()
    print(f"agent-proposal gate: {agent_arm['correct']}/{len(rows)}")
    print(f"best constant-proposal control ({best_control}): "
          f"{out['arms'][best_control]['correct']}/{len(rows)}")
    print(f"difference attributable to the agent's own proposal: "
          f"{agent_arm['correct'] - out['arms'][best_control]['correct']}")
    print(f"purely deterministic cross-origin gate: "
          f"{out['arms']['deterministic_cross_origin']['correct']}/{len(rows)}")

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
