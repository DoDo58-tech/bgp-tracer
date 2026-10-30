#!/usr/bin/env python3
"""Three-arm comparison on the ground-truth corpus.

The question this answers is narrow and important: *where does the
accuracy come from?*  Three arms, all scored through the same cause
normaliser, on the same resolvable events:

  ``rule``      the deterministic evidence mapping alone — no LLM, no
                coordination layer.  This is the floor.
  ``agent``     the full agent pipeline (reasoning agent + arbitration
                + evidence board).  Read from the agent ground-truth
                artefact.
  ``baseline``  a single monolithic LLM call over the same Phase-1
                evidence — the control the agent has to beat.

The agent arm is expensive (~45 s/event), so it is read from the
artefact the agent ground-truth run produced rather than recomputed.

Usage:
    python scripts/compare_agent_arms.py
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.agent_ground_truth_eval import (  # noqa: E402
    AGENT_VERDICT_TO_CAUSE,
    LABEL_CAUSES as LABELS,
    norm_verdict,
    normalize_cause_label,
)
from scripts.score_cause_mapping import load_gt  # noqa: E402
from detectors.evidence_chain_builder import EvidenceChainBuilder  # noqa: E402

EVAL_DIR = PROJECT_ROOT / "results" / "eval"
AGENT_PATH = EVAL_DIR / "gt_agent_full.json"
BASELINE_PATH = EVAL_DIR / "gt_baseline_monolithic.json"
OUT_PATH = EVAL_DIR / "agent_arm_comparison.json"


def score_records(records: list[dict], key: str) -> dict:
    ran = [r for r in records if r.get("resolved") and r.get("success")]
    correct = sum(1 for r in ran if r.get(key))
    per_cause = {}
    for cls in LABELS:
        rows = [r for r in ran if r.get("gt_cause") == cls]
        if not rows:
            continue
        per_cause[cls] = {
            "n": len(rows),
            "correct": sum(1 for r in rows if r.get(key)),
            "accuracy": round(
                sum(1 for r in rows if r.get(key)) / len(rows), 4
            ),
        }
    admits = sum(1 for r in ran if r.get("verdict_admits_gt"))
    return {
        "n": len(ran),
        "correct": correct,
        "accuracy": round(correct / len(ran), 4) if ran else None,
        "verdict_compatibility_accuracy": round(admits / len(ran), 4) if ran else None,
        "per_cause": per_cause,
        "confusion": {
            cls: dict(Counter(r.get("predicted_cause") for r in ran if r.get("gt_cause") == cls))
            for cls in LABELS
        },
    }


def main() -> int:
    builder = EvidenceChainBuilder()
    from agents.cache_resolution import resolve_cache
    from pathlib import Path as P

    # ── arm 1: the deterministic rule ────────────────────────────────────
    rule_records = []
    for ev in load_gt():
        match = resolve_cache(
            ev["asn"], ev["start"], ev["end"], P(PROJECT_ROOT / "results" / "quick"),
            event_id=ev["event_id"], allow_same_date=False,
        )
        if match is None:
            rule_records.append({**ev, "resolved": False})
            continue
        quick = json.loads(match.path.read_text())
        chain = builder.build(
            quick.get("traffic") or {}, quick.get("routing") or {}, None, None
        )
        pred = normalize_cause_label(chain.cause) or chain.cause
        rule_records.append(
            {
                **ev,
                "resolved": True,
                "success": True,
                "predicted_cause": pred,
                "verdict": chain.verdict,
                "cause_correct": pred == ev["gt_cause"],
                "verdict_admits_gt": ev["gt_cause"] in AGENT_VERDICT_TO_CAUSE.get(
                    norm_verdict(chain.verdict), set()
                ),
            }
        )

    arms = {"rule_only": score_records(rule_records, "cause_correct")}

    for name, path in (("agent_full", AGENT_PATH), ("baseline_monolithic", BASELINE_PATH)):
        if not path.exists():
            arms[name] = {"n": 0, "note": f"{path.name} not present"}
            continue
        data = json.loads(path.read_text())
        arms[name] = score_records(data.get("records", []), "cause_correct")
        # attribute the agent's override behaviour
        if name == "agent_full":
            ran = [r for r in data.get("records", []) if r.get("resolved") and r.get("success")]
            overrode = [r for r in ran if r.get("agent_overrode_rule")]
            arms[name]["agent_overrode_rule_n"] = len(overrode)
            arms[name]["agent_overrode_rule_correct"] = sum(
                1 for r in overrode if r.get("cause_correct")
            )
            arms[name]["agent_eligible_n"] = sum(
                1 for r in ran if r.get("agent_proposed_verdict")
            )
            arms[name]["rule_verdict_agrees_with_committed"] = sum(
                1 for r in ran if r.get("rule_verdict") == r.get("verdict_raw")
            )

    out = {"arms": arms, "labels": list(LABELS)}
    OUT_PATH.write_text(json.dumps(out, indent=1))

    print(f"{'arm':22s} {'n':>4s} {'cause acc':>10s} {'verdict compat':>15s}")
    for name, st in arms.items():
        print(
            f"{name:22s} {st.get('n', 0):4d} "
            f"{str(st.get('accuracy')):>10s} "
            f"{str(st.get('verdict_compatibility_accuracy')):>15s}"
        )
    for name in ("agent_full",):
        st = arms.get(name, {})
        if st.get("n"):
            print(
                f"\n{name}: agent proposed a verdict on {st.get('agent_eligible_n')} events, "
                f"overrode the rule on {st.get('agent_overrode_rule_n')}, "
                f"of which {st.get('agent_overrode_rule_correct')} were correct."
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
