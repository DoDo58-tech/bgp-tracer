"""Re-score the cause axis with the production rule, offline.

This script runs the *current* ``EvidenceChainBuilder.determine_cause``
over every cached event, using the agent's proposal recorded in the
existing ground-truth run, and reports the resulting accuracy.  It
needs no LLM call, so it turns a policy change into a measurement in
seconds rather than a full re-run of the pipeline.

It is a measurement harness, not the paper's number: the paper's
number comes from a full pipeline re-run, and this script exists to
verify that the policy change moved the cause axis in the direction the
offline analysis predicted before paying for that re-run.

Writes results/eval/cause_policy_check.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402
from detectors.evidence_chain_builder import EvidenceChainBuilder  # noqa: E402

QUICK_DIR = PROJECT_ROOT / "results" / "quick"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "cause_policy_check.json"
CLASSES = ("outage", "route_leak", "origin_hijack_victim")


def load_events() -> list[dict]:
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from component_ablation_gt import load_gt

    return load_gt()


def main() -> int:
    builder = EvidenceChainBuilder()
    events = {e["event_id"]: e for e in load_events()}
    agent = {
        r["event_id"]: r
        for r in json.loads(
            (PROJECT_ROOT / "results" / "eval" / "gt_agent_full.json").read_text()
        )["records"]
    }

    rows = []
    for eid, arec in agent.items():
        ev = events.get(eid)
        if not ev:
            continue
        match = resolve_cache(
            ev["asn"], ev["start"], ev["end"], QUICK_DIR,
            event_id=eid, allow_same_date=False,
        )
        if match is None:
            continue
        quick = json.loads(match.path.read_text())
        traffic = quick.get("traffic") or {}
        routing = quick.get("routing") or {}

        proposal = {
            "cause": arec.get("cause"),
            "incident_type": arec.get("cause"),
            "confidence": arec.get("agent_confidence"),
        }
        new_cause = builder.determine_cause(
            traffic, routing, proposal, arec.get("verdict_raw") or ""
        )
        old_cause = builder.cause_from_evidence(
            traffic, routing, arec.get("verdict_raw") or ""
        )
        rows.append({
            "event_id": eid,
            "gt_cause": arec.get("gt_cause"),
            "agent_cause": arec.get("cause"),
            "rule_only_cause": old_cause,
            "new_cause": new_cause,
            "corroborated": builder.agent_proposal_is_corroborated(
                arec.get("cause") or "", routing
            ),
            "traffic_available": bool(
                traffic.get("data_available", traffic.get("success", False))
            ),
        })

    def summarise(key):
        correct = sum(1 for r in rows if r[key] == r["gt_cause"])
        per_class = {c: {"n": 0, "correct": 0} for c in CLASSES}
        for r in rows:
            slot = per_class.setdefault(r["gt_cause"], {"n": 0, "correct": 0})
            slot["n"] += 1
            if r[key] == r["gt_cause"]:
                slot["correct"] += 1
        recalls = [
            per_class[c]["correct"] / per_class[c]["n"]
            for c in CLASSES if per_class[c]["n"]
        ]
        return {
            "correct": correct,
            "n": len(rows),
            "micro": round(correct / len(rows), 4),
            "balanced": round(sum(recalls) / len(recalls), 4),
            "per_class_recall": {
                c: round(per_class[c]["correct"] / per_class[c]["n"], 4)
                for c in CLASSES if per_class[c]["n"]
            },
        }

    out = {
        "n": len(rows),
        "agent_only": summarise("agent_cause"),
        "rule_only": summarise("rule_only_cause"),
        "new_policy": summarise("new_cause"),
        "rows": rows,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    for name in ("agent_only", "rule_only", "new_policy"):
        s = out[name]
        print(f"{name:14s} {s['correct']:>3d}/{s['n']} micro={s['micro']} "
              f"balanced={s['balanced']} {s['per_class_recall']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
