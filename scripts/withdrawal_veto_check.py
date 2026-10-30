"""Check whether the agent's arbitration bypasses the withdrawal veto.

``cause_from_evidence`` holds a physical veto: when the victim
withdrew its own routes, the prefixes are re-announced by other
networks, the hijack detector reports that as an origin hijack, and
the veto says the withdrawal is the direct evidence and outranks the
re-announcement artefact.  The agent's arbitration path does not apply
that veto, so an agent proposal can reintroduce exactly the artefact
the rule was written to suppress.

This script measures, for every event, whether the victim withdrew its
routes and whether the agent's proposal was accepted over a correct
rule reading anyway.  It separates the events where the veto would
have changed the outcome from the ones where it would not, which is
what decides whether the fix is a real correction or a fit to the
corpus.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402

GT_CSV = PROJECT_ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
QUICK_DIR = PROJECT_ROOT / "results" / "quick"
EVAL = PROJECT_ROOT / "results" / "eval"
OUT_PATH = EVAL / "withdrawal_veto_check.json"

WITHDRAWAL_RATIO_OUTAGE = 0.03
WITHDRAWAL_COUNT_MIN = 100
WITHDRAWAL_COUNT_HARD = 1000


def load_gt() -> list[dict]:
    out = []
    for r in csv.DictReader(GT_CSV.open()):
        out.append(
            {
                "event_id": r["event_id"],
                "asn": str(r.get("victim_as") or "").replace("AS", "").strip(),
                "start": (r.get("start_utc") or "").strip(),
                "end": (r.get("end_utc") or "").strip(),
                "gt_cause": (r.get("cause") or "").strip(),
            }
        )
    return out


def withdrawal_state(path: Path) -> dict:
    d = json.loads(path.read_text())
    routing = d.get("routing") or {}
    outage = routing.get("outage_analysis") or {}
    features = outage.get("event_features") or {}
    announcements = int(features.get("announcement_count") or 0)
    withdrawals = int(features.get("withdrawal_count") or 0)
    ratio = (withdrawals / announcements) if announcements else 0.0
    traffic = d.get("traffic") or {}
    return {
        "withdrawal_count": withdrawals,
        "announcement_count": announcements,
        "withdrawal_ratio": round(ratio, 6),
        "victim_withdrew": (
            ratio >= WITHDRAWAL_RATIO_OUTAGE and withdrawals >= WITHDRAWAL_COUNT_MIN
        ),
        "victim_withdrew_hard": (
            ratio >= WITHDRAWAL_RATIO_OUTAGE and withdrawals >= WITHDRAWAL_COUNT_HARD
        ),
        "is_outage_suspected": bool(outage.get("is_outage_suspected")),
        "outage_score": outage.get("outage_score"),
        "indicators": outage.get("indicators") or [],
        "traffic_available": bool(
            traffic.get("data_available", traffic.get("success", False))
        ),
        "n_origin_hijacked": len(routing.get("origin_hijacked") or []),
        "n_route_leaks": len(routing.get("route_leaks") or []),
        "leak_truncated": bool(routing.get("leak_results_truncated")),
    }


def main() -> int:
    agent = {
        r["event_id"]: r
        for r in json.loads((EVAL / "gt_agent_full_v2.json").read_text())["records"]
    }
    rules = {
        r["event_id"]: r
        for r in json.loads((EVAL / "gt_rule_only_v2.json").read_text())["records"]
    }

    rows = []
    for ev in load_gt():
        eid = ev["event_id"]
        if eid not in agent:
            continue
        match = resolve_cache(ev["asn"], ev["start"], ev["end"], QUICK_DIR)
        if not match or not match.path.exists():
            continue
        state = withdrawal_state(match.path)
        a = agent[eid]
        r = rules.get(eid) or {}
        agent_cause = a.get("cause")
        rule_cause = r.get("cause")
        gt = ev["gt_cause"]
        rows.append(
            {
                "event_id": eid,
                "gt_cause": gt,
                "agent_cause": agent_cause,
                "rule_cause": rule_cause,
                "agent_correct": agent_cause == gt,
                "rule_correct": rule_cause == gt,
                "agent_overrode_rule": bool(agent_cause and rule_cause
                                            and agent_cause != rule_cause),
                **state,
            }
        )

    OUT_PATH.write_text(json.dumps(rows, indent=1, default=str))

    print("events where the agent overrode the rule, with the withdrawal state")
    print(f"{'event_id':42s} {'gt':>18s} {'rule':>18s} {'agent':>18s} "
          f"{'wdRatio':>8s} {'wd':>7s} {'withdrew':>8s} {'outcome':>8s}")
    for row in sorted(rows, key=lambda x: x["event_id"]):
        if not row["agent_overrode_rule"]:
            continue
        if row["agent_correct"] and not row["rule_correct"]:
            outcome = "WIN"
        elif row["rule_correct"] and not row["agent_correct"]:
            outcome = "LOSS"
        else:
            outcome = "same"
        print(
            f"{row['event_id'][:42]:42s} {row['gt_cause'][:18]:>18s} "
            f"{str(row['rule_cause'])[:18]:>18s} {str(row['agent_cause'])[:18]:>18s} "
            f"{row['withdrawal_ratio']:>8.4f} {row['withdrawal_count']:>7d} "
            f"{str(row['victim_withdrew'])[:7]:>8s} {outcome:>8s}"
        )

    losses = [r for r in rows if r["rule_correct"] and not r["agent_correct"]]
    wins = [r for r in rows if r["agent_correct"] and not r["rule_correct"]]
    print()
    print(f"agent losses: {len(losses)}, of which the victim withdrew its routes: "
          f"{sum(1 for r in losses if r['victim_withdrew'])}")
    print(f"agent wins: {len(wins)}, of which the victim withdrew its routes: "
          f"{sum(1 for r in wins if r['victim_withdrew'])}")
    print()
    veto_would_fix = [
        r for r in losses
        if r["victim_withdrew"] and r["rule_cause"] == "outage"
    ]
    veto_would_break = [
        r for r in wins
        if r["victim_withdrew"] and r["rule_cause"] == "outage"
    ]
    print(f"applying the veto would restore: {len(veto_would_fix)} events "
          f"-> {[r['event_id'] for r in veto_would_fix]}")
    print(f"applying the veto would break: {len(veto_would_break)} events "
          f"-> {[r['event_id'] for r in veto_would_break]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
