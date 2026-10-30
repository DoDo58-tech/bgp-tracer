"""Does the agent's proposal carry independent corroboration?

The agent overrides the deterministic rule on most of the corpus, and
its own confidence does not predict whether the override is right.  The
hypothesis this script tests is narrower and falsifiable:

    an agent cause proposal that is corroborated by a physical signal
    the deterministic rule did *not* use is more often right than one
    that is not.

The corroborating signal is the *cross-origin* hijack record: a record
whose ``origin_as`` is neither the victim nor one of the victim's
legitimate origins.  Such a record asserts that some other network
announced the victim's prefixes, which is what an origin hijack is.
A record that names the victim itself is a detector artefact (the
expected-origin baseline was not built), and a corpus of such records
carries no information about which class the event belongs to.

The script reports, for every event:

  * the ground-truth label,
  * the agent's proposal and whether it was corroborated,
  * whether the agent was right,

and then the contingency table of ``corroborated x correct`` for the
subset of events where the agent proposed a cause that differs from the
deterministic rule's.

Writes results/eval/agent_corroboration.json.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402

QUICK_DIR = PROJECT_ROOT / "results" / "quick"
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "agent_corroboration.json"


def load_events() -> list[dict]:
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from component_ablation_gt import load_gt

    return load_gt()


def cross_origin_counts(routing: dict, victim: str) -> dict:
    records = routing.get("origin_hijacked") or []
    cross = 0
    self_flag = 0
    other = 0
    for rec in records:
        if not isinstance(rec, dict):
            continue
        origin = str(rec.get("origin_as") or "")
        legitimate = {
            str(x).replace("AS", "")
            for x in (rec.get("legitimate_origins") or [])
        }
        if origin and origin == victim:
            self_flag += 1
        elif victim in legitimate or (origin and origin in legitimate):
            cross += 1
        else:
            other += 1
    return {
        "cross_origin": cross,
        "self_flagged": self_flag,
        "other_origin": other,
        "total": len(records),
    }


def main() -> int:
    events = {e["event_id"]: e for e in load_events()}
    agent = {
        r["event_id"]: r
        for r in json.loads(
            (PROJECT_ROOT / "results" / "eval" / "gt_agent_full.json").read_text()
        )["records"]
    }
    rules = {
        r["event_id"]: r
        for r in json.loads(
            (PROJECT_ROOT / "results" / "eval" / "gt_rule_only.json").read_text()
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
        detail = {}
        if match is not None:
            quick = json.loads(match.path.read_text())
            routing = quick.get("routing") or {}
            victim = str(
                routing.get("target_asn") or routing.get("asn") or ev["asn"]
            ).replace("AS", "").strip()
            detail = cross_origin_counts(routing, victim)

        agent_cause = arec.get("cause")
        rule_cause = (rules.get(eid) or {}).get("cause")
        differs = agent_cause != rule_cause
        corroborated = detail.get("cross_origin", 0) > 0
        rows.append({
            "event_id": eid,
            "gt_cause": arec.get("gt_cause"),
            "agent_cause": agent_cause,
            "rule_cause": rule_cause,
            "agent_correct": agent_cause == arec.get("gt_cause"),
            "rule_correct": rule_cause == arec.get("gt_cause"),
            "differs_from_rule": differs,
            "corroborated": corroborated,
            "cross_origin": detail.get("cross_origin", 0),
            "self_flagged": detail.get("self_flagged", 0),
            "other_origin": detail.get("other_origin", 0),
            "hijack_records": detail.get("total", 0),
            "agent_confidence": arec.get("agent_confidence"),
        })

    disagreements = [r for r in rows if r["differs_from_rule"]]
    table = {
        "corroborated_correct": sum(
            1 for r in disagreements
            if r["corroborated"] and r["agent_correct"]),
        "corroborated_wrong": sum(
            1 for r in disagreements
            if r["corroborated"] and not r["agent_correct"]),
        "uncorroborated_correct": sum(
            1 for r in disagreements
            if not r["corroborated"] and r["agent_correct"]),
        "uncorroborated_wrong": sum(
            1 for r in disagreements
            if not r["corroborated"] and not r["agent_correct"]),
    }

    # The policy this hypothesis implies: keep the agent's proposal only
    # when it is corroborated; otherwise fall back to the rule.
    policy_correct = 0
    for r in rows:
        use_agent = r["differs_from_rule"] and r["corroborated"]
        pred = r["agent_cause"] if use_agent else r["rule_cause"]
        if pred == r["gt_cause"]:
            policy_correct += 1

    always_rule = sum(1 for r in rows if r["rule_correct"])
    always_agent = sum(1 for r in rows if r["agent_correct"])

    out = {
        "n": len(rows),
        "n_disagreements": len(disagreements),
        "contingency": table,
        "policy_corroborated_agent_correct": policy_correct,
        "policy_always_rule_correct": always_rule,
        "policy_always_agent_correct": always_agent,
        "rows": rows,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    print(f"n={len(rows)}  agent/rule disagreements={len(disagreements)}")
    print("contingency (on disagreements):")
    for k, v in table.items():
        print(f"  {k:26s} {v}")
    print()
    print(f"always rule      : {always_rule}/{len(rows)}")
    print(f"always agent     : {always_agent}/{len(rows)}")
    print(f"corroborated-agent policy: {policy_correct}/{len(rows)}")
    print()
    print("disagreements:")
    for r in disagreements:
        print(
            f"  {r['event_id']:42s} gt={r['gt_cause']:20s} "
            f"agent={str(r['agent_cause']):20s} rule={str(r['rule_cause']):20s} "
            f"corrob={r['cross_origin']:4d} agentOK={r['agent_correct']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
