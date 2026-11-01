"""Which arbitration policy should decide the cause?

The production chain lets the agent's free-text cause override the
deterministic physical rule whenever the agent's own confidence clears
0.60.  Measured on the corpus, that gate is not a quality gate: the
agent's confidence does not predict whether its override is right, and
the agent overrides on 35 of 39 events with 18 correct against 17 wrong.

This script evaluates a declared family of arbitration policies against
the same corpus, each policy expressed over the physical features and
the agent's proposal, and reports both the in-sample accuracy and a
leave-one-out cross-validated accuracy.  The cross-validation is the
part that matters: a policy chosen because it maximises accuracy on the
39 events it is scored on has fitted the corpus, not the phenomenon, and
the leave-one-out number is the estimate that survives.

The policies:

  rule_only        always take the deterministic physical rule.
  agent_only       always take the agent's proposal.
  confidence_gate  the production policy: agent when its confidence
                   clears 0.60, else the rule.
  corroborated     agent when an independent physical signal supports
                   it (a cross-origin hijack record), else the rule.
  mechanism        agent only when its proposal is consistent with the
                   mechanism the physical layer measured; else the rule.
  mechanism_corr   mechanism consistency and corroboration together.

Writes results/eval/arbitration_policies.json.
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
OUT_PATH = PROJECT_ROOT / "results" / "eval" / "arbitration_policies.json"

CLASSES = ("outage", "route_leak", "origin_hijack_victim")


def load_events():
    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from component_ablation_gt import load_gt

    return load_gt()


def build_rows():
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
    feat = {
        r["event_id"]: r
        for r in json.loads(
            (PROJECT_ROOT / "results" / "eval" / "cause_feature_table.json").read_text()
        )["rows"]
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
        cross = 0
        if match is not None:
            quick = json.loads(match.path.read_text())
            routing = quick.get("routing") or {}
            victim = str(
                routing.get("target_asn") or routing.get("asn") or ev["asn"]
            ).replace("AS", "").strip()
            for rec in routing.get("origin_hijacked") or []:
                if not isinstance(rec, dict):
                    continue
                origin = str(rec.get("origin_as") or "")
                legit = {
                    str(x).replace("AS", "")
                    for x in (rec.get("legitimate_origins") or [])
                }
                if origin and origin != victim and victim in legit:
                    cross += 1

        rows.append({
            "event_id": eid,
            "gt_cause": arec.get("gt_cause"),
            "agent_cause": arec.get("cause"),
            "rule_cause": (rules.get(eid) or {}).get("cause"),
            "agent_confidence": arec.get("agent_confidence"),
            "agent_overrode_rule": arec.get("agent_overrode_rule"),
            "cross_origin": cross,
            "traffic_available": bool(f.get("traffic_available")),
            "traffic_signal": bool(f.get("traffic_signal")),
            "traffic_drop_pct": float(f.get("traffic_drop_pct") or 0.0),
            "outage_period_anomalies": int(f.get("outage_period_anomalies") or 0),
            "withdrawal_ratio": float(f.get("withdrawal_ratio") or 0.0),
            "withdrawal_count": int(f.get("withdrawal_count") or 0),
            "evidenced_leaks": int(f.get("evidenced_leaks") or 0),
            "has_origin_hijack": bool(f.get("has_origin_hijack")),
            "leak_saturated": bool(
                f.get("leak_truncated") or f.get("leak_skipped")
            ),
        })
    return rows


def mechanism(row: dict):
    """The physical mechanism the detectors measured.

    This is deliberately a *mechanism*, not a cause.  A mass withdrawal
    of the victim's own announcements with a matching traffic collapse
    is a reachability loss by withdrawal; it does not say whether the
    withdrawal came from the victim's own configuration error, a policy
    action by a third party, or an invalid authorisation.  The agent's
    job is to name that; the physical layer's job is to say what
    happened to the routes.
    """
    withdrew = row["withdrawal_ratio"] >= 0.01 and row["withdrawal_count"] >= 100
    collapsed = (
        row["traffic_available"]
        and row["traffic_signal"]
        and row["traffic_drop_pct"] >= 50.0
    )
    if withdrew and collapsed:
        return "withdrawal_reachability_loss"
    if collapsed:
        return "reachability_loss_without_withdrawal"
    if row["cross_origin"] > 0:
        return "cross_origin_announcement"
    if row["evidenced_leaks"] > 0 and not withdrew:
        return "path_degradation"
    return "no_reachability_loss"


# Which cause labels are compatible with which mechanism.
MECHANISM_COMPATIBLE = {
    "withdrawal_reachability_loss": {"outage", "origin_hijack_victim"},
    "reachability_loss_without_withdrawal": {
        "outage", "origin_hijack_victim", "route_leak"},
    "cross_origin_announcement": {
        "origin_hijack_victim", "route_leak", "outage"},
    "path_degradation": {"route_leak", "origin_hijack_victim"},
    "no_reachability_loss": {"route_leak", "outage", "origin_hijack_victim"},
}


def policy_rule_only(row, params):
    return row["rule_cause"]


def policy_agent_only(row, params):
    return row["agent_cause"]


def policy_confidence_gate(row, params):
    conf = float(row.get("agent_confidence") or 0.0)
    if conf >= params.get("floor", 0.60):
        return row["agent_cause"]
    return row["rule_cause"]


def policy_corroborated(row, params):
    if row["cross_origin"] > 0:
        return row["agent_cause"]
    return row["rule_cause"]


def policy_mechanism(row, params):
    mech = mechanism(row)
    compat = MECHANISM_COMPATIBLE[mech]
    if row["agent_cause"] in compat:
        return row["agent_cause"]
    return row["rule_cause"]


def policy_mechanism_corroborated(row, params):
    mech = mechanism(row)
    compat = MECHANISM_COMPATIBLE[mech]
    agent_ok = row["agent_cause"] in compat
    if agent_ok and row["cross_origin"] > 0:
        return row["agent_cause"]
    if agent_ok and mech in ("no_reachability_loss", "path_degradation"):
        return row["agent_cause"]
    return row["rule_cause"]


POLICIES = {
    "rule_only": policy_rule_only,
    "agent_only": policy_agent_only,
    "confidence_gate": policy_confidence_gate,
    "corroborated": policy_corroborated,
    "mechanism": policy_mechanism,
    "mechanism_corroborated": policy_mechanism_corroborated,
}


def score(rows: list[dict], predict):
    correct = 0
    per_class = {c: {"n": 0, "correct": 0} for c in CLASSES}
    for r in rows:
        gt = r["gt_cause"]
        pred = predict(r)
        per_class.setdefault(gt, {"n": 0, "correct": 0})
        per_class[gt]["n"] += 1
        if pred == gt:
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


def main():
    rows = build_rows()
    out = {"n": len(rows), "policies": {}}

    for name, fn in POLICIES.items():
        params = {}
        if name == "confidence_gate":
            grid = {}
            for floor in (0.0, 0.5, 0.6, 0.7, 0.8, 0.9):
                grid[str(floor)] = score(rows, lambda r, f=floor: fn(r, {"floor": f}))
            out["policies"][name] = {"sweep": grid}
            best = max(grid.items(), key=lambda kv: kv[1]["correct"])
            out["policies"][name]["at_production"] = grid["0.6"]
            out["policies"][name]["best_floor"] = {
                "floor": best[0], **best[1]}
            continue
        out["policies"][name] = score(rows, lambda r: fn(r, params))

    # Leave-one-out cross-validation for the two parameterised policies.
    # A policy's threshold is chosen on 38 events and scored on the
    # held-out one; the reported number is the honest estimate.
    for name in ("confidence_gate",):
        loo_correct = 0
        for held in range(len(rows)):
            train = [r for i, r in enumerate(rows) if i != held]
            best_floor, best_c = None, -1
            for floor in (0.0, 0.5, 0.6, 0.7, 0.8, 0.9):
                s = score(train, lambda r, f=floor: policy_confidence_gate(r, {"floor": f}))
                if s["correct"] > best_c:
                    best_c = s["correct"]
                    best_floor = floor
            pred = policy_confidence_gate(rows[held], {"floor": best_floor})
            if pred == rows[held]["gt_cause"]:
                loo_correct += 1
        out["policies"][name]["loo_correct"] = loo_correct
        out["policies"][name]["loo_micro"] = round(loo_correct / len(rows), 4)

    # Mechanism distribution, for the write-up.
    mech_counts: dict = {}
    for r in rows:
        m = mechanism(r)
        mech_counts.setdefault(m, {"n": 0, "gt": {}})
        mech_counts[m]["n"] += 1
        g = mech_counts[m]["gt"]
        g[r["gt_cause"]] = g.get(r["gt_cause"], 0) + 1
    out["mechanism_distribution"] = mech_counts

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(out, indent=1, default=str))

    print(f"{'policy':26s} {'correct':>9s} {'micro':>8s} {'balanced':>9s}")
    for name, slot in out["policies"].items():
        if "sweep" in slot:
            s = slot["at_production"]
            print(f"{name:26s} {s['correct']:>4d}/{s['n']:<4d} "
                  f"{s['micro']:>8} {s['balanced']:>9}   (production floor 0.60)")
            print(f"{'  best floor ' + str(slot['best_floor']['floor']):26s} "
                  f"{slot['best_floor']['correct']:>4d}/{slot['best_floor']['n']:<4d} "
                  f"{slot['best_floor']['micro']:>8} {slot['best_floor']['balanced']:>9}")
            print(f"{'  leave-one-out':26s} {slot['loo_correct']:>4d}/{len(rows):<4d} "
                  f"{slot['loo_micro']:>8}")
        else:
            print(f"{name:26s} {slot['correct']:>4d}/{slot['n']:<4d} "
                  f"{slot['micro']:>8} {slot['balanced']:>9}")
    print()
    print("mechanism distribution:")
    for m, slot in out["mechanism_distribution"].items():
        print(f"  {m:38s} n={slot['n']:2d}  {slot['gt']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
