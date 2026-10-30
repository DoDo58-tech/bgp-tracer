"""Grid-search the CDPR protocol on the labelled corpus.

The protocol is a set of thresholds.  Choosing them by hand, one
refusal at a time, is slow and prone to over-fitting the events that
happen to be in the corpus.  This script sweeps the thresholds over a
grid and reports the operating points that maximise the objective, so
the choice is made on the whole corpus rather than on the last event
that was looked at.

The objective is deliberately not plain accuracy.  An estimator that
abstains on everything scores perfectly on accuracy over its committed
verdicts while being useless.  The objective is therefore the number of
*correct* verdicts, with the wrong verdicts and the coverage reported
alongside so a point that buys coverage with accuracy is visible.
"""
from __future__ import annotations

import argparse
import csv
import itertools
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.aea_runtime import parse_timestamp  # noqa: E402
from agents.cache_resolution import resolve_cache  # noqa: E402
from agents.cdpr_attribution import (  # noqa: E402
    R2T,
    T2R,
    UNKNOWN,
    attribute,
)
from agents.cdpr_runtime import (  # noqa: E402
    build_control_plane_series,
    build_traffic_observations,
    collect_mechanism,
    collect_scope,
)

GT_CSV = ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
QUICK = ROOT / "results" / "quick"

EXPECTED_DIRECTION = {
    "outage": R2T,
    "route_leak": R2T,
    "origin_hijack_victim": R2T,
    "roa_misconfig": R2T,
}

#: Events where the control plane is *not* what broke.  The dataset
#: records these as outages whose subtype names an infrastructure
#: failure rather than a routing fault, and a correct estimator must
#: not attribute them to the control plane.
NON_BGP_CAUSES = ("internal_failure_non_bgp",)


def load_events() -> List[Dict[str, Any]]:
    """Every ground-truth event with its cache and its two sides."""
    rows = list(csv.DictReader(open(GT_CSV, encoding="utf-8")))
    out: List[Dict[str, Any]] = []
    for row in rows:
        asn = row.get("victim_as") or row.get("target_as")
        match = resolve_cache(asn, row.get("start_utc"), row.get("end_utc"),
                              QUICK, event_id=row["event_id"],
                              allow_same_date=False)
        if match is None:
            continue
        try:
            data = json.loads(match.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        corr = data.get("correlation") or {}
        routing_block = data.get("routing") or {}

        def events(raw) -> List[dict]:
            if isinstance(raw, list):
                return [e for e in raw if isinstance(e, dict)]
            return []

        routing_events: List[dict] = []
        for key in ("origin_hijacked", "forge_hijacked", "origin_hijacking",
                    "forge_hijacking", "route_leaks"):
            routing_events.extend(events(routing_block.get(key)))
        if not routing_events:
            routing_events = events(corr.get("routing_events"))
        if not routing_events:
            routing_events = [
                e for e in events(corr.get("timeline"))
                if str(e.get("source", "")).lower() == "routing"
            ]

        traffic_events = events(corr.get("traffic_events_full"))
        if not traffic_events:
            traffic_events = events(routing_block.get("anomalies"))
        if not traffic_events:
            traffic_events = events(corr.get("traffic_events"))
        if not traffic_events:
            traffic_events = [
                e for e in events(corr.get("timeline"))
                if str(e.get("source", "")).lower() == "traffic"
            ]

        routing_timeline = []
        for ev in routing_events:
            ts = ev.get("timestamp") or ev.get("first_seen") or ev.get("time")
            if not ts:
                continue
            severity = ev.get("severity")
            score = float(severity) if isinstance(severity, (int, float)) else 0.8
            routing_timeline.append({
                "timestamp": ts, "score": max(score, 0.5),
                "event_type": str(ev.get("event_type") or ev.get("type") or ""),
                "raw_event": ev,
            })

        traffic_timeline = []
        for ev in traffic_events:
            ts = ev.get("timestamp") or ev.get("first_seen") or ev.get("time")
            if not ts:
                continue
            z = ev.get("z_score")
            if isinstance(z, (int, float)):
                score = abs(float(z))
            else:
                severity = ev.get("severity")
                score = float(severity) if isinstance(severity, (int, float)) else 0.8
            traffic_timeline.append({
                "timestamp": ts, "score": score, "event_type": "traffic",
                "raw_event": ev,
            })

        control = build_control_plane_series(
            routing_block.get("outage_analysis") or {},
            window_start=parse_timestamp(data.get("start_time")),
            window_end=parse_timestamp(data.get("end_time")),
        )
        if control.n_buckets < 4 or not traffic_timeline:
            continue
        observations = build_traffic_observations(traffic_timeline)
        r_scope, t_scope = collect_scope(routing_timeline, traffic_timeline, {})
        mechanism = collect_mechanism(routing_timeline, {})
        expected = EXPECTED_DIRECTION.get(row.get("cause", ""), UNKNOWN)
        out.append({
            "event_id": row["event_id"],
            "cause": row.get("cause", ""),
            "subtype": row.get("subtype", ""),
            "expected": expected,
            "control": control,
            "observations": observations,
            "routing_scope": r_scope,
            "traffic_scope": t_scope,
            "mechanism": mechanism,
        })
    return out


def score(events: List[Dict[str, Any]], protocol: Dict[str, Any]) -> Dict[str, Any]:
    correct = wrong = abstain = 0
    details: List[Dict[str, Any]] = []
    for ev in events:
        verdict = attribute(
            ev["control"], ev["observations"],
            routing_mechanism=ev["mechanism"],
            routing_scope=ev["routing_scope"],
            series_scope=ev["traffic_scope"],
            protocol=protocol,
        )
        if verdict.direction == UNKNOWN:
            outcome = "abstain"
            abstain += 1
        elif verdict.direction == ev["expected"]:
            outcome = "correct"
            correct += 1
        else:
            outcome = "wrong"
            wrong += 1
        details.append({
            "event_id": ev["event_id"],
            "outcome": outcome,
            "reason": verdict.reason,
            "direction": verdict.direction,
            "channel": verdict.channel,
            "lag_seconds": verdict.lag_seconds,
            "effect": verdict.effect,
            "ratio": verdict.exclusivity_ratio,
        })
    n = len(events)
    return {
        "correct": correct, "wrong": wrong, "abstain": abstain, "n": n,
        "coverage": round((correct + wrong) / n, 4) if n else 0.0,
        "precision": round(correct / (correct + wrong), 4) if (correct + wrong) else None,
        "details": details,
    }


GRID: Dict[str, List[Any]] = {
    "min_rate_deviation": [0.15, 0.25, 0.40, 0.60],
    "min_jump_t": [1.0, 1.5, 2.0, 3.0],
    "min_exclusivity_ratio": [1.0, 1.3, 1.6, 2.0],
    "max_response_lag_seconds": [1800.0, 3600.0, 5400.0, 10800.0],
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "results" / "eval" / "cdpr_grid.json"))
    ap.add_argument("--top", type=int, default=15)
    args = ap.parse_args()

    events = load_events()
    print(f"loaded {len(events)} events with both sides")

    keys = sorted(GRID)
    results: List[Dict[str, Any]] = []
    for combo in itertools.product(*(GRID[k] for k in keys)):
        protocol = dict(zip(keys, combo))
        outcome = score(events, protocol)
        results.append({
            "protocol": protocol,
            "correct": outcome["correct"],
            "wrong": outcome["wrong"],
            "abstain": outcome["abstain"],
            "coverage": outcome["coverage"],
            "precision": outcome["precision"],
        })

    # Rank by correct verdicts, then by precision, then by coverage.
    results.sort(key=lambda r: (-r["correct"],
                                 -(r["precision"] or 0.0),
                                 -r["coverage"]))
    print(f"\n{'correct':>8s} {'wrong':>6s} {'abst':>6s} {'cov':>6s} "
          f"{'prec':>6s}  protocol")
    for r in results[:args.top]:
        print(f"{r['correct']:>8d} {r['wrong']:>6d} {r['abstain']:>6d} "
              f"{r['coverage']:>6.2f} {str(r['precision']):>6s}  "
              f"{json.dumps(r['protocol'], sort_keys=True)}")

    best = results[0]
    outcome = score(events, best["protocol"])
    print(f"\nbest protocol: {json.dumps(best['protocol'], sort_keys=True)}")
    print("per-event:")
    for d in outcome["details"]:
        print(f"  {d['event_id'][:40]:42s} {d['outcome']:8s} {d['reason']:22s} "
              f"ch={d['channel']:14s} lag={d['lag_seconds']}")

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps({
        "n_events": len(events),
        "grid": GRID,
        "results": results,
        "best": best,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
