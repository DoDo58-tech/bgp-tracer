"""Evaluate the causal estimator on the final ground-truth dataset.

For every ground-truth event the harness resolves the local cache,
rebuilds the two sides *the way the production path builds them*, runs
the estimator, and records the verdict with the veto that produced it.

The output is a per-event table plus a summary, so a change to the
estimator can be judged on the same evidence rather than on a summary
line that hides the refusals.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402
from agents.control_plane import CONTROL_PLANE_CHANNELS  # noqa: E402
from agents.paddle_attribution import (  # noqa: E402
    PADDLE_PROTOCOL,
    R2T,
    T2R,
    UNKNOWN,
    attribute,
    protocol_hash,
)
from agents.paddle_runtime import (  # noqa: E402
    build_control_plane_series,
    build_traffic_observations,
    collect_mechanism,
    collect_scope,
    impact_window,
)
from agents.temporal import parse_timestamp  # noqa: E402

GT_CSV = ROOT / "data_check" / "ground_truth_collection/final_ground_truth.csv"
QUICK = ROOT / "results/quick"

#: The expected causal direction for each cause class.
#:
#: A route-level anomaly that precedes a measured traffic impact is a
#: routing-to-traffic cause.  The dataset records the *cause*, and the
#: direction the estimator must recover follows from it.
EXPECTED_DIRECTION = {
    "outage": R2T,
    "route_leak": R2T,
    "origin_hijack_victim": R2T,
    "roa_misconfig": R2T,
}


def build_sides(cache: Path) -> Optional[Dict[str, Any]]:
    """Rebuild the routing and traffic evidence from a quick cache.

    This mirrors ``WorkflowEngine.build_hcaf_timelines``: the routing side
    comes from the detector's own feature series and the event lists, the
    traffic side from the traffic anomalies.
    """
    try:
        data = json.loads(cache.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None

    corr = data.get("correlation") or {}
    routing_block = data.get("routing") or {}
    traffic_block = data.get("traffic") or {}

    def iter_events(raw) -> List[dict]:
        if isinstance(raw, list):
            return [e for e in raw if isinstance(e, dict)]
        return []

    routing_events: List[dict] = []
    for key in ("origin_hijacked", "forge_hijacked", "origin_hijacking",
                "forge_hijacking", "route_leaks"):
        routing_events.extend(iter_events(routing_block.get(key)))
    if not routing_events:
        routing_events = iter_events(corr.get("routing_events"))
    if not routing_events:
        routing_events = [
            e for e in iter_events(corr.get("timeline"))
            if str(e.get("source", "")).lower() == "routing"
        ]

    # The traffic side is the *continuous* observation series when the
    # detector could supply it: a series of measurements, each with the
    # magnitude of its deviation from the historical baseline.  The
    # anomaly list is only the subset that crossed the threshold, and a
    # threshold-crossing subset has no shape -- it cannot show whether
    # the response *followed* the control plane.
    traffic_events: List[dict] = []
    traffic_events.extend(iter_events(corr.get("traffic_events_full")))
    if not traffic_events:
        traffic_events.extend(iter_events(traffic_block.get("anomalies")))
    if not traffic_events:
        traffic_events = iter_events(corr.get("traffic_events"))
    if not traffic_events:
        traffic_events = [
            e for e in iter_events(corr.get("timeline"))
            if str(e.get("source", "")).lower() == "traffic"
        ]

    routing_timeline: List[dict] = []
    for ev in routing_events:
        ts = ev.get("timestamp") or ev.get("first_seen") or ev.get("time")
        if not ts:
            continue
        et = str(ev.get("event_type") or ev.get("type") or "")
        routing_timeline.append({
            "timestamp": ts,
            "event_type": et or "routing",
            "raw_event": ev,
        })

    traffic_timeline: List[dict] = []
    for ev in traffic_events:
        ts = ev.get("timestamp") or ev.get("first_seen") or ev.get("time")
        if not ts:
            continue
        traffic_timeline.append({
            "timestamp": ts,
            "raw_event": ev,
        })

    return {
        "data": data,
        "routing": routing_timeline,
        "traffic": traffic_timeline,
        "traffic_block": traffic_block,
        "analysis": routing_block.get("outage_analysis") or {},
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gt", default=str(GT_CSV))
    ap.add_argument("--out", default=str(ROOT / "results" / "eval" / "causal_estimator_eval.csv"))
    ap.add_argument("--meta", default=str(ROOT / "results" / "eval" / "causal_estimator_eval.json"))
    ap.add_argument("--protocol", default="", help="JSON overrides for the protocol")
    args = ap.parse_args()

    overrides = json.loads(args.protocol) if args.protocol else {}
    rows = list(csv.DictReader(open(args.gt, encoding="utf-8")))

    records: List[Dict[str, Any]] = []
    skipped: Dict[str, List[str]] = {}
    reasons: Counter = Counter()

    for row in rows:
        event_id = row["event_id"]
        asn = row.get("victim_as") or row.get("target_as")
        match = resolve_cache(
            asn, row.get("start_utc"), row.get("end_utc"), QUICK,
            event_id=event_id, allow_same_date=False,
        )
        if match is None:
            skipped.setdefault("no_cache", []).append(event_id)
            continue

        built = build_sides(match.path)
        if built is None:
            skipped.setdefault("unreadable_cache", []).append(event_id)
            continue

        routing = built["routing"]
        traffic = built["traffic"]
        data = built["data"]
        if not traffic:
            skipped.setdefault("no_traffic_evidence", []).append(event_id)
            continue

        start = parse_timestamp(data.get("start_time"))
        end = parse_timestamp(data.get("end_time"))
        control = build_control_plane_series(
            built["analysis"], window_start=start, window_end=end)
        if control.n_buckets < 4:
            skipped.setdefault("no_control_plane_series", []).append(event_id)
            continue

        traffic_observations = build_traffic_observations(traffic)
        routing_scope, traffic_scope = collect_scope(routing, traffic, {})
        mechanism = collect_mechanism(routing, {})
        window = impact_window(built.get("traffic_block"))

        verdict = attribute(
            control,
            traffic_observations,
            routing_mechanism=mechanism,
            routing_scope=routing_scope,
            series_scope=traffic_scope,
            impact_window=window,
            protocol=overrides or None,
        )
        reasons[verdict.reason] += 1

        expected = EXPECTED_DIRECTION.get(row.get("cause", ""), UNKNOWN)
        if verdict.direction == UNKNOWN:
            outcome = "abstain"
        elif verdict.direction == expected:
            outcome = "correct"
        else:
            outcome = "wrong"

        records.append({
            "event_id": event_id,
            "cause": row.get("cause", ""),
            "asn": asn,
            "expected": expected,
            "predicted": verdict.direction,
            "outcome": outcome,
            "reason": verdict.reason,
            "vetoes": json.dumps(verdict.vetoes),
            "channel": verdict.channel,
            "effect": None if verdict.effect is None else round(float(verdict.effect), 4),
            "exclusivity_ratio": (None if verdict.exclusivity_ratio is None
                                  else round(float(verdict.exclusivity_ratio), 4)),
            "baseline_displacement": (None if verdict.baseline_displacement is None
                                      else round(float(verdict.baseline_displacement), 4)),
            "tau_control": verdict.tau_control,
            "tau_response": (verdict.tau_response.isoformat()
                             if verdict.tau_response else None),
            "lag_seconds": verdict.lag_seconds,
            "mechanism": verdict.mechanism,
            "n_buckets": control.n_buckets,
            "has_baseline": control.has_baseline,
            "n_routing_events": len(routing),
            "n_traffic_events": len(traffic),
            "cache": str(match.path.relative_to(ROOT)),
        })

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if records:
        with open(out, "w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(records[0].keys()))
            writer.writeheader()
            writer.writerows(records)

    n_correct = sum(1 for r in records if r["outcome"] == "correct")
    n_wrong = sum(1 for r in records if r["outcome"] == "wrong")
    n_abstain = sum(1 for r in records if r["outcome"] == "abstain")
    committed = n_correct + n_wrong
    protocol = dict(PADDLE_PROTOCOL, **overrides)
    summary = {
        "estimator": "PADDLE",
        "protocol": protocol,
        "protocol_hash": protocol_hash(protocol),
        "n_gt": len(rows),
        "n_evaluated": len(records),
        "skipped": {k: {"count": len(v), "events": v} for k, v in sorted(skipped.items())},
        "n_correct": n_correct,
        "n_wrong": n_wrong,
        "n_abstain": n_abstain,
        "n_committed": committed,
        "accuracy_on_committed": round(n_correct / committed, 4) if committed else None,
        "coverage": round(committed / len(records), 4) if records else None,
        "accuracy_overall": round(n_correct / len(records), 4) if records else None,
        "reasons": dict(reasons.most_common()),
    }
    Path(args.meta).write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")

    print(f"GT {len(rows)}   evaluated {len(records)}   "
          f"correct {n_correct}  wrong {n_wrong}  abstain {n_abstain}")
    for reason, count in reasons.most_common():
        print(f"  {reason:<28}{count:>4}")
    for key, val in sorted(skipped.items()):
        print(f"  skipped[{key}] = {len(val)}")
    print(f"\naccuracy on committed: {summary['accuracy_on_committed']}   "
          f"coverage: {summary['coverage']}   "
          f"accuracy overall: {summary['accuracy_overall']}")
    print(f"wrote {out}\nwrote {Path(args.meta)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
