"""Evaluate PADDLE on the canonical ground truth, through the runtime.

This is the production path: the same :func:`agents.paddle_runtime.run_paddle`
the chief agent calls, fed the same detector payloads the chief agent is
fed.  The script does not re-implement any part of the estimator; it only
reproduces the *assembly* of the inputs, so that a verdict measured here
is the verdict the system would reach.

For every event the script records:

* the direction PADDLE committed, or the reason it abstained;
* which veto gate stopped it, when it did;
* the four gate results, so a reader can see why a claim was made and
  why a refusal was honest.

The output is a JSON artefact plus a readable table.  The artefact is the
evidence: the table is a rendering of it.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.cache_resolution import resolve_cache  # noqa: E402
from agents.paddle_runtime import run_paddle  # noqa: E402
from agents.temporal import parse_timestamp  # noqa: E402

GT_CSV = ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
QUICK = ROOT / "results" / "quick"
DEFAULT_OUT = ROOT / "results" / "eval" / "paddle_corpus.json"


def unwrap(payload: Any) -> Dict[str, Any]:
    """The result dict, whether it is wrapped or bare."""
    if isinstance(payload, dict):
        for key in ("result", "data", "payload"):
            inner = payload.get(key)
            if isinstance(inner, dict) and inner:
                return inner
    return payload if isinstance(payload, dict) else {}


def per_asn(block: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The per-ASN results of a detector block."""
    if not isinstance(block, dict):
        return []
    for key in ("asn_results", "results", "per_asn"):
        value = block.get(key)
        if isinstance(value, list) and value:
            return [v for v in value if isinstance(v, dict)]
    return [block]


def assemble(cache: Dict[str, Any], event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The runtime inputs, assembled the way the chief agent assembles them."""
    traffic_block = unwrap(cache.get("traffic"))
    routing_block = unwrap(cache.get("routing"))
    if not traffic_block or not routing_block:
        return None

    traffic_timeline: List[Dict[str, Any]] = []
    for asn_result in per_asn(traffic_block):
        for anomaly in (asn_result.get("anomalies") or []):
            if not isinstance(anomaly, dict):
                continue
            stamp = anomaly.get("timestamp") or anomaly.get("time")
            if not stamp:
                continue
            traffic_timeline.append({
                "timestamp": stamp,
                "event_type": "traffic_anomaly",
                "raw_event": anomaly,
            })
        break
    if not traffic_timeline:
        return None

    routing_timeline: List[Dict[str, Any]] = []
    routing_context: Dict[str, Any] = {}
    for key in ("origin_hijacked", "forge_hijacked",
                "origin_hijacking", "forge_hijacking",
                "route_leaks"):
        for found in (routing_block.get(key) or []):
            if not isinstance(found, dict):
                continue
            stamp = (found.get("timestamp") or found.get("first_seen")
                     or found.get("time"))
            if not stamp:
                continue
            routing_timeline.append({
                "timestamp": stamp,
                "event_type": found.get("event_type") or found.get("type"),
                "raw_event": found,
            })

    outage = (routing_block.get("outage_analysis")
              or routing_block.get("outage") or {})
    if outage.get("is_outage_suspected"):
        stamp = outage.get("timestamp") or outage.get("first_seen")
        if stamp:
            routing_timeline.append({
                "timestamp": stamp,
                "event_type": "outage",
                "raw_event": outage,
            })

    return {
        "routing_analysis": outage,
        "traffic_timeline": traffic_timeline,
        "routing_timeline": routing_timeline,
        "routing_context": routing_context,
        "traffic_block": traffic_block,
        "window_start": parse_timestamp(event.get("start_utc")),
        "window_end": parse_timestamp(event.get("end_utc")),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--gt", default=str(GT_CSV))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args()

    events = list(csv.DictReader(open(args.gt, encoding="utf-8")))
    records: List[Dict[str, Any]] = []

    for event in events:
        event_id = event.get("event_id") or ""
        asn = event.get("victim_as") or event.get("target_as") or ""
        match = resolve_cache(str(asn), event.get("start_utc"), event.get("end_utc"),
                              QUICK, event_id=event_id, allow_same_date=False)
        if match is None:
            records.append({"event_id": event_id, "cause": event.get("cause"),
                            "outcome": "no_cache"})
            continue
        cache = json.loads(match.path.read_text(encoding="utf-8"))
        inputs = assemble(cache, event)
        if inputs is None:
            records.append({"event_id": event_id, "cause": event.get("cause"),
                            "outcome": "no_inputs"})
            continue

        verdict, control, observations = run_paddle(**inputs)
        record: Dict[str, Any] = {
            "event_id": event_id,
            "cause": event.get("cause"),
            "outcome": "measured",
            "committed": bool(verdict.committed),
            "direction": verdict.direction if verdict.committed else "unknown",
            "reason": verdict.reason,
            "vetoes": dict(verdict.vetoes),
            "channel": verdict.channel,
            "evidence_file": str(match.path),
            "n_traffic_observations": len(observations),
            "n_control_slots": len(getattr(control, "slots", []) or []),
        }
        tests = getattr(verdict, "tests", None)
        if isinstance(tests, dict):
            trough = tests.get("trough") or {}
            record["trough"] = trough.get("stamp")
            record["trough_deviation"] = trough.get("deviation")
            record["channels"] = tests.get("channels")
        records.append(record)

    committed = [r for r in records if r.get("committed")]
    by_reason: Dict[str, int] = {}
    for record in records:
        reason = str(record.get("reason") or record.get("outcome") or "unknown")
        by_reason[reason] = by_reason.get(reason, 0) + 1

    out = {
        "records": records,
        "summary": {
            "corpus_total": len(events),
            "measured": len([r for r in records if r.get("outcome") == "measured"]),
            "committed": len(committed),
            "abstained": len(records) - len(committed),
            "by_reason": by_reason,
            "directions": {
                "routing_to_traffic": len([r for r in committed
                                           if r.get("direction") == "routing_to_traffic"]),
                "traffic_to_routing": len([r for r in committed
                                           if r.get("direction") == "traffic_to_routing"]),
            },
        },
        "meta": {
            "gt_source": str(Path(args.gt).relative_to(ROOT)),
            "runtime": "agents.paddle_runtime.run_paddle",
        },
    }
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")

    print(f"{'event':36s} {'committed':9s} {'direction':18s} {'reason':24s} vetoes")
    for record in records:
        print(f"{str(record.get('event_id',''))[:34]:36s} "
              f"{str(record.get('committed', record.get('outcome'))):9s} "
              f"{str(record.get('direction','-')):18s} "
              f"{str(record.get('reason', record.get('outcome','-')))[:24]:24s} "
              f"{record.get('vetoes', '')}")
    print()
    print(json.dumps(out["summary"], indent=1))
    print(f"\nwrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
