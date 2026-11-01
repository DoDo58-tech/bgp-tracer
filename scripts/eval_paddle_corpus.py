"""Evaluate PADDLE on the canonical ground truth, through the runtime.

This is the production path: the same :func:`agents.paddle_runtime.run_paddle`
the chief agent calls, fed the same detector payloads the chief agent is
fed.  The script re-implements no part of the estimator.

The control plane comes from the update archive, because that is the only
place the target's *own* announcements are recorded.  The detector's
cached feature series counts involvement, which stays flat through an
outage and therefore cannot support a causal claim.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.cache_resolution import resolve_cache
from agents.control_plane_archive import (
    BASELINE_DAYS,
    build_control_plane_evidence,
)
from agents.paddle_runtime import run_paddle
from agents.temporal import parse_timestamp

GT_CSV = ROOT / "data_check/ground_truth_collection/final_ground_truth.csv"
QUICK = ROOT / "results/quick"
EVIDENCE_CACHE = ROOT / "results/eval/control_evidence"
DEFAULT_OUT = ROOT / "results/eval/paddle_corpus.json"
SCAN_MARGIN_MINUTES = 120


def unwrap(payload):
    """The result dict, whether it is wrapped or bare."""
    if isinstance(payload, dict):
        for key in ("result", "data", "payload"):
            inner = payload.get(key)
            if isinstance(inner, dict) and inner:
                return inner
    return payload if isinstance(payload, dict) else {}


def first_asn_results(block):
    """The per-ASN results of a detector block."""
    if not isinstance(block, dict):
        return []
    for key in ("asn_results", "results", "per_asn"):
        value = block.get(key)
        if isinstance(value, list) and value:
            return [v for v in value if isinstance(v, dict)]
    return [block]


def traffic_timeline_of(traffic_block):
    """The traffic anomalies, as timestamped observations."""
    timeline = []
    for asn_result in first_asn_results(traffic_block):
        for anomaly in asn_result.get("anomalies") or []:
            if not isinstance(anomaly, dict):
                continue
            stamp = anomaly.get("timestamp") or anomaly.get("time")
            if stamp:
                timeline.append({"timestamp": stamp, "event_type": "traffic_anomaly",
                                 "raw_event": anomaly})
        break
    return timeline


def routing_timeline_of(routing_block):
    """The routing edges, as timestamped observations."""
    timeline = []
    for key in ("origin_hijacked", "forge_hijacked", "origin_hijacking",
                "forge_hijacking", "route_leaks"):
        for found in routing_block.get(key) or []:
            if not isinstance(found, dict):
                continue
            stamp = (found.get("timestamp") or found.get("first_seen")
                     or found.get("time"))
            if stamp:
                timeline.append({"timestamp": stamp,
                                 "event_type": found.get("event_type") or found.get("type"),
                                 "raw_event": found})
    outage = routing_block.get("outage_analysis") or routing_block.get("outage") or {}
    if outage.get("is_outage_suspected"):
        stamp = outage.get("timestamp") or outage.get("first_seen")
        if stamp:
            timeline.append({"timestamp": stamp, "event_type": "outage",
                             "raw_event": outage})
    return timeline


def scan_window(cache, event):
    """The window the archive is scanned over.

    It is the union of the published window and the traffic impact
    window, because for several events the traffic fell before the
    published window opened.
    """
    traffic_block = unwrap(cache.get("traffic"))
    window = traffic_block.get("consecutive_anomaly_windows") or []
    if not window and isinstance(traffic_block.get("expanded_windows"), list):
        window = traffic_block["expanded_windows"]
    bounds = [parse_timestamp(event.get("start_utc")), parse_timestamp(event.get("end_utc"))]
    for item in window:
        if isinstance(item, dict):
            bounds.append(parse_timestamp(item.get("start")))
            bounds.append(parse_timestamp(item.get("end")))
    bounds = [b for b in bounds if b is not None]
    if not bounds:
        return None, None
    margin = SCAN_MARGIN_MINUTES * 60
    return min(bounds), max(bounds)


def evidence_cache_path(asn, lo, hi):
    return EVIDENCE_CACHE / f"{asn}_{lo:%Y%m%d%H%M}_{hi:%Y%m%d%H%M}.json"


def load_evidence(asn, lo, hi, refresh=False):
    """The archive measurement for one window, cached on disk.

    The scan reads hundreds of millions of rows, so its result is kept.
    The payload holds the raw per-slot counts, so a later correction to
    the counterfactual's definition can be applied without re-scanning.
    """
    path = evidence_cache_path(asn, lo, hi)
    if path.is_file() and not refresh:
        payload = json.loads(path.read_text(encoding="utf-8"))
        from agents.control_plane_archive import ControlPlaneEvidence
        evidence = ControlPlaneEvidence.from_payload(
            payload, window_start=lo, baseline_days=BASELINE_DAYS)
        refreshed = evidence.to_payload()
        if refreshed.get("baseline") != payload.get("baseline"):
            path.write_text(json.dumps(refreshed), encoding="utf-8")
        return refreshed
    evidence = build_control_plane_evidence(asn, lo, hi)
    payload = evidence.to_payload()
    EVIDENCE_CACHE.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return payload


def warm_cache(events):
    """Build the parquet cache for every window the corpus needs.

    The scan reads every five-minute update file in the window and in
    the baseline days before it.  A file whose parquet is missing has
    to be decoded from its raw text first, and the same files are
    needed by every event.  So the cache is built once, for exactly
    the ranges the corpus covers, and the scan then reads parquet.

    The workers are few, because the decode is disk-heavy and the point
    is to keep the machine responsive.
    """
    from agents.control_plane import BASELINE_DAYS

    ranges = []
    for event in events:
        cache = load_cache_for(event)
        if cache is None:
            continue
        lo, hi = scan_window(cache, event)
        if lo is None:
            continue
        ranges.append((lo - timedelta(days=BASELINE_DAYS), hi))

    if not ranges:
        return

    stamps = set()
    for lo, hi in ranges:
        stamp = lo.replace(second=0, microsecond=0)
        stamp = stamp.replace(minute=(stamp.minute // 5) * 5)
        while stamp <= hi:
            stamps.add(stamp)
            stamp += timedelta(minutes=5)

    todo = [s for s in sorted(stamps) if not parquet_ready(s)]
    if not todo:
        print(f"parquet cache: {len(stamps)} window(s) ready")
        return
    print(f"parquet cache: building {len(todo)} of {len(stamps)} window(s)",
          flush=True)
    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(build_window, todo))
    print(f"parquet cache: {len(stamps)} window(s) ready", flush=True)


def parquet_ready(stamp):
    from data.parquet_cache import PARQUET_DIR, parquet_version_matches
    text = stamp.strftime("%Y%m%d.%H%M")
    path = PARQUET_DIR / f"updates.{text}.parquet"
    return path.exists() and parquet_version_matches(path)


def build_window(stamp):
    from data.parquet_cache import DECODED_DIR, UPDATES_ROOT, ensure_parquet
    text = stamp.strftime("%Y%m%d.%H%M")
    for source in (DECODED_DIR / f"updates.{text}.txt",
                   UPDATES_ROOT / f"updates.{text}.gz"):
        if source.exists() and source.stat().st_size > 0:
            ensure_parquet(source)
            return
    return


def load_cache_for(event):
    """The detector cache for one event, or None."""
    asn = str(event.get("victim_as") or event.get("target_as") or "")
    match = resolve_cache(asn, event.get("start_utc"), event.get("end_utc"),
                          QUICK, event_id=event.get("event_id") or "",
                          allow_same_date=False)
    if match is None:
        return None
    return json.loads(match.path.read_text(encoding="utf-8"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gt", default=str(GT_CSV))
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    ap.add_argument("--refresh", action="store_true")
    ap.add_argument("--no-warm", action="store_true")
    args = ap.parse_args()

    events = list(csv.DictReader(open(args.gt, encoding="utf-8")))
    if not args.no_warm:
        warm_cache(events)
    records = []

    for event in events:
        event_id = event.get("event_id") or ""
        asn = str(event.get("victim_as") or event.get("target_as") or "")
        match = resolve_cache(asn, event.get("start_utc"), event.get("end_utc"),
                              QUICK, event_id=event_id, allow_same_date=False)
        if match is None:
            records.append({"event_id": event_id, "cause": event.get("cause"),
                            "outcome": "no_cache"})
            continue

        cache = json.loads(match.path.read_text(encoding="utf-8"))
        traffic_block = unwrap(cache.get("traffic"))
        routing_block = unwrap(cache.get("routing"))
        traffic_timeline = traffic_timeline_of(traffic_block)
        if not traffic_timeline:
            records.append({"event_id": event_id, "cause": event.get("cause"),
                            "outcome": "no_traffic"})
            continue

        lo, hi = scan_window(cache, event)
        if lo is None:
            records.append({"event_id": event_id, "cause": event.get("cause"),
                            "outcome": "no_window"})
            continue
        payload = load_evidence(asn, lo, hi, refresh=args.refresh)

        outage = routing_block.get("outage_analysis") or routing_block.get("outage") or {}
        verdict, control, observations = run_paddle(
            routing_analysis=outage,
            traffic_timeline=traffic_timeline,
            routing_timeline=routing_timeline_of(routing_block),
            routing_context={},
            traffic_block=traffic_block,
            window_start=lo,
            window_end=hi,
            archive_evidence=payload,
        )

        tests = getattr(verdict, "tests", None) or {}
        trough = tests.get("trough") or {}
        record = {
            "event_id": event_id,
            "cause": event.get("cause"),
            "outcome": "measured",
            "committed": bool(verdict.committed),
            "direction": verdict.direction if verdict.committed else "unknown",
            "reason": verdict.reason,
            "vetoes": dict(verdict.vetoes),
            "channel": verdict.channel,
            "trough": trough.get("stamp"),
            "trough_deviation": trough.get("deviation"),
            "channels": tests.get("channels"),
            "evidence_file": str(match.path),
            "n_traffic_observations": len(observations),
            "n_control_slots": len(control.stamps),
        }
        records.append(record)

    committed = [r for r in records if r.get("committed")]
    reasons = {}
    for record in records:
        reason = str(record.get("reason") or record.get("outcome") or "unknown")
        reasons[reason] = reasons.get(reason, 0) + 1

    out = {
        "records": records,
        "summary": {
            "corpus_total": len(events),
            "measured": len([r for r in records if r.get("outcome") == "measured"]),
            "committed": len(committed),
            "abstained": len(records) - len(committed),
            "by_reason": reasons,
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
            "control_plane": "agents.control_plane_archive (update archive)",
        },
    }
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(out, indent=1, default=str), encoding="utf-8")

    print(f"{'event':36s} {'committed':9s} {'direction':18s} {'reason':22s} vetoes")
    for record in records:
        print(f"{str(record.get('event_id',''))[:34]:36s} "
              f"{str(record.get('committed', record.get('outcome'))):9s} "
              f"{str(record.get('direction','-')):18s} "
              f"{str(record.get('reason', record.get('outcome','-')))[:22]:22s} "
              f"{record.get('vetoes', '')}")
    print()
    print(json.dumps(out["summary"], indent=1))
    print(f"\nwrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
