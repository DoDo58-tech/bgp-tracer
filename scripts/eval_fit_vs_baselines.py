"""Evaluate FIT against the timestamp/lead-lag baselines on the real event set."""
from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.causal_baselines import (  # noqa: E402
    granger_baseline,
    timestamp_distance_baseline,
)
from agents.falsification_test import PROTOCOL, infer_direction  # noqa: E402
from scripts.eval_hcaf_vs_baselines import (  # noqa: E402
    load_traffic_csv_for_event,
    resolve_asn,
    expected_direction,
    find_quick_cache_match,
    split_merged_timeline,
)

R2T, T2R = "routing_to_traffic", "traffic_to_routing"


# Cache -> aligned series
def build_series(
    row: Dict[str, str],
    quick_dir: Path,
    traffic_dir: Optional[Path],
) -> Tuple[Optional[np.ndarray], Optional[np.ndarray], Dict[str, Any]]:
    """Return ``(routing, traffic, info)`` for one dataset row."""
    asn = resolve_asn(row)
    info: Dict[str, Any] = {
        "reason": "",
        "asn": asn,
        "cache_file": None,
        "match": None,
        "channels": None,
    }
    if not asn:
        info["reason"] = "no_asn"
        return None, None, info

    start, end = row.get("start_time_utc", ""), row.get("end_time_utc", "")
    match = find_quick_cache_match(asn, start, end, quick_dir)
    if match is None:
        info["reason"] = "no_cache"
        return None, None, info
    info["cache_file"] = str(match.path)
    info["match"] = match.kind

    win_start = win_end = None
    try:
        win_start = datetime.fromisoformat(
            start.replace("Z", "").replace("T", " ").split(".")[0])
        win_end = datetime.fromisoformat(
            end.replace("Z", "").replace("T", " ").split(".")[0])
    except (ValueError):
        pass

    try:
        data = json.loads(match.path.read_text(encoding="utf-8"))
    except (KeyError, IndexError):
        info["reason"] = "cache_unreadable"
        return None, None, info
    corr = data.get("correlation", {}) or {}
    routing_full = corr.get("routing_events_full")
    traffic_full = corr.get("traffic_events_full")
    timeline = corr.get("timeline")

    events: List[dict] = []
    if routing_full:
        events.extend(routing_full)
    if traffic_full:
        events.extend(traffic_full)
    r_src = "cache" if routing_full else "timeline"
    t_src = "cache" if traffic_full else "timeline"
    if not events and timeline:
        events = list(timeline)

    if not traffic_full and traffic_dir is not None:
        extra = load_traffic_csv_for_event(row, traffic_dir)
        if extra:
            events.extend(extra)
            t_src = "traffic_csv"
    info["channels"] = f"{r_src}+{t_src}"

    if not events:
        info["reason"] = "cache_empty"
        return None, None, info

    events.sort(key=lambda e: str(e.get("timestamp", "")))
    routing_tl, traffic_tl = split_merged_timeline(
        events, window_start=win_start, window_end=win_end)
    if not routing_tl or not traffic_tl:
        info["reason"] = "empty_timeline"
        return None, None, info
    # ``split_merged_timeline`` floors every bucket at 1e-9 so that a flat
    if max(float(p.get("score", 0.0)) for p in routing_tl) <= 1e-6:
        info["reason"] = "no_routing_events"
        return None, None, info
    if max(float(p.get("score", 0.0)) for p in traffic_tl) <= 1e-6:
        info["reason"] = "no_traffic_events"
        return None, None, info

    r = np.array([float(p.get("score", 0.0)) for p in routing_tl])
    t = np.array([float(p.get("score", 0.0)) for p in traffic_tl])
    return r, t, info


# Metrics
def wilson(k: int, n: int, z: float = 1.96) -> Tuple[float, float]:
    """Wilson score interval for a binomial proportion."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def summarise(rows: List[Dict[str, Any]], key: str) -> Dict[str, Any]:
    preds = [(r.get(key), r["expected"]) for r in rows]
    preds = [(p, e) for p, e in preds if e]
    committed = [(p, e) for p, e in preds if p in (R2T, T2R)]
    correct = sum(1 for p, e in committed if p == e)
    lo, hi = wilson(correct, len(committed))
    return {
        "n": len(preds),
        "committed": len(committed),
        "coverage": round(len(committed) / len(preds), 3) if preds else 0.0,
        "correct": correct,
        "acc_committed": round(correct / len(committed), 3) if committed else None,
        "acc_committed_ci": [round(lo, 3), round(hi, 3)],
        "acc_all": round(correct / len(preds), 3) if preds else None,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=str(
        ROOT / "data_check/ground_truth_collection/final_ground_truth.csv"))
    ap.add_argument("--quick-dir", default=str(ROOT / "results/quick"))
    ap.add_argument("--traffic-dir", default=str(ROOT / "data/traffic"))
    ap.add_argument("--out", default=str(ROOT / "results/eval/fit_vs_baselines.jsonl"))
    ap.add_argument("--no-negative-control", dest="negative_control",
                    action="store_false", default=True)
    args = ap.parse_args()

    csv_path = Path(args.csv)
    quick_dir = Path(args.quick_dir)
    traffic_dir = Path(args.traffic_dir)
    traffic_dir = traffic_dir if traffic_dir.exists() else None
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if not csv_path.exists():
        print(f"dataset not found: {csv_path}")
        return 2

    records: List[Dict[str, Any]] = []
    series: List[Tuple[np.ndarray, np.ndarray]] = []
    skipped: Dict[str, int] = {}
    with open(csv_path, encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            expected = expected_direction(row)
            if not expected:
                continue
            r, t, info = build_series(row, quick_dir, traffic_dir)
            if r is None or t is None:
                skipped[info["reason"]] = skipped.get(info["reason"], 0) + 1
                continue

            fit = infer_direction(r, t)
            tl_r = [{"timestamp": str(i), "score": float(v)} for i, v in enumerate(r)]
            tl_t = [{"timestamp": str(i), "score": float(v)} for i, v in enumerate(t)]
            td = timestamp_distance_baseline(tl_r, tl_t)
            try:
                gr = granger_baseline(tl_r, tl_t)
            except (ValueError):
                gr = None

            rec: Dict[str, Any] = {
                "event_id": row.get("event_id", ""),
                "date": row.get("date", ""),
                "asn": info["asn"],
                "cause": row.get("ground_truth_cause_label", ""),
                "subtype": row.get("ground_truth_root_cause_subtype", ""),
                "expected": expected,
                "cache_file": info["cache_file"],
                "match": info["match"],
                "provenance": info["channels"],
                "n_buckets": int(len(r)),
                "fit": fit.as_dict(include_protocol=False),
                "fit_direction": fit.direction,
                "ts_direction": getattr(td, "direction", None),
                "granger_direction": getattr(gr, "direction", None) if gr else None,
            }
            records.append(rec)
            series.append((r, t))

# Controls
    if args.negative_control and records:
        for i, rec in enumerate(records):
            r_i, t_i = series[i]
            swapped = infer_direction(t_i, r_i)
            rec["swap_direction"] = swapped.direction
            rec["swap_reason"] = swapped.reason
            donor = series[(i + 1) % len(series)]
            donor_fit = infer_direction(r_i, donor[1])
            rec["control_direction"] = donor_fit.direction
            rec["control_reason"] = donor_fit.reason

    with open(out_path, "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    # Protocol metadata goes in a sidecar, not on the first line: the previous
    # layout made every consumer treat the metadata line as an event record.
    meta_path = out_path.with_suffix(".meta.json")
    meta_path.write_text(json.dumps({
        "protocol": PROTOCOL,
        "n": len(records),
        "dataset": csv_path.name,
        "skipped": skipped,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    # -- Report ------------------------------------------------------
    print(f"dataset: {csv_path.name}   rows scored: {len(records)}")
    if skipped:
        print("rows not scored (never substituted):")
        for reason, count in sorted(skipped.items(), key=lambda kv: -kv[1]):
            print(f"  {reason:<24}{count:>4}")
    print(f"protocol: {json.dumps(PROTOCOL, sort_keys=True)}")
    print()
    header = (f"{'method':<22}{'n':>4}{'commit':>8}{'cover':>7}{'correct':>9}"
              f"{'acc|commit':>12}{'95% CI':>16}{'acc(all)':>10}")
    print(header)
    print("-" * len(header))
    for key, label in (("fit_direction", "FIT (this work)"),
                       ("ts_direction", "timestamp distance"),
                       ("granger_direction", "Granger")):
        s = summarise(records, key)
        ci = f"[{s['acc_committed_ci'][0]:.2f},{s['acc_committed_ci'][1]:.2f}]"
        acc = "-" if s["acc_committed"] is None else f"{s['acc_committed']:.3f}"
        alla = "-" if s["acc_all"] is None else f"{s['acc_all']:.3f}"
        print(f"{label:<22}{s['n']:>4}{s['committed']:>8}{s['coverage']:>7.2f}"
              f"{s['correct']:>9}{acc:>12}{ci:>16}{alla:>10}")

    if args.negative_control:
        print()
        print("negative controls")
        contradict = sum(
            1 for rec in records
            if rec.get("fit_direction") in (R2T, T2R)
            and rec.get("swap_direction") == rec.get("fit_direction"))
        print(f"  swap (same data, swapped inputs): "
              f"{contradict} direction(s) reproduced -- must be 0")
        s = summarise(records, "control_direction")
        print(f"  {'donor-response pairs':<22}{s['n']:>4}{s['committed']:>8}"
              f"{s['coverage']:>7.2f}{s['correct']:>9}"
              f"{str(s['acc_committed']):>12}{'':>16}"
              f"{str(s['acc_all']):>10}")

    print()
    print("abstention reasons (FIT)")
    reasons: Dict[str, int] = {}
    for rec in records:
        if rec["fit_direction"] not in (R2T, T2R):
            reasons[rec["fit"]["reason"]] = reasons.get(rec["fit"]["reason"], 0) + 1
    for reason, count in sorted(reasons.items(), key=lambda kv: -kv[1]):
        print(f"  {reason:<28}{count:>4}")

    print()
    print("per-event FIT outcomes")
    for rec in records:
        fit = rec["fit"]
        ok = "" if rec["fit_direction"] not in (R2T, T2R) else (
            "  ok" if rec["fit_direction"] == rec["expected"] else "  MISS")
        print(f"  {rec['event_id'][:34]:<34} exp={rec['expected']:<19}"
              f"got={rec['fit_direction']:<19} lag={str(fit['lag']):>4} "
              f"p={fit['p_value']:.3f} {rec['fit']['reason']:<24}{ok}")

    fit_summary = summarise(records, "fit_direction")
    if records and fit_summary["committed"] == 0:
        print()
        print("WARNING: FIT committed on none of the resolvable events.")
        reasons: Dict[str, int] = {}
        for rec in records:
            reasons[rec["fit"]["reason"]] = reasons.get(rec["fit"]["reason"], 0) + 1
        for reason, count in sorted(reasons.items(), key=lambda kv: -kv[1]):
            if reason in {"series_too_short", "routing_series_flat",
                          "traffic_series_flat", "pre_period_too_short",
                          "post_window_too_short"}:
                print(f"  {count:>3} x {reason}")
        if any(r in reasons for r in ("series_too_short", "pre_period_too_short")):
            print("  The evidence windows are too short (or start too late) for any")
            print("  identification test.  Cut windows with >=50% pre-baseline and")
            print("  at least 12 buckets before reading this table as a result.")

    print(f"\nwrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
