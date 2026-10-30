#!/usr/bin/env python3
"""Detector ablations computed from the real cached detector outputs.

Each ablation zeroes one detector's contribution in the cached routing /
traffic payload and re-runs the production arbitration function
(`agents.report_agent.compute_top_cause`) on the same 29 attributable
ground-truth rows.  Nothing is simulated: the only inputs are the cache
files written by the detector pipeline and the curated label file.

Outputs
-------
results/eval/detector_ablation_v21.json
results/eval/detector_ablation_v21.csv
"""
from __future__ import annotations

import copy
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import agents.report_agent as ra  # noqa: E402
from agents.cache_resolution import resolve_cache  # noqa: E402

GT_CSV = ROOT / "data_check" / "ground_truth_collection" / "final_ground_truth.csv"
QUICK_DIR = ROOT / "results" / "quick"
OUT_JSON = ROOT / "results" / "eval" / "detector_ablation_v21.json"
OUT_CSV = ROOT / "results" / "eval" / "detector_ablation_v21.csv"

CLASSES = ("outage", "route_leak", "origin_hijack_victim")


def load_rows():
    with GT_CSV.open(newline="") as fh:
        return list(csv.DictReader(fh))


def resolve(asn, start, end, event_id):
    match = resolve_cache(asn, start, end, QUICK_DIR, event_id=event_id,
                          allow_same_date=False)
    if match is None:
        return None
    return match.path


def zero_detector(routing_raw, traffic_raw, which):
    """Return copies of the cached payloads with one detector neutralised."""
    routing = copy.deepcopy(routing_raw or {})
    traffic = copy.deepcopy(traffic_raw or {})
    if which == "leak":
        routing["route_leaks"] = []
        routing["leak_count"] = 0
        routing["leak_count_total"] = 0
        routing["leak_analysis"] = {}
    elif which == "hijack":
        routing["origin_hijacked"] = []
        routing["forge_hijacked"] = []
        routing["origin_hijacking"] = []
        routing["forge_hijacking"] = []
        routing["total_prefix_hijacks"] = 0
    elif which == "outage":
        routing["outage_suspected"] = False
        routing["outage_score"] = 0.0
        routing["outage_analysis"] = {}
        routing["outage_analysis_skipped"] = True
    elif which == "traffic":
        traffic["anomaly_count"] = 0
        traffic["anomalies_detected"] = False
        traffic["anomalies"] = []
        traffic["confidence"] = 0.0
        traffic["peak_trough_drop_pct"] = 0.0
    return routing, traffic


def predict(routing_raw, traffic_raw, correlation_raw, asn):
    hcaf_dir = ""
    if isinstance(routing_raw, dict):
        hcaf_dir = routing_raw.get("hcaf_direction", "") or ""
    routing_norm = ra.normalize_routing(routing_raw) if routing_raw else {}
    traffic_norm = ra.normalize_traffic(traffic_raw) if traffic_raw else {}
    if correlation_raw:
        correlation_norm = ra.normalize_correlation(
            correlation_raw,
            hcaf_attribution={"direction": hcaf_dir} if hcaf_dir else None,
        )
    else:
        correlation_norm = {"temporal_proximity": "none", "confidence": 0.0}
    verdict = ra.compute_top_cause(
        routing_norm, traffic_norm, correlation_norm,
        target_as=asn, hcaf_direction=hcaf_dir,
    )
    return verdict.get("cause", "unknown")


def macro_f1(pairs):
    """Macro-F1 over the three cause classes.

    `pairs` is a list of (ground_truth, predicted).  The negative control is
    excluded: it carries no cause label.
    """
    scores = []
    for cls in CLASSES:
        tp = sum(1 for g, p in pairs if g == cls and p == cls)
        fp = sum(1 for g, p in pairs if g != cls and p == cls)
        fn = sum(1 for g, p in pairs if g == cls and p != cls)
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        scores.append(f1)
    return sum(scores) / len(scores)


def micro_f1(pairs):
    """Micro-F1 over all rows."""
    tp = sum(1 for g, p in pairs if g == p)
    fp = sum(1 for g, p in pairs if g != p and p in CLASSES)
    fn = sum(1 for g, p in pairs if g in CLASSES and p != g)
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    return 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0


def main():
    rows = load_rows()
    variants = ["full", "drop_leak", "drop_hijack", "drop_outage",
                "drop_traffic", "drop_all"]

    per_variant = {v: [] for v in variants}
    n_cache = 0
    skipped = []

    for row in rows:
        event_id = (row.get("event_id") or "").strip()
        cause = (row.get("cause") or "").strip()
        is_nc = str(row.get("is_negative_control", "")).strip().lower() in ("true", "1")
        asn = str(row.get("victim_as") or "").replace("AS", "").strip()
        start = (row.get("start_utc") or "").strip()
        end = (row.get("end_utc") or "").strip()

        if is_nc or cause not in CLASSES:
            skipped.append(event_id)
            continue

        cache_file = resolve(asn, start, end, event_id)
        if cache_file is None:
            skipped.append(event_id)
            continue
        n_cache += 1

        cache = json.loads(Path(cache_file).read_text())
        routing_raw = cache.get("routing") or {}
        traffic_raw = cache.get("traffic") or {}
        correlation_raw = cache.get("correlation") or {}

        for variant in variants:
            if variant == "full":
                r, t = copy.deepcopy(routing_raw), copy.deepcopy(traffic_raw)
            elif variant == "drop_all":
                r, t = zero_detector(routing_raw, traffic_raw, "leak")
                r, t = zero_detector(r, t, "hijack")
                r, t = zero_detector(r, t, "outage")
                r, t = zero_detector(r, t, "traffic")
            else:
                r, t = zero_detector(routing_raw, traffic_raw, variant[5:])
            pred = predict(r, t, correlation_raw, asn)
            per_variant[variant].append((cause, pred))

    base_correct = sum(1 for g, p in per_variant["full"] if g == p)
    base_n = len(per_variant["full"])

    results = {}
    for variant in variants:
        pairs = per_variant[variant]
        n = len(pairs)
        correct = sum(1 for g, p in pairs if g == p)
        pct = 100.0 * correct / n if n else 0.0
        results[variant] = {
            "correct": correct,
            "total": n,
            "pct": round(pct, 1),
            "delta_pp": round(pct - 100.0 * base_correct / base_n, 1) if n else 0.0,
            "macro_f1": round(macro_f1(pairs), 3),
            "micro_f1": round(micro_f1(pairs), 3),
        }

    payload = {
        "experiment": "detector_ablation",
        "dataset": "final_ground_truth.csv",
        "n_events": base_n,
        "n_with_cache": n_cache,
        "n_skipped": len(skipped),
        "skipped_event_ids": skipped,
        "baseline_correct": base_correct,
        "baseline_pct": round(100.0 * base_correct / base_n, 1) if base_n else 0.0,
        "baseline_macro_f1": results["full"]["macro_f1"],
        "ablations": {k: v for k, v in results.items() if k != "full"},
    }

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(payload, indent=2) + "\n")

    with OUT_CSV.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["configuration", "correct", "total", "pct",
                         "delta_pp", "macro_f1", "micro_f1"])
        writer.writerow(["full", results["full"]["correct"],
                         results["full"]["total"], results["full"]["pct"],
                         0.0, results["full"]["macro_f1"],
                         results["full"]["micro_f1"]])
        for variant in variants:
            if variant == "full":
                continue
            r = results[variant]
            writer.writerow([variant, r["correct"], r["total"], r["pct"],
                             r["delta_pp"], r["macro_f1"], r["micro_f1"]])

    print(f"detector ablation over {base_n} attributable cached events")
    for variant in variants:
        r = results[variant]
        print(f"  {variant:16s} {r['correct']:2d}/{r['total']} = {r['pct']:5.1f}%  "
              f"Δ={r['delta_pp']:+5.1f}pp  macroF1={r['macro_f1']:.3f}  "
              f"microF1={r['micro_f1']:.3f}")
    print(f"wrote {OUT_JSON}")
    print(f"wrote {OUT_CSV}")


if __name__ == "__main__":
    main()
