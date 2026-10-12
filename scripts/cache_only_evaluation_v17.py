#!/usr/bin/env python3
"""Generate a CSV of (event, ground_truth, predicted) for all 30 events
using ONLY the cached telemetry signals + the new compute_top_cause logic.

This bypasses the LLM entirely, so no LLM quota is consumed and it
finishes in seconds. The output is a clear 'what the deterministic
detectors would say right now' table.
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, "/data/bgp_tracer")
import importlib

import agents.report_agent as ra

importlib.reload(ra)
from agents.report_agent import compute_top_cause, _normalize_routing


ROOT = Path("/data/bgp_tracer")
CSV_PATH = ROOT / "data_check/ground_truth_collection/final_balanced_dataset_v17.csv"
QUICK_DIR = ROOT / "results/quick"
OUT = ROOT / "results/cache_predicted_v17.csv"


def _resolve_target_as(row: dict) -> str:
    """Mimic run_4mode_batch._resolve_target_asn exactly."""
    etype = (row.get("event_type") or "").strip().lower()
    label = (row.get("ground_truth_cause_label") or "").strip().lower()
    is_leak = etype in {"leak", "route_leak"} or label == "route_leak"
    order = ("leak_as", "attacker_as", "victim_as") if is_leak else (
        "victim_as", "attacker_as", "leak_as")
    for field in order:
        v = (row.get(field) or "").replace("AS", "").strip()
        if v:
            return v
    return ""


def _find_quick(event_id: str, victim_as: str, gt_start: str = "") -> Path | None:
    """Pick the most plausible quick_<victim_as>_*.json whose window
    matches the event date if available, else fall back to the most
    recently modified one. Among matched files, prefer the one with
    the shortest analysis window (smallest total duration implied by
    the filename timestamps).

    ``gt_start`` is the ground-truth start_time_utc (YYYY-MM-DD HH:MM).
    When ``event_id`` carries no specific date (e.g. ``outage_starlink_2025``)
    we fall back to the ground-truth start date so the cache selected
    actually corresponds to the same calendar day as the event. This
    prevents a low-precision year-only match (2025-05-20) from outvoting
    a high-precision YYYYMMDD match (2025-07-24).
    """
    import re
    from datetime import datetime
    candidates = list(QUICK_DIR.glob(f"quick_{victim_as}_*.json"))
    if not candidates:
        return None
    # Build date candidates ordered by specificity (most specific first).
    # Each batch is processed in order; the first batch that yields ≥1 match
    # wins. This prevents low-precision year-only matches from outvoting
    # high-precision YYYYMMDD matches.
    candidate_batches: list[list[str]] = []
    # Batch 0: ground-truth start_time_utc YYYYMMDD — used when the
    # event_id lacks an explicit date and we have authoritative GT info.
    if gt_start:
        gt_ymd = re.search(r"(20\d{2})-(\d{2})-(\d{2})", gt_start)
        if gt_ymd:
            candidate_batches.append([gt_ymd.group(1) + gt_ymd.group(2) + gt_ymd.group(3)])
    # Batch 1: full YYYYMMDD anywhere in event_id.
    full = re.findall(r"20\d{6}", event_id)
    if full:
        candidate_batches.append(full)
    # Batch 2: YYYY-MM-DD or YYYY_MM_DD form (e.g. "outage_grameenphone_2024_07_17").
    ymd = [m.group(1) + m.group(2) + m.group(3)
           for m in re.finditer(r"(20\d{2})[-_](\d{2})[-_](\d{2})", event_id)]
    if ymd:
        candidate_batches.append(ymd)
    # Batch 3: year only (fallback).
    m_year_only = re.search(r"(20\d{2})(?:\b|[^0-9])", event_id)
    if m_year_only:
        candidate_batches.append([m_year_only.group(1)])

    def _matches_date(p: Path, batch: list[str]) -> bool:
        c_clean = p.name.replace("-", "").replace(" ", "").replace("T", "")
        return any(d in c_clean for d in batch)

    matched: list[Path] = []
    for batch in candidate_batches:
        batch_matched = [c for c in candidates if _matches_date(c, batch)]
        if batch_matched:
            matched = batch_matched
            break
    if not matched:
        matched = []
    if matched:
        def _window_score(p: Path) -> float:
            ts = re.findall(r"\d{4}-\d{2}-\d{2}[ _T]?\d{2}[: ]?\d{2}", p.name)
            if len(ts) >= 2:
                try:
                    s = ts[0].replace(" ", "T").replace("_", "T").replace(":", "")
                    e = ts[-1].replace(" ", "T").replace("_", "T").replace(":", "")
                    s = re.sub(r"(\d{2})(\d{2})$", r"\1:\2", s)
                    e = re.sub(r"(\d{2})(\d{2})$", r"\1:\2", e)
                    ds = datetime.fromisoformat(s)
                    de = datetime.fromisoformat(e)
                    return (de - ds).total_seconds()
                except Exception:
                    pass
            return 999999.0
        # Among date-matched files, prefer the one with the smallest window.
        # If multiple files share the same minimum window, prefer the most
        # recently modified one.
        matched.sort(key=_window_score)
        # Group by window score and take the freshest within the smallest group.
        best_score = _window_score(matched[0])
        best = sorted(
            [m for m in matched if _window_score(m) == best_score],
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )[0]
        return best
    # No date match — fall back to freshest file.
    return sorted(candidates, key=lambda p: p.stat().st_mtime, reverse=True)[0]


def main() -> int:
    with open(CSV_PATH) as f:
        rows = list(csv.DictReader(f))

    out_rows: list[dict] = []
    n_correct = 0
    n_excl = 0
    n_excl_correct = 0
    print(f"Loaded {len(rows)} events from {CSV_PATH.name}")
    print()

    for row in rows:
        ev_id = row["event_id"]
        gt = (row.get("ground_truth_cause_label") or "").strip().lower()
        # Negative-control events are NOT BGP at all (e.g. Starlink).
        # The detector is expected to return 'no_clear_anomaly' — this
        # is the system working correctly, not an error.
        is_neg = (row.get("ground_truth_root_cause_subtype") or "").strip().lower() == "internal_failure_non_bgp"

        target_as = _resolve_target_as(row)
        gt_start = (row.get("start_time_utc") or "").strip()
        cache = _find_quick(ev_id, target_as, gt_start) if target_as else None
        if cache is None:
            pred = "MISSING_CACHE"
            ranked = []
            top = "n/a"
            conf = 0.0
            try:
                skipped = True
                match = False
            except Exception:
                skipped = True
                match = False
            print(f"  {ev_id:50} ASN={target_as:10} GT={gt:25} PRED=NO_CACHE            match=False")
            out_rows.append({
                "event_id": ev_id,
                "ground_truth": gt,
                "predicted": pred,
                "top1_confidence": 0.0,
                "ranked": "",
                "is_negative_control": is_neg,
                "match": False,
                "cache_path": "",
            })
            continue

        try:
            data = json.loads(cache.read_text())
        except Exception as e:
            print(f"  {ev_id:50} ERROR reading cache: {e}")
            continue
        # Print cache + ev for debugging mispredictions.
        rout = data.get("routing", {})
        traffic = data.get("traffic", {})
        corr = data.get("correlation", {})
        routing_norm = _normalize_routing(rout)
        traffic_norm = {
            "anomaly_count": int(traffic.get("anomaly_count", 0)),
            "peak_trough_drop_pct": float(traffic.get("peak_trough_drop_pct", 0.0)),
        }
        correlation_norm = {
            "temporal_proximity": corr.get("summary", {}).get("correlation_level", "none"),
            "confidence": corr.get("summary", {}).get("correlation_confidence", 0.0),
        }
        top = compute_top_cause(
            routing_norm=routing_norm,
            traffic_norm=traffic_norm,
            correlation_norm=correlation_norm,
            target_as=target_as,
            hcaf_direction=str(correlation_norm.get("hcaf_direction") or ""),
        )
        ranked = top.get("ranked", [])
        top_cause = top.get("cause", "")
        conf = float(top.get("confidence", 0.0))
        # Determine match
        if is_neg:
            match = (top_cause == "no_clear_anomaly" or top_cause == "traffic_anomaly_only")
        else:
            match = (top_cause == gt)
        if match:
            n_correct += 1
        if not is_neg:
            n_excl += 1
            if match:
                n_excl_correct += 1
        ranked_str = "|".join(f"{r['cause']}={r['confidence']:.2f}" for r in ranked[:3])
        print(f"  {ev_id:50} ASN={target_as:10} GT={gt:25} PRED={top_cause:25} conf={conf:.2f} {'OK' if match else 'X'}")
        out_rows.append({
            "event_id": ev_id,
            "ground_truth": gt,
            "predicted": top_cause,
            "top1_confidence": conf,
            "ranked": ranked_str,
            "is_negative_control": is_neg,
            "match": match,
            "cache_path": str(cache),
        })

    print()
    total = len(rows)
    print(f"=== Cache-based deterministic evaluation (no LLM) ===")
    print(f"All events:    {n_correct}/{total} = {n_correct/total:.1%}")
    print(f"Excl neg ctl:  {n_excl_correct}/{n_excl} = "
          f"{n_excl_correct/n_excl:.1%}  (Starlink is the negative control)")

    # Show the misses.
    misses = [r for r in out_rows if not r["match"]]
    if misses:
        print()
        print(f"Misses ({len(misses)}):")
        for r in misses:
            print(f"  {r['event_id']:50} GT={r['ground_truth']:25} PRED={r['predicted']:25}")
    # Save CSV.
    OUT.parent.mkdir(parents=True, exist_ok=True)
    keys = list(out_rows[0].keys())
    with open(OUT, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for r in out_rows:
            writer.writerow(r)
    print(f"\nWrote {OUT}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
