"""Paper §6 timing benchmark: phase-level wall-clock across multiple events.

Runs Phase 1 + CSS-only (no LLM) on the first 6 v11 events that have
real quick caches, and produces results/bench/multi_event_timing.csv
with per-phase elapsed times.
"""
from __future__ import annotations

import csv
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agents.css_engine import css_score, bayesian_synthesize  # noqa: E402

QUICK_DIR = ROOT / "results" / "quick"
JSONL = ROOT / "results" / "eval" / "hcaf_vs_baselines_v11.jsonl"
OUT_CSV = ROOT / "results" / "bench" / "multi_event_timing.csv"
OUT_CSV.parent.mkdir(parents=True, exist_ok=True)


def build_timelines_from_cache(cache_path: Path):
    """Mirror scripts/build_ablation.py — same timeline construction."""
    p = json.loads(cache_path.read_text())
    start = p.get("start_time") or p.get("start_time_utc")
    if not start:
        return [], []
    from datetime import datetime, timedelta
    end = p.get("end_time") or p.get("end_time_utc")
    try:
        if "T" in start:
            fmt = "%Y-%m-%dT%H:%M:%S"
        else:
            fmt = "%Y-%m-%d %H:%M:%S"
        t0 = datetime.strptime(start.split("+")[0].split("Z")[0], fmt)
        t1 = datetime.strptime(end.split("+")[0].split("Z")[0], fmt)
    except Exception:
        return [], []
    n_buckets = max(8, int((t1 - t0).total_seconds() // (5 * 60)))
    routing_score = [0.0] * n_buckets
    traffic_score = [0.0] * n_buckets
    routing = p.get("routing", {}) or {}
    routing_events = []
    for key in ("origin_hijacked", "forge_hijacked", "route_leaks", "leak_analysis",
                "outage_analysis", "hijack_events", "leak_events"):
        v = routing.get(key, [])
        if isinstance(v, list):
            routing_events.extend(v)
    for ev in routing_events:
        ts = ev.get("timestamp") or ev.get("time") or ev.get("start_time") or ""
        try:
            t = datetime.strptime(str(ts).split("+")[0].split("Z")[0], fmt)
            idx = int((t - t0).total_seconds() // (5 * 60))
            if 0 <= idx < n_buckets:
                routing_score[idx] += 1.0
        except Exception:
            continue
    routing_score = [min(s, 1.0) for s in routing_score]
    traffic = p.get("traffic", {}) or {}
    anomalies = traffic.get("anomalies", []) or []
    for an in anomalies:
        ts = an.get("timestamp") or an.get("time") or ""
        try:
            t = datetime.strptime(str(ts).split("+")[0].split("Z")[0], fmt)
            idx = int((t - t0).total_seconds() // (5 * 60))
            if 0 <= idx < n_buckets:
                traffic_score[idx] = 1.0
        except Exception:
            continue
    routing_tl = [{"score": s} for s in routing_score]
    traffic_tl = [{"score": s} for s in traffic_score]
    return routing_tl, traffic_tl


def main() -> None:
    real_events = [
        "hijack_orange_spain_2024",
        "leak_upx_2025",
        "leak_reliablesite_2025",
        "outage_starlink_2025",
        "outage_iran_2025",
        "outage_pakistan_2024",
    ]
    rows = []
    for line in JSONL.open():
        rec = json.loads(line)
        ev = rec["event_id"]
        if ev not in real_events:
            continue
        cache_path = ROOT / rec["cache_source"]
        if not cache_path.exists():
            continue
        t_total = time.perf_counter()
        t0 = time.perf_counter()
        routing_tl, traffic_tl = build_timelines_from_cache(cache_path)
        t_phase1 = time.perf_counter() - t0

        t0 = time.perf_counter()
        try:
            css_res = css_score(routing_tl, traffic_tl, n_bootstrap=500, min_samples=2)
        except Exception:
            css_res = None
        t_css = time.perf_counter() - t0

        t0 = time.perf_counter()
        # Mock channels
        ch = {"msbd": {"direction": css_res.direction if css_res else "unknown",
                       "likelihood": {"routing_to_traffic": 1.5, "traffic_to_routing": 1.0, "independent": 1.0}}}
        try:
            posterior = bayesian_synthesize(css_res, ch)
        except Exception:
            posterior = {}
        t_bayes = time.perf_counter() - t0

        t_full = time.perf_counter() - t_total

        rows.append({
            "event_id": ev,
            "n_buckets": len(routing_tl),
            "phase1_load_s": round(t_phase1, 4),
            "css_score_s": round(t_css, 4),
            "bayesian_synthesize_s": round(t_bayes, 4),
            "phase1_plus_causal_s": round(t_full, 4),
            "css_is_causal": css_res.is_causal if css_res else None,
            "css_direction": css_res.direction if css_res else None,
        })

    if not rows:
        print("FATAL: no events timed", file=sys.stderr)
        sys.exit(1)
    fieldnames = list(rows[0].keys())
    with OUT_CSV.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    print(f"{'event_id':<32} {'phase1':>8} {'css':>8} {'bayes':>8} {'total':>8}  css_dir")
    print("-" * 80)
    for r in rows:
        print(f"{r['event_id']:<32} {r['phase1_load_s']:>8.3f} {r['css_score_s']:>8.3f} "
              f"{r['bayesian_synthesize_s']:>8.3f} {r['phase1_plus_causal_s']:>8.3f}  {r['css_direction']}")
    print()
    print(f"Wrote → {OUT_CSV.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
