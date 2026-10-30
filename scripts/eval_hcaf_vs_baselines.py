"""Paper §6 ablation: CSS (Pearl PNS) + HCAF vs 4 traditional baselines."""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agents.causal_baselines import run_all_baselines                # noqa: E402
from agents.cache_resolution import CacheMatch, resolve_cache        # noqa: E402
from agents.causal_attribution import CausalAttributionEngine        # noqa: E402
from agents.css_engine import css_score                              # noqa: E402

# Reporting cutoff for the paper's "CSS alone" row: the posterior mass the
CSS_ALONE_POSTERIOR_FLOOR = 0.34


# Ground-truth → expected direction mapping
# Same logic as tests/test_hcaf_consistency.py so the paper table is
# directly comparable to the unit-test result.
def expected_direction(row: Dict[str, str]):
    """Map a ground-truth row to the expected HCAF direction label."""
    cause = row.get("ground_truth_cause_label", "")
    subtype = row.get("ground_truth_root_cause_subtype", "")
    # Tier C derived attacker_view rows have no independent ground truth;
    # skip them (matches tests/test_hcaf_consistency.py behaviour).
    if "_attacker_view" in row.get("event_id", ""):
        return None
    if cause in {"route_leak", "origin_hijack_victim", "origin_hijack_attacker",
                 "roa_misconfig"}:
        return "routing_to_traffic"
    if cause == "outage":
        # FIX: internal_network_failure (e.g. Starlink) is a traffic-side fault
        # whose BGP signal is a side-effect, not a causal driver. The routing
        # withdrawal rate for Starlink is 2/406845 = 0.0005%, clearly noise.
        if subtype == "internal_network_failure":
            return "traffic_to_routing"
        # New authoritative source: routing_event_in_window was filled from
        # the cited public report. The numeric routing_withdrawal_count is
        # only consulted when this is empty / unknown.
        rei = (row.get("routing_event_in_window", "") or "").strip().lower()
        if rei == "yes":
            return "routing_to_traffic"
        if rei == "no":
            return "traffic_to_routing"
        try:
            withdrawal = int(row.get("routing_withdrawal_count", 0) or 0)
        except ValueError:
            withdrawal = 0
        if withdrawal > 0:
            return "routing_to_traffic"
        # No BGP withdrawal → DPI / filternet / internal fault → T→R
        return "traffic_to_routing"
    return None


# Quick-cache loader
def normalise_start(s):
    """v10 dataset uses ``YYYY-MM-DD HH:MM``; quick cache uses
    ``YYYY-MM-DDTHH:MM:SS``. Normalise both to ``YYYY-MM-DDTHH:MM`` so
    we can match cache files to dataset rows."""
    return s.replace(" ", "T")[:16]


def load_traffic_csv_for_event(
    row: Dict[str, str],
    traffic_dir: Path,
    sigma: float = 1.5,
) -> List[dict]:
    """Load traffic CSV for an event and return traffic anomaly events."""
    try:
        import pandas as pd
    except ImportError:
        return []

    from datetime import datetime, timedelta, timezone

    cause = row.get("ground_truth_cause_label", "")
    if cause == "route_leak":
        asn = row.get("leak_as", "").replace("AS", "").strip()
    else:
        asn = row.get("victim_as", "").replace("AS", "").strip()

    if not asn:
        return []

    event_start_str = row.get("start_time_utc", "")
    event_end_str = row.get("end_time_utc", "")

    # Find traffic CSV for this ASN.
    csv_paths = sorted(traffic_dir.glob(f"AS{asn}_traffic_*.csv"))
    if not csv_paths:
        return []

    # Parse the event window as NAIVE datetimes. The dataset writes these as
    try:
        ev_start_dt = datetime.fromisoformat(
            event_start_str.replace("Z", "+00:00").replace("T", " ").split(".")[0]
        )
        ev_end_dt = datetime.fromisoformat(
            event_end_str.replace("Z", "+00:00").replace("T", " ").split(".")[0]
        )
    except (ValueError):
        return []
    if ev_start_dt.tzinfo is not None:
        ev_start_dt = ev_start_dt.astimezone(timezone.utc).replace(tzinfo=None)
    if ev_end_dt.tzinfo is not None:
        ev_end_dt = ev_end_dt.astimezone(timezone.utc).replace(tzinfo=None)

    frames = []
    unit_by_file = {}
    for path in csv_paths:
        try:
            cand = pd.read_csv(path)
        except (ValueError):
            continue
        if "timestamp" not in cand.columns:
            continue
        col = next((c for c in ("normalized_traffic", "value") if c in cand.columns), None)
        if col is None:
            continue
        try:
            cand_ts = pd.to_datetime(cand["timestamp"], format="mixed", utc=True, errors="coerce")
        except (ValueError):
            continue
        cand_naive = cand_ts.dt.tz_localize(None)
        try:
            cand_vals = cand[col].astype(float).values
        except (ValueError):
            continue
        window = (cand_naive >= ev_start_dt) & (cand_naive <= ev_end_dt)
        # Keep a file only if it actually samples the event window, and keep
        # enough leading history to still form a pre-event baseline.
        if not window.any():
            continue
        lead = (cand_naive < ev_start_dt) & (cand_naive >= ev_start_dt - timedelta(days=7))
        if not (window | lead).any():
            continue
        peak = float(abs(cand_vals).max()) if len(cand_vals) else 0.0
        unit_by_file[path.name] = "raw" if peak > 100.0 else "normalized"
        frames.append(cand_naive[window | lead].to_frame("ts").assign(
            value=cand_vals[(window | lead).to_numpy()]))

    if not frames:
        return []

    units = set(unit_by_file.values())
    if len(units) > 1:
        # Prefer the unit used by the most covering files; never merge scales.
        counts: dict = {}
        for u in unit_by_file.values():
            counts[u] = counts.get(u, 0) + 1
        keep = max(counts, key=counts.get)
        frames = [
            f for f, name in zip(frames, unit_by_file.keys())
            if unit_by_file[name] == keep
        ]
    merged = pd.concat(frames).drop_duplicates(subset=["ts"]).sort_values("ts")
    df = pd.DataFrame({"timestamp": merged["ts"], "value": merged["value"]})

    # Determine value column
    val_col = "value"

    # Parse timestamps — use UTC-aware parsing then strip tzinfo to get naive datetimes.
    # This avoids timezone comparison bugs between pandas Series and Timestamp objects.
    try:
        ts_raw = pd.to_datetime(df["timestamp"], format="mixed", utc=True, errors="coerce")
        ts_naive = ts_raw.dt.tz_localize(None)  # strip UTC tzinfo → naive
    except (ValueError):
        return []

    try:
        vals = df[val_col].astype(float).values
    except (ValueError):
        return []

    # Remove NaT and NaN by converting to numpy arrays early.
    import numpy as np
    ts_np = np.array(ts_naive, dtype="datetime64[s]")
    valid = ~(np.isnat(ts_np) | np.isnan(vals))
    ts_np = ts_np[valid]
    vals = vals[valid]

    if len(ts_np) < 10:
        return []

    # ev_start_dt / ev_end_dt were already parsed above, while selecting the
    # covering cache files. np is imported above for the same reason.
    ev_start_np = np.datetime64(ev_start_dt)
    ev_end_np = np.datetime64(ev_end_dt)
    pre_start_np = ev_start_np - np.timedelta64(7, "D")

    # Baseline from pre-event window
    pre_mask = (ts_np >= pre_start_np) & (ts_np < ev_start_np)
    pre_vals = vals[pre_mask]
    if len(pre_vals) < 5:
        return []

    baseline_mean = float(np.mean(pre_vals))
    baseline_std = float(np.std(pre_vals))
    if baseline_std <= 0:
        baseline_std = 1.0

    upper_thresh = baseline_mean + sigma * baseline_std
    lower_thresh = baseline_mean - sigma * baseline_std

    # Event window
    ev_mask = (ts_np >= ev_start_np) & (ts_np <= ev_end_np)
    ev_ts = ts_np[ev_mask]
    ev_vals = vals[ev_mask]

    events = []
    for i in range(len(ev_ts)):
        v = float(ev_vals[i])
        ts_val = ev_ts[i]
        if v > upper_thresh:
            sev = min((v - upper_thresh) / baseline_std, 5.0)
            ts_str = str(ts_val).replace("+00:00", "").replace("T", " ")
            events.append({
                "timestamp": ts_str,
                "source": "traffic",
                "severity": float(sev),
            })
        elif v < lower_thresh:
            sev = min((lower_thresh - v) / baseline_std, 5.0)
            ts_str = str(ts_val).replace("+00:00", "").replace("T", " ")
            events.append({
                "timestamp": ts_str,
                "source": "traffic",
                "severity": float(sev),
            })

    return events


def resolve_asn(row: Dict[str, str]):
    """Pick the right ASN column for quick-cache lookup."""
    for col in ("victim_as", "leak_as", "attacker_as"):
        v = row.get(col, "").strip()
        if v:
            return v.replace("AS", "")
    return ""


def find_quick_cache_match(
    asn: str,
    start: str,
    end: str,
    quick_dir: Path,
    *,
    event_id: Optional[str] = None,
) -> Optional[CacheMatch]:
    """Resolve an event to a cache file and say *why* it matched."""
    return resolve_cache(asn, start, end, quick_dir, event_id=event_id)


def find_quick_cache(
    asn: str,
    start: str,
    end: str,
    quick_dir: Path,
) -> Optional[Path]:
    """Path-only wrapper around :func:`find_quick_cache_match`."""
    match = find_quick_cache_match(asn, start, end, quick_dir)
    return match.path if match else None


def posterior_to_css_direction(posterior: Dict[str, float]) -> str:
    """Return the ungated CSS-dominant direction from a synthesis posterior."""
    post = {
        d: float((posterior or {}).get(d, 0.0) or 0.0)
        for d in ("routing_to_traffic", "traffic_to_routing", "independent")
    }
    best = max(post, key=post.get)
    if (
        best in ("routing_to_traffic", "traffic_to_routing")
        and post[best] > CSS_ALONE_POSTERIOR_FLOOR
    ):
        return best
    return "unknown"


def split_merged_timeline(
    merged: List[dict],
    bucket_seconds: int = 30,
    window_start: Optional[datetime] = None,
    window_end: Optional[datetime] = None,
    repair_offset: Optional[object] = None,
) -> Tuple[List[dict], List[dict]]:
    """Build routing + traffic time-series from a list of event records."""
    if not merged:
        return [], []

    def to_dt(s):
        from datetime import datetime
        try:
            return datetime.fromisoformat(s.replace("Z", "").replace("T", " ").split(".")[0])
        except (ValueError):
            return None

    # Parse all event timestamps once
    parsed_events: List[Tuple[datetime, dict]] = []
    for e in merged:
        ts = e.get("timestamp")
        if not ts:
            continue
        d = to_dt(ts)
        if d is not None:
            parsed_events.append((d, e))

    if not parsed_events:
        return [], []

    # If window_start/window_end provided, anchor bucket grid to them
    # and drop events outside the window. Otherwise fall back to legacy
    # min/max behaviour.
    if window_start is not None and window_end is not None:
        t_min = window_start
        t_max = window_end
        offset_hours = 0
        if repair_offset == "auto":
            from agents.cache_resolution import infer_hour_offset
            offset_hours = infer_hour_offset(
                [d for d, _ in parsed_events], t_min, t_max)
        elif isinstance(repair_offset, (int, float)) and not isinstance(
                repair_offset, bool):
            offset_hours = int(repair_offset)
        if offset_hours:
            from datetime import timedelta
            shift = timedelta(hours=offset_hours)
            parsed_events = [(d + shift, e) for d, e in parsed_events]
        parsed_events = [(d, e) for d, e in parsed_events if t_min <= d <= t_max]
        if not parsed_events:
            # No events in window — return empty timelines with proper window span
            return [], []
    else:
        times = [d for d, _ in parsed_events]
        t_min, t_max = min(times), max(times)

    total_seconds = int((t_max - t_min).total_seconds())
    if total_seconds <= 0:
        # All events collapse into a single instant.  Emit two *distinct*
        from datetime import timedelta
        routing_score = sum(1.0 for _, e in parsed_events if e.get("source") == "routing")
        traffic_score = sum(1.0 for _, e in parsed_events if e.get("source") == "traffic")
        ts0 = t_min.isoformat() + "Z"
        ts1 = (t_min + timedelta(seconds=1)).isoformat() + "Z"
        return (
            [{"timestamp": ts0, "score": max(routing_score, 1e-9)},
             {"timestamp": ts1, "score": 1e-9}],
            [{"timestamp": ts0, "score": max(traffic_score, 1e-9)},
             {"timestamp": ts1, "score": 1e-9}],
        )

    n_buckets = max(8, min(120, total_seconds // bucket_seconds + 1))
    bucket_width = total_seconds / n_buckets
    routing_buckets = [0.0] * n_buckets
    traffic_buckets = [0.0] * n_buckets
    for d, e in parsed_events:
        offset = (d - t_min).total_seconds()
        idx = min(n_buckets - 1, max(0, int(offset / bucket_width)))
        # FIX: Use presence scoring (1.0 for event, 0.0 for no event) instead of
        if e.get("source") == "routing":
            routing_buckets[idx] += 1.0
        elif e.get("source") == "traffic":
            traffic_buckets[idx] += 1.0

    from datetime import timedelta
    routing_timeline = [
        {
            "timestamp": (t_min + timedelta(seconds=idx * bucket_width)).isoformat() + "Z",
            "score": max(s, 1e-9),  # avoid zero-variance
        }
        for idx, s in enumerate(routing_buckets)
    ]
    traffic_timeline = [
        {
            "timestamp": (t_min + timedelta(seconds=idx * bucket_width)).isoformat() + "Z",
            "score": max(s, 1e-9),
        }
        for idx, s in enumerate(traffic_buckets)
    ]
    return routing_timeline, traffic_timeline


# Synthetic timeline generator (fallback only — kept for --use-synthetic)
# Mirrors tests/test_hcaf_consistency.py.
def synth_timeline(
    routing_origin_count: int,
    routing_withdrawal_count: int,
    traffic_pct_deviation_pct: float,
    n_points: int = 60,
) -> Tuple[List[dict], List[dict]]:
    routing_baseline = 1.0
    traffic_baseline = 100.0
    elevated_routing = 5.0
    if routing_origin_count > 0:
        routing_pattern = (
            [routing_baseline] * 20
            + [elevated_routing] * 10
            + [routing_baseline] * 30
        )
    elif routing_withdrawal_count > 0:
        routing_pattern = (
            [routing_baseline] * 20
            + [0.0] * 10
            + [routing_baseline] * 30
        )
    else:
        routing_pattern = [routing_baseline] * n_points

    if traffic_pct_deviation_pct < 0:
        new_avg = traffic_baseline * (1.0 + traffic_pct_deviation_pct / 100.0)
        trough = max(new_avg, 0.0)
        traffic_pattern = (
            [traffic_baseline] * 30
            + [trough] * 15
            + [traffic_baseline] * 15
        )
    else:
        traffic_pattern = [traffic_baseline] * n_points

    # Timestamps: both series are 60 one-minute points.  The traffic series is
    from datetime import timedelta
    base = datetime(2026, 9, 29, 0, 0, 0)
    routing_timeline = [
        {"timestamp": (base + timedelta(minutes=i)).isoformat(), "score": routing_pattern[i]}
        for i in range(min(n_points, len(routing_pattern)))
    ]
    traffic_timeline = [
        {"timestamp": (base + timedelta(minutes=i + 10)).isoformat(), "score": traffic_pattern[i]}
        for i in range(min(n_points, len(traffic_pattern)))
    ]
    return routing_timeline, traffic_timeline


# Per-row ablation
def evaluate_row(
    row: Dict[str, str],
    engine: CausalAttributionEngine,
    quick_dir: Optional[Path] = None,
    use_synthetic: bool = False,
    traffic_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    try:
        origin = int(row.get("routing_origin_count", 0) or 0)
    except ValueError:
        origin = 0
    try:
        withdrawal = int(row.get("routing_withdrawal_count", 0) or 0)
    except ValueError:
        withdrawal = 0
    try:
        pct = float(row.get("traffic_pct_deviation_pct", 0) or 0)
    except ValueError:
        pct = 0.0
    expected = expected_direction(row)

    # Resolve timelines: prefer real project cache, fall back to synthetic.
    cache_used: Optional[str] = None
    routing_tl: List[dict] = []
    traffic_tl: List[dict] = []
    if not use_synthetic and quick_dir is not None:
        asn = resolve_asn(row)
        start = row.get("start_time_utc", "")
        end = row.get("end_time_utc", "")
        # Parse event window for bucket grid anchoring
        from datetime import datetime
        win_start: Optional[datetime] = None
        win_end: Optional[datetime] = None
        try:
            if start:
                win_start = datetime.fromisoformat(
                    start.replace("Z", "").replace("T", " ").split(".")[0])
        except (ValueError):
            win_start = None
        try:
            if end:
                win_end = datetime.fromisoformat(
                    end.replace("Z", "").replace("T", " ").split(".")[0])
        except (ValueError):
            win_end = None
        if asn:
            cache = find_quick_cache(asn, start, end, quick_dir)
            if cache is not None:
                data = json.loads(cache.read_text(encoding="utf-8"))
                # Prefer the full event streams if available (no 50-event
                routing_full = data.get("correlation", {}).get("routing_events_full")
                traffic_full = data.get("correlation", {}).get("traffic_events_full")
                # FIX: Check `is not None` (not `if traffic_full`) so that an empty
                if routing_full or traffic_full is not None:
                    merged = []
                    if routing_full:
                        merged.extend(routing_full)
                    if traffic_full is not None:
                        merged.extend(traffic_full)
                    merged.sort(key=lambda e: e.get("timestamp", ""))
                    if merged:
                        routing_tl, traffic_tl = split_merged_timeline(
                            merged, window_start=win_start, window_end=win_end,
                        )
                        cache_used = str(cache)
                    # FIX: If routing_full exists but traffic_events_full is empty
                    if routing_full and (traffic_full is None or len(traffic_full) == 0):
                        if traffic_dir is not None:
                            traffic_csv_events = load_traffic_csv_for_event(row, traffic_dir)
                            if traffic_csv_events:
                                merged_with_traffic = list(routing_full) + traffic_csv_events
                                merged_with_traffic.sort(key=lambda e: e.get("timestamp", ""))
                                routing_tl, traffic_tl = split_merged_timeline(
                                    merged_with_traffic,
                                    window_start=win_start, window_end=win_end,
                                )
                                cache_used = f"{cache} + traffic_csv"
                            else:
                                # No CSV traffic signal available — emit
                                if not routing_tl:
                                    routing_tl, traffic_tl = split_merged_timeline(
                                        list(routing_full),
                                        window_start=win_start, window_end=win_end,
                                    )
                                    cache_used = f"{cache} (routing_only)"
                else:
                    merged = data.get("correlation", {}).get("timeline", []) or []
                    if merged:
                        routing_tl, traffic_tl = split_merged_timeline(
                            merged, window_start=win_start, window_end=win_end,
                        )
                        cache_used = str(cache)
        if not cache_used:
            cache_used = (
                f"synthetic (no cache: AS{asn or '?'}, {start or '?'} → {end or '?'})"
            )
    if not routing_tl and not traffic_tl:
        if origin == 0 and withdrawal == 0:
            # No cache, and the label row carries no routing signal either
            cache_used = (
                "no data (no cache; flat routing signal: "
                f"AS{resolve_asn(row) or '?'}, "
                f"{row.get('start_time_utc', '?')} → {row.get('end_time_utc', '?')})"
            )
        else:
            routing_tl, traffic_tl = synth_timeline(origin, withdrawal, pct)
            if cache_used is None:
                cache_used = "synthetic"

    # Map ground-truth cause label to event_type for Bayesian domain prior.
    cause = row.get("ground_truth_cause_label", "")
    try:
        withdrawal = int(row.get("routing_withdrawal_count", 0) or 0)
    except (ValueError, TypeError):
        withdrawal = 0

    # ── DATA LEAKAGE FIX (2026-10-05) ──────────────────────────────────────
    routing_ctx = {
        "has_routing_withdrawal": withdrawal > 0,
        "routing_withdrawal_count": withdrawal,
        "has_routing_origin": int(row.get("routing_origin_count", 0) or 0) > 0,
    }
    traffic_ctx: dict = {}

    # HCAF
    try:
        hcaf_out = engine.analyze(
            routing_timeline=routing_tl,
            traffic_timeline=traffic_tl,
            target_as=row.get("victim_as") or row.get("leak_as") or row.get("asn", ""),
            routing_context=routing_ctx,
            traffic_context=traffic_ctx,
        )
    except (ValueError) as e:
        hcaf_out = {"direction": "unknown", "confidence": 0.0, "error": repr(e)}
    # HCAF returns a dataclass (CausalAttributionResult), not a dict.
    raw_direction = getattr(hcaf_out, "direction", "unknown") if hcaf_out is not None else "unknown"
    if raw_direction == "routing -> traffic":
        hcaf_direction = "routing_to_traffic"
    elif raw_direction == "traffic -> routing":
        hcaf_direction = "traffic_to_routing"
    elif raw_direction in ("routing_to_traffic", "traffic_to_routing", "independent", "unknown"):
        # CausalAttributionResult sometimes returns the canonical 3-way
        # form directly (e.g. via single_sided_result). Pass it through.
        hcaf_direction = raw_direction
    else:
        hcaf_direction = "unknown"
    hcaf_conf = float(getattr(hcaf_out, "confidence", 0) or 0) if hcaf_out is not None else 0.0

    # Baselines
    base_results = run_all_baselines(routing_tl, traffic_tl)
    base_dict = {name: br.direction for name, br in base_results.items()}
    base_conf = {name: br.confidence for name, br in base_results.items()}

    # CSS / evidence_support come back as dataclass attributes; pull
    # the dict explicitly so JSON serialisation is clean.
    evidence = hcaf_out.evidence_support if hasattr(hcaf_out, "evidence_support") else {}
    # Two different quantities live here and must not be conflated:
    posterior = evidence.get("posterior", {}) if isinstance(evidence, dict) else {}
    # Strict argmax, uniform → unknown.  See posterior_to_css_direction().
    css_direction = posterior_to_css_direction(posterior)
    css_direction_engine = evidence.get("css_direction", "unknown") if isinstance(evidence, dict) else "unknown"
    # Compute hcaf_correct: matches unit-test expected_set logic (unknown is non-error
    # per review §1.3.3). This field was missing in all prior eval runs — every
    # event showed hcaf_correct=None, making all prior v13/v17 "eval results" useless.
    hcaf_correct: bool | None = None
    if expected is not None:  # skip attacker_view derived rows
        if hcaf_direction != "unknown":
            hcaf_correct = (hcaf_direction == expected)
        # else: unknown → abstain, not wrong → None

    return {
        "event_id": row.get("event_id"),
        "tier": row.get("tier"),
        "ground_truth_cause_label": row.get("ground_truth_cause_label"),
        "expected_direction": expected,
        "cache_source": cache_used,
        "hcaf_direction": hcaf_direction,
        "hcaf_confidence": round(hcaf_conf, 3),
        "hcaf_correct": hcaf_correct,
        # CSS (Pearl PNS) — the paper's primary contribution.
        "css_direction": css_direction,
        "css_direction_engine": css_direction_engine,
        "css_is_causal": evidence.get("css_is_causal", False),
        "css_routing_to_traffic": evidence.get("css_routing_to_traffic"),
        "css_traffic_to_routing": evidence.get("css_traffic_to_routing"),
        "css_p_value": evidence.get("css_p_value"),
        "css_ci_lower": evidence.get("css_ci_lower"),
        "css_ci_upper": evidence.get("css_ci_upper"),
        "posterior": posterior,
        # Baselines: 4 (Pearson, Granger, Timestamp, Transfer Entropy).
        "pearson_direction": base_dict["pearson"],
        "pearson_confidence": base_conf["pearson"],
        "granger_direction": base_dict["granger"],
        "granger_confidence": base_conf["granger"],
        "ts_distance_direction": base_dict["timestamp_distance"],
        "ts_distance_confidence": base_conf["timestamp_distance"],
        "transfer_entropy_direction": base_dict.get("transfer_entropy", "unknown"),
        "transfer_entropy_confidence": base_conf.get("transfer_entropy", 0.0),
    }


# Main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--csv",
        default=str(ROOT / "data_check/ground_truth_collection/final_ground_truth.csv"),
    )
    ap.add_argument(
        "--quick-dir",
        default=str(ROOT / "results/quick"),
    )
    ap.add_argument(
        "--out",
        default=str(ROOT / "results/eval/hcaf_vs_baselines.jsonl"),
    )
    ap.add_argument(
        "--use-synthetic",
        action="store_true",
        help="Skip quick-cache lookup; use synthetic timelines for every row.",
    )
    args = ap.parse_args()

    csv_path = Path(args.csv)
    quick_dir: Optional[Path] = Path(args.quick_dir) if not args.use_synthetic else None
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    # Traffic CSVs are in data/traffic relative to the project root.
    traffic_dir: Path = ROOT / "data" / "traffic"

    rows = list(csv.DictReader(open(csv_path, encoding="utf-8")))
    engine = CausalAttributionEngine()
    per_row = [
        evaluate_row(r, engine, quick_dir=quick_dir, use_synthetic=args.use_synthetic,
                    traffic_dir=traffic_dir)
        for r in rows
    ]
    with open(out_path, "w", encoding="utf-8") as f:
        for pr in per_row:
            f.write(json.dumps(pr, ensure_ascii=False) + "\n")
    print(f"Wrote {len(per_row)} rows to {out_path}")

    # Ablation table. Every method is scored on the SAME event set -- the full
    scored = [r for r in per_row if r.get("expected_direction")]

    methods = [
        ("HCAF (CSS+B)", "hcaf_direction"),
        ("CSS only",     "css_direction"),
        ("Pearson",      "pearson_direction"),
        ("Granger",      "granger_direction"),
        ("Ts-Distance",  "ts_distance_direction"),
        ("Transfer Entropy", "transfer_entropy_direction"),
        # Majority-class control. 18 of the 26 real-cache events expect R→T,
        ("Always R→T",   "__always_rt__"),
    ]
    # `css_direction` is the CSS-dominant posterior without the abstention
    # gate (generous to CSS). Newer runs also record the CSS estimator's own,
    # significance-gated verdict; add it as a separate row when present.
    if any("css_direction_engine" in r for r in scored):
        methods.insert(2, ("CSS gated", "css_direction_engine"))

    def pred(row, key):
        if key == "__always_rt__":
            return "routing_to_traffic"
        return row.get(key) or "unknown"

    def wilson(k, n, z=1.96):
        """Wilson score interval for a binomial proportion."""
        if n == 0:
            return (0.0, 0.0)
        p = k / n
        denom = 1 + z * z / n
        centre = (p + z * z / (2 * n)) / denom
        half = (z / denom) * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5)
        return (max(0.0, centre - half), min(1.0, centre + half))

    def tally(rows, key):
        n = len(rows)
        correct = sum(1 for r in rows if pred(r, key) == r["expected_direction"])
        abstained = sum(1 for r in rows if pred(r, key) in ("unknown", "insufficient"))
        wrong = n - correct - abstained
        committed = correct + wrong
        return {
            "correct": correct,
            "wrong": wrong,
            "abstain": abstained,
            "n": n,
            "coverage": committed / n if n else 0.0,
            "selective": correct / committed if committed else 0.0,
            "risk": wrong / n if n else 0.0,
            "ci": wilson(correct, committed),
        }

    def print_table(rows, title):
        print()
        print("=" * 104)
        print(title)
        print("=" * 104)
        print(f"{'Method':<18} {'Corr':>5} {'Wrong':>6} {'Abs':>5} {'N':>4} "
              f"{'Cov':>6} {'SelAcc':>7} {'95% CI':>16} {'Risk':>6}")
        print("─" * 104)
        for label, key in methods:
            t = tally(rows, key)
            lo, hi = t["ci"]
            print(f"{label:<18} {t['correct']:>5} {t['wrong']:>6} {t['abstain']:>5} {t['n']:>4} "
                  f"{t['coverage']:>6.3f} {t['selective']:>7.3f} "
                  f"  [{lo:.2f}, {hi:.2f}] {t['risk']:>6.3f}")

    def provenance(row):
        """Classify where a row's timelines came from."""
        src = (row.get("cache_source") or "").lower()
        if src.startswith("no data"):
            return "nodata"
        if "synthetic" in src:
            return "synthetic"
        return "real"

    real_rows = [r for r in scored if provenance(r) == "real"]
    synth_rows = [r for r in scored if provenance(r) == "synthetic"]
    nodata_rows = [r for r in scored if provenance(r) == "nodata"]
    print_table(
        real_rows,
        f"REAL CACHE ONLY (n={len(real_rows)}) — abstention is a cost, not a correct answer",
    )
    if synth_rows:
        print_table(
            synth_rows,
            f"SYNTHETIC TIMELINES (n={len(synth_rows)}) — NOT comparable to the real-cache table",
        )
    if nodata_rows:
        print()
        print(
            f"NO DATA: {len(nodata_rows)} events had neither a cache nor a routing "
            "signal column. They are excluded from both tables: their abstention "
            "is forced by the absent input, so they are not a measurement of any "
            "method's skill."
        )

    # Real-cache vs synthetic provenance is already reported as two separate
    # tables above; they must never be pooled into one headline number.
    print()
    # CSS-contributing events only: where css_is_causal=True.
    css_contrib = [r for r in real_rows if r.get("css_is_causal")]
    print(f"CSS-causal verdicts on real data: {len(css_contrib)}/{len(real_rows)}")
    if css_contrib:
        c = sum(1 for r in css_contrib if r.get("hcaf_direction") == r["expected_direction"])
        ab = sum(1 for r in css_contrib if (r.get("hcaf_direction") or "unknown") == "unknown")
        print(f"  HCAF on CSS-causal subset: {c} correct, "
              f"{len(css_contrib) - c - ab} wrong, {ab} abstain")
    # HCAF confidence distribution on real data
    hcaf_confs_real = [r["hcaf_confidence"] for r in real_rows if isinstance(r.get("hcaf_confidence"), (int, float))]
    hcaf_confs_real = [c for c in hcaf_confs_real if not (c != c)]  # drop NaN
    if hcaf_confs_real:
        hcaf_confs_real.sort()
        median = hcaf_confs_real[len(hcaf_confs_real) // 2]
        print(f"  HCAF confidence (real data): median={median:.3f}, "
              f"min={hcaf_confs_real[0]:.3f}, max={hcaf_confs_real[-1]:.3f}, "
              f"mean={sum(hcaf_confs_real)/len(hcaf_confs_real):.3f}")

    # Per-cause HCAF precision (use precomputed hcaf_correct)
    by_cause: Counter = Counter()
    correct_by_cause: Counter = Counter()
    css_correct_by_cause: Counter = Counter()
    abstain_by_cause: Counter = Counter()
    for r in scored:
        cause = r["ground_truth_cause_label"]
        by_cause[cause] += 1
        if r.get("hcaf_direction") == r.get("expected_direction"):
            correct_by_cause[cause] += 1
        if r.get("css_direction") == r.get("expected_direction"):
            css_correct_by_cause[cause] += 1
    # Also count abstain events per cause. An abstention is HCAF reporting
    all_evaluable = [r for r in per_row if r.get("expected_direction") is not None]
    for r in all_evaluable:
        cause = r["ground_truth_cause_label"]
        if (r.get("hcaf_direction") or "unknown") == "unknown":
            abstain_by_cause[cause] += 1
    print()
    print("HCAF per-cause precision (with abstain count):")
    print(f"  {'cause':<30} {'corr/total':>10}  {'prec':>6}  {'abstain':>8}  {'CSS':>8}")
    print("  " + "─" * 66)
    for cause, n in by_cause.most_common():
        c = correct_by_cause[cause]
        c_css = css_correct_by_cause[cause]
        a = abstain_by_cause.get(cause, 0)
        prec = c / n if n else 0
        print(f"  {cause:<30} {c:>4}/{n:<5}  {prec:>6.3f}  {a:>8}  {c_css:>4}/{n}")

    # Cache-source breakdown
    cache_counter = Counter(r.get("cache_source", "?") for r in per_row)
    print()
    print("Cache source breakdown:")
    for src, n in cache_counter.most_common():
        print(f"  {src:<40} {n:>3}")


if __name__ == "__main__":
    main()