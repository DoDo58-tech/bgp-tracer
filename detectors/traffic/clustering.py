import numpy as np
from datetime import datetime


def _parse_ts(ts_str):
    if isinstance(ts_str, str):
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S+00:00", "%Y-%m-%d %H:%M:%S"):
            try:
                return datetime.strptime(ts_str, fmt)
            except Exception:
                continue
    return None


def cluster_and_expand_anomaly_windows(anomalies, timestamps, current_values, historical_means,
                                       historical_stds=None, gap_minutes=30, expansion_hours=2,
                                       min_cluster_size=1):
    if not anomalies or not timestamps:
        return []
    indices = sorted({int(anom["index"]) for anom in anomalies if isinstance(anom.get("index"), (int, float))})
    if not indices:
        return []
    stds = historical_stds if historical_stds is not None else np.zeros_like(historical_means)
    pts_per_hour, gap_pts = 4, max(1, int(gap_minutes / 15))

    clusters, current = [], [indices[0]]
    prev_idx = indices[0]
    for idx in indices[1:]:
        if idx - prev_idx <= gap_pts:
            current.append(idx)
        else:
            clusters.append(current)
            current = [idx]
        prev_idx = idx
    clusters.append(current)

    windows = []
    for cluster in clusters:
        mn, mx = cluster[0], cluster[-1]
        exp_pts = expansion_hours * pts_per_hour
        ext_min = max(0, mn - exp_pts)
        ext_max = min(len(current_values) - 1, mx + exp_pts)
        while ext_min > 0:
            val, mean = current_values[ext_min], historical_means[ext_min]
            sv = stds[ext_min] if ext_min < len(stds) else 0.0
            sv = sv if sv > 1e-6 else max(0.05 * max(abs(mean), 1.0), 0.02)
            if abs(val - mean) > 2 * sv:
                ext_min -= 1
            else:
                break
        while ext_max < len(current_values) - 1:
            val, mean = current_values[ext_max], historical_means[ext_max]
            sv = stds[ext_max] if ext_max < len(stds) else 0.0
            sv = sv if sv > 1e-6 else max(0.05 * max(abs(mean), 1.0), 0.02)
            if abs(val - mean) > 2 * sv:
                ext_max += 1
            else:
                break
        try:
            start_ts, end_ts = timestamps[ext_min], timestamps[ext_max]
        except (IndexError, ValueError):
            start_ts, end_ts = timestamps[mn], timestamps[mx]
        windows.append({"start": start_ts, "end": end_ts, "anomaly_count": len(cluster), "indices": list(cluster)})
    return windows


def expand_anomaly_boundaries(anomalies, timestamps, current_values, historical_means, expansion_hours=2):
    wins = cluster_and_expand_anomaly_windows(anomalies, timestamps, current_values, historical_means,
                                             expansion_hours=expansion_hours, min_cluster_size=1)
    return (wins[0]["start"], wins[0]["end"]) if wins else (None, None)


def calculate_traffic_statistics(current_values, historical_means):
    """
    Calculate comprehensive traffic statistics.
    
    Returns both:
    - percent_change: average comparison (existing behavior)
    - peak_trough_drop_pct: peak-to-trough drop relative to peak (new)
    - trough_drop_from_peak: absolute drop from peak to trough
    """
    # `current_values` / `historical_means` may be numpy arrays, so test size
    # directly instead of truthiness.
    #
    # BUG-R151: peak/trough/drop are *intra-series* statistics -- they compare
    # samples of the current window against each other and need no history at
    # all. Returning the all-zero block when `historical_means` was empty threw
    # that information away, so an AS with no usable historical windows (missing
    # cache, or no API token to backfill it) always reported a 0.0% drop even
    # when the series had collapsed by 80%+. Only the *comparison* fields
    # (historical_avg, percent_change) genuinely require a baseline.
    if len(current_values) == 0:
        return {
            "current_avg": 0.0,
            "historical_avg": 0.0,
            "percent_change": 0.0,
            "data_points": 0,
            "peak_trough_drop_pct": 0.0,
            "trough_drop_from_peak": 0.0,
            "peak_value": 0.0,
            "trough_value": 0.0,
        }

    if len(historical_means) == 0:
        # No baseline, but peak/trough/drop are still well defined from the
        # current window alone (see BUG-R151 note above).
        _arr = np.asarray(current_values, dtype=float)
        _peak = float(np.max(_arr))
        _trough = float(np.min(_arr))
        _drop = float((_peak - _trough) / _peak * 100.0) if _peak > 0 else 0.0
        return {
            "current_avg": float(np.mean(_arr)),
            "historical_avg": 0.0,
            "percent_change": 0.0,
            "data_points": len(_arr),
            "peak_trough_drop_pct": _drop,
            "trough_drop_from_peak": _peak - _trough,
            "peak_value": _peak,
            "trough_value": _trough,
        }

    curr_avg = float(np.mean(current_values))
    hist_avg = float(np.mean(historical_means))

    # BUG-R141 2026-09-29: a near-zero historical baseline made this
    # division explode — AS22773 (Cox) rendered "+266727751609.52%" in the
    # operator report, which is both nonsense and a credibility killer. A
    # ratio against a baseline this small carries no information, so treat
    # it as "no comparable baseline" rather than reporting a huge number.
    # Relative changes beyond ±1000% are also treated as baseline noise
    # (a legitimate AS-level traffic swing does not exceed 10x).
    MIN_MEANINGFUL_BASELINE = 1e-6
    if hist_avg > MIN_MEANINGFUL_BASELINE:
        raw_pct = (curr_avg - hist_avg) / hist_avg * 100.0
        pct = raw_pct if -1000.0 <= raw_pct <= 1000.0 else 0.0
    else:
        pct = 0.0
    
    # Calculate peak-to-trough drop (the actual drop visible in the chart)
    peak_value = float(np.max(current_values))
    trough_value = float(np.min(current_values))
    trough_drop_from_peak = peak_value - trough_value
    
    # Calculate drop relative to peak value
    if peak_value > 0:
        peak_trough_drop_pct = (trough_drop_from_peak / peak_value) * 100
    else:
        peak_trough_drop_pct = 0.0
    
    return {
        "current_avg": curr_avg, 
        "historical_avg": hist_avg, 
        "percent_change": float(pct), 
        "data_points": len(current_values),
        "peak_trough_drop_pct": float(peak_trough_drop_pct),
        "trough_drop_from_peak": float(trough_drop_from_peak),
        "peak_value": peak_value,
        "trough_value": trough_value,
    }
