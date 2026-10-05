"""
 — 
=========================

，（）。
：
- 「」(AND) 「」(OR)：
- 「」：
-  context_filter：，
-  sudden_drop ： 0.50  0.35，min_consecutive  3  1
- ：，
"""

import numpy as np
from datetime import datetime, timedelta

from detectors.traffic.detectors import (
    detect_anomalies_statistical,
    detect_anomalies_percentile,
    detect_anomalies_isolation_forest,
)
from detectors.traffic.sudden import (
    detect_anomalies_sudden_drop,
    detect_anomalies_sudden_drop_to_zero,
    detect_anomalies_sudden_jump,
    detect_anomalies_post_jump_drop,
)
from detectors.traffic.sustained import (
    detect_anomalies_sustained_outage,
)
from detectors.traffic.preprocessing import filter_consecutive_anomalies
from utils.logger import logger


def detect_anomalies_combined(
    current_values,
    historical_means,
    historical_stds,
    historical_values,
    timestamps=None,
    threshold=3.0,
    detect_direction="both",
    context_window=1,
    context_threshold=0.35,
    min_consecutive_context=2,
    event_start_time=None,    # P0 Fix 2026-09-07: 
    event_end_time=None,
):
    """
    。
    
    ：
    1.  → ：
    2.  context ： + 
    3. ：
    4. ：
    """
    curr = np.array(current_values, dtype=float)
    n = len(curr)
    hist = np.array(historical_means, dtype=float) if len(historical_means) == n else None

    # ── 1.  ────────────────────────────────────────────
    stat_anomalies = detect_anomalies_statistical(
        current_values, historical_means, historical_stds, threshold
    )
    ml_anomalies = detect_anomalies_isolation_forest(
        current_values, historical_values
    )

    # ── 2.  (UNION)， ──────────────────────────────
    s_idx = {a["index"] for a in stat_anomalies}
    m_idx = {a["index"] for a in ml_anomalies}

    combined: list = []

    # ： → 
    for idx in s_idx & m_idx:
        sa = next(a for a in stat_anomalies if a["index"] == idx)
        ma = next(a for a in ml_anomalies if a["index"] == idx)
        combined.append({
            **sa,
            "method": "combined_both",
            "ml_score": ma["anomaly_score"],
            "confidence": "high",
            "severity": "high",
            "detected_by": ["statistical", "isolation_forest"],
        })

    # （）
    for idx in s_idx - m_idx:
        a = next(x for x in stat_anomalies if x["index"] == idx)
        combined.append({
            **a,
            "method": "statistical_only",
            "confidence": "medium",
            "ml_detected": False,
            "detected_by": ["statistical"],
        })

    # （ML）
    for idx in m_idx - s_idx:
        ma = next(a for a in ml_anomalies if a["index"] == idx)
        combined.append({
            **ma,
            "method": "ml_only",
            "confidence": "medium",
            "z_score": 0.0,
            "detected_by": ["isolation_forest"],
        })

    # ── 3.  ──────────────────────────────────────────
    if detect_direction in ("both", "lower_only"):
        for oa in detect_anomalies_sustained_outage(
            current_values, historical_means, historical_stds
        ):
            idx = oa["index"]
            if idx not in {a["index"] for a in combined}:
                combined.append({**oa, "confidence": "high", "ml_detected": False,
                                 "detected_by": ["sustained_outage"]})
            else:
                for a in combined:
                    if a.get("index") == idx:
                        a["sustained_outage"] = True
                        if "detected_by" in a:
                            a["detected_by"].append("sustained_outage")
                        break

    # ── 4. （）────────────────────────────────────
    if detect_direction in ("both", "lower_only") and timestamps:
        try:
            #  0.50 → 0.35，min_consecutive  3 → 1
            for oa in detect_anomalies_sudden_drop(
                current_values, historical_means, timestamps,
                drop_threshold_ratio=0.35,   # ，
                min_prev_baseline=0.08,
                min_consecutive=1,           # 
            ):
                idx = oa["index"]
                if idx not in {a["index"] for a in combined}:
                    combined.append({**oa, "confidence": "high", "ml_detected": False,
                                     "detected_by": ["sudden_drop"]})
                else:
                    for a in combined:
                        if a.get("index") == idx:
                            a["sudden_drop"] = True
                            break
        except Exception as e:
            logger.warning(f"Sudden drop detection failed: {e}")

    # ── 5.  ────────────────────────────────────────────
    if detect_direction in ("both", "lower_only") and timestamps:
        try:
            for oa in detect_anomalies_sudden_drop_to_zero(
                current_values, historical_means, timestamps,
                min_consecutive=2,   # 
            ):
                idx = oa["index"]
                if idx not in {a["index"] for a in combined}:
                    combined.append({**oa, "confidence": "high", "ml_detected": False,
                                     "detected_by": ["sudden_drop_to_zero"]})
                else:
                    for a in combined:
                        if a.get("index") == idx:
                            a["sudden_drop_to_zero"] = True
                            break
        except Exception as e:
            logger.warning(f"Sudden drop-to-zero detection failed: {e}")

    # ── 6.  ────────────────────────────────────────────────
    if detect_direction in ("both", "upper_only") and timestamps:
        try:
            for oa in detect_anomalies_sudden_jump(
                current_values, historical_means, timestamps,
                jump_threshold_ratio=0.40,   # 
                min_jump_magnitude=0.08,
                min_consecutive=1,
            ):
                combined.append({**oa, "_skip_context_filter": True,
                                 "confidence": "high", "ml_detected": False,
                                 "detected_by": ["sudden_jump"]})
        except Exception as e:
            logger.warning(f"Sudden jump detection failed: {e}")

    # ── 7.  ─────────────────────────────────────────
    if timestamps and len(historical_means) == len(current_values):
        try:
            for oa in detect_anomalies_post_jump_drop(
                current_values, historical_means, timestamps
            ):
                idx = oa.get("index")
                if idx not in {a.get("index") for a in combined}:
                    combined.append({**oa, "confidence": "high", "ml_detected": False,
                                     "detected_by": ["post_jump_drop"]})
                else:
                    for a in combined:
                        if a.get("index") == idx:
                            a["post_jump_drop"] = True
                            break
        except Exception as e:
            logger.warning(f"Post-jump drop detection failed: {e}")

    # ── 8.  ──────────────────────────────────────────────
    if historical_values and len(historical_values) >= 2:
        try:
            for oa in detect_anomalies_percentile(
                current_values=current_values,
                historical_values_list=historical_values,
                timestamps=timestamps,
                lower_pct=5, upper_pct=95,
                min_consecutive=1,    # 
                detect_only_upper=(detect_direction == "upper_only"),
                detect_only_lower=(detect_direction == "lower_only"),
                context_window=context_window,
                context_threshold=context_threshold,
            ):
                idx = oa["index"]
                if idx not in {a["index"] for a in combined}:
                    combined.append({**oa, "confidence": "high", "ml_detected": False,
                                     "detected_by": ["percentile"]})
                else:
                    for a in combined:
                        if a.get("index") == idx:
                            a["percentile_deviation"] = oa.get("deviation")
                            a["percentile_direction"] = oa.get("direction")
                            break
        except Exception as e:
            logger.warning(f"Percentile detection failed: {e}")

    # ── 9. （「」）────────────────
    if n >= 4 and len(historical_means) == n:
        try:
            for oa in _detect_peak_trough_drops(
                current_values, historical_means, timestamps,
                min_drop_ratio=0.25,   # 25%
                min_sustained_points=3,  # 3
                # P0 Fix 2026-09-07: ， peak/trough 
                event_start_timestamp=event_start_time if event_start_time else None,
                event_end_timestamp=event_end_time if event_end_time else None,
            ):
                idx = oa["index"]
                if idx not in {a["index"] for a in combined}:
                    combined.append({**oa, "confidence": "high", "ml_detected": False,
                                     "detected_by": ["peak_trough"]})
                else:
                    for a in combined:
                        if a.get("index") == idx:
                            a["peak_trough"] = True
                            break
        except Exception as e:
            logger.warning(f"Peak-trough detection failed: {e}")

    # ── 10.  context  ──────────────────────────────────────
    if context_threshold > 0 and n > 0:
        ctx_filtered = []
        for anom in combined:
            if anom.get("_skip_context_filter"):
                ctx_filtered.append(anom)
                continue
            idx = anom.get("index", -1)
            if idx < 0 or idx >= n:
                ctx_filtered.append(anom)
                continue

            # ： context_window 
            ctx_vals = []
            for w in range(1, context_window + 1):
                if idx - w >= 0:
                    ctx_vals.append(curr[idx - w])
                if idx + w < n:
                    ctx_vals.append(curr[idx + w])

            if not ctx_vals:
                ctx_filtered.append(anom)
                continue

            ctx_avg = float(np.mean(ctx_vals))
            current_val = float(curr[idx])

            #  = 
            if abs(ctx_avg) > 1e-6:
                deviation = abs(current_val - ctx_avg) / ctx_avg
            else:
                deviation = 0.0

            # ，，
            # ，（）
            hist_mean = float(historical_means[idx]) if idx < len(historical_means) else ctx_avg
            hist_deviation = abs(current_val - hist_mean) / abs(hist_mean) if abs(hist_mean) > 1e-6 else 0.0

            # ，
            if hist_deviation >= 0.30:  # 30% → 
                ctx_filtered.append(anom)
            elif deviation >= context_threshold:
                #  → 
                ctx_filtered.append(anom)
            else:
                # ， → 
                anom["filtered_by_context"] = True
        combined = ctx_filtered

    # ── 11.  ────────────────────────────────────────────
    if timestamps:
        for anom in combined:
            idx = anom.get("index")
            if idx is not None and idx < len(timestamps):
                anom["timestamp"] = timestamps[idx]

    # ── 12. （P0 Fix 2026-09-07）────────────────────
    hist_filter_threshold = 0.30
    hist_filtered = []
    for anom in combined:
        idx = anom.get("index", -1)
        if idx < 0 or idx >= n:
            hist_filtered.append(anom)
            continue
        cv = float(curr[idx])
        hv = float(hist[idx]) if hist is not None and idx < len(hist) else float(np.mean(hist)) if hist is not None else cv
        if abs(hv) > 1e-6:
            hist_dev = abs(cv - hv) / abs(hv)
        else:
            hist_dev = 0.0
        if hist_dev < hist_filter_threshold:
            logger.info(
                f"[ContextFilter] Dropping {anom.get('method','?')} anomaly at idx={idx}: "
                f"val={cv:.4f} hist={hv:.4f} hist_dev={hist_dev:.1%} < {hist_filter_threshold:.0%} — not anomalous."
            )
            continue
        hist_filtered.append(anom)
    combined = hist_filtered

    # ── 13.  ──────────────────────────────────────────
    skip = [a for a in combined if a.get("_skip_context_filter")]
    others = [a for a in combined if not a.get("_skip_context_filter")]
    filtered = filter_consecutive_anomalies(others, min_consecutive=1)
    filtered.extend(skip)

    # ── 13. ： ─────────────
    if not filtered and n >= 4:
        fallback = _fallback_detection(
            current_values, historical_means, historical_stds, timestamps
        )
        if fallback:
            logger.info(f"⚠️ Fallback detection triggered: {len(fallback)} anomalies")
            filtered.extend(fallback)

    return sorted(filtered, key=lambda x: x.get("index", 0)), sorted(combined, key=lambda x: x.get("index", 0))


# ─────────────────────────────────────────────────────────────────
def _parse_event_ts(s):
    """ datetime（ tz） None。"""
    if s is None:
        return None
    if isinstance(s, str):
        s_clean = s.replace("Z", "").replace("T", " ").strip()
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                return datetime.strptime(s_clean, fmt)
            except ValueError:
                continue
        return None
    return s


def _find_peak_trough_in_event_window(
    curr, hist, timestamps, event_start_timestamp, event_end_timestamp,
):
    """
     peak/trough，。

    ：
    - ：peak  [event_start - 4h, event_end + 6h] ，
      trough （：trough ，）
    - ：（）
    """
    n = len(curr)
    if n == 0:
        return None, None

    ev_start = _parse_event_ts(event_start_timestamp)
    ev_end = _parse_event_ts(event_end_timestamp)

    # ：（）
    if ev_start is None or ev_end is None or timestamps is None or len(timestamps) != n:
        peak_idx = int(np.argmax(curr))
        if peak_idx < n - 1:
            trough_idx = peak_idx + int(np.argmin(curr[peak_idx:]))
        else:
            trough_idx = int(np.argmin(curr[:peak_idx + 1])) if peak_idx >= 0 else 0
        return peak_idx, trough_idx

    # ──  ─────────────────────────────────────────
    parsed_ts = []
    for ts in timestamps:
        parsed_ts.append(_parse_event_ts(ts))

    # -  ev_start - 2h ：（""）
    window_start = ev_start - timedelta(hours=2)
    window_end = ev_end + timedelta(hours=12)

    candidate_idx = [i for i, ts in enumerate(parsed_ts)
                     if ts is not None and window_start <= ts <= window_end]

    if not candidate_idx:
        peak_idx = int(np.argmax(curr))
        if peak_idx < n - 1:
            trough_idx = peak_idx + int(np.argmin(curr[peak_idx:]))
        else:
            trough_idx = int(np.argmin(curr[:peak_idx + 1])) if peak_idx >= 0 else 0
        return peak_idx, trough_idx

    #  peak
    candidate_vals = [float(curr[i]) for i in candidate_idx]
    local_peak_pos = int(np.argmax(candidate_vals))
    peak_idx = candidate_idx[local_peak_pos]

    # Trough  peak （）
    after_peak_window = [i for i in candidate_idx if i > peak_idx]
    if not after_peak_window:
        return peak_idx, None
    trough_idx = min(after_peak_window, key=lambda i: float(curr[i]))
    return peak_idx, trough_idx


# ─────────────────────────────────────────────────────────────────
def _detect_peak_trough_drops(
    current_values, historical_means, timestamps=None,
    min_drop_ratio=0.25, min_sustained_points=3,
    min_historical_deviation_ratio=0.20,
    event_start_timestamp=None, event_end_timestamp=None,
):
    """
    ： →  → 

     13:00-16:00 「」。
     sudden_drop ，peak_trough （peak -> sustained low -> recovery）。

    （2026-09-04）： current values  historical_means 
    。（peak-to-trough ）。

    （2026-09-07）：（）。
     event_start_timestamp，（）。

    Args:
        min_historical_deviation_ratio: （20%）。
             current_value  historical_mean，。
        event_start_timestamp / event_end_timestamp: （ datetime）。
            Peak  trough （）。
            ""。
    """
    curr = np.array(current_values, dtype=float)
    hist = np.array(historical_means, dtype=float) if len(historical_means) == len(curr) else None
    n = len(curr)
    anomalies = []

    if n < 4:
        return anomalies

    # ── P0 Fix 2026-09-07:  ─────────────────────
    # "、"
    peak_idx, trough_idx = _find_peak_trough_in_event_window(
        curr, hist, timestamps, event_start_timestamp, event_end_timestamp,
    )

    if peak_idx is None or trough_idx is None:
        logger.info(
            f"[PeakTrough] No suitable peak/trough found"
            + (" in event window" if event_start_timestamp else "")
            + ", returning empty."
        )
        return anomalies

    peak_val = float(curr[peak_idx])
    trough_val = float(curr[trough_idx])

    # ── P0 Fix:  ─────────────────
    if hist is not None and trough_idx < len(hist):
        hist_trough_val = float(hist[trough_idx])
        hist_peak_val = float(hist[peak_idx]) if peak_idx < len(hist) else float(np.mean(hist))
        # 
        if abs(hist_trough_val) > 1e-6:
            hist_deviation = abs(trough_val - hist_trough_val) / hist_trough_val
        elif abs(peak_val) > 1e-6:
            # 0，
            hist_deviation = abs(peak_val - trough_val) / peak_val
        else:
            hist_deviation = 0.0

        # ，，
        if hist_deviation < min_historical_deviation_ratio:
            logger.info(
                f"[PeakTrough] Skipping: trough={trough_val:.3f} vs hist_trough={hist_trough_val:.3f} "
                f"(deviation={hist_deviation:.1%} < {min_historical_deviation_ratio:.1%}) — "
                f"looks like normal periodic day/night variation, not an anomaly."
            )
            return anomalies

    # （）
    if peak_val > 1e-6:
        drop_ratio = (peak_val - trough_val) / peak_val
    else:
        drop_ratio = 0.0

    # ，
    if drop_ratio < min_drop_ratio:
        return anomalies

    # （）（）
    threshold = trough_val + (peak_val - trough_val) * 0.3  # 30% 

    # （： 8 ，）
    #  Starlink ：" 13 "
    max_lookback = min(8, peak_idx)
    drop_start = peak_idx
    for i in range(peak_idx - 1, peak_idx - max_lookback - 1, -1):
        if i < 0:
            break
        if curr[i] < curr[i + 1] * 0.98:  # 
            drop_start = i
        else:
            break

    # 
    recovery_end = trough_idx
    for i in range(trough_idx, n):
        if curr[i] >= threshold:
            recovery_end = i
        else:
            break

    # 
    sustained_points = recovery_end - drop_start + 1

    # ，
    if sustained_points < min_sustained_points:
        return anomalies

    # ── （P0 Fix 2026-09-07）： ──
    if hist is not None:
        sig_points = 0
        total_points = 0
        for idx in range(drop_start, recovery_end + 1):
            if idx >= len(hist):
                continue
            cv = float(curr[idx])
            hv = float(hist[idx])
            total_points += 1
            if abs(hv) > 1e-6:
                dev = abs(cv - hv) / abs(hv)
            else:
                dev = 0.0
            if dev > 0.15:  # vs>15%
                sig_points += 1

        sig_ratio = sig_points / total_points if total_points > 0 else 0.0
        if sig_ratio < 0.5:
            logger.info(
                f"[PeakTrough] Interval {drop_start}→{recovery_end} only {sig_ratio:.1%} "
                f"({sig_points}/{total_points}) points significantly deviate from history — "
                f"natural periodic variation, not an anomaly."
            )
            return anomalies

    # 
    for idx in range(drop_start, recovery_end + 1):
        ts = timestamps[idx] if timestamps and idx < len(timestamps) else None

        # 
        if peak_val > 1e-6:
            local_drop = (peak_val - float(curr[idx])) / peak_val
        else:
            local_drop = 0.0

        # 
        hist_val = float(hist[idx]) if hist is not None else float(np.mean(hist)) if hist is not None else peak_val
        if abs(hist_val) > 1e-6:
            z = abs(float(curr[idx]) - hist_val) / abs(hist_val)
        else:
            z = 0.0

        anomalies.append({
            "index": idx,
            "timestamp": ts,
            "current_value": float(curr[idx]),
            "peak_value": peak_val,
            "trough_value": trough_val,
            "drop_start_index": drop_start,
            "recovery_end_index": recovery_end,
            "drop_ratio": float(drop_ratio),
            "local_drop_from_peak": float(local_drop),
            "z_score": float(z),
            "method": "peak_trough",
            "severity": "critical" if drop_ratio > 0.7 else "high" if drop_ratio > 0.4 else "medium",
            "confidence": "high",
            "_skip_context_filter": True,  #  context 
        })

    return anomalies


# ─────────────────────────────────────────────────────────────────
def _fallback_detection(
    current_values, historical_means, historical_stds, timestamps=None,
):
    """
    ：。

    ，。
    """
    curr = np.array(current_values, dtype=float)
    n = len(curr)

    if n < 4:
        return []

    hist = np.array(historical_means, dtype=float) if len(historical_means) == n else None
    stds = np.array(historical_stds, dtype=float) if historical_stds is not None and len(historical_stds) == n else None

    anomalies = []

    # 1：（ combined ，）
    try:
        pt_anomalies = _detect_peak_trough_drops(
            current_values, historical_means, timestamps,
            min_drop_ratio=0.30,  # 
            min_sustained_points=3,
        )
        if pt_anomalies:
            logger.info(f"Fallback peak-trough: {len(pt_anomalies)} anomalies")
            return pt_anomalies
    except Exception as e:
        logger.debug(f"Fallback peak-trough failed: {e}")

    # 2：Z-score（ P0 Fix 2026-09-07）
    if hist is not None:
        z_threshold = 3.0
        z_anomalies_idx = []
        for i in range(n):
            cv = float(curr[i])
            hm = float(hist[i])
            if stds is not None and abs(float(stds[i])) > 1e-6:
                sv = float(stds[i])
                z = abs(cv - hm) / sv
            elif abs(hm) > 1e-6:
                z = abs(cv - hm) / (abs(hm) * 0.2)
            else:
                z = 0.0

            if z > z_threshold:
                z_anomalies_idx.append(i)

        #  3 
        consecutive_idx = []
        if len(z_anomalies_idx) > 0:
            sorted_z = sorted(z_anomalies_idx)
            groups, current = [], [sorted_z[0]]
            for idx in sorted_z[1:]:
                if idx == current[-1] + 1:
                    current.append(idx)
                else:
                    groups.append(current)
                    current = [idx]
            groups.append(current)
            for g in groups:
                if len(g) >= 3:
                    consecutive_idx.extend(g)

        for i in sorted(set(consecutive_idx)):
            cv = float(curr[i])
            hm = float(hist[i])
            if stds is not None and abs(float(stds[i])) > 1e-6:
                z = abs(cv - hm) / float(stds[i])
            elif abs(hm) > 1e-6:
                z = abs(cv - hm) / (abs(hm) * 0.2)
            else:
                z = 0.0
            ts = timestamps[i] if timestamps and i < len(timestamps) else None
            anomalies.append({
                "index": i,
                "timestamp": ts,
                "current_value": cv,
                "historical_mean": hm,
                "z_score": float(z),
                "method": "fallback_zscore",
                "severity": "high" if z > 5 else "medium",
                "confidence": "medium",
                "_skip_context_filter": True,
            })

    # 3：
    drops = []
    for i in range(1, n):
        if curr[i] < curr[i - 1] * 0.9:  # 10%
            drops.append(i)

    if len(drops) >= 3:
        # 
        groups, current = [], [drops[0]]
        for idx in drops[1:]:
            if idx == current[-1] + 1:
                current.append(idx)
            else:
                groups.append(current)
                current = [idx]
        groups.append(current)

        longest = max(groups, key=len) if groups else []
        if len(longest) >= 3:
            for i in longest:
                ts = timestamps[i] if timestamps and i < len(timestamps) else None
                anomalies.append({
                    "index": i,
                    "timestamp": ts,
                    "current_value": float(curr[i]),
                    "method": "fallback_consecutive_drop",
                    "severity": "medium",
                    "confidence": "low",
                    "_skip_context_filter": True,
                })

    return anomalies
