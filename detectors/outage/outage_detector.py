from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple

try:
    from bgp_tracer.detectors.outage.extract_event_features import (
        extract_timeseries_for_as,
        find_update_files,
        detect_anomalies_timeseries,
        detect_anomalies_timeseries_periodic,
    )
except ImportError:
    # Handle relative imports when running as script
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    from detectors.outage.extract_event_features import (
        extract_timeseries_for_as,
        find_update_files,
        detect_anomalies_timeseries,
        detect_anomalies_timeseries_periodic,
    )
try:
    from bgp_tracer.utils import logger
except ImportError:
    # Handle relative imports when running as script
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    from utils import logger


def aggregate_timeseries(series):
    """Aggregate timeseries buckets into totals. Works with both dict and DataFrame."""
    if not series:
        return {}

    # Handle DataFrame input
    if hasattr(series, 'to_dict'):
        series = series.to_dict(orient='index')

    totals = {
        "announcement_count": 0,
        "withdrawal_count": 0,
        "total_messages": 0,
        "announced_prefix_count": 0,
        "withdrawn_prefix_count": 0,
        "unique_prefix_count": 0,
        "flapping_prefix_count": 0,
        "avg_path_length_samples": [],
        "max_path_length": 0,
        "min_path_length": 0,
    }

    for bucket in series.values():
        if isinstance(bucket, dict):
            totals["announcement_count"] += bucket.get("announcement_count", 0)
            totals["withdrawal_count"] += bucket.get("withdrawal_count", 0)
            totals["total_messages"] += bucket.get("total_messages", 0)
            totals["announced_prefix_count"] += bucket.get("announced_prefix_count", 0)
            totals["withdrawn_prefix_count"] += bucket.get("withdrawn_prefix_count", 0)
            totals["unique_prefix_count"] += bucket.get("unique_prefix_count", 0)
            totals["flapping_prefix_count"] += bucket.get("flapping_prefix_count", 0)

            path_length = bucket.get("avg_path_length")
            if path_length:
                totals["avg_path_length_samples"].append(path_length)

            totals["max_path_length"] = max(
                totals["max_path_length"], bucket.get("max_path_length", 0)
            )
            min_path = bucket.get("min_path_length", 0)
            if totals["min_path_length"] == 0:
                totals["min_path_length"] = min_path
            elif min_path:
                totals["min_path_length"] = min(totals["min_path_length"], min_path)
        else:
            # Handle simple numeric value
            totals["announcement_count"] += bucket if isinstance(bucket, (int, float)) else 0

    avg_samples = totals.pop("avg_path_length_samples")
    totals["avg_path_length"] = (
        sum(avg_samples) / len(avg_samples) if avg_samples else 0
    )
    return totals


# Feature detection rules definition for reporting
FEATURE_DETECTION_RULES = [
    {
        "name": "announcement_drop",
        "display_name": "Announcement Drop",
        "formula": "event_val / baseline_mean",
        "condition": "ratio < 0.5",
        "weight": 0.3,
        "direction": "decrease",
    },
    {
        "name": "withdrawal_surge",
        "display_name": "Withdrawal Surge",
        "formula": "event_val / baseline_mean",
        "condition": "ratio > 4.0",
        "weight": 0.25,
        "direction": "increase",
    },
    {
        "name": "flapping_spike",
        "display_name": "Flapping Spike",
        "formula": "event_val / baseline_mean",
        "condition": "ratio > 3.0 AND count > 20",
        "weight": 0.2,
        "direction": "increase",
    },
    {
        "name": "prefix_disappearance",
        "display_name": "Prefix Disappearance",
        "formula": "event_val / baseline_mean",
        "condition": "ratio < 0.6",
        "weight": 0.15,
        "direction": "decrease",
    },
    {
        "name": "timeseries_anomaly",
        "display_name": "Timeseries Anomaly",
        "formula": "|z-score| >= 3.0",
        "condition": "anomaly points detected",
        "weight": 0.2,
        "direction": "both",
    },
    {
        "name": "message_drop",
        "display_name": "Message Drop",
        "formula": "event_val / baseline_mean",
        "condition": "ratio < 0.5",
        "weight": 0.1,
        "direction": "decrease",
    },
]


def compute_adaptive_threshold(feature_name, baseline_features):
    """
    Compute adaptive threshold based on baseline distribution.
    Uses mean ± 2*std as the adaptive threshold range.
    """
    if not baseline_features or feature_name not in baseline_features:
        return None, None

    bf = baseline_features.get(feature_name, {})
    mean = bf.get("mean", 0)
    std = bf.get("std", 0)

    if mean == 0 and std == 0:
        return None, None

    # Adaptive thresholds: 2 standard deviations
    lower = mean - 2 * std if std > 0 else 0
    upper = mean + 2 * std if std > 0 else float('inf')

    return lower, upper


def compute_z_score(value, baseline_features, feature_name):
    """Compute z-score for a feature value."""
    if not baseline_features or feature_name not in baseline_features:
        return 0.0

    bf = baseline_features.get(feature_name, {})
    mean = bf.get("mean", 0)
    std = bf.get("std", 0)

    if std <= 0:
        return 0.0 if mean == 0 else float('inf') * (1 if value > mean else -1)

    return (value - mean) / std


def score_outage_by_sliding_window(event_ts, baseline_features, window_minutes=60, slide_minutes=30):
    """
    Score outage using sliding window approach to detect partial-window outages.

    Args:
        event_ts: dict of timestamp -> features for event window
        baseline_features: dict with 'mean' and 'std' for each feature
        window_minutes: sliding window size in minutes (default 60)
        slide_minutes: slide step in minutes (default 30)

    Returns:
        (max_score, avg_score, window_scores) tuple
    """
    if not event_ts or not baseline_features:
        return 0.0, 0.0, []

    # Sort timestamps
    sorted_ts = sorted(event_ts.keys())
    if len(sorted_ts) < 2:
        return 0.0, 0.0, []

    # Calculate window and slide sizes in buckets (5-min buckets)
    window_buckets = max(1, window_minutes // 5)
    slide_buckets = max(1, slide_minutes // 5)

    window_scores = []

    for start_idx in range(0, len(sorted_ts), slide_buckets):
        end_idx = min(start_idx + window_buckets, len(sorted_ts))
        if end_idx - start_idx < 1:
            continue

        window_ts = {k: event_ts[k] for k in sorted_ts[start_idx:end_idx]}
        window_features = aggregate_timeseries(window_ts)

        score, _, _ = score_outage(window_features, baseline_features, [])
        window_scores.append({
            "start": sorted_ts[start_idx],
            "end": sorted_ts[end_idx - 1],
            "score": score,
            "features": window_features,
        })

    if not window_scores:
        return 0.0, 0.0, []

    max_score = max(ws["score"] for ws in window_scores)
    avg_score = sum(ws["score"] for ws in window_scores) / len(window_scores)

    return max_score, avg_score, window_scores


def score_outage(
    event_features,
    baseline_features,
    anomalies
):
    """
    Score outage likelihood based on event features vs baseline.
    Returns enhanced scoring with detailed feature information for reporting.

    Args:
        event_features: dict of aggregated features for event window
        baseline_features: dict with 'mean' and 'std' for each feature (from multiple periods)
        anomalies: list of detected anomalies from timeseries analysis

    Returns:
        (score, indicators, feature_scores) tuple
        - score: 0.0 to 1.0 outage likelihood
        - indicators: list of triggered indicator names
        - feature_scores: dict with detailed scoring info for each feature
    """
    if not baseline_features:
        logger.warning("[score_outage] baseline_features is empty, returning 0 score")
        return 0.0, [], {}
    
    # Debug: log input data
    logger.info(f"[score_outage] event_features: {event_features}")
    logger.info(f"[score_outage] baseline_features keys: {list(baseline_features.keys())[:5]}...")
    if baseline_features:
        sample_key = list(baseline_features.keys())[0] if baseline_features else None
        if sample_key:
            logger.info(f"[score_outage] baseline_features['{sample_key}']: {baseline_features[sample_key]}")

    indicators = []
    feature_scores = {}

    def get_baseline_mean(key):
        bf = baseline_features.get(key, {})
        return bf.get("mean", 0) if isinstance(bf, dict) else bf

    def get_baseline_std(key):
        bf = baseline_features.get(key, {})
        return bf.get("std", 0) if isinstance(bf, dict) else 0

    def ratio(key, fallback=0.0):
        """Compute event/baseline ratio using mean."""
        baseline_val = get_baseline_mean(key)
        event_val = event_features.get(key, 0)
        if baseline_val <= 0:
            return None  # Return None to indicate invalid ratio
        return event_val / baseline_val

    # Helper to check if ratio is valid (baseline > 0)
    def ratio_is_valid(r):
        return r is not None

    # 1. Announcement Drop
    announce_ratio = ratio("announcement_count")
    announce_z = compute_z_score(event_features.get("announcement_count", 0), baseline_features, "announcement_count")
    # Only trigger if ratio is valid AND ratio < 0.5
    announce_triggered = ratio_is_valid(announce_ratio) and announce_ratio < 0.5
    feature_scores["announcement_drop"] = {
        "feature": "announcement_count",
        "event_val": event_features.get("announcement_count", 0),
        "baseline_mean": get_baseline_mean("announcement_count"),
        "baseline_std": get_baseline_std("announcement_count"),
        "ratio": announce_ratio if ratio_is_valid(announce_ratio) else 0.0,
        "ratio_valid": ratio_is_valid(announce_ratio),
        "z_score": announce_z,
        "threshold": 0.5,
        "triggered": announce_triggered,
        "condition": "ratio < 0.5",
        "weight": 0.3,
    }
    if announce_triggered:
        indicators.append("announcement_drop")

    # 2. Withdrawal Surge
    withdraw_ratio = ratio("withdrawal_count")
    withdraw_z = compute_z_score(event_features.get("withdrawal_count", 0), baseline_features, "withdrawal_count")
    # Only trigger if ratio is valid AND ratio > 4.0
    withdraw_triggered = ratio_is_valid(withdraw_ratio) and withdraw_ratio > 4.0
    feature_scores["withdrawal_surge"] = {
        "feature": "withdrawal_count",
        "event_val": event_features.get("withdrawal_count", 0),
        "baseline_mean": get_baseline_mean("withdrawal_count"),
        "baseline_std": get_baseline_std("withdrawal_count"),
        "ratio": withdraw_ratio if ratio_is_valid(withdraw_ratio) else 0.0,
        "ratio_valid": ratio_is_valid(withdraw_ratio),
        "z_score": withdraw_z,
        "threshold": 4.0,
        "triggered": withdraw_triggered,
        "condition": "ratio > 4.0",
        "weight": 0.25,
    }
    if withdraw_triggered:
        indicators.append("withdrawal_surge")

    # 3. Flapping Spike
    flapping_ratio = ratio("flapping_prefix_count")
    flapping_abs = event_features.get("flapping_prefix_count", 0)
    flapping_z = compute_z_score(flapping_abs, baseline_features, "flapping_prefix_count")
    # Only trigger if ratio is valid AND ratio > 3.0 AND count > 20
    flapping_triggered = ratio_is_valid(flapping_ratio) and flapping_ratio > 3.0 and flapping_abs > 20
    feature_scores["flapping_spike"] = {
        "feature": "flapping_prefix_count",
        "event_val": flapping_abs,
        "baseline_mean": get_baseline_mean("flapping_prefix_count"),
        "baseline_std": get_baseline_std("flapping_prefix_count"),
        "ratio": flapping_ratio if ratio_is_valid(flapping_ratio) else 0.0,
        "ratio_valid": ratio_is_valid(flapping_ratio),
        "z_score": flapping_z,
        "threshold": "ratio > 3.0 AND count > 20",
        "triggered": flapping_triggered,
        "condition": "ratio > 3.0 AND count > 20",
        "weight": 0.2,
    }
    if flapping_triggered:
        indicators.append("flapping_spike")

    # 4. Prefix Disappearance
    unique_prefix_ratio = ratio("unique_prefix_count")
    unique_prefix_z = compute_z_score(event_features.get("unique_prefix_count", 0), baseline_features, "unique_prefix_count")
    # Only trigger if ratio is valid AND ratio < 0.6
    prefix_triggered = ratio_is_valid(unique_prefix_ratio) and unique_prefix_ratio < 0.6
    feature_scores["prefix_disappearance"] = {
        "feature": "unique_prefix_count",
        "event_val": event_features.get("unique_prefix_count", 0),
        "baseline_mean": get_baseline_mean("unique_prefix_count"),
        "baseline_std": get_baseline_std("unique_prefix_count"),
        "ratio": unique_prefix_ratio if ratio_is_valid(unique_prefix_ratio) else 0.0,
        "ratio_valid": ratio_is_valid(unique_prefix_ratio),
        "z_score": unique_prefix_z,
        "threshold": 0.6,
        "triggered": prefix_triggered,
        "condition": "ratio < 0.6",
        "weight": 0.15,
    }
    if prefix_triggered:
        indicators.append("prefix_disappearance")

    # 5. Timeseries Anomaly
    outage_anomalies = [
        a for a in anomalies
        if a.get("feature") in {
            "announcement_count", "withdrawal_count", "flapping_prefix_count",
            "unique_prefix_count", "announcement_drop", "withdrawal_surge",
            "route_flapping", "ori_change_rate", "num_ori_change",
            "origin_change_count", "path_change_rate", "dup_A_rate",
            "avg_arrival_interval", "editDis_entropy", "unique_as_count",
            "unique_peer_as_count", "avg_path_length", "max_path_length",
        }
    ]

    max_z = 0.0
    anomaly_count = len(outage_anomalies)
    if outage_anomalies:
        max_z = max(abs(a.get("z_score", 0)) for a in outage_anomalies)

    timeseries_triggered = anomaly_count > 0
    feature_scores["timeseries_anomaly"] = {
        "feature": "multiple",
        "event_val": anomaly_count,
        "baseline_mean": 0,
        "baseline_std": 0,
        "ratio": 0,
        "ratio_valid": True,  # This is a count-based metric, always valid
        "z_score": max_z,
        "threshold": 3.0,
        "triggered": timeseries_triggered,
        "condition": "anomaly points detected",
        "weight": 0.2,
        "anomaly_count": anomaly_count,
        "max_z": max_z,
    }
    if timeseries_triggered:
        indicators.append("timeseries_anomaly")

    # 6. Message Drop
    total_msg_ratio = ratio("total_messages")
    msg_z = compute_z_score(event_features.get("total_messages", 0), baseline_features, "total_messages")
    # Only trigger if ratio is valid AND ratio < 0.5
    msg_triggered = ratio_is_valid(total_msg_ratio) and total_msg_ratio < 0.5
    feature_scores["message_drop"] = {
        "feature": "total_messages",
        "event_val": event_features.get("total_messages", 0),
        "baseline_mean": get_baseline_mean("total_messages"),
        "baseline_std": get_baseline_std("total_messages"),
        "ratio": total_msg_ratio if ratio_is_valid(total_msg_ratio) else 0.0,
        "ratio_valid": ratio_is_valid(total_msg_ratio),
        "z_score": msg_z,
        "threshold": 0.5,
        "triggered": msg_triggered,
        "condition": "ratio < 0.5",
        "weight": 0.1,
    }
    if msg_triggered:
        indicators.append("message_drop")

    # Calculate final score
    score = 0.0
    for indicator in indicators:
        if indicator in feature_scores:
            score += feature_scores[indicator]["weight"]

    # Cap score at 1.0
    score = min(1.0, score)

    return score, indicators, feature_scores


@dataclass
class RouteOutageDetector:
    baseline_hours: int = 24
    min_required_buckets: int = 6
    parsed_cache: Dict[str, datetime] = field(default_factory=dict, init=False)

    def analyze(self, asn, start_time, end_time, periodicity=None, periodicity_confidence=0.0):
        """
        Analyze BGP updates for potential outages.

        Args:
            asn: The AS number to analyze
            start_time: Start time of the event window
            end_time: End time of the event window
            periodicity: Detected periodicity from traffic detection (e.g., "daily", "weekly")
            periodicity_confidence: Confidence of the periodicity detection
        """
        try:
            start_dt = self.parse_time(start_time)
            end_dt = self.parse_time(end_time)
        except ValueError as exc:
            return {
                "success": False,
                "error": f"Invalid time input: {exc}",
                "asn": asn,
            }

        if end_dt <= start_dt:
            return {
                "success": False,
                "error": "End time must be later than start time.",
                "asn": asn,
            }

        # Determine baseline strategy based on periodicity
        baseline_periods = self._get_baseline_periods(start_dt, end_dt, periodicity)
        event_duration = end_dt - start_dt

        # Query data range: from earliest baseline to end of event
        earliest_baseline_start = min(p["start"] for p in baseline_periods) if baseline_periods else start_dt - timedelta(hours=24)
        query_start = earliest_baseline_start
        query_end = end_dt

        logger.info(
            "Running outage detector for AS%s using anomaly time window: %s -> %s "
            "(baseline: %d period(s), periodicity: %s, confidence: %.2f)",
            asn,
            start_dt,
            end_dt,
            len(baseline_periods),
            periodicity or "none",
            periodicity_confidence,
        )

        # Find update files for the entire query range
        plot_files = find_update_files(query_start, query_end)

        # For logging purposes, define the main baseline period start
        if baseline_periods:
            baseline_start = baseline_periods[0]["start"]
        else:
            baseline_start = start_dt - timedelta(hours=self.baseline_hours)

        if not plot_files:
            logger.info(
                "Outage detector: no decoded BGP update files in detectors/outage/data/...; "
                "returning no-outage (success=True). To enable outage scoring, populate decoded updates there."
            )
            return self._no_data_result(asn, start_time, end_time, baseline_start,
                error="No decoded BGP update files found for the requested window. "
                "Outage detection uses detectors/outage/data/updates_rrc00/decoded/ with 5-min bucket files.")

        try:
            timeseries = extract_timeseries_for_as(plot_files, {int(asn)})
        except FileNotFoundError as exc:
            logger.warning("Outage detector file error: %s", exc)
            return self._no_data_result(asn, start_time, end_time, baseline_start, error=str(exc))
        except Exception as exc:
            logger.error("Outage detector failed: %s", exc)
            return self._no_data_result(asn, start_time, end_time, baseline_start, error=str(exc))

        if not timeseries:
            return self._no_data_result(asn, start_time, end_time, baseline_start,
                error="Unable to build time-series features for the target AS.")

        # Split data into event window and multiple baseline periods
        event_ts, baseline_ts_dict = self.split_windows_periodic(timeseries, start_dt, end_dt, baseline_periods)

        if len(event_ts) < self.min_required_buckets:
            return self._no_data_result(asn, start_time, end_time, baseline_start,
                error=f"Insufficient event window coverage (got {len(event_ts)} buckets, need {self.min_required_buckets}).")

        event_features = aggregate_timeseries(event_ts)

        # Aggregate baseline from multiple periods (compute mean and std for each feature)
        baseline_features = self.aggregate_multiple_periods(baseline_ts_dict)

        # Compute anomalies using periodic baseline (mean and std from multiple periods)
        anomalies = detect_anomalies_timeseries_periodic(event_ts, baseline_ts_dict) if baseline_ts_dict else []
        anomaly_timeslots = {a.get("timestamp") for a in anomalies if a.get("timestamp")}
        high_severity_timeslots = {
            a.get("timestamp")
            for a in anomalies
            if a.get("timestamp") and abs(a.get("z_score", 0)) >= 3.0
        }

        # Get feature scores for reporting (now returns 3 values)
        outage_score, indicators, feature_scores = score_outage(event_features, baseline_features, anomalies)

        # Also compute sliding window scores for enhanced detection
        window_max_score, window_avg_score, window_scores = score_outage_by_sliding_window(
            event_ts, baseline_features, window_minutes=60, slide_minutes=30
        )

        # Use the maximum of full-window and sliding-window scores
        final_outage_score = max(outage_score, window_max_score)
        is_outage = final_outage_score >= 0.25

        if not is_outage and anomalies:
            high_severity_anomalies = [a for a in anomalies if abs(a.get("z_score", 0)) >= 3.0]
            if len(high_severity_anomalies) >= 2:
                is_outage = True
                indicators.append(f"high_severity_anomalies: {len(high_severity_anomalies)} anomalies with z-score >= 3.0")
                final_outage_score = max(final_outage_score, 0.4)

        if not is_outage and anomalies:
            unique_features_with_anomalies = set(a.get("feature") for a in anomalies if abs(a.get("z_score", 0)) >= 2.5)
            if len(unique_features_with_anomalies) >= 3:
                is_outage = True
                indicators.append(f"multi_feature_anomalies: {len(unique_features_with_anomalies)} different features with anomalies")
                outage_score = max(outage_score, 0.35)

        if is_outage:
            logger.warning(
                f"🚨 OUTAGE SUSPECTED for AS{asn} during anomaly period [{start_time} to {end_time}]: "
                f"score={final_outage_score:.2f}, indicators={len(indicators)}, anomalies={len(anomalies)}"
            )
            anomaly_by_feature = {}
            for anomaly in anomalies:
                feature = anomaly.get("feature", "unknown")
                if feature not in anomaly_by_feature:
                    anomaly_by_feature[feature] = {
                        "count": 0,
                        "max_z": 0,
                        "max_value": None,
                        "baseline_mean": None,
                        "timestamps": []
                    }
                anomaly_by_feature[feature]["count"] += 1
                z_score = abs(anomaly.get("z_score", 0))
                if z_score > anomaly_by_feature[feature]["max_z"]:
                    anomaly_by_feature[feature]["max_z"] = z_score
                    anomaly_by_feature[feature]["max_value"] = anomaly.get("value")
                    anomaly_by_feature[feature]["baseline_mean"] = anomaly.get("baseline_mean")
                ts = anomaly.get("timestamp", "")
                if ts and ts not in anomaly_by_feature[feature]["timestamps"]:
                    anomaly_by_feature[feature]["timestamps"].append(ts)
            
            logger.warning(f"  Anomaly features detected in period [{start_time} to {end_time}]:")
            for feature, info in sorted(anomaly_by_feature.items(), key=lambda x: x[1]["max_z"], reverse=True):
                logger.warning(
                    f"    - {feature}: {info['count']} anomalies, max_z={info['max_z']:.2f}, "
                    f"value={info['max_value']:.1f} vs baseline={info['baseline_mean']:.1f}"
                )
        else:
            logger.info(
                f"✅ No outage detected for AS{asn} during anomaly period [{start_time} to {end_time}]: "
                f"score={final_outage_score:.2f}, indicators={len(indicators)}, anomalies={len(anomalies)}"
            )

        anomaly_by_feature_summary = {}
        for anomaly in anomalies:
            feature = anomaly.get("feature", "unknown")
            if feature not in anomaly_by_feature_summary:
                anomaly_by_feature_summary[feature] = {
                    "count": 0,
                    "max_z_score": 0,
                    "max_value": None,
                    "baseline_mean": None,
                    "anomaly_type": anomaly.get("anomaly_type", "unknown"),
                    "timestamps": []
                }
            anomaly_by_feature_summary[feature]["count"] += 1
            z_score = abs(anomaly.get("z_score", 0))
            if z_score > anomaly_by_feature_summary[feature]["max_z_score"]:
                anomaly_by_feature_summary[feature]["max_z_score"] = z_score
                anomaly_by_feature_summary[feature]["max_value"] = anomaly.get("value")
                anomaly_by_feature_summary[feature]["baseline_mean"] = anomaly.get("baseline_mean")
            ts = anomaly.get("timestamp", "")
            if ts and ts not in anomaly_by_feature_summary[feature]["timestamps"]:
                anomaly_by_feature_summary[feature]["timestamps"].append(ts)
        
        return {
            "success": True,
            "asn": asn,
            "analysis_period": f"{start_time} to {end_time}",
            "anomaly_time_window": f"{start_time} to {end_time}",
            "baseline_period": f"{baseline_start.strftime('%Y-%m-%d %H:%M')} to {start_time}",
            "event_features": event_features,
            "baseline_features": baseline_features,
            "feature_scores": feature_scores,  # New: detailed feature scoring
            "timeseries_event": event_ts,
            "timeseries_baseline": list(baseline_ts_dict.values())[0] if baseline_ts_dict else {},
            "anomalies": anomalies,
            "anomaly_by_feature": anomaly_by_feature_summary,
            "outage_score": final_outage_score,
            "outage_score_full_window": outage_score,
            "outage_score_sliding_max": window_max_score,
            "outage_score_sliding_avg": window_avg_score,
            "sliding_window_scores": window_scores,
            "indicators": indicators,
            "is_outage_suspected": is_outage,
            "anomaly_count": len(anomaly_timeslots),
            "anomaly_feature_count": len(anomalies),
            "high_severity_anomaly_count": len(high_severity_timeslots),
            "unique_features_with_anomalies": list(anomaly_by_feature_summary.keys()),
            "data_files": [str(p) for p in plot_files],
        }

    def _get_baseline_periods(self, start_dt, end_dt, periodicity):
        """
        Determine baseline periods based on detected periodicity.

        Args:
            start_dt: Event window start time
            end_dt: Event window end time
            periodicity: Detected periodicity ("daily", "weekly", "6h", etc.)

        Returns:
            List of baseline period dicts with 'start' and 'end' keys
        """
        event_duration = end_dt - start_dt
        periods = []

        if periodicity == "weekly":
            # Use past 4 weeks same time period
            num_periods = 4
            for i in range(1, num_periods + 1):
                period_start = start_dt - timedelta(weeks=i)
                period_end = end_dt - timedelta(weeks=i)
                periods.append({"start": period_start, "end": period_end, "offset_weeks": i})

        elif periodicity == "daily":
            # Use past 7 days same time period
            num_periods = 7
            for i in range(1, num_periods + 1):
                period_start = start_dt - timedelta(days=i)
                period_end = end_dt - timedelta(days=i)
                periods.append({"start": period_start, "end": period_end, "offset_days": i})

        elif periodicity and periodicity.endswith("h"):
            # Handle hourly patterns like "6h"
            try:
                hours = int(periodicity[:-1])
                num_periods = max(4, 24 // hours)  # At least 4 periods
                for i in range(1, num_periods + 1):
                    period_start = start_dt - timedelta(hours=hours * i)
                    period_end = end_dt - timedelta(hours=hours * i)
                    periods.append({"start": period_start, "end": period_end, "offset_hours": hours * i})
            except ValueError:
                pass

        # Fallback: use default 24h baseline if no periodicity detected or not enough periods
        if not periods:
            period_start = start_dt - timedelta(hours=24)
            period_end = start_dt
            periods.append({"start": period_start, "end": period_end, "offset_hours": 24})

        return periods

    def split_windows_periodic(self, timeseries, start_dt, end_dt, baseline_periods):
        """
        Split timeseries into event window and multiple baseline periods.

        Returns:
            (event_ts, baseline_ts_dict)
            - event_ts: dict of timestamp -> features for event window
            - baseline_ts_dict: dict of period_index -> (timestamp -> features)
        """
        event_ts = {}
        baseline_ts_dict = {}

        for period_idx, period in enumerate(baseline_periods):
            period_start = period["start"]
            period_end = period["end"]
            baseline_ts_dict[period_idx] = {}

            for ts_str, payload in timeseries.items():
                ts_dt = self.parse_cached(ts_str)
                if start_dt <= ts_dt <= end_dt:
                    event_ts[ts_str] = payload
                elif period_start <= ts_dt < period_end:
                    baseline_ts_dict[period_idx][ts_str] = payload

        return event_ts, baseline_ts_dict

    def aggregate_multiple_periods(self, baseline_ts_dict):
        """
        Aggregate features from multiple baseline periods.
        Computes mean and std for each feature across all periods.

        Returns:
            dict with feature keys containing 'mean' and 'std' for each metric
        """
        import numpy as np

        features = [
            "announcement_count", "withdrawal_count", "total_messages",
            "announced_prefix_count", "withdrawn_prefix_count",
            "unique_prefix_count", "flapping_prefix_count",
            "unique_peer_as_count", "avg_path_length", "max_path_length", "min_path_length",
            "ori_change_rate", "num_ori_change", "origin_change_count",
            "path_change_rate", "dup_A_rate", "avg_arrival_interval",
            "editDis_entropy", "unique_as_count",
        ]

        # Collect all values for each feature across all periods
        feature_values = {f: [] for f in features}

        for period_ts in baseline_ts_dict.values():
            period_agg = aggregate_timeseries(period_ts)
            logger.info(f"[aggregate_multiple_periods] period_agg: {period_agg}")
            for f in features:
                if f in period_agg and period_agg[f] is not None:
                    feature_values[f].append(period_agg[f])

        # Compute mean and std for each feature
        result = {}
        for f, vals in feature_values.items():
            if vals:
                result[f] = {
                    "mean": float(np.mean(vals)),
                    "std": float(np.std(vals)),
                    "min": float(np.min(vals)),
                    "max": float(np.max(vals)),
                    "period_count": len(vals),
                }
            else:
                result[f] = {"mean": 0.0, "std": 0.0, "min": 0.0, "max": 0.0, "period_count": 0}

        return result

    def split_windows(
        self,
        timeseries,
        start_dt,
        end_dt,
        baseline_start,
    ):
        event_ts = {}
        baseline_ts = {}
        for ts_str, payload in timeseries.items():
            ts_dt = self.parse_cached(ts_str)
            if start_dt <= ts_dt <= end_dt:
                event_ts[ts_str] = payload
            elif baseline_start <= ts_dt < start_dt:
                baseline_ts[ts_str] = payload
        return event_ts, baseline_ts

    def parse_cached(self, iso_ts):
        cached = self.parsed_cache.get(iso_ts)
        if cached:
            return cached
        parsed = datetime.fromisoformat(iso_ts)
        self.parsed_cache[iso_ts] = parsed
        return parsed

    @staticmethod
    def parse_time(raw):
        raw_str = str(raw)
        # Try with seconds first, fallback to without seconds
        try:
            return datetime.strptime(raw_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return datetime.strptime(raw_str, "%Y-%m-%d %H:%M")

    def _no_data_result(self, asn, start_time, end_time, baseline_start, error: str = ""):
        """Return a consistent result when outage detection has no data, so downstream always gets success=True and defined fields."""
        empty_features = {
            "announcement_count": 0,
            "withdrawal_count": 0,
            "total_messages": 0,
            "announced_prefix_count": 0,
            "withdrawn_prefix_count": 0,
            "unique_prefix_count": 0,
            "flapping_prefix_count": 0,
            "avg_path_length": 0,
            "max_path_length": 0,
            "min_path_length": 0,
        }
        return {
            "success": True,
            "asn": asn,
            "analysis_period": f"{start_time} to {end_time}",
            "anomaly_time_window": f"{start_time} to {end_time}",
            "baseline_period": f"{baseline_start.strftime('%Y-%m-%d %H:%M')} to {start_time}",
            "outage_score": 0.0,
            "is_outage_suspected": False,
            "indicators": [],
            "anomalies": [],
            "event_features": empty_features,
            "baseline_features": empty_features,
            "error": error,
            "note": "Outage score not computed (no or insufficient data).",
        }


# Create a singleton instance for import
OUTAGE_DETECTOR = RouteOutageDetector()

__all__ = ["RouteOutageDetector", "OUTAGE_DETECTOR"]

