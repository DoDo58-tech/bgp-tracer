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
    if not series:
        return {}

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

    avg_samples = totals.pop("avg_path_length_samples")
    totals["avg_path_length"] = (
        sum(avg_samples) / len(avg_samples) if avg_samples else 0
    )
    return totals


def score_outage(
    event_features,
    baseline_features,
    anomalies
):
    if not baseline_features:
        return 0.0, []

    indicators = []
    anomaly_details = []

    def ratio(key, fallback = 0.0):
        baseline_val = baseline_features.get(key, 0)
        event_val = event_features.get(key, 0)
        if baseline_val <= 0:
            return fallback
        return event_val / baseline_val

    announce_ratio = ratio("announcement_count")
    if announce_ratio < 0.5:
        indicators.append("announcement_drop")
        anomaly_details.append(f"announcement_drop: {announce_ratio:.2f}x baseline")
    
    withdraw_ratio = ratio("withdrawal_count", fallback=1.0)
    if withdraw_ratio > 4.0:
        indicators.append("withdrawal_surge")
        anomaly_details.append(f"withdrawal_surge: {withdraw_ratio:.2f}x baseline")
    
    flapping_ratio = ratio("flapping_prefix_count", fallback=1.0)
    if flapping_ratio > 3.0 and event_features.get("flapping_prefix_count", 0) > 20:
        indicators.append("flapping_spike")
        anomaly_details.append(f"flapping_spike: {flapping_ratio:.2f}x baseline, {event_features.get('flapping_prefix_count', 0)} prefixes")
    
    unique_prefix_ratio = ratio("unique_prefix_count", fallback=1.0)
    if unique_prefix_ratio < 0.6:
        indicators.append("prefix_disappearance")
        anomaly_details.append(f"prefix_disappearance: {unique_prefix_ratio:.2f}x baseline")
    
    total_msg_ratio = ratio("total_messages", fallback=1.0)
    if total_msg_ratio < 0.5:
        indicators.append("message_drop")
        anomaly_details.append(f"message_drop: {total_msg_ratio:.2f}x baseline")

    outage_anomalies = [
        a
        for a in anomalies
        if a.get("feature")
        in {
            "announcement_count",
            "withdrawal_count",
            "flapping_prefix_count",
            "unique_prefix_count",
            "announcement_drop",
            "withdrawal_surge",
            "route_flapping",
            "ori_change_rate",
            "num_ori_change",
            "path_change_rate",
            "dup_A_rate",
            "avg_arrival_interval",
            "editDis_entropy",
            "unique_as_count",
        }
    ]
    
    if outage_anomalies:
        indicators.append("timeseries_anomaly")
        anomaly_by_feature = {}
        for a in outage_anomalies:
            feature = a.get("feature", "unknown")
            z_score = abs(a.get("z_score", 0))
            if feature not in anomaly_by_feature or z_score > anomaly_by_feature[feature].get("max_z", 0):
                anomaly_by_feature[feature] = {
                    "count": anomaly_by_feature.get(feature, {}).get("count", 0) + 1,
                    "max_z": z_score,
                    "value": a.get("value", 0),
                    "baseline_mean": a.get("baseline_mean", 0)
                }
        
        for feature, info in anomaly_by_feature.items():
            anomaly_details.append(
                f"{feature}: {info['count']} anomalies, max_z={info['max_z']:.2f}, "
                f"value={info['value']:.1f} vs baseline={info['baseline_mean']:.1f}"
            )

    if not indicators:
        return 0.0, []

    score = 0.0
    if "announcement_drop" in indicators:
        score += 0.3
    if "withdrawal_surge" in indicators:
        score += 0.25
    if "flapping_spike" in indicators:
        score += 0.2
    if "prefix_disappearance" in indicators:
        score += 0.15
    if "timeseries_anomaly" in indicators:
        score += 0.2
    if "message_drop" in indicators:
        score += 0.1
    
    score = min(1.0, score)
    
    detailed_indicators = indicators.copy()
    if anomaly_details:
        detailed_indicators.extend(anomaly_details)
    
    return score, detailed_indicators


@dataclass
class RouteOutageDetector:
    baseline_hours: int = 24
    min_required_buckets: int = 6
    parsed_cache: Dict[str, datetime] = field(default_factory=dict, init=False)

    def analyze(self, asn, start_time, end_time):
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

        baseline_start = start_dt - timedelta(hours=self.baseline_hours)
        logger.info(
            "Running outage detector for AS%s using anomaly time window: %s -> %s (baseline: %s -> %s)",
            asn,
            start_dt,
            end_dt,
            baseline_start,
            start_dt,
        )

        plot_files = find_update_files(baseline_start, end_dt)
        if not plot_files:
            return {
                "success": False,
                "error": "No decoded BGP update files found for the requested window.",
                "asn": asn,
            }

        try:
            timeseries = extract_timeseries_for_as(plot_files, {int(asn)})
        except FileNotFoundError as exc:
            return {
                "success": False,
                "error": f"Decoded update files missing: {exc}",
                "asn": asn,
            }
        except Exception as exc:
            logger.error("Outage detector failed: %s", exc)
            return {"success": False, "error": str(exc), "asn": asn}

        if not timeseries:
            return {
                "success": False,
                "error": "Unable to build time-series features for the target AS.",
                "asn": asn,
            }

        event_ts, baseline_ts = self.split_windows(timeseries, start_dt, end_dt, baseline_start)

        if len(event_ts) < self.min_required_buckets:
            return {
                "success": False,
                "error": "Insufficient event window coverage for outage detection.",
                "asn": asn,
                "timeseries_event": event_ts,
            }

        event_features = aggregate_timeseries(event_ts)
        baseline_features = aggregate_timeseries(baseline_ts)
        anomalies = detect_anomalies_timeseries(event_ts, baseline_ts) if baseline_ts else []
        anomaly_timeslots = {a.get("timestamp") for a in anomalies if a.get("timestamp")}
        high_severity_timeslots = {
            a.get("timestamp")
            for a in anomalies
            if a.get("timestamp") and abs(a.get("z_score", 0)) >= 3.0
        }
        outage_score, indicators = score_outage(event_features, baseline_features, anomalies)

        is_outage = outage_score >= 0.25
        
        if not is_outage and anomalies:
            high_severity_anomalies = [a for a in anomalies if abs(a.get("z_score", 0)) >= 3.0]
            if len(high_severity_anomalies) >= 2:
                is_outage = True
                indicators.append(f"high_severity_anomalies: {len(high_severity_anomalies)} anomalies with z-score >= 3.0")
                outage_score = max(outage_score, 0.4)
        
        if not is_outage and anomalies:
            unique_features_with_anomalies = set(a.get("feature") for a in anomalies if abs(a.get("z_score", 0)) >= 2.5)
            if len(unique_features_with_anomalies) >= 3:
                is_outage = True
                indicators.append(f"multi_feature_anomalies: {len(unique_features_with_anomalies)} different features with anomalies")
                outage_score = max(outage_score, 0.35)

        if is_outage:
            logger.warning(
                f"🚨 OUTAGE SUSPECTED for AS{asn} during anomaly period [{start_time} to {end_time}]: "
                f"score={outage_score:.2f}, indicators={len(indicators)}, anomalies={len(anomalies)}"
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
                f"score={outage_score:.2f}, indicators={len(indicators)}, anomalies={len(anomalies)}"
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
            "timeseries_event": event_ts,
            "timeseries_baseline": baseline_ts,
            "anomalies": anomalies,
            "anomaly_by_feature": anomaly_by_feature_summary,
            "outage_score": outage_score,
            "indicators": indicators,
            "is_outage_suspected": is_outage,
            "anomaly_count": len(anomaly_timeslots),
            "anomaly_feature_count": len(anomalies),
            "high_severity_anomaly_count": len(high_severity_timeslots),
            "unique_features_with_anomalies": list(anomaly_by_feature_summary.keys()),
            "data_files": [str(p) for p in plot_files],
        }

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
        return datetime.strptime(str(raw), "%Y-%m-%d %H:%M")


# Create a singleton instance for import
OUTAGE_DETECTOR = RouteOutageDetector()

__all__ = ["RouteOutageDetector", "OUTAGE_DETECTOR"]

