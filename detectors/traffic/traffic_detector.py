import csv
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import numpy as np
import requests

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger
from config import (
    CLOUDFLARE_HTTP_TIMESERIES_AS_URL,
    CLOUDFLARE_API_TOKEN,
    CLOUDFLARE_TIMEOUT,
    CLOUDFLARE_DEFAULT_AGG_INTERVAL,
    CLOUDFLARE_RADAR_LOCATION,
    CLOUDFLARE_RADAR_NORMALIZATION,
)
from data.asorg_loader import get_asn_org_info
from detectors.traffic.traffic_plotting import plot_traffic_comparison_beautiful
from detectors.traffic.traffic_analysis_utils import (
    detect_anomalies_combined,
    detect_anomalies_non_periodic,
    detect_anomalies_by_event_type,
    preprocess_traffic_data,
    preprocess_traffic_data_aligned,
    calculate_traffic_statistics,
    detect_period_automatically,
    cluster_and_expand_anomaly_windows,
)
from detectors.traffic.multi_scale_baseline import MultiScaleBaseline
from detectors.unified_result import wrap, DetectionType

_as_country_cache: dict = {}


def _extract_series_from_result(result, asn):
    """Cloudflare Radar 可能返回多种 result 结构，提取 (timestamps, values)。"""
    if result is None:
        return None, None
    if isinstance(result, dict) and "timestamps" in result and "values" in result:
        return result.get("timestamps"), result.get("values")
    if isinstance(result, list):
        for item in result:
            if isinstance(item, dict) and "timestamps" in item and "values" in item:
                return item.get("timestamps"), item.get("values")
        return None, None
    if not isinstance(result, dict):
        return None, None
    for key, val in result.items():
        if key == "meta":
            continue
        if isinstance(val, dict) and "timestamps" in val and "values" in val:
            return val.get("timestamps"), val.get("values")
    asn_node = result.get(f"AS{asn}")
    if isinstance(asn_node, dict) and "timestamps" in asn_node and "values" in asn_node:
        return asn_node.get("timestamps"), asn_node.get("values")
    return None, None


def _get_as_country(asn, target_time=None):
    """根据 AS 编号查询其所属国家（ISO alpha-2），结果缓存到模块字典。"""
    asn_str = str(asn)
    if asn_str in _as_country_cache:
        return _as_country_cache[asn_str]
    lookup_time = target_time or datetime(2025, 1, 1)
    info = get_asn_org_info(lookup_time, asn)
    raw_country = info.get("country") if info.get("success") else None
    country = None
    if isinstance(raw_country, str):
        cleaned = raw_country.strip().upper()
        if len(cleaned) == 2 and cleaned.isalpha():
            country = cleaned
        else:
            logger.debug(f"AS{asn} country {raw_country!r} is not ISO alpha-2; skipping Radar location.")
    _as_country_cache[asn_str] = country
    if country:
        logger.info(f"AS{asn} country: {country} ({info.get('org_name', '')})")
    else:
        logger.warning(f"AS{asn} no valid ISO country; using global view.")
    return country


def _parse_iso(s):
    try:
        return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return datetime.strptime(s, "%Y-%m-%d %H:%M")


def _parse_iso_utc(s):
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        return None


def _build_request_params(asn, start_dt, end_dt, location):
    """构造 Cloudflare Radar 请求参数。location 必须为 ISO alpha-2 或 None。"""
    params = {
        "dateStart": start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dateEnd": end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "asn": int(asn) if str(asn).isdigit() else asn,
        "format": "json",
        "aggInterval": CLOUDFLARE_DEFAULT_AGG_INTERVAL,
    }
    if location:
        params["location"] = location
    if CLOUDFLARE_RADAR_NORMALIZATION:
        params["normalization"] = CLOUDFLARE_RADAR_NORMALIZATION
    return params


def _normalize_location(value):
    """过滤无效的 location 值，仅返回 ISO alpha-2 字符串。"""
    if not isinstance(value, str):
        return None
    cleaned = value.strip().upper()
    if cleaned in ("", "NONE", "UNKNOWN", "NULL", "WORLD", "GLOBAL", "WW"):
        return None
    if len(cleaned) != 2 or not cleaned.isalpha():
        return None
    return cleaned


def _resolve_location(asn):
    """依次：环境变量 > 运行时解析的国家 > 无 location。"""
    loc = CLOUDFLARE_RADAR_LOCATION or _as_country_cache.get(str(asn))
    return _normalize_location(loc)


def _extract_ts_values(resp_json, asn):
    if resp_json.get("success") and "result" in resp_json:
        ts, vals = _extract_series_from_result(resp_json["result"], asn)
        if ts and vals:
            try:
                return ts, [float(v) for v in vals if v is not None]
            except (ValueError, TypeError) as e:
                logger.warning(f"Data conversion error for AS{asn}: {e}")
    return None, None


def _response_error(resp):
    try:
        return resp.json()
    except Exception:
        return {"raw": resp.text[:500]}


def _request_with_location(api, params, asn):
    """向 Cloudflare Radar 发起请求，必要时去掉 location 回退一次。"""
    for attempt in range(5):
        if attempt > 0:
            wait = min(2 ** attempt + 0.5, 30)
            logger.warning(f"AS{asn}: HTTP 429 retry {attempt}/4 in {wait:.1f}s")
            time.sleep(wait)
        resp = api.session.get(api.base_url, params=params, timeout=CLOUDFLARE_TIMEOUT)
        if resp.status_code == 200:
            ts, vals = _extract_ts_values(resp.json(), asn)
            if ts:
                return ts, vals
            if "location" in params:
                fallback = {k: v for k, v in params.items() if k != "location"}
                fb = api.session.get(api.base_url, params=fallback, timeout=CLOUDFLARE_TIMEOUT)
                if fb.status_code == 200:
                    ts, vals = _extract_ts_values(fb.json(), asn)
                    if ts:
                        api._resolved_country.pop(str(asn), None)
                        return ts, vals
            raise Exception(f"AS{asn}: HTTP 200 without usable result")
        if resp.status_code == 429:
            continue
        if resp.status_code in (401, 403):
            raise PermissionError(f"Cloudflare Radar auth failed for AS{asn}: HTTP {resp.status_code}")
        if resp.status_code == 400:
            err_text = str(_response_error(resp)).lower()
            if any(s in err_text for s in ("missing x-auth-key", "authorization headers", "missing authorization", "invalid api token")):
                raise PermissionError(f"Cloudflare Radar auth failed for AS{asn}: HTTP 400")
            if "location" not in params:
                raise Exception(f"AS{asn}: HTTP 400")
            fb = api.session.get(api.base_url, params={k: v for k, v in params.items() if k != "location"}, timeout=CLOUDFLARE_TIMEOUT)
            if fb.status_code == 200:
                ts, vals = _extract_ts_values(fb.json(), asn)
                if ts:
                    return ts, vals
            raise Exception(f"AS{asn}: HTTP 400 after removing location")
        raise Exception(f"AS{asn}: HTTP {resp.status_code}")
    raise Exception(f"AS{asn}: HTTP 429 after 4 retries")


def _consecutive_windows(anomalies, timestamps, min_consecutive=4):
    if not anomalies or not timestamps:
        return []
    sorted_a = sorted(anomalies, key=lambda x: x.get("timestamp", ""))
    indices = sorted({a.get("index", i) for i, a in enumerate(sorted_a)})
    groups, current = [], [indices[0]]
    for idx in indices[1:]:
        if idx == current[-1] + 1:
            current.append(idx)
        else:
            groups.append(current); current = [idx]
    groups.append(current)
    windows = []
    for g in groups:
        if len(g) >= min_consecutive and g[0] < len(timestamps) and g[-1] < len(timestamps):
            windows.append({"start": timestamps[g[0]], "end": timestamps[g[-1]], "duration_points": len(g)})
            logger.info(f"📊 Consecutive anomaly window: {windows[-1]['start']} → {windows[-1]['end']} ({len(g)} pts)")
    return windows


def _resolve_country_for_event(asn, event_time):
    """事件级国家解析：环境变量优先，否则查 AS-Org。"""
    if CLOUDFLARE_RADAR_LOCATION:
        return CLOUDFLARE_RADAR_LOCATION
    country = _get_as_country(asn, target_time=event_time)
    if not country:
        logger.warning(f"AS{asn} no country; using global view.")
    return country


def _select_use_periodicity(detected, daily_conf, weekly_conf, historical_count):
    """选择基线周期：仅当 daily 显著优于 weekly 时切换。"""
    if detected == "daily" and daily_conf > 3 * weekly_conf:
        logger.info(f"🔄 Daily ({daily_conf:.2%}) > 3x weekly ({weekly_conf:.2%}), using daily.")
        return "daily"
    if detected == "weekly":
        return "weekly"
    if detected == "none" and historical_count >= 2:
        logger.info("🔄 No clear period; using weekly as reference (relaxed mode).")
        return "weekly"
    return "weekly"


def _safe_multi_scale(api, asn, current_values, timestamps, query_start, query_end):
    try:
        result = MultiScaleBaseline(api.get_traffic_data).detect(
            asn=str(asn), current_values=current_values,
            current_timestamps=timestamps,
            current_start=query_start, current_end=query_end,
        )
        logger.info(f"Multi-scale: anomaly={result.is_anomaly}, score={result.weighted_score:.2f}")
        return result
    except Exception as e:
        logger.warning(f"Multi-scale detection failed: {e}")
        return None


def _multi_scale_dict(result):
    if not result:
        return None
    return {
        "is_anomaly": result.is_anomaly, "confidence": result.confidence,
        "weighted_score": result.weighted_score, "consensus_count": result.consensus_count,
        "reasoning": result.reasoning,
        "scales": [
            {"scale": r.scale, "available": r.available, "z_score": r.z_score,
             "is_anomaly": r.is_anomaly, "direction": r.direction, "deviation_pct": r.deviation_pct}
            for r in result.scales
        ],
    }


class CloudflareRadarAPI:
    def __init__(self):
        self.base_url = CLOUDFLARE_HTTP_TIMESERIES_AS_URL
        self.hasCredentials = bool(CLOUDFLARE_API_TOKEN and CLOUDFLARE_API_TOKEN.strip())
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        if self.hasCredentials:
            self.session.headers.update({"Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}"})
        self._resolved_country = {}
        self.traffic_cache_dir = Path(__file__).resolve().parents[2] / "data" / "traffic"

    def quick_screening(self, asn, start_time, end_time):
        """5-10 秒内完成预检，决定是否触发完整检测。"""
        user_start_dt, user_end_dt = _parse_iso(start_time), _parse_iso(end_time)
        timestamps, current_values = self.get_traffic_data(asn, user_start_dt, user_end_dt)
        if not current_values or len(current_values) < 5:
            return {"need_full_analysis": False, "quick_score": 0.0, "data_available": False,
                    "anomaly_signals": [], "decision_reasons": ["insufficient data points"]}

        current_arr = np.array(current_values)
        current_avg, current_std = float(np.mean(current_arr)), float(np.std(current_arr))
        anomaly_signals, quick_score = [], 0.0

        for week_offset in (1, 2):
            try:
                _, past_values = self.get_traffic_data(asn,
                    user_start_dt - timedelta(days=7 * week_offset),
                    user_end_dt - timedelta(days=7 * week_offset))
                if not past_values or len(past_values) < 5:
                    continue
                past_arr = np.array(past_values)
                past_avg, past_std = float(np.mean(past_arr)), float(np.std(past_arr))
                if current_avg > 0:
                    change_pct = abs(current_avg - past_avg) / past_avg * 100
                    if change_pct > 50:
                        anomaly_signals.append(f"major change: {change_pct:.1f}% (vs {week_offset}w ago)")
                        quick_score += 0.4
                    elif change_pct > 30:
                        anomaly_signals.append(f"moderate change: {change_pct:.1f}%")
                        quick_score += 0.25
                    elif change_pct > 15:
                        anomaly_signals.append(f"minor change: {change_pct:.1f}%")
                        quick_score += 0.1
                if past_avg > 0 and current_std / past_avg > 2:
                    anomaly_signals.append(f"volatility spike: {current_std / past_avg:.2f}x")
                    quick_score += 0.2
                break
            except Exception:
                continue

        if timestamps and len(current_values) < len(timestamps) * 0.5:
            anomaly_signals.append("data sparsity")
            quick_score += 0.15

        quick_score = min(1.0, quick_score)
        HIGH, LOW = 0.5, 0.2
        reasons, need_full = [], False
        if quick_score >= HIGH:
            need_full = True
            reasons.append(f"score {quick_score:.2f} >= {HIGH}, high confidence")
        elif quick_score >= LOW and anomaly_signals:
            need_full = True
            reasons.append(f"score {quick_score:.2f} >= {LOW}, has signals")
        else:
            reasons.append(f"score {quick_score:.2f} < {LOW}, no signals")

        logger.info(f"Quick screening AS{asn}: score={quick_score:.2f} signals={len(anomaly_signals)} need_full={need_full}")
        return {
            "need_full_analysis": need_full, "quick_score": quick_score,
            "data_available": True, "anomaly_signals": anomaly_signals,
            "decision_reasons": reasons, "data_points_checked": len(current_values),
            "screening_time": datetime.now().isoformat(),
        }

    def detect_anomalies(self, asn, start_time, end_time, plot_result=False,
                         event_start_time=None, event_end_time=None,
                         fast_mode=True, historical_weeks=None,
                         anomaly_method="combined", auto_expand_boundaries=True):
        user_start_dt, user_end_dt = _parse_iso(start_time), _parse_iso(end_time)
        self._resolved_country[str(asn)] = _resolve_country_for_event(asn, user_start_dt)

        query_start = user_start_dt - timedelta(days=1)
        query_end = user_end_dt + timedelta(hours=6)

        periodicity_info = self.analyze_periodicity(asn, query_start, query_end)
        detected = periodicity_info.get("detected_periodicity", "none")
        periodicity_confidence = periodicity_info.get("periodicity_confidence", 0.0)
        detection_method = periodicity_info.get("detection_method", "unknown")
        best_effort = periodicity_info.get("best_effort", False)

        daily_corrs = periodicity_info.get("daily_correlations", [])
        weekly_corrs = periodicity_info.get("weekly_correlations", [])
        daily_conf = max(daily_corrs) if daily_corrs else 0.0
        weekly_conf = max(weekly_corrs) if weekly_corrs else 0.0
        use_periodicity = _select_use_periodicity(
            detected, daily_conf, weekly_conf,
            periodicity_info.get("historical_periods_analyzed", 0))

        logger.info(f"🔄 Periodicity: {detected} (conf={periodicity_confidence:.2%}, method={detection_method}), using: {use_periodicity}")
        if best_effort:
            logger.info("🔄 Using period as best-effort reference.")

        timestamps, current_values = self.get_traffic_data(asn, query_start, query_end)

        if not current_values or len(current_values) < 10:
            try:
                wider_start = user_start_dt - timedelta(days=7)
                wider_end = user_end_dt + timedelta(days=7)
                ts_w, vals_w = self.get_traffic_data(asn, wider_start, wider_end)
                if vals_w and len(vals_w) >= 10:
                    logger.info(f"🔁 Adaptive retry: ±7-day window ({len(vals_w)} pts)")
                    query_start, query_end = wider_start, wider_end
                    timestamps, current_values = ts_w, vals_w
            except Exception as e:
                logger.warning(f"Adaptive retry failed: {e}")

        anomalies, historical_data = [], []
        historical_means = np.array([])
        historical_stds = np.array([])
        historical_values_list = []

        if use_periodicity in ("daily", "weekly") and periodicity_info.get("historical_periods"):
            historical_data = [
                {"timestamps": p.get("timestamps", []), "values": p.get("values", [])}
                for p in periodicity_info.get("historical_periods", [])
                if p.get("values")
            ]
            current_values, historical_means, historical_stds, historical_values_list = preprocess_traffic_data(
                current_values, historical_data)
            timestamps = timestamps[:len(current_values)]

            adj_threshold = 2.5 if periodicity_confidence < 0.1 else 3.0
            filtered_anomalies, all_anomalies = detect_anomalies_combined(
                current_values=current_values, historical_means=historical_means,
                historical_stds=historical_stds, historical_values=historical_values_list,
                timestamps=timestamps, threshold=adj_threshold,
                detect_direction="both", context_window=1, context_threshold=0.35)
            anomalies = filtered_anomalies

            # Fallback: if no anomalies detected but peak-trough shows clear drop,
            # force-run peak_trough detection directly
            if not anomalies:
                stats = calculate_traffic_statistics(current_values, historical_means)
                peak_drop = stats.get("peak_trough_drop_pct", 0.0)
                if peak_drop > 30.0:  # >30% drop from peak to trough
                    logger.info(f"⚠️ No anomalies from combined detection but peak-drop={peak_drop:.1f}%, forcing peak-trough analysis")
                    from detectors.traffic.combined import _detect_peak_trough_drops
                    pt_anomalies = _detect_peak_trough_drops(
                        current_values, historical_means, timestamps,
                        min_drop_ratio=0.25, min_sustained_points=3,
                    )
                    if pt_anomalies:
                        logger.info(f"⚠️ Peak-trough fallback found {len(pt_anomalies)} anomalies")
                        anomalies = pt_anomalies
                        all_anomalies = pt_anomalies
        else:
            current_values_array = np.array(current_values)
            raw_anomalies = detect_anomalies_non_periodic(current_values_array, threshold=2.5)
            anomalies = [
                {**a, "timestamp": timestamps[a["index"]] if a["index"] < len(timestamps) else timestamps[-1],
                 "is_anomaly": True}
                for a in raw_anomalies
            ]
            all_anomalies = anomalies

        expanded_windows = []
        if auto_expand_boundaries and all_anomalies and len(historical_means) > 0:
            try:
                expanded_windows = cluster_and_expand_anomaly_windows(
                    all_anomalies, timestamps, current_values, historical_means,
                    historical_stds=historical_stds, gap_minutes=30, expansion_hours=2)
                for w in expanded_windows:
                    logger.info(f"📊 Anomaly cluster window: {w['start']} ~ {w['end']} ({w['anomaly_count']} pts)")
            except Exception as e:
                logger.warning(f"Cluster & boundary expansion failed: {e}")

        plot_path = None
        if plot_result:
            title_suffix = ""
            if CLOUDFLARE_RADAR_LOCATION:
                title_suffix += f" [Radar geo={CLOUDFLARE_RADAR_LOCATION}]"
            else:
                country = _as_country_cache.get(str(asn))
                if country:
                    title_suffix += f" [AS org country={country}]"
            if CLOUDFLARE_RADAR_NORMALIZATION:
                title_suffix += f" [norm={CLOUDFLARE_RADAR_NORMALIZATION}]"
            plot_path = plot_traffic_comparison_beautiful(
                asn=asn, start_date=start_time, end_date=end_time,
                timestamps=timestamps, current_values=current_values,
                historical_data=historical_data, historical_means=historical_means,
                historical_stds=historical_stds, anomalies=anomalies,
                historical_values_list=historical_values_list, title_suffix=title_suffix)

        data_points = len(current_values)
        if data_points == 0:
            data_available, no_data_reason = False, "api_returned_empty"
        elif data_points < 10:
            data_available, no_data_reason = False, "insufficient_data_points"
        else:
            data_available, no_data_reason = True, ""

        stats = calculate_traffic_statistics(current_values, historical_means)
        multi_scale = _safe_multi_scale(self, asn, current_values, timestamps, query_start, query_end)
        consecutive_windows = _consecutive_windows(anomalies, timestamps)

        return {
            "success": True, "asn": asn,
            "anomalies_detected": bool(anomalies),
            "anomaly_count": len(anomalies), "anomalies": anomalies,
            "data_points": data_points, "data_available": data_available,
            "no_data_reason": no_data_reason,
            "percent_change": stats["percent_change"],
            "current_avg": stats["current_avg"], "historical_avg": stats["historical_avg"],
            # New: peak-to-trough drop statistics for better anomaly visibility
            "peak_trough_drop_pct": stats.get("peak_trough_drop_pct", 0.0),
            "trough_drop_from_peak": stats.get("trough_drop_from_peak", 0.0),
            "peak_value": stats.get("peak_value", 0.0),
            "trough_value": stats.get("trough_value", 0.0),
            "plot_path": plot_path, "expanded_windows": expanded_windows,
            "expanded_boundaries": {
                "expanded_start": expanded_windows[0]["start"] if expanded_windows else query_start.strftime("%Y-%m-%d %H:%M"),
                "expanded_end": expanded_windows[0]["end"] if expanded_windows else query_end.strftime("%Y-%m-%d %H:%M"),
            },
            "outage_period_anomalies": [],
            "consecutive_anomaly_windows": consecutive_windows,
            "use_periodicity": use_periodicity,
            "periodicity_confidence": periodicity_confidence,
            "baseline_method": (
                f"periodic_{use_periodicity}"
                if use_periodicity in ("daily", "weekly") and periodicity_confidence > 0.1
                else "non_periodic_fallback"),
            "anomaly_threshold_adjusted": (
                2.5 if (use_periodicity == "none" or periodicity_confidence < 0.1) else 3.0),
            "periodicity_analysis": periodicity_info,
            "multi_scale_analysis": _multi_scale_dict(multi_scale),
        }

    def analyze_periodicity(self, asn, query_start, query_end):
        historical_periods = []
        for week_offset in range(1, 5):
            try:
                period_start = query_start - timedelta(days=7 * week_offset)
                period_end = query_end - timedelta(days=7 * week_offset)
                timestamps, values = self.get_traffic_data(asn, period_start, period_end)
                if len(values) > 10:
                    historical_periods.append({"week_offset": week_offset, "weekly_ago": week_offset,
                                               "period_kind": "week", "start": period_start, "end": period_end,
                                               "timestamps": timestamps, "values": values})
            except Exception as e:
                logger.warning(f"Failed historical week {week_offset}: {e}")

        analysis_period = f"Previous 4 weeks before {query_start.strftime('%Y-%m-%d %H:%M')} to {query_end.strftime('%Y-%m-%d %H:%M')}"
        if len(historical_periods) < 2:
            return {"detected_periodicity": "none", "periodicity_confidence": 0.0,
                    "weekly_correlations": [], "daily_correlations": [],
                    "analysis_period": analysis_period, "note": "insufficient historical data",
                    "historical_periods_analyzed": len(historical_periods), "best_effort": True,
                    "historical_periods": historical_periods}

        all_values, all_timestamps = [], []
        for p in historical_periods:
            all_values.extend(p["values"]); all_timestamps.extend(p["timestamps"])
        if len(all_values) < 24:
            return {"detected_periodicity": "none", "periodicity_confidence": 0.0,
                    "weekly_correlations": [], "daily_correlations": [],
                    "analysis_period": analysis_period, "note": "insufficient data points",
                    "historical_periods_analyzed": len(historical_periods), "best_effort": True,
                    "historical_periods": historical_periods}

        period_result = detect_period_automatically(all_values, all_timestamps)
        weekly_corrs = [c["confidence"] for c in period_result.get("all_candidates", []) if c["period"] == "weekly"]
        daily_corrs = [c["confidence"] for c in period_result.get("all_candidates", []) if c["period"] == "daily"]
        return {
            "detected_periodicity": period_result.get("period_name", "none"),
            "periodicity_confidence": period_result.get("confidence", 0.0),
            "weekly_correlations": weekly_corrs, "daily_correlations": daily_corrs,
            "analysis_period": analysis_period,
            "detection_method": period_result.get("method", "unknown"),
            "historical_periods_analyzed": len(historical_periods),
            "best_effort": period_result.get("best_effort", False),
            "historical_periods": historical_periods,
        }

    def _load_cached_traffic_data(self, asn, start_dt, end_dt):
        if not self.traffic_cache_dir.is_dir():
            return None
        try:
            requested_start = start_dt.replace(tzinfo=None)
            requested_end = end_dt.replace(tzinfo=None)
        except AttributeError:
            return None

        samples = {}
        for cache_file in self.traffic_cache_dir.glob(f"AS{asn}_traffic_*_to_*.csv"):
            try:
                with cache_file.open(newline="", encoding="utf-8") as handle:
                    for row in csv.DictReader(handle):
                        ts = _parse_iso_utc(row.get("timestamp") or "")
                        if ts is None or not (requested_start <= ts <= requested_end):
                            continue
                        samples[ts] = float(row["value"])
            except (OSError, KeyError, TypeError, ValueError) as exc:
                logger.warning("Ignoring invalid cache file %s: %s", cache_file, exc)

        if not samples:
            return None
        ordered = sorted(samples.items())
        timestamps = [t.strftime("%Y-%m-%dT%H:%M:%SZ") for t, _ in ordered]
        values = [v for _, v in ordered]
        logger.info("Loaded %d cached traffic samples for AS%s (%s → %s)",
                    len(values), asn, ordered[0][0].isoformat(), ordered[-1][0].isoformat())
        return timestamps, values

    def get_traffic_data(self, asn, start_dt, end_dt):
        cached = self._load_cached_traffic_data(asn, start_dt, end_dt)
        if cached is not None:
            return cached
        if not self.hasCredentials:
            raise RuntimeError("Cloudflare Radar API token is not configured; set CLOUDFLARE_API_TOKEN.")

        location = _resolve_location(asn)
        params = _build_request_params(asn, start_dt, end_dt, location)
        logger.info(f"Fetching traffic for AS{asn} ({params['dateStart']} → {params['dateEnd']}, "
                    f"aggInterval={CLOUDFLARE_DEFAULT_AGG_INTERVAL}, location={location or 'worldwide'})")
        return _request_with_location(self, params, asn)

    def detect_anomalies_for_event(self, asn, start_time, end_time,
                                    event_type="hijack", as_role="victim",
                                    plot_result=True, use_aligned_baseline=True):
        """基于事件类型的异常检测，统一 schema 返回。"""
        user_start_dt, user_end_dt = _parse_iso(start_time), _parse_iso(end_time)

        try:
            query_start = user_start_dt - timedelta(days=1)
            query_end = user_end_dt + timedelta(hours=6)
            timestamps, current_values = self.get_traffic_data(asn, query_start, query_end)
        except Exception as e:
            error_text = str(e).lower()
            no_data_reason = ("cloudflare_authentication_failed"
                              if "token is not configured" in error_text or "authentication failed" in error_text
                              else "cloudflare_request_failed")
            logger.error(f"Traffic data unavailable for AS{asn}: {e}")
            return wrap(DetectionType.TRAFFIC, {
                "success": False, "asn": asn, "event_type": event_type, "as_role": as_role,
                "error": str(e), "data_available": False, "no_data_reason": no_data_reason,
                "data_points": 0, "anomalies": [], "anomaly_count": 0, "anomalies_detected": False,
            }, asn=asn).to_dict()

        if not timestamps or not current_values:
            return {
                "success": False, "asn": asn, "event_type": event_type, "as_role": as_role,
                "error": "No traffic data available", "data_available": False,
                "no_data_reason": "cloudflare_no_points", "data_points": 0,
                "anomalies": [], "anomaly_count": 0, "anomalies_detected": False,
            }

        historical_data = []
        for i in range(1, 5):
            try:
                ts_hist, vals_hist = self.get_traffic_data(
                    asn, user_start_dt - timedelta(days=7 * i + 1),
                    user_start_dt - timedelta(days=7 * i - 1))
                if ts_hist and vals_hist:
                    historical_data.append({"weekly_ago": i, "timestamps": ts_hist, "values": vals_hist})
            except Exception as e:
                logger.warning(f"Historical week {i} failed: {e}")

        if use_aligned_baseline and historical_data:
            current_arr, historical_means, historical_stds, historical_list = preprocess_traffic_data_aligned(
                current_values, historical_data, timestamps)
        else:
            current_arr, historical_means, historical_stds, historical_list = preprocess_traffic_data(
                current_values, historical_data)
            timestamps = timestamps[:len(current_arr)]

        anomalies = detect_anomalies_by_event_type(
            current_arr, historical_means, historical_stds, timestamps,
            event_type=event_type, as_role=as_role)

        if not anomalies:
            logger.info("No event-type anomalies, fallback to combined method")
            filtered, _ = detect_anomalies_combined(
                current_values=current_arr, historical_means=historical_means,
                historical_stds=historical_stds, historical_values=historical_list,
                timestamps=timestamps, threshold=2.5, detect_direction="both",
                context_window=1, context_threshold=0.2)
            anomalies = filtered

        stats = calculate_traffic_statistics(current_arr, historical_means)
        plot_path = None
        if plot_result:
            try:
                plot_path = plot_traffic_comparison_beautiful(
                    asn=asn, start_date=start_time, end_date=end_time,
                    timestamps=timestamps, current_values=current_arr.tolist() if hasattr(current_arr, "tolist") else current_arr,
                    historical_data=historical_data,
                    historical_means=historical_means.tolist() if hasattr(historical_means, "tolist") else historical_means,
                    historical_stds=historical_stds.tolist() if hasattr(historical_stds, "tolist") else historical_stds,
                    anomalies=anomalies,
                    title_suffix=f" [{event_type.upper()} - {as_role.upper()}]")
            except Exception as e:
                logger.warning(f"Plot generation failed: {e}")

        return wrap(DetectionType.TRAFFIC, {
            "success": True, "asn": asn, "event_type": event_type, "as_role": as_role,
            "anomalies": anomalies, "anomaly_count": len(anomalies),
            "anomalies_detected": bool(anomalies),
            "statistics": stats, "plot_path": plot_path,
            "analysis_timestamp": datetime.now().isoformat(),
            "data_available": bool(stats.get("data_points", 0)),
            "no_data_reason": "" if stats.get("data_points", 0) > 0 else "cloudflare_no_points",
            "data_points": stats.get("data_points", 0),
        }, asn=asn).to_dict()


def detect_anomalies_for_event_batch(events, output_dir=None):
    """批量检测事件异常。"""
    api = CloudflareRadarAPI()
    results = []
    for event in events:
        result = api.detect_anomalies_for_event(
            asn=event.get("asn"), start_time=event.get("start_time"),
            end_time=event.get("end_time"), event_type=event.get("event_type", "hijack"),
            as_role=event.get("as_role", "victim"), plot_result=True)
        results.append(result)
        if result.get("anomalies_detected"):
            logger.info(f"AS{result['asn']} ({result['as_role']}): {result['anomaly_count']} anomalies")
        else:
            logger.info(f"AS{result['asn']} ({result['as_role']}): no anomalies")
    return results