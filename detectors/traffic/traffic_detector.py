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
# Periodicity + preprocessing
from detectors.traffic.periodicity import detect_period_automatically
from detectors.traffic.preprocessing import filter_consecutive_anomalies, preprocess_traffic_data
from detectors.traffic.preprocessing_aligned import preprocess_traffic_data_aligned
# Clustering + stats
from detectors.traffic.clustering import (
    cluster_and_expand_anomaly_windows,
    calculate_traffic_statistics,
)
# Combined / sustained / sudden detectors
from detectors.traffic.combined import detect_anomalies_combined
from detectors.traffic.sustained import (
    detect_anomalies_by_event_type,
    detect_anomalies_non_periodic,
)
from detectors.traffic.sudden import detect_anomalies_sudden_jump
from detectors.traffic.multi_scale_baseline import MultiScaleBaseline
from detectors.unified_result import wrap, DetectionType

_as_country_cache: dict = {}

# Shared detection parameters. Both public entry points (`detect_anomalies` and
# `detect_anomalies_for_event`) must agree on these, otherwise the same event
# scores differently depending on which path the caller happened to use.
TRAFFIC_Z_THRESHOLD = 2.5           # lenient z gate (low periodicity confidence)
TRAFFIC_Z_THRESHOLD_STRICT = 3.0    # strict z gate (confident periodicity)
TRAFFIC_CONTEXT_THRESHOLD = 0.35     # neighbourhood agreement for a real drop


def _extract_series_from_result(result, asn):
    """Cloudflare Radar  result ， (timestamps, values)。"""
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
    """ AS （ISO alpha-2），。"""
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
    """Parse a time string in any of several common formats.

    Bug fix 2026-09-15: the previous implementation only accepted
    ``"%Y-%m-%d %H:%M:%S"`` and ``"%Y-%m-%d %H:%M"`` — every other variant
    (ISO 8601 with ``T`` separator, ``Z`` suffix, microseconds, ...) raised
    ``ValueError`` and the tool returned a confusing "time data does not
    match format" error to the ReAct agent. The ReAct loop would then
    repeatedly retry with the same bad format, wasting both tokens and
    time. Now we iterate over every supported format so that any input
    the LLM generates is silently normalised.
    """
    if not s:
        raise ValueError("empty time string")
    s = str(s).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+0000"
    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d %H:%M",
    ):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    # Fall back to fromisoformat which handles many edge cases including
    # offset suffixes that ``strptime`` cannot.
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            f"time data {s!r} does not match any supported format"
        ) from exc


def _parse_iso_utc(s):
    """Parse a UTC time string. Returns ``None`` on failure.

    Bug fix 2026-09-15: ``fromisoformat`` accepts many formats including
    plain ``"%Y-%m-%d %H:%M:%S"`` (no ``T``). Previously, non-ISO inputs
    raised ``ValueError`` and we silently swallowed the error, returning
    ``None`` — which then propagated as a confusing crash deeper in the
    pipeline. Now we fall back to ``_parse_iso`` so we accept the same
    wide range of inputs as the normal-time parser.
    """
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).strip().replace("Z", "+00:00")).replace(tzinfo=None)
    except (ValueError, TypeError):
        pass
    try:
        return _parse_iso(s)
    except ValueError:
        return None


def _build_request_params(asn, start_dt, end_dt, location):
    """ Cloudflare Radar 。location  ISO alpha-2  None。"""
    asn_str = str(asn).strip().upper()
    if asn_str.startswith("AS"):
        asn_str = asn_str[2:].strip()
    params = {
        "dateStart": start_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dateEnd": end_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "asn": int(asn_str) if asn_str.isdigit() else asn,
        "format": "json",
        "aggInterval": CLOUDFLARE_DEFAULT_AGG_INTERVAL,
    }
    if location:
        params["location"] = location
    if CLOUDFLARE_RADAR_NORMALIZATION:
        params["normalization"] = CLOUDFLARE_RADAR_NORMALIZATION
    return params


def _normalize_location(value):
    """ location ， ISO alpha-2 。"""
    if not isinstance(value, str):
        return None
    cleaned = value.strip().upper()
    if cleaned in ("", "NONE", "UNKNOWN", "NULL", "WORLD", "GLOBAL", "WW"):
        return None
    if len(cleaned) != 2 or not cleaned.isalpha():
        return None
    return cleaned


def _resolve_location(asn):
    """： >  >  location。"""
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
        # ── Diagnose WHY the result was unusable ─────────────────────────────
        result = resp_json["result"]
        logger.warning(
            f"Cloudflare Radar returned HTTP 200 for AS{asn} but no usable "
            f"timeseries. resp_json.keys()={list(resp_json.keys())}, "
            f"result type={type(result).__name__}, result.keys()="
            f"{list(result.keys()) if isinstance(result, dict) else type(result)}"
        )
    return None, None


def _response_error(resp):
    try:
        return resp.json()
    except Exception:
        return {"raw": resp.text[:500]}


class _RadarSpanFetcher:
    """Fetch several sub-windows that must share one normalization scale.

    Cloudflare's ``MIN0_MAX`` normalization rescales **every response
    independently** to its own ``[0, 1]`` range. Issuing one request per
    baseline week therefore returns series on mutually incompatible scales, so
    comparing an event window against those weeks measures their internal
    shapes rather than their relative traffic. That artefact is the source of
    the phantom anomaly counts recorded in saved payloads (e.g. 192
    "anomalies" over 97 points, every ``z_score`` 0.0).

    Fetching the whole span in a single request and slicing afterwards keeps one
    shared scale across the event and all baseline weeks.
    """

    def __init__(self, api, asn, location=None):
        self.api = api
        self.asn = asn
        self.location = location
        self._cache: dict[tuple, tuple[list[str], list[float]]] = {}

    def fetch(self, spans: list[tuple[datetime, datetime]]):
        """Return one ``(timestamps, values)`` pair covering all spans."""
        if not spans:
            return [], []

        lo = min(s for s, _ in spans)
        hi = max(e for _, e in spans)
        key = (lo, hi)
        if key in self._cache:
            return self._cache[key]

        params = {
            "dateStart": lo.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "dateEnd": hi.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "asn": int(self.asn),
            "format": "json",
            "aggInterval": CLOUDFLARE_DEFAULT_AGG_INTERVAL,
        }
        if self.location:
            params["location"] = self.location
        if CLOUDFLARE_RADAR_NORMALIZATION:
            params["normalization"] = CLOUDFLARE_RADAR_NORMALIZATION

        last_error = ""
        for attempt in range(3):
            try:
                resp = self.api.session.get(
                    self.api.base_url, params=params, timeout=CLOUDFLARE_TIMEOUT
                )
            except Exception as exc:  # noqa: BLE001 — transient TLS/reset
                last_error = f"{type(exc).__name__}: {exc}"
                time.sleep(2 ** attempt)
                continue
            if resp.status_code == 200:
                ts, vals = _extract_ts_values(resp.json(), self.asn)
                self._cache[key] = (ts, vals)
                return ts, vals
            last_error = f"HTTP {resp.status_code}"
            if resp.status_code in (401, 403):
                break
            time.sleep(2 ** attempt)

        raise Exception(f"AS{self.asn}: shared-span fetch failed ({last_error})")

    def slice(self, spans, start, end):
        """Return only the samples of a shared-span fetch inside one window."""
        ts_all, vals_all = self.fetch(spans)
        lo = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        hi = end.strftime("%Y-%m-%dT%H:%M:%SZ")
        picked = [
            (t, v) for t, v in zip(ts_all, vals_all) if lo <= t <= hi
        ]
        return [t for t, _ in picked], [v for _, v in picked]


def _request_with_location(api, params, asn):
    """ Cloudflare Radar ， location 。

    Fallback strategy when HTTP 400 is returned:
    1. Try coarser aggInterval + no location (handles "interval too granular")
    2. Try even coarser aggInterval = 1d
    3. Log the actual error text for diagnostics.
    """
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

            # NEW: Multi-step fallback for HTTP 400.
            current_interval = params.get("aggInterval", "15m")
            coarser_map = {"1m": "15m", "5m": "1h", "15m": "1h", "30m": "1h", "1h": "1d"}
            coarser = coarser_map.get(current_interval)

            if coarser:
                fallback_params = {k: v for k, v in params.items() if k != "location"}
                fallback_params["aggInterval"] = coarser
                logger.warning(
                    f"AS{asn}: HTTP 400, retrying with aggInterval={coarser} "
                    f"and no location. error={err_text[:300]}"
                )
                fb = api.session.get(api.base_url, params=fallback_params, timeout=CLOUDFLARE_TIMEOUT)
                if fb.status_code == 200:
                    ts, vals = _extract_ts_values(fb.json(), asn)
                    if ts:
                        return ts, vals
                # Try even coarser (1d)
                fallback_params2 = {k: v for k, v in params.items() if k != "location"}
                fallback_params2["aggInterval"] = "1d"
                logger.warning(
                    f"AS{asn}: HTTP 400, retrying with aggInterval=1d and no location"
                )
                fb2 = api.session.get(api.base_url, params=fallback_params2, timeout=CLOUDFLARE_TIMEOUT)
                if fb2.status_code == 200:
                    ts, vals = _extract_ts_values(fb2.json(), asn)
                    if ts:
                        return ts, vals
                raise Exception(
                    f"AS{asn}: HTTP 400 even after aggInterval fallback. "
                    f"error={err_text[:300]}"
                )

            if "location" not in params:
                raise Exception(f"AS{asn}: HTTP 400: {err_text[:300]}")
            fb = api.session.get(api.base_url, params={k: v for k, v in params.items() if k != "location"}, timeout=CLOUDFLARE_TIMEOUT)
            if fb.status_code == 200:
                ts, vals = _extract_ts_values(fb.json(), asn)
                if ts:
                    return ts, vals
            raise Exception(f"AS{asn}: HTTP 400 after removing location: {err_text[:300]}")
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
    """：， AS-Org。"""
    if CLOUDFLARE_RADAR_LOCATION:
        return CLOUDFLARE_RADAR_LOCATION
    country = _get_as_country(asn, target_time=event_time)
    if not country:
        logger.warning(f"AS{asn} no country; using global view.")
    return country


def _select_use_periodicity(detected, daily_conf, weekly_conf, historical_count):
    """： daily  weekly 。"""
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
        # NOTE: the bound method is passed on purpose -- MultiScaleBaseline
        # reaches back through it to the API instance in order to pre-fetch all
        # scale offsets on a single shared normalization scale.
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
        """5-10 ，。"""
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

        # Fetch the query window and all four baseline weeks on ONE shared
        # normalization scale. Cloudflare's MIN0_MAX rescales every response
        # independently, so fetching the weeks separately would stretch each
        # one until its own peak equals 1.0 and make the event window
        # incomparable with its own baseline.
        baseline_windows = [
            (query_start - timedelta(days=7 * i), query_end - timedelta(days=7 * i))
            for i in range(1, 5)
        ]
        shared = self.get_traffic_windows_shared_scale(
            asn, [(query_start, query_end)] + baseline_windows)

        periodicity_info = self.analyze_periodicity(
            asn, query_start, query_end, windows=shared or None)
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

        timestamps, current_values = (shared or {}).get((query_start, query_end), ([], []))
        if not current_values:
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
            n_before = len(current_values)
            current_values, historical_means, historical_stds, historical_values_list = preprocess_traffic_data(
                current_values, historical_data)
            # preprocess_traffic_data keeps the most recent samples of the
            # current window, so the timestamp slice must keep the same tail or
            # values and timestamps silently drift apart (which would misplace
            # every anomaly index and the peak/trough search).
            n_after = len(current_values)
            if n_after == n_before:
                timestamps = timestamps[:n_after]
            else:
                timestamps = timestamps[len(timestamps) - n_after:]

            adj_threshold = (TRAFFIC_Z_THRESHOLD
                            if periodicity_confidence < 0.1 else TRAFFIC_Z_THRESHOLD_STRICT)
            filtered_anomalies, all_anomalies = detect_anomalies_combined(
                current_values=current_values, historical_means=historical_means,
                historical_stds=historical_stds, historical_values=historical_values_list,
                timestamps=timestamps, threshold=adj_threshold,
                detect_direction="both", context_window=1,
                context_threshold=TRAFFIC_CONTEXT_THRESHOLD,
                event_start_time=event_start_time, event_end_time=event_end_time,)
            anomalies = filtered_anomalies

            # Fallback: if no anomalies detected but peak-trough shows EXTREME drop
            if not anomalies:
                stats = calculate_traffic_statistics(current_values, historical_means)
                peak_drop = stats.get("peak_trough_drop_pct", 0.0)
                curr_min = stats.get("trough_value", 0.0)
                hist_min = float(np.min(historical_means)) if len(historical_means) > 0 else 0.0
                # Both conditions: >50% peak drop AND trough at least 30% below historical
                hist_deviation = abs(curr_min - hist_min) / max(abs(hist_min), 1e-6) if hist_min > 0 else 0.0
                if peak_drop > 50.0 and hist_deviation > 0.30:
                    logger.info(
                        f"⚠️ No anomalies from combined detection but extreme peak-drop={peak_drop:.1f}% "
                        f"and hist_deviation={hist_deviation:.1%}, forcing peak-trough analysis"
                    )
                    from detectors.traffic.combined import _detect_peak_trough_drops
                    pt_anomalies = _detect_peak_trough_drops(
                        current_values, historical_means, timestamps,
                        min_drop_ratio=0.40,  # ：40%
                        min_sustained_points=3,
                        min_historical_deviation_ratio=0.30,
                    )
                    if pt_anomalies:
                        logger.info(f"⚠️ Peak-trough fallback found {len(pt_anomalies)} anomalies")
                        anomalies = pt_anomalies
                        all_anomalies = pt_anomalies
                elif peak_drop > 30.0:
                    logger.info(
                        f"ℹ️ peak-drop={peak_drop:.1f}% but hist_deviation={hist_deviation:.1%} — "
                        f"normal periodic variation, not flagging as anomaly."
                    )
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
            # Which scale the query window and its baselines were built on.
            # "shared" means one normalization scope covered all of them, so
            # cross-window comparison is valid; "separate" means each window
            # was MIN0_MAX'd against itself and the baseline is indicative only.
            "baseline_scale_source": "shared" if shared else "separate",
            "baseline_weeks_available": periodicity_info.get("historical_periods_analyzed", 0),
            "baseline_method": (
                f"periodic_{use_periodicity}"
                if use_periodicity in ("daily", "weekly") and periodicity_confidence > 0.1
                else "non_periodic_fallback"),
            "anomaly_threshold_adjusted": (
                2.5 if (use_periodicity == "none" or periodicity_confidence < 0.1) else 3.0),
            "periodicity_analysis": periodicity_info,
            "multi_scale_analysis": _multi_scale_dict(multi_scale),
        }

    def analyze_periodicity(self, asn, query_start, query_end, windows=None):
        """Build the historical baseline for a query window.

        ``windows`` optionally supplies the baseline weeks pre-fetched on a
        shared normalization scale (see ``get_traffic_windows_shared_scale``).
        Supplying it is what keeps every baseline week on the same scale as the
        event window; fetching each week separately lets ``MIN0_MAX`` rescale
        each response against itself, which makes the weeks incomparable.
        """
        historical_periods = []
        for week_offset in range(1, 5):
            period_start = query_start - timedelta(days=7 * week_offset)
            period_end = query_end - timedelta(days=7 * week_offset)
            try:
                if windows is not None:
                    timestamps, values = windows.get((period_start, period_end), ([], []))
                else:
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

    # Cloudflare's MIN0_MAX normalization rescales each *response* into
    # [0, 1], while an un-normalized fetch yields raw request counts. The
    # on-disk cache holds BOTH kinds of file for the same ASN (measured: 45
    # raw vs 204 normalized across 249 files, 11 ASNs holding both), so
    # merging them by timestamp produces a series that is half request counts
    # and half 0-1 floats. Any baseline/threshold computed from such a series
    # is meaningless -- verified at runtime for AS134840 and AS23470, where a
    # single returned series contained 1441 normalized and 1021 raw points.
    #
    # Mixing units is not the same as changing the schema: the value column
    # keeps its meaning, the detector consumes floats either way, and the
    # report template never sees raw samples. So we classify each file and
    # refuse to merge across systems, rather than rewriting the cache.
    UNIT_SPLIT_THRESHOLD = 100.0

    def _classify_traffic_unit(self, values):
        """Return "raw" for request counts, "normalized" for MIN0_MAX floats.

        MIN0_MAX output is bounded by 1.0, so anything above the split
        threshold is unambiguously a raw count. The threshold sits far from
        both ranges so it cannot misclassify realistic data.
        """
        peak = 0.0
        for v in values:
            av = abs(v)
            if av > peak:
                peak = av
        return "raw" if peak > self.UNIT_SPLIT_THRESHOLD else "normalized"

    def _load_cached_traffic_data(self, asn, start_dt, end_dt):
        """Single-window convenience wrapper.

        Returns ``None`` when the cache holds nothing for this window, so the
        caller falls through to a live fetch. ``_load_cached_windows`` returns
        ``None`` for a cache miss (it is also the "no such ASN" signal), so the
        result must be checked before indexing.
        """
        loaded = self._load_cached_windows(asn, [(start_dt, end_dt)])
        if loaded is None:
            return None
        return loaded.get((start_dt, end_dt))

    def _load_cached_windows(self, asn, windows):
        """Load every requested window from cache on ONE shared unit scale.

        Returns ``{(start, end): (timestamps, values)}`` for windows the cache
        covers, and ``None`` when the cache holds nothing for the ASN at all.

        The unit bucket is chosen once for the whole set of windows rather than
        per window. Choosing per window is what produced mutually incomparable
        baselines: an event window could resolve to the ``normalized`` bucket
        while its baseline week resolved to ``raw``, or two baseline weeks could
        come from different cache files that were each ``MIN0_MAX``-scaled
        independently. Both make the resulting z-scores meaningless.
        """
        if not windows:
            return {}
        if not self.traffic_cache_dir.is_dir():
            return None

        try:
            # Keep the caller's original keys so lookups by the requested
            # window succeed, but compare against tz-naive bounds because that
            # is how cache timestamps are parsed.
            spans = [(w[0], w[1]) for w in windows]
            naive = [(s.replace(tzinfo=None), e.replace(tzinfo=None)) for s, e in spans]
        except AttributeError:
            return None
        if any(s > e for s, e in naive):
            return None
        lo = min(s for s, _ in naive)
        hi = max(e for _, e in naive)

        # bucket unit -> {timestamp: value}
        by_unit: dict = {}
        for cache_file in self.traffic_cache_dir.glob(f"AS{asn}_traffic_*_to_*.csv"):
            try:
                rows = []
                with cache_file.open(newline="", encoding="utf-8") as handle:
                    for row in csv.DictReader(handle):
                        ts = _parse_iso_utc(row.get("timestamp") or "")
                        if ts is None or not (lo <= ts <= hi):
                            continue
                        rows.append((ts, float(row["value"])))
                if not rows:
                    continue
                unit = self._classify_traffic_unit([v for _, v in rows])
                by_unit.setdefault(unit, {}).update(rows)
            except (OSError, KeyError, TypeError, ValueError) as exc:
                logger.warning("Ignoring invalid cache file %s: %s", cache_file, exc)

        if not by_unit:
            return None

        if len(by_unit) > 1:
            # Refuse to build a series that spans two unit systems. Pick the
            # unit with the most samples across the whole requested span and
            # drop the other, and say so loudly -- silently preferring one would
            # hide that a caller asked for a window covered by mixed data.
            # Choosing once for all windows is what keeps the event window and
            # its baseline weeks on a single scale.
            counts = {u: len(s) for u, s in by_unit.items()}
            chosen = max(counts, key=counts.get)
            dropped = {u: c for u, c in counts.items() if u != chosen}
            logger.warning(
                "AS%s %s→%s spans mixed traffic units %s; using %r (%d pts) and "
                "discarding %s. Mixing raw counts with MIN0_MAX floats makes "
                "baseline and threshold statistics meaningless.",
                asn, lo, hi, counts, chosen, counts[chosen], dropped,
            )
            by_unit = {chosen: by_unit[chosen]}

        unit = next(iter(by_unit))
        ordered = sorted(by_unit[unit].items())

        out: dict = {}
        for (orig_start, orig_end), (start, end) in zip(spans, naive):
            picked = [(t, v) for t, v in ordered if start <= t <= end]
            out[(orig_start, orig_end)] = (
                [t.strftime("%Y-%m-%dT%H:%M:%SZ") for t, _ in picked],
                [v for _, v in picked],
            )
        logger.info("Loaded %d cached traffic samples for AS%s (%s → %s, unit=%s)",
                    len(ordered), asn, ordered[0][0].isoformat(), ordered[-1][0].isoformat(),
                    unit)
        return out

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

    def get_traffic_windows_shared_scale(self, asn, windows):
        """Return ``{(start, end): (timestamps, values)}`` on ONE shared scale.

        Every window that will be compared against another must come from a
        single normalization scope. ``MIN0_MAX`` rescales each HTTP *response*
        into its own ``[0, 1]`` range, so fetching the event window and its
        four baseline weeks independently produces five mutually incomparable
        series: each week is stretched so its own peak becomes exactly 1.0.
        Comparing an event week against such a baseline measures the shape of
        two unrelated rescalings instead of the change in traffic.

        This is the live equivalent of the on-disk invariant enforced by
        ``_load_cached_traffic_data``: cached files are classified into unit
        buckets and never merged across systems. Here the same rule is applied
        to requests, so a cached series and a live series are always built the
        same way.

        Falls back to per-window fetching when no credentials are available, so
        cache-only runs keep working; the caller can detect that case through
        the ``scale_shared`` flag.
        """
        windows = [w for w in windows if w and w[0] and w[1]]
        if not windows:
            return {}

        # Cache first, and resolve the unit bucket once for the whole set so a
        # cached event window and cached baseline weeks share one scale. This
        # mirrors the single-request live path below.
        cached = self._load_cached_windows(asn, windows)
        if cached is not None:
            return cached

        if not self.hasCredentials:
            out = {}
            for start_dt, end_dt in windows:
                try:
                    out[(start_dt, end_dt)] = self.get_traffic_data(asn, start_dt, end_dt)
                except Exception as exc:  # noqa: BLE001 - degrade to no baseline
                    logger.warning("AS%s window %s→%s unavailable: %s",
                                   asn, start_dt, end_dt, exc)
                    out[(start_dt, end_dt)] = ([], [])
            return out

        asn_clean = str(asn).replace("AS", "").strip()
        location = _resolve_location(asn)
        fetcher = _RadarSpanFetcher(self, asn_clean, location)
        out: dict = {}
        for start_dt, end_dt in windows:
            try:
                out[(start_dt, end_dt)] = fetcher.slice(windows, start_dt, end_dt)
            except Exception as exc:  # noqa: BLE001 - degrade to no baseline
                logger.warning("AS%s window %s→%s unavailable: %s",
                               asn, start_dt, end_dt, exc)
                out[(start_dt, end_dt)] = ([], [])
        return out

    def detect_anomalies_for_event(self, asn, start_time, end_time,
                                    event_type="hijack", as_role="victim",
                                    plot_result=True, use_aligned_baseline=True):
        """Event-typed wrapper around the shared-scale detection path.

        Both entry points now obtain their windows through
        ``get_traffic_windows_shared_scale``, so the query window and its four
        baseline weeks are always built on one normalization scale and the two
        functions can no longer drift apart in how they source traffic.
        """
        user_start_dt, user_end_dt = _parse_iso(start_time), _parse_iso(end_time)

        try:
            query_start = user_start_dt - timedelta(days=1)
            query_end = user_end_dt + timedelta(hours=6)
            # Use the same baseline geometry as detect_anomalies(): each week is
            # the query window shifted back by whole weeks, so both entry points
            # compare the event against identical spans.
            windows = [(query_start, query_end)]
            for i in range(1, 5):
                windows.append((
                    query_start - timedelta(days=7 * i),
                    query_end - timedelta(days=7 * i),
                ))
            shared = self.get_traffic_windows_shared_scale(asn, windows)
            timestamps, current_values = shared.get((query_start, query_end), ([], []))
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
            win = (query_start - timedelta(days=7 * i), query_end - timedelta(days=7 * i))
            ts_hist, vals_hist = shared.get(win, ([], []))
            if ts_hist and vals_hist:
                historical_data.append({"weekly_ago": i, "timestamps": ts_hist, "values": vals_hist})

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

        # Both the event-typed and the combined detector index historical_means
        # and historical_stds sample-by-sample, so they require a baseline. When
        # no historical week could be loaded (short cache, missing history, no
        # API token) those arrays are empty and the detectors raise IndexError.
        # Fall back to the intra-window detector exactly as detect_anomalies
        # does, so an AS with no baseline degrades instead of crashing.
        has_baseline = len(historical_means) > 0 and len(historical_stds) == len(historical_means)
        if has_baseline and not anomalies:
            logger.info("No event-type anomalies, fallback to combined method")
            filtered, _ = detect_anomalies_combined(
                current_values=current_arr, historical_means=historical_means,
                historical_stds=historical_stds, historical_values=historical_list,
                timestamps=timestamps, threshold=TRAFFIC_Z_THRESHOLD,
                detect_direction="both", context_window=1,
                context_threshold=TRAFFIC_CONTEXT_THRESHOLD,
                event_start_time=start_time, event_end_time=end_time,)
            anomalies = filtered
        elif not has_baseline:
            logger.info("AS%s has no usable baseline weeks; using intra-window detection", asn)
            raw = detect_anomalies_non_periodic(np.array(current_arr), threshold=TRAFFIC_Z_THRESHOLD)
            anomalies = [
                {**a, "timestamp": timestamps[a["index"]] if a["index"] < len(timestamps) else timestamps[-1],
                 "is_anomaly": True}
                for a in raw
            ]

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
    """。"""
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