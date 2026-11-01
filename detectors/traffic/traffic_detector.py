import csv
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import numpy as np
import requests

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import logger
from config import (
    CLOUDFLARE_HTTP_TIMESERIES_AS_URL,
    CLOUDFLARE_DNS_TIMESERIES_URL,
    CLOUDFLARE_API_TOKEN,
    CLOUDFLARE_TIMEOUT,
    CLOUDFLARE_DEFAULT_AGG_INTERVAL,
    CLOUDFLARE_RADAR_LOCATION,
    CLOUDFLARE_RADAR_NORMALIZATION,
)
from data.asorg_loader import get_asn_org_info
from detectors.traffic import timeparse
from detectors.traffic.traffic_plotting import plot_traffic_comparison_beautiful
# Periodicity + preprocessing
from detectors.traffic.periodicity import detect_period_automatically
from detectors.traffic.preprocessing import preprocess_traffic_data
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
from detectors.traffic.multi_scale_baseline import MultiScaleBaseline
from detectors.unified_result import wrap, DetectionType
from typing import Optional
from detectors.traffic.preprocessing import filter_consecutive_anomalies
from detectors.traffic.sudden import detect_anomalies_sudden_jump

_as_country_cache: dict = {}

# Shared detection parameters. Both public entry points (`detect_anomalies` and
# `detect_anomalies_for_event`) must agree on these, otherwise the same event
# scores differently depending on which path the caller happened to use.
TRAFFIC_Z_THRESHOLD = 2.5           # lenient z gate (low periodicity confidence)
TRAFFIC_Z_THRESHOLD_STRICT = 3.0    # strict z gate (confident periodicity)
TRAFFIC_CONTEXT_THRESHOLD = 0.35     # neighbourhood agreement for a real drop


def extract_series_from_result(result, asn):
    """Cloudflare Radar result , (timestamps, values). """
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


def get_as_country(asn, target_time=None):
    """ AS (ISO alpha-2), . """
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


def parse_iso(s):
    """Parse a time string in any of several common formats."""
    return timeparse.parse_iso(s)


def parse_iso_utc(s):
    """Parse a UTC time string. Returns ``None`` on failure."""
    return timeparse.parse_iso_utc(s)


def build_request_params(asn, start_dt, end_dt, location):
    """ Cloudflare Radar . location ISO alpha-2 None. """
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


def normalize_location(value):
    """ location , ISO alpha-2 . """
    if not isinstance(value, str):
        return None
    cleaned = value.strip().upper()
    if cleaned in ("", "NONE", "UNKNOWN", "NULL", "WORLD", "GLOBAL", "WW"):
        return None
    if len(cleaned) != 2 or not cleaned.isalpha():
        return None
    return cleaned


def resolve_location(asn):
    """: > > location. """
    loc = CLOUDFLARE_RADAR_LOCATION or _as_country_cache.get(str(asn))
    return normalize_location(loc)


def extract_ts_values(resp_json, asn):
    if resp_json.get("success") and "result" in resp_json:
        ts, vals = extract_series_from_result(resp_json["result"], asn)
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


def response_error(resp):
    try:
        return resp.json()
    except (KeyError, IndexError, AttributeError):
        return {"raw": resp.text[:500]}


class RadarSpanFetcher:
    """Fetch several sub-windows that must share one normalization scale."""

    #: Cloudflare rejects ``aggInterval=15m`` beyond 31 days (code 2001).
    MAX_SPAN = timedelta(days=30)

    #: Overlap between consecutive chunks, used to fit the shared scale.
    OVERLAP = timedelta(days=2)

    def __init__(self, api, asn, location=None, prefix=None, endpoint=None,
                 global_series=False):
        self.api = api
        self.asn = asn
        self.location = location
        #: When set, the series is fetched for a prefix instead of an
        #: ASN.  A hijack is a *prefix* event: the rest of the victim's
        #: traffic keeps flowing, so an ASN-level series cannot show the
        #: impact of a hijacked prefix at all.
        self.prefix = prefix
        #: The Radar endpoint to query.  ``http`` measures requests to
        #: Cloudflare-served websites; ``dns`` measures queries to the
        #: 1.1.1.1 resolver.  They are different data sources and are
        #: not interchangeable.
        self.endpoint = endpoint or "http"
        #: When set, no ``asn`` filter is sent and the series covers all
        #: clients.  The resolver series is global: an outage of the
        #: resolver address hits every client at once, so the impact of
        #: such a hijack is visible in the unfiltered series and is
        #: *not* visible in any single client's series.
        self.global_series = global_series
        self._cache: dict[tuple, tuple[list[str], list[float]]] = {}

    def chunk_bounds(self, lo: datetime, hi: datetime):
        """Split ``[lo, hi]`` into overlapping spans that fit inside the limit.

        Each span is at most ``MAX_SPAN`` long, and consecutive spans
        start ``MAX_SPAN - OVERLAP`` apart, so the tail of one span
        overlaps the head of the next.
        """
        if hi - lo <= self.MAX_SPAN:
            return [(lo, hi)]
        step = self.MAX_SPAN - self.OVERLAP
        bounds: list[tuple[datetime, datetime]] = []
        span_start = lo
        while span_start < hi:
            span_end = min(span_start + self.MAX_SPAN, hi)
            bounds.append((span_start, span_end))
            if span_end >= hi:
                break
            span_start += step
        return bounds

    @staticmethod
    def align_series(src_ts, src_vals, ref_ts, ref_vals):
        """Return ``src_vals`` mapped onto the scale of ``ref_vals``.
        
        Returns ``None`` when the two series do not overlap, which happens
        when Cloudflare drops samples at a chunk boundary."""
        ref_map = dict(zip(ref_ts, ref_vals))
        pairs: list[tuple[float, float]] = []
        for t, v in zip(src_ts, src_vals):
            r = ref_map.get(t)
            if r is not None:
                pairs.append((v, r))
        if len(pairs) < 2:
            return None
        # ``a`` minimises sum (a*src - ref)^2 with no intercept.
        num = sum(s * r for s, r in pairs)
        den = sum(s * s for s, _ in pairs)
        if den == 0:
            return None
        a = num / den
        # Guard against a degenerate fit: the residual on the overlap must be
        # small relative to the signal, otherwise the two series are not
        # related by a scale and merging them would corrupt the data.
        resid = [abs(a * s - r) for s, r in pairs]
        signal = max(abs(r) for _, r in pairs) or 1.0
        if max(resid) > 0.02 * signal:
            logger.warning(
                "AS: shared-span chunk alignment residual %.4f exceeds 2%% of "
                "signal %.4f; the chunks may not share a normalization scope",
                max(resid), signal,
            )
        return [a * v for v in src_vals]

    def fetch_chunk(self, lo: datetime, hi: datetime):
        """Fetch one chunk, applying the interval fallback chain on HTTP 400."""
        params = {
            "dateStart": lo.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "dateEnd": hi.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "format": "json",
            "aggInterval": CLOUDFLARE_DEFAULT_AGG_INTERVAL,
        }
        # The DNS endpoint and the HTTP endpoint are different data
        # sources: one measures queries to the 1.1.1.1 resolver, the
        # other measures requests to Cloudflare-served websites.  The
        # ``asn`` filter is the *client* network in both cases.
        if self.prefix:
            # Radar has no per-prefix filter.  A prefix-scoped
            # measurement is therefore not expressible, and the caller
            # has to fall back to the ASN or the global series.
            params["asn"] = int(self.asn)
        elif not self.global_series:
            params["asn"] = int(self.asn)
        if self.location:
            params["location"] = self.location
        if CLOUDFLARE_RADAR_NORMALIZATION:
            params["normalization"] = CLOUDFLARE_RADAR_NORMALIZATION

        url = self.api.base_url
        if self.endpoint == "dns":
            url = CLOUDFLARE_DNS_TIMESERIES_URL

        last_error = ""
        for attempt in range(3):
            try:
                resp = self.api.session.get(
                    url, params=params, timeout=CLOUDFLARE_TIMEOUT
                )
            except Exception as exc:  # noqa: BLE001 — transient TLS/reset
                last_error = f"{type(exc).__name__}: {exc}"
                time.sleep(2 ** attempt)
                continue
            if resp.status_code == 200:
                ts, vals = extract_ts_values(resp.json(), self.asn)
                if ts:
                    return ts, vals
                last_error = "HTTP 200 without usable timeseries"
                break
            last_error = f"HTTP {resp.status_code}"
            if resp.status_code in (401, 403):
                break
            if resp.status_code == 400:
                # "aggregation interval is too low for date range" — the
                # chunk is still too wide for 15m.  Coarsen and retry once.
                err_text = str(response_error(resp)).lower()
                coarser = {"15m": "1h", "1h": "1d"}.get(params.get("aggInterval"))
                if coarser and "aggregation interval is too low" in err_text:
                    params["aggInterval"] = coarser
                    params.pop("location", None)
                    last_error = f"HTTP 400 ({err_text[:120]}) -> retry aggInterval={coarser}"
                    continue
            time.sleep(2 ** attempt)

        target = self.prefix or f"AS{self.asn}"
        raise Exception(f"{target}: shared-span fetch failed ({last_error})")

    def fetch(self, spans: list[tuple[datetime, datetime]]):
        """Return one ``(timestamps, values)`` pair covering all spans."""
        if not spans:
            return [], []

        lo = min(s for s, _ in spans)
        hi = max(e for _, e in spans)
        key = (lo, hi)
        if key in self._cache:
            return self._cache[key]

        chunks = self.chunk_bounds(lo, hi)
        merged_ts: list[str] = []
        merged_vals: list[float] = []
        for idx, (c_lo, c_hi) in enumerate(chunks):
            ts, vals = self.fetch_chunk(c_lo, c_hi)
            if not ts:
                continue
            if merged_ts:
                aligned = self.align_series(ts, vals, merged_ts, merged_vals)
                if aligned is None:
                    logger.warning(
                        "AS%s: chunk %d/%d does not overlap the accumulated "
                        "series; appending it on its own scale",
                        self.asn, idx + 1, len(chunks),
                    )
                else:
                    vals = aligned
            merged_ts.extend(ts)
            merged_vals.extend(vals)

        if not merged_ts:
            raise Exception(f"AS{self.asn}: shared-span fetch returned no samples")

        # De-duplicate timestamps: overlapping chunks report the shared band
        # twice, and the first occurrence wins so the series is monotonic.
        seen: set[str] = set()
        out_ts: list[str] = []
        out_vals: list[float] = []
        for t, v in zip(merged_ts, merged_vals):
            if t in seen:
                continue
            seen.add(t)
            out_ts.append(t)
            out_vals.append(v)
        out_ts.sort()
        out_vals = [v for _, v in sorted(zip(out_ts, out_vals), key=lambda p: p[0])]

        self._cache[key] = (out_ts, out_vals)
        return out_ts, out_vals

    def slice(self, spans, start, end):
        """Return only the samples of a shared-span fetch inside one window."""
        ts_all, vals_all = self.fetch(spans)
        lo = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        hi = end.strftime("%Y-%m-%dT%H:%M:%SZ")
        picked = [
            (t, v) for t, v in zip(ts_all, vals_all) if lo <= t <= hi
        ]
        return [t for t, _ in picked], [v for _, v in picked]


def request_with_location(api, params, asn):
    """Cloudflare Radar , location ."""
    for attempt in range(5):
        if attempt > 0:
            wait = min(2 ** attempt + 0.5, 30)
            logger.warning(f"AS{asn}: HTTP 429 retry {attempt}/4 in {wait:.1f}s")
            time.sleep(wait)
        resp = api.session.get(api.base_url, params=params, timeout=CLOUDFLARE_TIMEOUT)
        if resp.status_code == 200:
            ts, vals = extract_ts_values(resp.json(), asn)
            if ts:
                return ts, vals
            if "location" in params:
                fallback = {k: v for k, v in params.items() if k != "location"}
                fb = api.session.get(api.base_url, params=fallback, timeout=CLOUDFLARE_TIMEOUT)
                if fb.status_code == 200:
                    ts, vals = extract_ts_values(fb.json(), asn)
                    if ts:
                        api._resolved_country.pop(str(asn), None)
                        return ts, vals
            raise Exception(f"AS{asn}: HTTP 200 without usable result")
        if resp.status_code == 429:
            continue
        if resp.status_code in (401, 403):
            raise PermissionError(f"Cloudflare Radar auth failed for AS{asn}: HTTP {resp.status_code}")
        if resp.status_code == 400:
            err_text = str(response_error(resp)).lower()
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
                    ts, vals = extract_ts_values(fb.json(), asn)
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
                    ts, vals = extract_ts_values(fb2.json(), asn)
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
                ts, vals = extract_ts_values(fb.json(), asn)
                if ts:
                    return ts, vals
            raise Exception(f"AS{asn}: HTTP 400 after removing location: {err_text[:300]}")
        raise Exception(f"AS{asn}: HTTP {resp.status_code}")
    raise Exception(f"AS{asn}: HTTP 429 after 4 retries")


def consecutive_windows(anomalies, timestamps, min_consecutive=4):
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


def resolve_country_for_event(asn, event_time):
    """: , AS-Org. """
    if CLOUDFLARE_RADAR_LOCATION:
        return CLOUDFLARE_RADAR_LOCATION
    country = get_as_country(asn, target_time=event_time)
    if not country:
        logger.warning(f"AS{asn} no country; using global view.")
    return country


def select_use_periodicity(detected, daily_conf, weekly_conf, historical_count):
    """: daily weekly . """
    if detected == "daily" and daily_conf > 3 * weekly_conf:
        logger.info(f"🔄 Daily ({daily_conf:.2%}) > 3x weekly ({weekly_conf:.2%}), using daily.")
        return "daily"
    if detected == "weekly":
        return "weekly"
    if detected == "none" and historical_count >= 2:
        logger.info("🔄 No clear period; using weekly as reference (relaxed mode).")
        return "weekly"
    return "weekly"


def safe_multi_scale(api, asn, current_values, timestamps, query_start, query_end):
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
    except AttributeError as e:
        logger.warning(f"Multi-scale detection failed: {e}")
        return None


def multi_scale_dict(result):
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


    def detect_anomalies(self, asn, start_time, end_time, plot_result=False,
                         event_start_time=None, event_end_time=None,
                         fast_mode=True, historical_weeks=None,
                         anomaly_method="combined", auto_expand_boundaries=True):
        user_start_dt, user_end_dt = parse_iso(start_time), parse_iso(end_time)
        self._resolved_country[str(asn)] = resolve_country_for_event(asn, user_start_dt)

        query_start = user_start_dt - timedelta(days=1)
        query_end = user_end_dt + timedelta(hours=6)

        # Fetch the query window and all four baseline weeks on ONE shared
        baseline_windows = [
            (query_start - timedelta(days=7 * i), query_end - timedelta(days=7 * i))
            for i in range(1, 5)
        ]
        # The upstream fetch can fail for reasons outside our control (an
        # AS the provider has no series for, a truncated response, a 5xx
        # after retries).  That is an absence of traffic evidence, not a
        # crash of the analysis: report it as a data-availability result so
        # the caller can fall back to the routing evidence.
        try:
            shared = self.get_traffic_windows_shared_scale(
                asn, [(query_start, query_end)] + baseline_windows)
        except Exception as exc:
            logger.error(f"Traffic data unavailable for AS{asn}: {exc}")
            error_text = str(exc).lower()
            no_data_reason = (
                "cloudflare_authentication_failed"
                if "token is not configured" in error_text
                or "authentication failed" in error_text
                else "cloudflare_request_failed"
            )
            return wrap(DetectionType.TRAFFIC, {
                "success": False,
                "asn": asn,
                "error": str(exc),
                "data_available": False,
                "no_data_reason": no_data_reason,
                "data_points": 0,
                "anomalies": [],
                "anomaly_count": 0,
                "anomalies_detected": False,
                "traffic_signal_present": False,
            }, asn=asn).to_dict()

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
        use_periodicity = select_use_periodicity(
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
            except AttributeError as e:
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
                    from detectors.traffic.combined import detect_peak_trough_drops
                    pt_anomalies = detect_peak_trough_drops(
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
            except AttributeError as e:
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
        multi_scale = safe_multi_scale(self, asn, current_values, timestamps, query_start, query_end)
        consecutive = consecutive_windows(anomalies, timestamps)

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
            "consecutive_anomaly_windows": consecutive,
            "use_periodicity": use_periodicity,
            "periodicity_confidence": periodicity_confidence,
            # Which scale the query window and its baselines were built on.
            "baseline_scale_source": "shared" if shared else "separate",
            "baseline_weeks_available": periodicity_info.get("historical_periods_analyzed", 0),
            "baseline_method": (
                f"periodic_{use_periodicity}"
                if use_periodicity in ("daily", "weekly") and periodicity_confidence > 0.1
                else "non_periodic_fallback"),
            "anomaly_threshold_adjusted": (
                2.5 if (use_periodicity == "none" or periodicity_confidence < 0.1) else 3.0),
            "periodicity_analysis": periodicity_info,
            "multi_scale_analysis": multi_scale_dict(multi_scale),
        }

    def analyze_periodicity(self, asn, query_start, query_end, windows=None):
        """Build the historical baseline for a query window."""
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
            except AttributeError as e:
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
    UNIT_SPLIT_THRESHOLD = 100.0

    def classify_traffic_unit(self, values):
        """Return "raw" for request counts, "normalized" for MIN0_MAX floats."""
        peak = 0.0
        for v in values:
            av = abs(v)
            if av > peak:
                peak = av
        return "raw" if peak > self.UNIT_SPLIT_THRESHOLD else "normalized"

    def load_cached_traffic_data(self, asn, start_dt, end_dt):
        """Single-window convenience wrapper.
        
        Returns ``None`` when the cache holds nothing for this window, so the
        caller falls through to a live fetch. ``load_cached_windows`` returns
        ``None`` for a cache miss (it is also the "no such ASN" signal), so the
        result must be checked before indexing."""
        loaded = self.load_cached_windows(asn, [(start_dt, end_dt)])
        if loaded is None:
            return None
        return loaded.get((start_dt, end_dt))

    def load_cached_windows(self, asn, windows):
        """Load every requested window from cache on ONE shared unit scale.
        
        Returns ``{(start, end): (timestamps, values)}`` for windows the cache
        covers, and ``None`` when the cache holds nothing for the ASN at all."""
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
                        ts = parse_iso_utc(row.get("timestamp") or "")
                        if ts is None or not (lo <= ts <= hi):
                            continue
                        rows.append((ts, float(row["value"])))
                if not rows:
                    continue
                unit = self.classify_traffic_unit([v for _, v in rows])
                by_unit.setdefault(unit, {}).update(rows)
            except (OSError, KeyError, TypeError, ValueError) as exc:
                logger.warning("Ignoring invalid cache file %s: %s", cache_file, exc)

        if not by_unit:
            return None

        if len(by_unit) > 1:
            # Refuse to build a series that spans two unit systems. Pick the
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
        cached = self.load_cached_traffic_data(asn, start_dt, end_dt)
        if cached is not None:
            return cached
        if not self.hasCredentials:
            raise RuntimeError("Cloudflare Radar API token is not configured; set CLOUDFLARE_API_TOKEN.")

        location = resolve_location(asn)
        params = build_request_params(asn, start_dt, end_dt, location)
        logger.info(f"Fetching traffic for AS{asn} ({params['dateStart']} → {params['dateEnd']}, "
                    f"aggInterval={CLOUDFLARE_DEFAULT_AGG_INTERVAL}, location={location or 'worldwide'})")
        return request_with_location(self, params, asn)

    def get_traffic_windows_shared_scale(self, asn, windows):
        """Return ``{(start, end): (timestamps, values)}`` on ONE shared scale."""
        windows = [w for w in windows if w and w[0] and w[1]]
        if not windows:
            return {}

        # Cache first, and resolve the unit bucket once for the whole set so a
        # cached event window and cached baseline weeks share one scale. This
        # mirrors the single-request live path below.
        cached = self.load_cached_windows(asn, windows)
        if cached is not None:
            return cached

        if not self.hasCredentials:
            out = {}
            for start_dt, end_dt in windows:
                try:
                    out[(start_dt, end_dt)] = self.get_traffic_data(asn, start_dt, end_dt)
                except (KeyError, IndexError, AttributeError) as exc:  # noqa: BLE001 - degrade to no baseline
                    logger.warning("AS%s window %s→%s unavailable: %s",
                                   asn, start_dt, end_dt, exc)
                    out[(start_dt, end_dt)] = ([], [])
            return out

        asn_clean = str(asn).replace("AS", "").strip()
        location = resolve_location(asn)
        fetcher = RadarSpanFetcher(self, asn_clean, location)
        out: dict = {}
        for start_dt, end_dt in windows:
            try:
                out[(start_dt, end_dt)] = fetcher.slice(windows, start_dt, end_dt)
            except (KeyError, IndexError, AttributeError) as exc:  # noqa: BLE001 - degrade to no baseline
                logger.warning("AS%s window %s→%s unavailable: %s",
                               asn, start_dt, end_dt, exc)
                out[(start_dt, end_dt)] = ([], [])
        return out

    def detect_anomalies_for_event(self, asn, start_time, end_time,
                                    event_type="hijack", as_role="victim",
                                    plot_result=True, use_aligned_baseline=True):
        """Event-typed wrapper around the shared-scale detection path."""
        user_start_dt, user_end_dt = parse_iso(start_time), parse_iso(end_time)

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
        except AttributeError as e:
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
            except AttributeError as e:
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