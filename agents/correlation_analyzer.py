"""
Correlation Analyzer Module
==========================

: traffic_raw routing_result 
 ΔT() . 

 report_agent.before_rewrite.py , 
 report_agent.py correlation_analysis . 

:
 from agents.correlation_analyzer import analyze_temporal_correlation
 result = analyze_temporal_correlation(traffic_raw, routing_result, target_as="16509")
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Optional

# ---------------------------------------------------------------------------
class TemporalEvent:
    """A timestamped anomaly event from either traffic or routing detection."""

    def __init__(
        self,
        timestamp: datetime,
        source: Literal["traffic", "routing"],
        event_type: str,
        severity: float,
        details: dict,
        asn: Optional[str] = None,
    ):
        self.timestamp = timestamp
        self.source = source  # "traffic" or "routing"
        self.event_type = event_type  # e.g., "traffic_drop", "origin_hijack", "route_leak"
        self.severity = severity  # 0-1, z-score normalized
        self.details = details
        self.asn = asn  # relevant AS for routing events


# ---------------------------------------------------------------------------
def parse_timestamp(ts: Any) -> Optional[datetime]:
    """Parse a timestamp string to datetime, trying multiple formats."""
    if ts is None:
        return None
    if isinstance(ts, datetime):
        return ts
    ts_str = str(ts).replace("Z", "+00:00").rstrip("Z")

    formats = [
        "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S%z",
        "%m/%d/%y %H:%M:%S", "%m/%d/%y %H:%M",
        "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M",
        "%Y-%m-%d", "%d-%m-%Y",
        "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S%z",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts_str, fmt)
        except (ValueError, IndexError):
            pass

    # Try truncated
    for fmt in ["%m/%d/%y %H:%M:%S", "%m/%d/%y %H:%M",
                "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M",
                "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"]:
        try:
            return datetime.strptime(ts_str[:19], fmt)
        except (ValueError, IndexError):
            pass

    # ISO
    try:
        return datetime.fromisoformat(ts_str[:19])
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(ts_str)
    except ValueError:
        pass

    # Month name fallback
    month_names = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
                   "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}
    match = re.match(r'(\w+)\s+(\d+),?\s+(\d+)', ts_str)
    if match:
        month_str, day, year = match.groups()
        month_str = month_str.lower()[:3]
        if month_str in month_names:
            try:
                return datetime(int(year), month_names[month_str], int(day))
            except ValueError:
                pass
    return None


# ---------------------------------------------------------------------------
def to_dict_helper(value):
    """Coerce AnomalyDetail / dataclass / dict-like to a plain dict."""
    if isinstance(value, dict):
        return value
    if hasattr(value, "__dict__"):
        return dict(getattr(value, "__dict__", {}) or {})
    return {}


def _resolve_fallback_timestamp(routing_result: dict, analysis_window) -> Optional[datetime]:
    """Pick a single deterministic fallback timestamp for events whose own
 timestamp field is missing/unparseable.

 Priority:
 1. ``analysis_window`` midpoint - most accurate since callers know it.
 2. ``routing_result["analysis_period"]`` (string "start to end").
 3. ``datetime(1970, 1, 1)`` - extreme but always valid.

 Returning ``None`` means "no information" and the caller should drop the
 event with a loud warning (we can't synthesise a meaningful timestamp).
 """
    if analysis_window:
        start = analysis_window.get("start") or analysis_window.get("detected_start")
        end = analysis_window.get("end") or analysis_window.get("detected_end")
        if start and end:
            s = parse_timestamp(start)
            e = parse_timestamp(end)
            if s and e:
                return s + (e - s) / 2
        # Single-point window
        ts = parse_timestamp(start or end)
        if ts:
            return ts
    period = (routing_result or {}).get("analysis_period") if isinstance(routing_result, dict) else None
    if isinstance(period, str) and " to " in period:
        try:
            start, end = period.split(" to ", 1)
            s, e = parse_timestamp(start.strip()), parse_timestamp(end.strip())
            if s and e:
                return s + (e - s) / 2
        except Exception:
            pass
    # Last resort — keep events "real" so the routing_event_count matches
    return datetime(1970, 1, 1)


def _resolve_event_timestamp(event_dict, fallback_ts, fallback_used_box):
    """Parse timestamp from an event dict, falling back to ``fallback_ts``.

 Returns ``(timestamp, None)`` on success. On fallback the first event
 triggers a single warning and ``fallback_used_box`` is mutated to True
 so subsequent events stay quiet (avoids log floods on 401-event payloads).

 ``fallback_used_box`` is a single-element list used as a mutable flag.
 """
    raw = event_dict.get("timestamp") or event_dict.get("first_seen") or event_dict.get("time")
    ts = parse_timestamp(raw)
    if ts is not None:
        return ts, None
    if fallback_ts is None:
        return None, None
    if not fallback_used_box[0]:
        from utils.logger import logger as _logger
        # Only mention once per call — but enough context to find the source.
        _logger.warning(
            "[extract_routing_events] routing event with missing/unparseable timestamp; "
            f"using fallback={fallback_ts.isoformat()}. event_keys={list(event_dict.keys())[:8]}"
        )
        fallback_used_box[0] = True
    return fallback_ts, None


# ---------------------------------------------------------------------------
def extract_traffic_events(
    traffic_raw=None,
    traffic_anomaly_window=None,
) -> list[TemporalEvent]:
    """Pull TemporalEvent objects from traffic_raw, falling back to window synthesis.

 Accepts several input shapes so callers don't have to know which one to pass:

 1. ``{"result": {...}}`` - workflow-style blackboard entry (unwrapped to ``result``).
 2. ``{"anomalies": [...], "anomaly_count": N, ...}`` - raw result dict.
 3. ``{"<asn_str>": {...same as case 2...}}`` - react-mode multi-AS wrapper
 where the tool returned ``{"results": {"12479": raw_result}}`` and the
 caller already unwrapped one level, leaving a dict keyed by ASN.
 We pick the first AS-typed key.
 """
    events: list[TemporalEvent] = []
    traffic_raw = traffic_raw or {}

    tr = traffic_raw
    if isinstance(tr, dict) and "result" in tr and isinstance(tr["result"], dict):
        tr = tr["result"]
    # React mode sometimes hands us {asn_str: raw_result} directly when the
    if isinstance(tr, dict) and not tr.get("anomalies") and not tr.get("extended_anomalies"):
        asn_candidates = [
            v for v in tr.values()
            if isinstance(v, dict) and (
                v.get("anomalies") or v.get("anomaly_count") or v.get("anomalies_detected")
            )
        ]
        if len(asn_candidates) == 1:
            tr = asn_candidates[0]
        elif asn_candidates:
            # Multi-AS payload: pick the entry with the highest anomaly_count.
            tr = max(asn_candidates, key=lambda v: v.get("anomaly_count", 0) or 0)

    anomalies = tr.get("anomalies") or tr.get("extended_anomalies") or tr.get("peak_anomalies") or []

    try:
        pct_change_val = float(tr.get("percent_change") or 0)
    except (TypeError, ValueError):
        pct_change_val = 0.0

    for a in anomalies:
        ts = parse_timestamp(a.get("timestamp") or a.get("time"))
        if ts is None:
            continue
        if ts.tzinfo is not None:
            ts = ts.astimezone(timezone.utc).replace(tzinfo=None)

        direction = a.get("direction", "unknown")
        z_score = abs(float(a.get("z_score") or 0))
        severity = min(1.0, z_score / 5.0)

        events.append(TemporalEvent(
            timestamp=ts,
            source="traffic",
            event_type=f"traffic_{direction}",
            severity=severity,
            details={
                "value": a.get("current_value") or a.get("value", 0),
                "mean": a.get("mean") or 0.001,
                "z_score": z_score,
                "pct_change": abs(float(a.get("pct_change") or 0)),
                "direction": direction,
            },
        ))

    if events:
        return sorted(events, key=lambda e: e.timestamp)

    # Fallback: synthesize from cluster windows
    peak_trough_drop_pct = 0.0
    try:
        peak_trough_drop_pct = float(tr.get("peak_trough_drop_pct") or 0)
    except (TypeError, ValueError):
        peak_trough_drop_pct = 0.0

    window_candidates: list[dict] = []
    for key in ("expanded_windows", "consecutive_anomaly_windows"):
        wins = tr.get(key) or []
        if isinstance(wins, list):
            window_candidates.extend([w for w in wins if isinstance(w, dict)])
    if traffic_anomaly_window and isinstance(traffic_anomaly_window, dict):
        window_candidates.append(traffic_anomaly_window)
    expanded_boundaries = tr.get("expanded_boundaries")
    if isinstance(expanded_boundaries, dict):
        window_candidates.append(expanded_boundaries)

    for w in window_candidates:
        start_ts = parse_timestamp(w.get("start") or w.get("expanded_start") or w.get("detected_start"))
        end_ts = parse_timestamp(w.get("end") or w.get("expanded_end") or w.get("detected_end"))
        if not start_ts or not end_ts:
            continue
        if start_ts == end_ts:
            end_ts = start_ts

        if start_ts.tzinfo is not None and end_ts.tzinfo is None:
            end_ts = end_ts.replace(tzinfo=start_ts.tzinfo)
        elif start_ts.tzinfo is None and end_ts.tzinfo is not None:
            start_ts = start_ts.replace(tzinfo=end_ts.tzinfo)

        anomaly_count = int(w.get("anomaly_count", w.get("indices_len", 0)) or 0)

        if peak_trough_drop_pct > 0:
            severity = min(1.0, peak_trough_drop_pct / 100.0) if peak_trough_drop_pct > 10 else min(1.0, peak_trough_drop_pct)
        else:
            severity = min(1.0, abs(pct_change_val) / 50.0)
        severity = max(severity, 0.4 if anomaly_count > 0 else 0.0)

        midpoint = start_ts + (end_ts - start_ts) / 2
        if midpoint.tzinfo is not None:
            midpoint = midpoint.astimezone(timezone.utc).replace(tzinfo=None)

        events.append(TemporalEvent(
            timestamp=midpoint,
            source="traffic",
            event_type="traffic_cluster_anomaly",
            severity=severity,
            details={
                "synthesized_from": "expanded_window",
                "start": start_ts.isoformat(),
                "end": end_ts.isoformat(),
                "duration_minutes": round((end_ts - start_ts).total_seconds() / 60.0, 2),
                "cluster_anomaly_count": anomaly_count,
                "pct_change": pct_change_val,
                "peak_trough_drop_pct": peak_trough_drop_pct,
                "current_avg": tr.get("current_avg"),
                "historical_avg": tr.get("historical_avg"),
            },
        ))

    # Deduplicate by (timestamp, event_type) so coincident events of
    seen_midpoints = set()
    deduped = []
    for ev in sorted(events, key=lambda e: e.timestamp):
        mp = (ev.timestamp.isoformat(), ev.event_type)
        if mp not in seen_midpoints:
            seen_midpoints.add(mp)
            deduped.append(ev)
    return deduped


# ---------------------------------------------------------------------------
def extract_routing_events(routing_result=None, target_as="", analysis_window=None) -> list[TemporalEvent]:
    """Pull TemporalEvent objects from routing_result across flat/nested/annotation_package formats.

 Behavior change (Bug #R1, 2026-09-13): events whose ``timestamp``,
 ``first_seen``, or ``time`` field is missing or unparseable are no
 longer silently dropped - that was the root cause of verdict
 divergence between runs (e.g. AS12479 showed 401 events in one report
 and 0 in another). Instead we fall back to:

 1. The mid-point of ``analysis_window`` (if provided).
 2. The analysis_period field inside ``routing_result``.
 3. ``datetime.min`` (1970-01-01) as last resort.

 A WARNING is logged the first time a fallback fires so operators can
 see the data quality issue.

 Also handles (Bug #R6, 2026-09-13): a react-mode ``{asn_str: raw_result}``
 wrapper - same shape as the new ``extract_traffic_events`` fix.
 """
    events = []
    routing_result = routing_result or {}
    seen = set()

    # Unwrap react-mode multi-AS wrapper BEFORE the slim path so the
    # fingerprint / summary counters are computed on the real payload.
    if isinstance(routing_result, dict) and not (
        routing_result.get("origin_hijacked")
        or routing_result.get("origin_hijacking")
        or routing_result.get("hijacks")
        or routing_result.get("hijack")
        or routing_result.get("leak")
        or routing_result.get("route_leaks")
        or routing_result.get("alerts")
        or routing_result.get("result")
    ):
        asn_candidates = [
            v for v in routing_result.values()
            if isinstance(v, dict) and (
                v.get("origin_hijacked") or v.get("origin_hijacking")
                or v.get("hijacks") or v.get("hijack")
                or v.get("leak") or v.get("route_leaks")
                or v.get("alerts") or v.get("forge_hijacked")
                or v.get("forge_hijacking")
            )
        ]
        if len(asn_candidates) == 1:
            routing_result = asn_candidates[0]
        elif asn_candidates:
            routing_result = max(
                asn_candidates,
                key=lambda v: (
                    len(v.get("origin_hijacked") or [])
                    + len(v.get("origin_hijacking") or [])
                    + len(v.get("hijacks") or [])
                    + len(v.get("route_leaks") or [])
                ),
            )

    # Pick a fallback timestamp once per call so all unparseable events in
    # the same run share the same fallback (deterministic).
    fallback_ts = _resolve_fallback_timestamp(routing_result, analysis_window)
    fallback_used_box = [False]  # mutable flag so helper can flip it
    if fallback_ts is None:
        # No analysis window info at all — every event is lost. Log loudly.
        from utils.logger import logger as _logger
        _logger.warning(
            "[extract_routing_events] no fallback timestamp available; "
            "events with missing/unparseable timestamps will be dropped."
        )

    def add_event(event):
        if event.timestamp.tzinfo is not None:
            event.timestamp = event.timestamp.astimezone(timezone.utc).replace(tzinfo=None)
        key = (str(event.timestamp), event.event_type, str(event.details.get("prefix", "")))
        if key not in seen:
            seen.add(key)
            events.append(event)

    # Unwrap "result" key
    rr = routing_result
    if isinstance(rr, dict) and "result" in rr and isinstance(rr["result"], dict):
        rr = rr["result"]

    # annotation_package format: {hijack: {...}, leak: {...}}
    hijack_section = rr.get("hijack") or {}
    leak_section = rr.get("leak") or {}
    if hijack_section or leak_section:
        rr = dict(rr)
        for key in ["origin_hijacked", "forge_hijacked", "origin_hijacking", "forge_hijacking"]:
            if key not in rr or not rr.get(key):
                rr[key] = hijack_section.get(key)
        for key in ["route_leaks"]:
            if key not in rr or not rr.get(key):
                rr[key] = leak_section.get(key)

    # ---- origin_hijacked (victim) ----
    for h in (rr.get("origin_hijacked") or []):
        h = to_dict_helper(h)
        ts, _ = _resolve_event_timestamp(h, fallback_ts, fallback_used_box)
        if ts is None:
            continue
        hijacker_as = h.get("hijacker_as") or h.get("origin_as") or h.get("asn")
        victim_as = h.get("victim_as") or h.get("target_as") or h.get("asn")
        add_event(TemporalEvent(
            timestamp=ts, source="routing", event_type="origin_hijacked", severity=1.0,
            details={
                "prefix": h.get("prefix"),
                "hijacker_as": hijacker_as,
                "claimed_as": h.get("claimed_as") or hijacker_as,
                "victim_as": victim_as,
                "role": "victim",
            },
            asn=victim_as,
        ))

    # ---- origin_hijacking (attacker) ----
    for h in (rr.get("origin_hijacking") or []):
        h = to_dict_helper(h)
        ts, _ = _resolve_event_timestamp(h, fallback_ts, fallback_used_box)
        if ts is None:
            continue
        claimed_as = h.get("claimed_as") or h.get("hijacker_as") or h.get("origin_as") or h.get("asn")
        add_event(TemporalEvent(
            timestamp=ts, source="routing", event_type="origin_hijacking", severity=1.0,
            details={
                "prefix": h.get("prefix"),
                "claimed_as": claimed_as,
                "hijacker_as": h.get("hijacker_as") or h.get("asn"),
                "victim_as": h.get("victim_as"),
                "role": "attacker",
            },
            asn=h.get("hijacker_as") or h.get("asn"),
        ))

    # ---- forge_hijacked (victim) ----
    for h in (rr.get("forge_hijacked") or []):
        h = to_dict_helper(h)
        ts, _ = _resolve_event_timestamp(h, fallback_ts, fallback_used_box)
        if ts is None:
            continue
        hijacker_as = h.get("hijacker_as") or h.get("origin_as") or h.get("asn")
        add_event(TemporalEvent(
            timestamp=ts, source="routing", event_type="forge_hijacked", severity=1.0,
            details={
                "prefix": h.get("prefix"),
                "hijacker_as": hijacker_as,
                "claimed_as": h.get("claimed_as") or hijacker_as,
                "victim_as": h.get("victim_as") or h.get("target_as") or h.get("asn"),
            },
            asn=h.get("victim_as") or h.get("target_as") or h.get("asn"),
        ))

    # ---- route_leaks ----
    # BUG-R143 2026-09-29: filter out null-noise records.
    # Detector batches emit ``leaked_by=null/prefix=null`` rows when the
    # filter pass yields no real signal (e.g. when only BGPStream events
    # match the time window but no RRC00 evidence exists). Without the
    # filter, ``leak_n`` inflates to ~3000+ on those events, drowning out
    # the real signal and feeding ``compute_top_cause`` a bogus leak count.
    # A record is "real" iff at least one of ``prefix`` or ``leaked_by``
    # is populated.
    for lk in (rr.get("route_leaks") or []):
        lk = to_dict_helper(lk)
        prefix = lk.get("prefix")
        leaked_by = lk.get("leaked_by")
        if prefix is None and leaked_by is None:
            continue
        ts, _ = _resolve_event_timestamp(lk, fallback_ts, fallback_used_box)
        if ts is None:
            continue
        add_event(TemporalEvent(
            timestamp=ts, source="routing", event_type="route_leak", severity=0.8,
            details={"prefix": prefix, "leaked_by": leaked_by},
        ))

    # ---- annotation_package nested format fallback ----
    for key, ev_type, role, hijacker_field, claimed_field, victim_field in (
        ("origin_hijacked", "origin_hijacked", "victim", "hijacker_as", None, "victim_as"),
        ("origin_hijacking", "origin_hijacking", "attacker", "hijacker_as", "claimed_as", None),
        ("forge_hijacked", "forge_hijacked", "victim", "hijacker_as", None, "victim_as"),
        ("forge_hijacking", "forge_hijacking", "attacker", "hijacker_as", "claimed_as", None),
    ):
        for h in (hijack_section.get(key) or []):
            if not isinstance(h, dict):
                continue
            ts, _ = _resolve_event_timestamp(h, fallback_ts, fallback_used_box)
            if ts is None:
                continue
            details = {"prefix": h.get("prefix"), "role": role}
            if hijacker_field:
                details["hijacker_as"] = h.get(hijacker_field) or h.get("asn") or h.get("origin_as")
            if claimed_field:
                details["claimed_as"] = h.get(claimed_field) or h.get("hijacker_as") or h.get("origin_as") or h.get("asn")
            if victim_field:
                details["victim_as"] = h.get(victim_field) or h.get("target_as") or h.get("asn")
            add_event(TemporalEvent(
                timestamp=ts, source="routing", event_type=ev_type, severity=1.0,
                details=details, asn=h.get("victim_as") or h.get("asn"),
            ))

    # annotation_package leaks
    # BUG-R143 2026-09-29: same null-filter as the flat format above.
    for lk in ((routing_result.get("leak") or {}).get("route_leaks") or []):
        if not isinstance(lk, dict):
            continue
        prefix = lk.get("prefix")
        leaked_by = lk.get("leaked_by")
        if prefix is None and leaked_by is None:
            continue
        ts, _ = _resolve_event_timestamp(lk, fallback_ts, fallback_used_box)
        if ts is None:
            continue
        add_event(TemporalEvent(
            timestamp=ts, source="routing", event_type="route_leak", severity=0.8,
            details={"prefix": prefix, "leaked_by": leaked_by},
        ))

    # annotation_package outages
    outage_section = routing_result.get("outage") or {}
    for oe in (outage_section.get("outages") or []):
        if not isinstance(oe, dict):
            continue
        ts, _ = _resolve_event_timestamp(oe, fallback_ts, fallback_used_box)
        if ts is None:
            continue
        add_event(TemporalEvent(
            timestamp=ts, source="routing", event_type="outage", severity=0.9,
            details={"prefix": oe.get("prefix"), "asn": oe.get("asn") or oe.get("affected_as")},
        ))

    # ---- alerts dict format (saved per-batch JSON) ----
    alerts = routing_result.get("alerts", {})
    if isinstance(alerts, dict):
        for h in (alerts.get("origin_hijacks") or []):
            if not isinstance(h, dict):
                continue
            ts, _ = _resolve_event_timestamp(h, fallback_ts, fallback_used_box)
            if ts is None:
                continue
            hijack_type = h.get("hijack_type") or h.get("type") or ""
            is_victim = "hijacked" in hijack_type or "victim" in hijack_type.lower()
            if is_victim:
                add_event(TemporalEvent(
                    timestamp=ts, source="routing", event_type="origin_hijacked", severity=1.0,
                    details={
                        "prefix": h.get("prefix"),
                        "hijacker_as": h.get("hijacker_as") or "",
                        "victim_as": h.get("victim_as") or h.get("target_as") or "",
                        "role": "victim",
                        "as_path": h.get("as_path"),
                    },
                    asn=h.get("victim_as") or h.get("target_as"),
                ))
            else:
                add_event(TemporalEvent(
                    timestamp=ts, source="routing", event_type="origin_hijacking", severity=1.0,
                    details={
                        "prefix": h.get("prefix"),
                        "hijacker_as": h.get("hijacker_as") or "",
                        "victim_as": h.get("victim_as") or "",
                        "role": "attacker",
                        "as_path": h.get("as_path"),
                    },
                    asn=h.get("hijacker_as"),
                ))
        for lk in (alerts.get("route_leaks") or []):
            if not isinstance(lk, dict):
                continue
            # BUG-R143 2026-09-29: same null-filter as the other leak paths.
            prefix = lk.get("prefix")
            leaked_by = lk.get("leaked_by")
            if prefix is None and leaked_by is None:
                continue
            ts, _ = _resolve_event_timestamp(lk, fallback_ts, fallback_used_box)
            if ts is None:
                continue
            add_event(TemporalEvent(
                timestamp=ts, source="routing", event_type="route_leak", severity=0.8,
                details={"prefix": prefix, "leaked_by": leaked_by},
            ))

    return sorted(events, key=lambda e: e.timestamp)


# ---------------------------------------------------------------------------
def compute_delta_t(
    traffic_events,
    routing_events,
    traffic_anomaly_window=None,
) -> list[dict]:
    """ΔT per traffic event = traffic_ts - earliest_routing_ts."""
    if not routing_events:
        return []
    earliest_routing = min(e.timestamp for e in routing_events)
    if earliest_routing.tzinfo is not None:
        earliest_routing = earliest_routing.astimezone(timezone.utc).replace(tzinfo=None)

    results = []
    for te in traffic_events:
        te_ts = te.timestamp
        if te_ts.tzinfo is not None:
            te_ts = te_ts.astimezone(timezone.utc).replace(tzinfo=None)
        er_ts = earliest_routing
        if te_ts.tzinfo is not None and er_ts.tzinfo is None:
            er_ts = er_ts.replace(tzinfo=te_ts.tzinfo)
        elif te_ts.tzinfo is None and er_ts.tzinfo is not None:
            te_ts = te_ts.replace(tzinfo=er_ts.tzinfo)
        delta = te_ts - er_ts
        results.append({
            "traffic_ts": te.timestamp.isoformat(),
            "traffic_type": te.event_type,
            "earliest_routing_ts": earliest_routing.isoformat(),
            "delta_hours": round(delta.total_seconds() / 3600, 2),
            "traffic_severity": te.severity,
            "direction": te.details.get("direction", "unknown"),
        })

    # Fallback: synthesize from cluster window
    if not results and traffic_anomaly_window:
        try:
            cs = datetime.fromisoformat(str(traffic_anomaly_window.get("start") or traffic_anomaly_window.get("detected_start", "")).replace("Z", "+00:00")).replace(tzinfo=None)
            ce = datetime.fromisoformat(str(traffic_anomaly_window.get("end") or traffic_anomaly_window.get("detected_end", "")).replace("Z", "+00:00")).replace(tzinfo=None)
            midpoint = cs + (ce - cs) / 2
            delta_hours = (midpoint - earliest_routing).total_seconds() / 3600
            results.append({
                "traffic_ts": midpoint.isoformat(),
                "traffic_type": "traffic_cluster_anomaly",
                "earliest_routing_ts": earliest_routing.isoformat(),
                "delta_hours": round(delta_hours, 2),
                "traffic_severity": 0.4,
                "direction": "drop",
                "synthesized_from_cluster_window": True,
            })
        except Exception:
            pass
    return results


# ---------------------------------------------------------------------------
def assign_correlation_level(
    traffic_events,
    routing_events,
    delta_ts,
    traffic_anomaly_window=None,
    traffic_raw=None,
) -> dict:
    """Pre-compute correlation signal indicators."""
    routing_count = len(routing_events)
    traffic_count = len(traffic_events)
    traffic_max_severity = max((e.severity for e in traffic_events), default=0)

    pct_change = 0.0
    peak_trough_drop_pct = 0.0
    if traffic_raw and isinstance(traffic_raw, dict):
        peak_trough_drop_pct = float(traffic_raw.get("peak_trough_drop_pct") or 0)
        try:
            pct_change = float(traffic_raw.get("percent_change") or 0)
        except (TypeError, ValueError):
            pct_change = 0.0
        inner = traffic_raw.get("result") if isinstance(traffic_raw, dict) else None
        if isinstance(inner, dict):
            peak_trough_drop_pct = float(inner.get("peak_trough_drop_pct") or 0) or peak_trough_drop_pct
            try:
                pct_change = float(inner.get("percent_change") or 0) or pct_change
            except (TypeError, ValueError):
                pass

    has_cluster_signal = bool(traffic_anomaly_window) and bool(
        (traffic_anomaly_window.get("start") or traffic_anomaly_window.get("detected_start"))
        and (traffic_anomaly_window.get("end") or traffic_anomaly_window.get("detected_end"))
    )

    if traffic_count == 0 and has_cluster_signal:
        if peak_trough_drop_pct > 0:
            pct_severity = min(1.0, peak_trough_drop_pct / 100.0) if peak_trough_drop_pct > 10 else min(1.0, peak_trough_drop_pct)
        else:
            pct_severity = min(1.0, abs(pct_change) / 50.0)
        traffic_max_severity = max(traffic_max_severity, pct_severity)

    signals = {
        "routing_signal_present": routing_count > 0,
        "routing_event_count": routing_count,
        "traffic_signal_present": traffic_count > 0 or has_cluster_signal,
        "traffic_event_count": traffic_count,
        "traffic_max_severity": traffic_max_severity,
        "delta_ts_available": len(delta_ts) > 0,
        "delta_ts_count": len(delta_ts),
        "traffic_percent_change": pct_change,
        "traffic_peak_trough_drop_pct": peak_trough_drop_pct,
        "traffic_cluster_window": traffic_anomaly_window,
    }

    if delta_ts:
        min_delta = min(abs(d["delta_hours"]) for d in delta_ts)
        if min_delta <= 2:
            signals["temporal_proximity"] = "strong"
        elif min_delta <= 8:
            signals["temporal_proximity"] = "moderate"
        elif min_delta <= 24:
            signals["temporal_proximity"] = "weak"
        else:
            signals["temporal_proximity"] = "none"
    else:
        signals["temporal_proximity"] = "none"

    hijack_events = [e for e in routing_events if "hijack" in e.event_type]
    leak_events = [e for e in routing_events if "leak" in e.event_type]
    signals["hijack_events_count"] = len(hijack_events)
    signals["leak_events_count"] = len(leak_events)

    if delta_ts and traffic_count > 0:
        confidence = 0.8
    elif has_cluster_signal and routing_count > 0:
        confidence = 0.6
    elif has_cluster_signal or traffic_count > 0:
        confidence = 0.55
    else:
        confidence = 0.5

    return {
        "level": "SIGNALS_PRECOMPUTED",
        "label": "Signal Indicators Provided",
        "signals": signals,
        "delta_ts_summary": [
            {"earliest_routing": d.get("earliest_routing_ts"),
             "traffic_ts": d.get("traffic_ts"),
             "delta_hours": d.get("delta_hours")}
            for d in delta_ts[:5]
        ] if delta_ts else [],
        "reasoning": (
            f"Routing signal: {routing_count} events ({len(hijack_events)} hijacks, {len(leak_events)} leaks). "
            f"Traffic signal: {traffic_count} events, max severity={traffic_max_severity:.2f}, "
            f"percent_change={pct_change:.2f}%, cluster_window={'yes' if has_cluster_signal else 'no'}. "
            f"Temporal proximity: {signals['temporal_proximity']}. "
            f"These are observational signals and do not establish causation."
        ),
        "confidence": confidence,
    }


# ---------------------------------------------------------------------------
def build_merged_timeline(traffic_events, routing_events) -> list[dict]:
    """Build a sorted merged timeline."""
    all_events = []
    for e in traffic_events:
        entry = {"timestamp": e.timestamp.isoformat(), "source": "traffic",
                 "type": e.event_type, "severity": e.severity, **e.details}
        all_events.append(entry)
    for e in routing_events:
        entry = {"timestamp": e.timestamp.isoformat(), "source": "routing",
                 "type": e.event_type, "severity": e.severity, **e.details}
        all_events.append(entry)
    all_events.sort(key=lambda x: x["timestamp"])
    return all_events


# ---------------------------------------------------------------------------
def cross_validate_correlation(correlation: dict, correlation_score_result: dict | None) -> dict:
    """Summarize signals with quantitative association score."""
    score_total = None
    level_from_score = None
    avg_delta_hours = None
    if correlation_score_result and isinstance(correlation_score_result, dict):
        score_total = correlation_score_result.get("total_score")
        level_from_score = correlation_score_result.get("correlation_level", "NONE")
        avg_delta_hours = correlation_score_result.get("avg_delta_hours")

    signals = correlation.get("signals", {})
    routing_count = signals.get("routing_event_count", 0)
    traffic_count = signals.get("traffic_event_count", 0)
    temporal_proximity = signals.get("temporal_proximity", "none")

    return {
        "verdict": "OBSERVATIONAL_ONLY",
        "reconciled_level": "OBSERVATIONAL_ONLY",
        "reconciled_label": "Association evidence only; causation is unproven",
        "reconciliation": (
            f"Signals: {routing_count} routing events, {traffic_count} traffic events, "
            f"temporal proximity: {temporal_proximity}; quantitative score: "
            f"{level_from_score} ({score_total}/100 if available)."
        ),
        "conflicts": [],
        "level_from_score": level_from_score,
        "level_from_deltaT": "OBSERVATIONAL_ONLY",
        "avg_delta_hours": avg_delta_hours,
    }


# ---------------------------------------------------------------------------
def generate_refutable_hypotheses(
    correlation: dict,
    routing_events,
    traffic_events,
    delta_ts,
    target_as: str,
) -> list[dict]:
    """Build 2-4 ranked refutable hypotheses."""
    hypotheses = []
    signals = correlation.get("signals", {})
    routing_count = signals.get("routing_event_count", len(routing_events))
    traffic_count = signals.get("traffic_event_count", len(traffic_events))
    traffic_max_severity = signals.get("traffic_max_severity", 0)
    temporal_proximity = signals.get("temporal_proximity", "none")

    if routing_count == 0:
        routing_count = len(routing_events)
    if traffic_count == 0:
        traffic_count = len(traffic_events)

    victim_events = [e for e in routing_events if e.event_type in ("origin_hijacked", "forge_hijacked")]
    attacker_events = [e for e in routing_events if e.event_type in ("origin_hijacking", "forge_hijacking")]
    leak_events = [e for e in routing_events if e.event_type == "route_leak"]
    victim_count = len(victim_events)
    attacker_count = len(attacker_events)

    traffic_directions = [e.details.get("direction") for e in traffic_events if e.details.get("direction")]
    traffic_drop_count = sum(1 for d in traffic_directions if "below" in str(d).lower() or "drop" in str(d).lower())
    traffic_rise_count = sum(1 for d in traffic_directions if "above" in str(d).lower() or "rise" in str(d).lower())
    traffic_dominant_direction = "drop" if traffic_drop_count > traffic_rise_count else ("rise" if traffic_rise_count > traffic_drop_count else "mixed")

    earliest_routing_ts = min((e.timestamp for e in routing_events), default=None)
    earliest_delta = delta_ts[0] if delta_ts else None
    earliest_delta_h = earliest_delta.get("delta_hours", 0) if earliest_delta else 0

    def ev(text, citation_key=""):
        item = {"text": text}
        if citation_key:
            item["citation"] = citation_key
        return item

    has_routing = routing_count > 0
    has_traffic = traffic_count > 0 or signals.get("traffic_signal_present")
    has_temporal = temporal_proximity in ("strong", "moderate")

    # Case 1: Both signals + temporal proximity
    if has_routing and has_traffic and has_temporal:
        hypotheses.append({
            "id": "A", "rank": "A (highest confidence)", "causal_type": "observational_association",
            "statement": (
                f"{victim_count if victim_count > 0 else routing_count} routing anomaly event(s) "
                f"{'detected starting at ' + earliest_routing_ts.isoformat() + '. ' if earliest_routing_ts else ''}"
                f"Traffic anomalies {'(dropped' if traffic_dominant_direction == 'drop' else '(changed'} "
                f"{f'approximately {earliest_delta_h:.1f}h later' if earliest_delta_h else 'around the same time'} "
                f"(ΔT={earliest_delta_h:.1f}h), "
                f"{'within the configured temporal-association range' if 0.5 <= earliest_delta_h <= 8 else 'but temporal proximity is weak'}. "
                f"The signals support an observational association that requires further verification."
            ),
            "evidence": [
                ev(f"{routing_count} routing anomaly event(s) detected", "correlation.signals.routing_event_count"),
                ev(f"{traffic_count} traffic anomaly event(s) detected", "correlation.signals.traffic_event_count"),
                ev(f"Traffic max severity: {traffic_max_severity:.2f}", "correlation.signals.traffic_max_severity"),
                ev(f"Temporal proximity: {temporal_proximity}", "correlation.signals.temporal_proximity"),
                ev(f"ΔT = {earliest_delta_h:.1f}h", "delta_ts[0].delta_hours") if delta_ts else ev("No ΔT data available", ""),
            ],
            "key_assumptions": [
                {"text": "The temporal proximity is consistent with routing anomalies affecting traffic.", "risk": "medium"},
                {"text": f"The signal strength (routing={routing_count}, traffic={traffic_count}, severity={traffic_max_severity:.2f}) is sufficient for correlation.", "risk": "medium"},
            ],
            "how_to_refute": [
                {"test": "Check if ΔT is consistent across multiple events", "expected_if_wrong": "ΔT varies significantly, suggesting independent causes", "data_needed": "All traffic and routing anomaly timestamps"},
            ],
            "confidence_base": 0.7,
        })
        hypotheses.append({
            "id": "B", "rank": "B (alternative)", "causal_type": "independent_coincidence",
            "statement": (
                f"The {routing_count} routing anomalies and {traffic_count} traffic anomalies "
                f"occurred simultaneously but independently. "
                f"AS{target_as}'s traffic drop had a separate cause "
                f"(e.g., upstream link failure, maintenance, instrumentation issue)."
            ),
            "evidence": [
                ev(f"{routing_count} routing events, {traffic_count} traffic events detected", "signals"),
                ev(f"Traffic dominant direction: {traffic_dominant_direction}", "traffic_events[*].direction"),
            ],
            "key_assumptions": [
                {"text": "The traffic drop has an independent cause unrelated to routing.", "risk": "medium"},
            ],
            "how_to_refute": [
                {"test": "Check if traffic drop is specific to routing-affected prefixes", "expected_if_wrong": "Traffic drop is specific to routing-affected prefixes", "data_needed": "Prefix-level traffic breakdown"},
            ],
            "confidence_base": 0.3,
        })

    # Case 2: Routing signal, no traffic
    elif has_routing and not has_traffic:
        hypotheses.append({
            "id": "A", "rank": "A (routing signal present, traffic unclear)", "causal_type": "routing_signal_no_traffic",
            "statement": (
                f"Routing anomalies ({routing_count} events) were detected "
                f"{'at ' + earliest_routing_ts.isoformat() if earliest_routing_ts else ''}. "
                f"However, no significant traffic anomalies were detected in the analysis window. "
                f"The routing anomalies may have been resolved quickly, had minimal traffic impact, "
                f"or affected prefixes with low traffic volume."
            ),
            "evidence": [
                ev(f"{routing_count} routing anomaly event(s) detected", "correlation.signals.routing_event_count"),
                ev(f"{traffic_count} traffic anomaly events detected", "correlation.signals.traffic_event_count"),
                ev(f"Traffic severity: {traffic_max_severity:.2f}", "correlation.signals.traffic_max_severity"),
            ],
            "key_assumptions": [
                {"text": "The routing anomalies did not significantly affect traffic, or the traffic data resolution is too coarse.", "risk": "high"},
            ],
            "how_to_refute": [
                {"test": "Verify with victim traffic analysis", "expected_if_wrong": "Victim ASes show traffic drops", "data_needed": "Prefix-level traffic data for affected ASes"},
            ],
            "confidence_base": 0.5,
        })

    # Case 3: Traffic signal, no routing
    elif has_traffic and not has_routing:
        hypotheses.append({
            "id": "A", "rank": "A (traffic signal present, routing unclear)", "causal_type": "traffic_signal_no_routing",
            "statement": (
                f"Traffic anomalies ({traffic_count} events) were detected, "
                f"but no routing anomalies were found in the analysis window. "
                f"The traffic drop may be caused by factors other than BGP routing "
                f"(e.g., upstream link failure, DDoS attack, application-level issues)."
            ),
            "evidence": [
                ev(f"{traffic_count} traffic anomaly event(s) detected", "correlation.signals.traffic_event_count"),
                ev(f"Traffic severity: {traffic_max_severity:.2f}", "correlation.signals.traffic_max_severity"),
                ev(f"0 routing anomalies detected", "correlation.signals.routing_event_count"),
            ],
            "key_assumptions": [
                {"text": "The routing data coverage is sufficient to detect BGP-related anomalies.", "risk": "high"},
            ],
            "how_to_refute": [
                {"test": "Check routing data time window and coverage", "expected_if_wrong": "Routing data shows anomalies in expanded window", "data_needed": "Expanded routing analysis window"},
            ],
            "confidence_base": 0.4,
        })

    # Case 4: Neither signal
    else:
        hypotheses.append({
            "id": "A", "rank": "A (insufficient evidence)", "causal_type": "insufficient_data",
            "statement": (
                f"Neither routing signal (0 events) nor traffic signal "
                f"(0 events, severity={traffic_max_severity:.2f}) is strong enough to establish a correlation. "
                f"The analysis window may not cover the actual event, "
                f"the event may have been brief, or the data sources may not have coverage."
            ),
            "evidence": [
                ev(f"0 routing anomalies detected", "correlation.signals.routing_event_count"),
                ev(f"0 traffic anomalies detected", "correlation.signals.traffic_event_count"),
                ev(f"Traffic severity: {traffic_max_severity:.2f}", "correlation.signals.traffic_max_severity"),
            ],
            "key_assumptions": [
                {"text": "The analysis window covers the actual event.", "risk": "high"},
            ],
            "how_to_refute": [
                {"test": "Verify time window with ground truth", "expected_if_wrong": "Event occurred outside the analysis window", "data_needed": "Ground truth event timing"},
            ],
            "confidence_base": 0.2,
        })

    return hypotheses


def build_victim_verification(victim_traffic_results: dict, victim_asns: list) -> list:
    """Build victim verification summary."""
    if not victim_asns or not victim_traffic_results:
        return []
    verification = []
    for asn in victim_asns:
        traffic_data = victim_traffic_results.get(str(asn)) or {}
        anomalies = traffic_data.get("anomalies_detected", False)
        count = traffic_data.get("anomaly_count", 0)
        verification.append({
            "asn": str(asn),
            "traffic_anomalous": bool(anomalies),
            "anomaly_count": count,
            "anomalies": (traffic_data.get("anomalies") or [])[:5],
        })
    return verification


# ---------------------------------------------------------------------------
def analyze_temporal_correlation(
    traffic_raw: dict,
    routing_result: dict,
    target_as: str,
    victim_traffic_results=None,
    victim_asns=None,
    prefix_traffic_results=None,
    correlation_score_result=None,
    traffic_anomaly_window=None,
) -> dict:
    """Pre-compute temporal features (ΔT, signal indicators, timeline, hypotheses) for correlation analysis."""
    traffic_events = extract_traffic_events(traffic_raw or {}, traffic_anomaly_window)
    routing_events = extract_routing_events(
        routing_result or {}, target_as=target_as, analysis_window=traffic_anomaly_window
    ) or []
    delta_ts = compute_delta_t(traffic_events, routing_events, traffic_anomaly_window)
    correlation = assign_correlation_level(
        traffic_events, routing_events, delta_ts,
        traffic_anomaly_window=traffic_anomaly_window,
        traffic_raw=traffic_raw,
    )
    cross_validation = cross_validate_correlation(correlation, correlation_score_result)
    timeline = build_merged_timeline(traffic_events, routing_events)
    hypotheses = generate_refutable_hypotheses(
        correlation, routing_events, traffic_events, delta_ts, target_as
    )

    return {
        "summary": {
            "routing_event_count": len(routing_events),
            "traffic_event_count": len(traffic_events),
            "correlation_level": correlation["level"],
            "correlation_label": correlation["label"],
            "correlation_confidence": correlation["confidence"],
        },
        "correlation": correlation,
        "cross_validation": cross_validation,
        "delta_ts": delta_ts,
        # Keep the 50-event cap on the correlation.timeline (Phase 2
        # only needs top-50 for cross-validation). The full event
        # stream is preserved in `routing_events` / `traffic_events`
        # below, which is what CSS's bucketize-then-evaluate path
        # consumes. Removing the cap causes CSS to see a fully-saturated
        # routing series on persistent attacks (e.g.\ Orange Espa\~na)
        # where every bucket has severity 1.0, producing a degenerate
        # shift_magnitude = 0σ and CSS abstains incorrectly. The cap
        # introduces a controlled event-density gradient that lets the
        # PNS difference-in-means estimator see a non-trivial pre/post
        # shift on real incidents.
        "timeline": timeline[:50],
        "hypotheses": hypotheses,
        "routing_events": [
            {"timestamp": e.timestamp.isoformat(), "type": e.event_type,
             "severity": e.severity, **e.details}
            for e in routing_events[:20]
        ],
        "traffic_events": [
            {"timestamp": e.timestamp.isoformat(), "type": e.event_type,
             "severity": e.severity, **e.details}
            for e in traffic_events
        ],
        # Full routing event stream for CSS's bucketize-then-evaluate
        # path. CSS needs every event to compute the per-bucket PNS
        # estimator; the 20-event cap above is only for LLM narrative
        # and report rendering, not for the analytical core.
        "routing_events_full": [
            {"timestamp": e.timestamp.isoformat(), "type": e.event_type,
             "source": "routing", "severity": e.severity, **e.details}
            for e in routing_events
        ],
        "traffic_events_full": [
            {"timestamp": e.timestamp.isoformat(), "type": e.event_type,
             "source": "traffic", "severity": e.severity, **e.details}
            for e in traffic_events
        ],
        "victim_verification": build_victim_verification(victim_traffic_results or {}, victim_asns or []),
        "prefix_traffic_results": prefix_traffic_results or {},
    }
