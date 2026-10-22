"""
Tool implementations for the chat-based multi-agent system.
=========================================================

Each tool follows the signature:
 async def handler(tool_input, session) -> dict

The return dict is converted to a ToolResult by the registry.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import polars as pl


# Simple in-memory cache for API calls with TTL
class APICache:
    """Simple TTL-based cache for API responses."""

    def __init__(self, ttl_seconds=3600, max_entries=4096):  # Default 1 hour TTL
        self._cache: Dict[str, tuple[Any, float]] = {}  # key -> (value, timestamp)
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._hits = 0
        self._misses = 0

    def _make_key(self, prefix, *args, **kwargs):
        """Create a cache key from function name and arguments."""
        key_data = f"{prefix}:{args}:{sorted(kwargs.items())}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def get(self, key):
        """Get value from cache if not expired."""
        if key in self._cache:
            value, timestamp = self._cache[key]
            if time.time() - timestamp < self._ttl:
                self._hits += 1
                return value
            else:
                del self._cache[key]
        self._misses += 1
        return None

    def set(self, key, value):
        """Set value in cache with current timestamp.

 A bounded ``max_entries`` cap protects against runaway memory growth
 when callers feed us ever-changing keys (different prefixes / ASNs
 across many events). When the cap is hit we drop the oldest
 ``max(64, max_entries // 16)`` entries, keeping the cap loose enough
 to amortise but tight enough that memory stays bounded.
 """
        # Opportunistically prune expired entries on every set so the
        # cap rarely has to do the heavy lifting.
        if self._cache:
            now = time.time()
            expired = [k for k, (_, ts) in self._cache.items()
                       if now - ts >= self._ttl]
            for k in expired:
                self._cache.pop(k, None)

        if len(self._cache) >= self._max_entries:
            # Drop the oldest entries by insertion order (dict preserves it).
            drop_count = max(64, self._max_entries // 16)
            for k in list(self._cache.keys())[:drop_count]:
                self._cache.pop(k, None)
        self._cache[key] = (value, time.time())

    def clear(self):
        """Clear all cache entries."""
        self._cache.clear()

    def stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        return {"hits": self._hits, "misses": self._misses, "size": len(self._cache)}


# Global cache instance for BGPView API calls
_bgpview_cache = APICache(ttl_seconds=3600)  # 1 hour TTL for AS info
_prefix_cache = APICache(ttl_seconds=3600)  # 1 hour TTL for prefix info


async def _async_get_json(url, timeout=15.0):
    """GET a URL and parse JSON without blocking the event loop.

 ``requests.get`` is synchronous and would freeze every concurrent
 coroutine on the same loop. Wrap it in ``asyncio.to_thread`` so the
 network I/O happens on a worker thread, then return ``None`` on any
 failure so callers can fall back to defaults.
 """
    import requests

    def _do_request():
        return requests.get(url, timeout=timeout)

    try:
        resp = await asyncio.to_thread(_do_request)
    except Exception:
        return None
    try:
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


# Accepted input time formats. Index 0 is the canonical (used when emitting).
_TIME_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%dT%H:%M",
    "%Y-%m-%d %H",
    "%Y-%m-%d",
)


def _parse_dt(value, fmt=None):
    """Parse a time string in multiple common formats. Returns datetime."""
    if not value:
        raise ValueError("Empty time string")
    if isinstance(value, datetime):
        return value
    v = value.strip()
    # If caller specified a format, try it first then fall back to common formats
    if fmt is not None:
        try:
            return datetime.strptime(v, fmt)
        except ValueError:
            pass
    for f in _TIME_FORMATS:
        try:
            return datetime.strptime(v, f)
        except ValueError:
            continue
    try:
        return datetime.strptime(v, "%m/%d/%y %H:%M:%S")
    except ValueError:
        pass
    raise ValueError(f"Unrecognized time format: {value!r}")

from agents.traffic_agent import run_traffic_agent
from agents.routing_agent import run_routing_agent_async
from agents.reasoning_agent import run_reasoning_agent
from agents.report_agent import generate_report_html


# ══════════════════════════════════════════════════════════════════════════════
def _unwrap_traffic_for_payload_standalone(t, target_asn=""):
    """Flatten ``{ASN: {...detector fields...}}`` → detector-level ``{...}``.

 The legacy ``analyze_traffic`` tool output is a wrapper:

 {"success": True, "results": {"8048": {...}, "12345": {...}}, ...}

 Downstream consumers (the LLM payload, ``_substitute_field_references``,
 ``_inject_code_rendered_tables``) all read fields at the **top** level of
 the traffic dict - e.g. ``traffic.anomaly_count`` or
 ``traffic.peak_trough_drop_pct``. Without this unwrap, the prompt shows
 the nested structure and the LLM/HTML report never finds the metrics,
 leaving placeholders like ``(no data)`` and ``[traffic.anomaly_count]``
 in the rendered report.

 Selection rules:
 1. If the dict already looks like a detector payload (top-level keys
 like ``anomaly_count`` / ``percent_change``), return it unchanged.
 2. If the dict is keyed by ASN values, prefer the entry whose key
 matches ``target_asn`` if given.
 3. Otherwise prefer the ASN with the highest ``anomaly_count``.

 Returns the input unchanged when none of the above apply (preserves
 the contract: tests can pass a raw payload through without alteration).
 """
    if not isinstance(t, dict) or not t:
        return t
    detector_keys = {
        "success", "anomalies_detected", "anomaly_count",
        "percent_change", "peak_trough_drop_pct", "max_severity",
        "expanded_windows", "anomalies",
    }
    # Detect ASN-nested shape: every value is a dict AND at least one value
    # has detector fields.
    if all(isinstance(v, dict) for v in t.values()) and any(
        detector_keys & set(v.keys()) if isinstance(v, dict) else False
        for v in t.values()
    ):
        target = str(target_asn or "")
        if target and target in t and isinstance(t[target], dict):
            return t[target]
        # Pick the most anomalous ASN
        candidates = []
        for k, v in t.items():
            if not isinstance(v, dict):
                continue
            ac = v.get("anomaly_count") or 0
            candidates.append((ac, k, v))
        if candidates:
            candidates.sort(key=lambda x: -x[0])
            return candidates[0][2]
        return next(iter(t.values()))
    return t


# ══════════════════════════════════════════════════════════════════════════════
from llm.llm_factory import (
    setup_llm_settings,
    DEFAULT_TEMP_REASONING,
    DEFAULT_TEMP_CLASSIFY,
)
from tools.tool_registry import ToolParameter, ToolResult, register_tool
from utils.logger import logger
from config import MODEL, API_KEY, BASE_URL, SKIP_FORGE_DETECTION
from agents.payload_builder import PayloadBudget, build_payload, cap_payload, estimate_bytes


# ══════════════════════════════════════════════════════════════════════════════
async def _analyze_traffic(tool_input, session):
    """
 Analyze traffic anomalies for one or more ASes within a time window.

 Required params:
 asn (str or list[str]): AS number(s) to analyze
 start_time (str): ISO datetime, e.g. "2025-06-21 00:30"
 end_time (str): ISO datetime
 country (str, optional): country code filter (e.g. "CN")
 """
    asn_list = tool_input.get("asn", [])
    if isinstance(asn_list, str):
        asn_list = [asn_list]
    # Bug fix 2026-09-13 (BUG-R58): previously an empty ``asn_list``
    if not asn_list:
        return {
            "success": False,
            "error": "Empty asn_list: caller must provide at least one AS number",
            "results": {},
            "observation": "analyze_traffic was called without an ASN — refusing to claim an empty anomaly verdict.",
        }
    start = tool_input.get("start_time", tool_input.get("start"))
    end = tool_input.get("end_time", tool_input.get("end"))
    country = tool_input.get("country")

    if start is None:
        raise KeyError("start_time")
    if end is None:
        raise KeyError("end_time")

    results = {}
    for asn in asn_list:
        logger.info(f"[traffic_tool] Analyzing AS{asn}  {start} → {end}")
        try:
            result = await asyncio.to_thread(
                run_traffic_agent,
                asn=str(asn),
                start_time=start,
                end_time=end,
            )
        except Exception as e:
            result = {"success": False, "error": str(e)}
        results[str(asn)] = result

    successful = [r for r in results.values() if r.get("success")]
    anomalous = [k for k, v in results.items() if v.get("anomalies_detected")]
    if not successful:
        # Every ASN failed — surface a unified error observation.
        return {
            "success": False,
            "results": results,
            "observation": (
                "All ASes failed: " + "; ".join(
                    f"AS{k}: {v.get('error', 'unknown')}"
                    for k, v in results.items()
                )
            ),
        }
    all_anomalous = bool(anomalous) and len(anomalous) == len(successful)
    obs = (
        f"Traffic anomalies detected for ASes: {anomalous}"
        if all_anomalous else
        f"No significant traffic anomalies found for the given time window."
    )
    return {"success": True, "results": results, "observation": obs}


register_tool(
    name="analyze_traffic",
    description="Detect traffic anomalies (spikes/dips) for given AS(es) in a time window using Cloudflare data.",
    parameters=[
        ToolParameter("asn", "AS number(s) — can be a single string or JSON list", "string"),
        ToolParameter("start_time", "Analysis window start, ISO format 'YYYY-MM-DD HH:MM'", "string"),
        ToolParameter("end_time", "Analysis window end, ISO format 'YYYY-MM-DD HH:MM'", "string"),
        ToolParameter("country", "Optional: filter ASes by country code (e.g. 'CN')", "string", required=False),
    ],
    handler=_analyze_traffic,
)


# ══════════════════════════════════════════════════════════════════════════════
async def _analyze_routing(tool_input, session):
    """
 Analyze BGP routing anomalies (hijacks, leaks, outages) for an AS
 within a time window.

 Required params:
 asn (str)
 start_time (str)
 end_time (str)
 Optional params:
 detail_level (str): "light" (fast, no leak detection) or "full" (all detectors).
 Default: "full". Use "light" when you just need a quick check.
 """
    asn = str(tool_input["asn"])
    start = tool_input.get("start_time", tool_input.get("start"))
    end = tool_input.get("end_time", tool_input.get("end"))
    detail = tool_input.get("detail_level", "light")

    if start is None:
        start = ""
    if end is None:
        end = ""
    # Fall back to run_context if caller didn't pass start/end.
    if isinstance(tool_input.get("asn"), type(None)) or not asn:
        rc_ar = getattr(session, "run_context", {}) or {}
        asn = str(tool_input.get("asn") or rc_ar.get("asn", "") or "")
        if not start:
            start = rc_ar.get("start_time", "")
        if not end:
            end = rc_ar.get("end_time", "")

    logger.info(f"[routing_tool] Analyzing AS{asn}  {start} → {end}  (detail={detail})")

    # ── Pre-computed shortcut ────────────────────────────────────────────────
    try:
        from agents.react_agent import _SHARED_EVIDENCE
        # Bug fix 2026-09-16: ReactAgent writes the precomputed payload to
        pre = {}
        for _run_id, _bucket in (_SHARED_EVIDENCE or {}).items():
            candidate = _bucket.get("precomputed_routing") if isinstance(_bucket, dict) else None
            if candidate and (candidate.get("hijack") or candidate.get("leak") or candidate.get("outage")):
                pre = candidate
                break
        if pre and (pre.get("hijack") or pre.get("leak") or pre.get("outage")):
            logger.info(
                f"[routing_tool] Using precomputed routing data "
                f"(hijacks={len(pre.get('hijack', {}).get('origin_hijacked', []))}, "
                f"leaks={len(pre.get('leak', {}).get('route_leaks', []))})"
            )
            # Flatten annotation_package format into the same shape that
            result = {
                "success": True,
                "origin_hijacked": pre.get("hijack", {}).get("origin_hijacked", []),
                "origin_hijacking": pre.get("hijack", {}).get("origin_hijacking", []),
                "forge_hijacked": pre.get("hijack", {}).get("forge_hijacked", []),
                "forge_hijacking": pre.get("hijack", {}).get("forge_hijacking", []),
                "route_leaks": pre.get("leak", {}).get("route_leaks", []),
                "outage_analysis": pre.get("outage", {}),
            }
            return result
    except Exception as e:
        logger.debug(f"[routing_tool] precomputed check failed: {e}; falling through to live detection")

    try:
        # BUG-R135 2026-09-28: the previous mapping (`"light" if detail !=
        # "deep_full"`) conflated the React-loop LLM's `detail_level=full`
        # intent with the legacy one-phase default. When the LLM explicitly
        # says `detail_level=full`, run full detection (leak + streaming
        # hijack + outage). Only fall back to light mode for the empty /
        # unknown explicit request.
        explicit_level = (detail or "").strip().lower()
        if explicit_level in ("full", "deep_full"):
            effective_detail = "full"
        elif explicit_level == "light":
            effective_detail = "light"
        else:
            effective_detail = "full"  # default to full so leak/hijack/origin all run
        result = await run_routing_agent_async(
            asn=asn,
            start_time=start,
            end_time=end,
            enable_mitm=not SKIP_FORGE_DETECTION,
            skip_leak=(effective_detail == "light"),
            skip_outage=(effective_detail == "light"),
            skip_hijack_streaming=(effective_detail == "light"),
        )
    except Exception as e:
        result = {"success": False, "error": str(e)}

    def _ev(ev):
        return ev.to_dict() if not isinstance(ev, dict) else ev

    if isinstance(result, dict):
        for _key in ["origin_hijacked", "forge_hijacked", "origin_hijacking", "forge_hijacking", "route_leaks"]:
            if _key in result and isinstance(result[_key], list):
                result[_key] = [_ev(e) for e in result[_key]]
    else:
        result = {}

    hijacks = result.get("origin_hijacked", []) + result.get("forge_hijacked", [])
    leaks = result.get("route_leaks", [])
    outage = result.get("outage_analysis") or {}

    # ── Extract victim ASes from routing events ─────────────────────────────────
    victim_asns = set()
    if result.get("origin_hijacked") or result.get("forge_hijacked"):
        # Queried AS was a victim — extract origin_as from victim_anomalies
        for ev in (result.get("origin_hijacked", []) + result.get("forge_hijacked", [])):
            if ev.get("origin_as"):
                victim_asns.add(str(ev["origin_as"]))
    if result.get("origin_hijacking") or result.get("forge_hijacking"):
        # Queried AS was an attacker — extract origin_as from attacker_anomalies
        for ev in (result.get("origin_hijacking", []) + result.get("forge_hijacking", [])):
            if ev.get("origin_as"):
                victim_asns.add(str(ev["origin_as"]))
    # For leaks, origin_as in route_leaks points to the prefix owner whose routes leaked
    for ev in leaks:
        if ev.get("origin-as"):
            victim_asns.add(str(ev["origin-as"]))
    # Exclude the queried AS itself from victim list
    victim_asns.discard(asn)
    victim_asns_sorted = sorted(victim_asns)

    # ──  observation， LLM  ──
    obs_parts = []

    # 
    obs_parts.append(
        f"Routing anomalies: {len(hijacks)} hijack events, {len(leaks)} leaks, "
        f"outage_score={outage.get('outage_score', 'N/A')}"
    )

    # （！）
    if hijacks:
        obs_parts.append("\nTop hijack examples (prefix -> hijacker -> victim):")
        for ev in hijacks[:3]:
            prefix = ev.get("prefix", "?")
            hijacker = ev.get("hijacker_as", ev.get("hijacker_as_list", ["?"])[0] if ev.get("hijacker_as_list") else "?")
            expected = ev.get("expected_origin", "?")
            victim = ev.get("victim_as", "?")
            obs_parts.append(
                f"  - {prefix}: expected origin={expected}, hijacked by={hijacker}, victim_as={victim}"
            )
        if len(hijacks) > 3:
            obs_parts.append(f"  ... ({len(hijacks) - 3} more)")

    #  AS 
    if victim_asns_sorted:
        obs_parts.append(f"\nDiscovered {len(victim_asns_sorted)} potential victim AS(es): {victim_asns_sorted[:5]}")
        if len(victim_asns_sorted) > 5:
            obs_parts.append(f"  (+{len(victim_asns_sorted) - 5} more)")

    # 
    if leaks:
        obs_parts.append(f"\nRoute leak examples (prefix -> leaking AS):")
        for ev in leaks[:3]:
            prefix = ev.get("prefix", "?")
            leaking_as = ev.get("leaking_as", ev.get("asns", ["?"])[0] if ev.get("asns") else "?")
            obs_parts.append(f"  - {prefix}: leaked by {leaking_as}")
        if len(leaks) > 3:
            obs_parts.append(f"  ... ({len(leaks) - 3} more)")

    obs = "\n".join(obs_parts)

    return {
        "success": True,
        "result": result,
        "victim_asns": victim_asns_sorted,
        "observation": obs,
    }


register_tool(
    name="analyze_routing",
    description="Detect BGP hijacks, route leaks, and outages for a given AS in a time window using RouteViews MRT data. Pass detail_level='light' for a fast check (no leak detection), 'full' for comprehensive analysis (all detectors).",
    parameters=[
        ToolParameter("asn", "AS number to analyze", "string"),
        ToolParameter("start_time", "Analysis window start, ISO format", "string"),
        ToolParameter("end_time", "Analysis window end, ISO format", "string"),
        ToolParameter("detail_level", "Analysis depth: 'light' (fast, no leak detection) or 'full' (all detectors)", "string", required=False, default="full"),
    ],
    handler=_analyze_routing,
)


# ══════════════════════════════════════════════════════════════════════════════
async def _check_correlation(tool_input, session):
    """Three-card joint-evidence analysis for routing and traffic signals.

    Card 1: temporal alignment with decay scoring. Card 2: blast radius
    (prefix-level AS-path shift + victim AS traffic). Card 3: falsification
    tree (which alternative explanations are excluded). Returns a C1/C2/C3
    tier for the LLM to calibrate causal confidence.
    """
    from detectors.traffic.joint_evidence import analyse_joint_evidence

    # Fall back to run_context / session evidence when caller omits asn/start/end.
    rc = getattr(session, "run_context", {}) or {}
    asn = str(tool_input.get("asn") or rc.get("asn", "") or "")
    if not asn:
        ev0 = getattr(session, "evidence", {}) or {}
        qai = ev0.get("query_as_info", {}) or {}
        if isinstance(qai, dict):
            asn = qai.get("info", {}).get("asn") or qai.get("result", {}).get("asn") or "unknown"
            asn = str(asn)
    if not asn or asn == "unknown":
        return {"success": False, "error": "No asn provided in tool_input or run_context",
                "observation": "check_correlation requires an AS number context."}
    start = tool_input.get("start_time") or rc.get("start_time", "") or ""
    end = tool_input.get("end_time") or rc.get("end_time", "") or ""

    # ── resolve traffic ──────────────────────────────────────────────────────────
    traffic_raw = tool_input.get("traffic_result")
    if isinstance(traffic_raw, dict) and traffic_raw:
        traffic_result = traffic_raw.get("results", {}) or traffic_raw.get("result", {}) or traffic_raw
    elif isinstance(traffic_raw, str):
        try:
            parsed = json.loads(traffic_raw)
            traffic_result = parsed.get("results", {}) or parsed.get("result", {}) or {}
        except Exception:
            ev = getattr(session, "evidence", {}) or {}
            traffic_result = (ev.get("analyze_traffic", {}) or {}).get("results", {}) or (
                ev.get("analyze_traffic", {}) or {}
            ).get("result", {}) or {}
    else:
        ev = getattr(session, "evidence", {}) or {}
        traffic_result = (ev.get("analyze_traffic", {}) or {}).get("results", {}) or (
            ev.get("analyze_traffic", {}) or {}
        ).get("result", {}) or {}

    # ── resolve routing ─────────────────────────────────────────────────────────
    routing_raw = tool_input.get("routing_result")
    if isinstance(routing_raw, dict) and routing_raw:
        routing_result = routing_raw.get("result", {}) or routing_raw
    elif isinstance(routing_raw, str):
        try:
            parsed = json.loads(routing_raw)
            routing_result = parsed.get("result", {}) or {}
        except Exception:
            ev = getattr(session, "evidence", {}) or {}
            routing_result = (ev.get("analyze_routing", {}) or {}).get("result", {}) or {}
    else:
        ev = getattr(session, "evidence", {}) or {}
        routing_result = (ev.get("analyze_routing", {}) or {}).get("result", {}) or {}

    # ── resolve auxiliary fields (prefix traffic, victim traffic, causal evidence) ─
    def _from_session(key):
        ev = getattr(session, "evidence", {}) or {}
        raw = ev.get(key, {})
        if isinstance(raw, dict):
            return raw.get("prefix_traffic_results", {}) or raw.get("victim_traffic_results", {}) or raw.get("causal_evidence", {}) or raw
        return {}

    classification = tool_input.get("classification_result") or _from_session("reason_and_classify")
    prefix_traffic = tool_input.get("prefix_traffic") or classification.get("prefix_traffic_results", {})
    victim_traffic = tool_input.get("victim_traffic") or classification.get("victim_traffic_results", {})
    causal_evidence = tool_input.get("causal_evidence") or classification.get("causal_evidence", {})

    # ── coerce routing events from result dict ───────────────────────────────────
    routing_events = []
    for key in ("origin_hijacked", "forge_hijacked", "origin_hijacking", "forge_hijacking", "route_leaks"):
        items = routing_result.get(key, []) or []
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict):
                routing_events.append(item)

    traffic_anomalies = traffic_result.get("anomalies", []) if isinstance(traffic_result, dict) else []
    if not isinstance(traffic_anomalies, list):
        traffic_anomalies = [traffic_anomalies] if isinstance(traffic_anomalies, dict) else []

    # ── run the three-card analyser ─────────────────────────────────────────────
    _confounders = tool_input.get("confounders")
    if not isinstance(_confounders, dict):
        _confounders = {}
    joint = analyse_joint_evidence(
        routing_events=routing_events,
        traffic_anomalies=traffic_anomalies,
        prefix_traffic=prefix_traffic if isinstance(prefix_traffic, dict) else None,
        victim_traffic=victim_traffic if isinstance(victim_traffic, dict) else None,
        confounders=_confounders,
        causal_evidence=causal_evidence if isinstance(causal_evidence, dict) else None,
        routing_available=routing_result.get("data_available", routing_result.get("success", True)) if isinstance(routing_result, dict) else True,
        traffic_available=traffic_result.get("data_available", traffic_result.get("success", True)) if isinstance(traffic_result, dict) else True,
    )

    # ── retain the legacy summary for any caller still consuming it ─────────────
    routing_anomaly_count = 0
    if isinstance(routing_result, dict):
        for _k in ("origin_hijacked", "forge_hijacked", "origin_hijacking", "forge_hijacking", "route_leaks"):
            _v = routing_result.get(_k)
            if isinstance(_v, list):
                routing_anomaly_count += len(_v)
    traffic_anomaly_count = traffic_result.get("anomaly_count", 0) if isinstance(traffic_result, dict) else 0
    outage_analysis = routing_result.get("outage_analysis") or {}
    evidence_summary = {
        "asn": asn,
        "time_window": f"{start} to {end}",
        "traffic": {
            "anomalies_detected": bool(traffic_anomaly_count),
            "anomaly_count": traffic_anomaly_count,
        },
        "routing": {
            "anomalies_detected": routing_anomaly_count > 0,
            "anomaly_count": routing_anomaly_count,
            "outage_suspected": bool(outage_analysis.get("is_outage_suspected")),
            "outage_score": outage_analysis.get("outage_score", 0),
        },
        "comparison": {
            "both_present": bool(traffic_anomaly_count) and routing_anomaly_count > 0,
            "traffic_only": bool(traffic_anomaly_count) and routing_anomaly_count == 0,
            "routing_only": not traffic_anomaly_count and routing_anomaly_count > 0,
            "neither": not traffic_anomaly_count and routing_anomaly_count == 0,
        },
        # new joint-evidence tier
        "joint_tier": joint["tier"],
        "joint_average_score": joint["average_score"],
        "evidence_cards": joint["evidence_cards"],
    }

    narrative = (
        f"Joint-evidence tier: {joint['tier']} (score={joint['average_score']:.3f}). "
        f"Routing anomalies: {routing_anomaly_count}, "
        f"traffic anomalies: {traffic_anomaly_count}. "
        f"Cards: temporal={next((c for c in joint['evidence_cards'] if c['name']=='temporal_alignment'), {}).get('score','n/a')}, "
        f"blast_radius={next((c for c in joint['evidence_cards'] if c['name']=='blast_radius'), {}).get('score','n/a')}, "
        f"falsification={next((c for c in joint['evidence_cards'] if c['name']=='falsification'), {}).get('score','n/a')}. "
        f"Rationale: {'; '.join(joint['rationale'])}."
    )

    return {
        "success": True,
        "evidence_summary": evidence_summary,
        "joint_tier": joint["tier"],
        "joint_score": joint["average_score"],
        "evidence_cards": joint["evidence_cards"],
        "rationale": joint["rationale"],
        "observation": narrative,
    }


register_tool(
    name="check_traffic_routing_correlation",
    description="Three-card joint-evidence analysis (temporal alignment / blast radius / falsification tree) with C1/C2/C3 verdict. Also returns the legacy evidence summary for backward compatibility.",
    parameters=[
        ToolParameter("asn", "AS number", "string"),
        ToolParameter("traffic_result", "Output of analyze_traffic tool", "object", required=False),
        ToolParameter("routing_result", "Output of analyze_routing tool", "object", required=False),
        ToolParameter("prefix_traffic", "Output of prefix-level traffic analysis", "object", required=False),
        ToolParameter("victim_traffic", "Output of victim AS traffic verification", "object", required=False),
        ToolParameter("confounders", "Dict of known confounders (e.g. maintenance, cdn_switch)", "object", required=False),
        ToolParameter("causal_evidence", "Verified causal evidence from independent sources", "object", required=False),
        ToolParameter("start_time", "Time window start", "string"),
        ToolParameter("end_time", "Time window end", "string"),
    ],
    handler=_check_correlation,
)


# ══════════════════════════════════════════════════════════════════════════════
async def _query_as_info(tool_input, session):
    """
 Enrich AS data with org info, AS relationships, and announced prefixes.
 Uses RIPE Whois Database REST API (authenticated) + BGPView.

 Required params:
 asn (str)
 """
    from config import RIPE_DB_WHOIS_USERNAME

    # Fall back to run_context when caller omits asn.
    rc_qa = getattr(session, "run_context", {}) or {}
    asn = str(tool_input.get("asn") or rc_qa.get("asn", "") or "")
    if not asn or asn == "unknown":
        return {"success": False, "error": "No asn provided in tool_input or run_context",
                "observation": "query_as_info requires an AS number."}

    # RIPE Whois DB: keyId in URL, follow redirects
    def _ripe_url(path):
        # RIPE Whois DB REST API is publicly accessible (no auth needed)
        return f"https://rest.db.ripe.net/ripe{path}"

    info = {"asn": asn}

    # 1. RIPE Whois DB: aut-num object
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            resp = await client.get(_ripe_url(f"/aut-num/AS{asn}"))
            if resp.status_code == 200:
                data = resp.json()
                attrs = (
                    data.get("objects", {})
                    .get("object", [{}])[0]
                    .get("attributes", {})
                    .get("attribute", [])
                )
                for a in attrs:
                    name = a.get("name", "")
                    value = a.get("value", "")
                    if name == "as-name":
                        info["as_name"] = value
                    elif name == "descr":
                        info.setdefault("descriptions", []).append(value)
                    elif name == "country":
                        info["country"] = value
                    elif name == "org":
                        info.setdefault("orgs", []).append(value)
                    elif name == "mnt-by":
                        info.setdefault("maintainers", []).append(value)
                    elif name == "abuse-c":
                        info.setdefault("abuse_contacts", []).append(value)
                info["description"] = "; ".join(info.get("descriptions", []))
    except Exception as e:
        info["whois_error"] = str(e)

    # 2. RIPE Whois DB: search route objects for prefixes + relationships
    try:
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            resp = await client.get(
                _ripe_url("/search.json"),
                params={"source": "RIPE", "query-string": f"originAS{asn}", "type-filter": "route"},
            )
            if resp.status_code == 200:
                data = resp.json()
                prefixes = []
                for obj in data.get("objects", {}).get("object", []):
                    p = next(
                        (a["value"] for a in obj.get("attributes", {}).get("attribute", [])
                         if a.get("name") == "route"),
                        None,
                    )
                    if p:
                        prefixes.append(p)
                info["announced_prefixes"] = prefixes
    except Exception as e:
        info["prefix_error"] = str(e)

    # 3. BGPView: owner / IRR info + country (free, no auth) - improved fallback with caching
    cache_key = _bgpview_cache._make_key("asn_info", asn)
    cached_info = _bgpview_cache.get(cache_key)
    if cached_info:
        # Use cached data and merge with existing info
        for key, value in cached_info.items():
            if not info.get(key):  # Only fill in missing fields from cache
                info[key] = value
    else:
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(f"https://api.bgpview.io/asn/{asn}/info")
                if resp.status_code == 200:
                    d = resp.json().get("data", {})
                    # Use BGPView data as fallback for missing fields
                    if not info.get("as_name") and d.get("name"):
                        info["as_name"] = d.get("name", "")
                    if not info.get("country") and d.get("country_code"):
                        info["country"] = d.get("country_code", "")
                    info["bgpview_owner"] = d.get("owner", {}).get("name", "")
                    info["bgpview_source"] = d.get("source", "")
                    info["bgpview_country"] = d.get("country_code", "")

                    # Cache the BGPView info for future use
                    _bgpview_cache.set(cache_key, {
                        "as_name": info.get("as_name"),
                        "country": info.get("country"),
                        "bgpview_owner": info.get("bgpview_owner"),
                        "bgpview_source": info.get("bgpview_source"),
                        "bgpview_country": info.get("bgpview_country"),
                    })

                    # Get prefixes from BGPView if not already set (also cache them)
                    if not info.get("announced_prefixes"):
                        prefix_cache_key = _prefix_cache._make_key("prefixes", asn)
                        cached_prefixes = _prefix_cache.get(prefix_cache_key)
                        if cached_prefixes:
                            info["announced_prefixes"] = cached_prefixes
                        else:
                            prefixes_resp = await client.get(f"https://api.bgpview.io/asn/{asn}/prefixes")
                            if prefixes_resp.status_code == 200:
                                prefixes_data = prefixes_resp.json().get("data", {})
                                ipv4_prefixes = prefixes_data.get("ipv4_prefixes", [])
                                ipv6_prefixes = prefixes_data.get("ipv6_prefixes", [])
                                info["announced_prefixes"] = ipv4_prefixes + ipv6_prefixes
                                # Cache the prefixes
                                _prefix_cache.set(prefix_cache_key, info["announced_prefixes"])
        except Exception as e:
            info["bgpview_error"] = str(e)

    # Use local CAIDA AS-organization data when external registries do not
    if not info.get("as_name") or not info.get("country"):
        lookup_time = tool_input.get("start_time") or tool_input.get("time")
        try:
            if isinstance(lookup_time, str):
                lookup_time = datetime.fromisoformat(lookup_time.replace("Z", "+00:00"))
            if not isinstance(lookup_time, datetime):
                lookup_time = datetime.now()
            from data.asorg_loader import get_asn_org_info
            local_info = get_asn_org_info(lookup_time, asn)
            if local_info.get("success"):
                if not info.get("as_name"):
                    info["as_name"] = local_info.get("as_name") or local_info.get("org_name")
                if not info.get("country"):
                    info["country"] = local_info.get("country")
                info["asorg_org_name"] = local_info.get("org_name", "")
                info["asorg_source"] = local_info.get("source", "")
        except Exception as e:
            info["asorg_error"] = str(e)

    obs = (
        f"AS info for AS{asn}: name={info.get('as_name', 'N/A')}, "
        f"country={info.get('country', 'N/A')}, "
        f"prefixes={len(info.get('announced_prefixes', []))}"
    )
    return {"success": True, "info": info, "observation": obs}


register_tool(
    name="query_as_info",
    description=(
        "Look up organization name, country, maintainers, abuse contacts, and announced prefixes "
        "for an AS using the RIPE Whois Database REST API (authenticated) + BGPView."
    ),
    parameters=[
        ToolParameter("asn", "AS number", "string"),
    ],
    handler=_query_as_info,
)


# ══════════════════════════════════════════════════════════════════════════════
async def _reason_and_classify(tool_input, session):
    """
 LLM-powered reasoning on traffic + routing results to produce a final
 incident classification and evidence summary.

 Required params:
 asn (str)
 traffic_result (dict)
 routing_result (dict)
 asn_info (dict, optional)
 start_time (str)
 end_time (str)

 All data is read from session.evidence when not provided in tool_input,
 so the LLM always receives the full evidence even when the caller omits
 explicit parameters.

 Run context (asn/start/end) is taken from `session.run_context` - an
 explicit per-run dict. We do NOT fall back to `sys.modules["agents.react_agent"]`
 globals; that pattern made concurrent runs and re-entrancy unsafe.
 """
    rc = getattr(session, "run_context", {}) or {}
    _run_asn = rc.get("asn", "") or ""
    _run_start = rc.get("start_time", "") or ""
    _run_end = rc.get("end_time", "") or ""

    ev = getattr(session, "evidence", {}) or {}

    asn = tool_input.get("asn") or _run_asn or ""
    if not asn:
        #  query_as_info  {"info": {"asn": ...}} 
        qai = ev.get("query_as_info", {})
        asn = qai.get("info", {}).get("asn") or qai.get("result", {}).get("asn") or "unknown"
    asn = str(asn)

    start = tool_input.get("start_time") or _run_start or ""
    end = tool_input.get("end_time") or _run_end or ""

    # ── Resolve traffic (from session.evidence when tool_input is empty) ───────
    traffic = tool_input.get("traffic_result") or {}
    # Guard: LLM sometimes passes a plain string (e.g. "No significant traffic
    if isinstance(traffic, str):
        try:
            traffic = json.loads(traffic)
        except Exception:
            traffic = {}
    if not traffic:
        raw = ev.get("analyze_traffic", {})
        if isinstance(raw, dict):
            traffic = raw.get("results", {}) or raw.get("result", {}) or raw
    # Guard: if LLM passed a string (malformed tool call), parse or fall back to session
    if isinstance(traffic, str):
        try:
            traffic = json.loads(traffic)
        except Exception:
            raw = ev.get("analyze_traffic", {})
            if isinstance(raw, dict):
                traffic = raw.get("results", {}) or raw.get("result", {}) or {}
            else:
                traffic = {}

    # ── Resolve routing (from session.evidence when tool_input is empty) ───────
    routing_raw = tool_input.get("routing_result") or {}
    if not routing_raw:
        raw = ev.get("analyze_routing", {})
        if isinstance(raw, dict):
            routing_raw = raw.get("result", {}) or raw
    if isinstance(routing_raw, str):
        try:
            routing_raw = json.loads(routing_raw)
        except Exception:
            routing_raw = {}
    routing = routing_raw.get("result", {}) if isinstance(routing_raw, dict) else (routing_raw if isinstance(routing_raw, dict) else {})

    # ── Resolve asn_info ─────────────────────────────────────────────────────
    asn_info = tool_input.get("asn_info") or {}
    if not asn_info or isinstance(asn_info, str):
        raw = ev.get("query_as_info", {})
        if isinstance(raw, dict):
            asn_info = raw.get("info", {}) or raw.get("result", {}) or {}
        else:
            asn_info = {}
    elif isinstance(asn_info, str):
        try:
            asn_info = json.loads(asn_info)
        except Exception:
            asn_info = {}

    # ── Auto-discover victim ASes from routing result and query their traffic ─────
    victim_traffic = {}
    routing_evidence = ev.get("analyze_routing", {})
    victim_asns_from_routing = routing_evidence.get("victim_asns", []) if isinstance(routing_evidence, dict) else []
    if not isinstance(victim_asns_from_routing, list):
        victim_asns_from_routing = []
    if isinstance(routing_raw, dict) and not victim_asns_from_routing:
        victim_asns_from_routing = routing_raw.get("victim_asns", []) or []
    # Deduplicate, exclude the primary AS, ensure strings
    victim_asns_clean = [str(v) for v in victim_asns_from_routing if v is not None]
    all_victim_asns = list(set(victim_asns_clean) - {str(asn)})[:10]  # max 10

    if all_victim_asns and start and end:
        logger.info(f"[reason_and_classify] Discovered {len(all_victim_asns)} victim ASes to verify: {all_victim_asns}")
        traffic_tasks = []
        for vas in all_victim_asns:
            traffic_tasks.append(
                asyncio.to_thread(run_traffic_agent, asn=str(vas), start_time=start, end_time=end)
            )
        victim_results = await asyncio.gather(*traffic_tasks, return_exceptions=True)
        for vas, res in zip(all_victim_asns, victim_results):
            if isinstance(res, Exception):
                victim_traffic[vas] = {"success": False, "error": str(res)}
            else:
                victim_traffic[vas] = res if isinstance(res, dict) else {"success": False, "error": "unexpected result"}
        logger.info(f"[reason_and_classify] Victim traffic query complete: {len(victim_traffic)} results")

    # ── Auto-analyze prefix-level traffic impact if hijack detected ───────────
    prefix_traffic_results = {}
    routing_unwrapped_for_prefix = routing if isinstance(routing, dict) else {}
    has_hijack = bool(
        routing_unwrapped_for_prefix.get("origin_hijacked") or
        routing_unwrapped_for_prefix.get("forge_hijacked")
    )
    if has_hijack and start and end:
        try:
            prefixes = []
            hijacker_asn_str = ""
            victim_asn_str = ""
            for ev in routing_unwrapped_for_prefix.get("origin_hijacked", []):
                if ev.get("prefix") and ev.get("prefix") not in prefixes:
                    prefixes.append(ev["prefix"])
                if ev.get("hijacker_as"):
                    hijacker_asn_str = str(ev["hijacker_as"])
            for ev in routing_unwrapped_for_prefix.get("forge_hijacked", []):
                if ev.get("prefix") and ev.get("prefix") not in prefixes:
                    prefixes.append(ev["prefix"])
            attacker_anomalies = routing_unwrapped_for_prefix.get("origin_hijacking", [])
            if not hijacker_asn_str and attacker_anomalies:
                hijacker_asn_str = str(attacker_anomalies[0].get("origin_as", ""))

            if prefixes:
                logger.info(f"[reason_and_classify] Triggering prefix traffic analysis for {len(prefixes)} prefixes")
                prefix_result = await _analyze_prefix_traffic({
                    "prefixes": prefixes,
                    "hijacker_asn": hijacker_asn_str,
                    "victim_asn": asn,
                    "start_time": start,
                    "end_time": end,
                    "routing_result": routing_unwrapped_for_prefix,
                }, session)
                if prefix_result.get("success"):
                    prefix_traffic_results = prefix_result.get("results", {})
                logger.info(f"[reason_and_classify] Prefix traffic analysis complete")
        except Exception as e:
            logger.warning(f"[reason_and_classify] Prefix traffic analysis failed: {e}")

    # ── Compute quantitative correlation score (P1: compute_traffic_routing_correlation_score) ─
    correlation_score_result = {}
    if traffic and routing:
        try:
            corr_input = {
                "traffic_result": traffic,
                "routing_result": routing_unwrapped_for_prefix,
                "victim_traffic": victim_traffic,
                "prefix_traffic": prefix_traffic_results,
            }
            correlation_score_result = await _compute_traffic_routing_correlation_score(corr_input, session)
            logger.info(f"[reason_and_classify] Correlation score: {correlation_score_result.get('total_score', 'N/A')}")
        except Exception as e:
            logger.warning(f"[reason_and_classify] Correlation score computation failed: {e}")

    # ── Analyze AS-path structural changes (P1: analyze_as_path_delta) ───────────
    as_path_delta_result = {}
    if routing_unwrapped_for_prefix and start and end:
        try:
            path_input = {
                "routing_result": routing_unwrapped_for_prefix,
                "start_time": start,
                "end_time": end,
            }
            as_path_delta_result = await _analyze_as_path_delta(path_input, session)
            logger.info(f"[reason_and_classify] AS-path delta: {as_path_delta_result.get('overall_verdict', {}).get('level', 'N/A')}")
        except Exception as e:
            logger.warning(f"[reason_and_classify] AS-path delta analysis failed: {e}")

    # ── Analyze AS relationships and blast radius (P2: analyze_as_relationships) ───
    as_relationships_result = {}
    if routing_unwrapped_for_prefix and start:
        try:
            # Extract attacker and victim ASes
            attacker_asn = ""
            victim_asn = asn
            origin_hijacked = routing_unwrapped_for_prefix.get("origin_hijacked", [])
            for ev in origin_hijacked:
                if ev.get("hijacker_as"):
                    attacker_asn = str(ev["hijacker_as"])
                    break
            if not attacker_asn:
                attacker_anomalies = routing_unwrapped_for_prefix.get("origin_hijacking", [])
                if attacker_anomalies:
                    attacker_asn = str(attacker_anomalies[0].get("origin_as", ""))

            if attacker_asn:
                rel_input = {
                    "attacker_asn": attacker_asn,
                    "victim_asn": victim_asn,
                    "start_time": start,
                    "routing_result": routing_unwrapped_for_prefix,
                    "asn_info": asn_info,
                }
                as_relationships_result = await _analyze_as_relationships(rel_input, session)
                logger.info(f"[reason_and_classify] AS relationships: "
                           f"{as_relationships_result.get('relationship', {}).get('attacker_to_victim', 'N/A')}")
        except Exception as e:
            logger.warning(f"[reason_and_classify] AS relationships analysis failed: {e}")

    # ── Probe prefix reachability (P2: probe_prefix_reachability) ───────────────
    probe_result = {}
    if routing_unwrapped_for_prefix and start and end:
        try:
            prefixes = []
            origin_hijacked = routing_unwrapped_for_prefix.get("origin_hijacked", [])
            for ev in origin_hijacked:
                pf = ev.get("prefix", "")
                if pf and pf not in prefixes:
                    prefixes.append(pf)
            if prefixes:
                attacker_asn_str = ""
                attacker_anomalies = routing_unwrapped_for_prefix.get("origin_hijacking", [])
                if attacker_anomalies:
                    attacker_asn_str = str(attacker_anomalies[0].get("origin_as", ""))
                probe_input = {
                    "prefixes": prefixes,
                    "start_time": start,
                    "end_time": end,
                    "attacker_asn": attacker_asn_str,
                    "victim_asn": asn,
                    "routing_result": routing_unwrapped_for_prefix,
                }
                probe_result = await _probe_prefix_reachability(probe_input, session)
                logger.info(f"[reason_and_classify] Probe reachability: "
                           f"{probe_result.get('synthesis', {}).get('overall_verdict', 'N/A')}")
        except Exception as e:
            logger.warning(f"[reason_and_classify] Prefix reachability probe failed: {e}")

    # ── Validate ROA status (P3: validate_roa_status) ─────────────────────────
    roa_validation_result = {}
    if routing_unwrapped_for_prefix:
        try:
            roa_input = {
                "routing_result": routing_unwrapped_for_prefix,
                "start_time": start,
                "end_time": end,
            }
            roa_validation_result = await _validate_roa_status(roa_input, session)
            logger.info(f"[reason_and_classify] ROA validation: "
                       f"{roa_validation_result.get('summary', {}).get('risk_level', 'N/A')}")
        except Exception as e:
            logger.warning(f"[reason_and_classify] ROA validation failed: {e}")

    # ── Threat intel lookup for attacker AS (P3: lookup_as_threat_intel) ──────
    threat_intel_result = {}
    attacker_asn_for_intel = ""
    if routing_unwrapped_for_prefix:
        try:
            origin_hijacked = routing_unwrapped_for_prefix.get("origin_hijacked", [])
            for ev in origin_hijacked:
                if ev.get("hijacker_as"):
                    attacker_asn_for_intel = str(ev["hijacker_as"])
                    break
            if not attacker_asn_for_intel:
                attacker_anomalies = routing_unwrapped_for_prefix.get("origin_hijacking", [])
                if attacker_anomalies:
                    attacker_asn_for_intel = str(attacker_anomalies[0].get("origin_as", ""))

            if attacker_asn_for_intel:
                intel_input = {
                    "attacker_asn": attacker_asn_for_intel,
                    "victim_asn": asn,
                    "routing_result": routing_unwrapped_for_prefix,
                    "start_time": start,
                }
                threat_intel_result = await _lookup_as_threat_intel(intel_input, session)
                logger.info(f"[reason_and_classify] Threat intel: "
                           f"{threat_intel_result.get('threat_level', 'N/A')} "
                           f"(risk_score={threat_intel_result.get('risk_score', 'N/A')})")
        except Exception as e:
            logger.warning(f"[reason_and_classify] Threat intel lookup failed: {e}")

    llm, _ = setup_llm_settings(
        model=MODEL, api_key=API_KEY, base_url=BASE_URL,
        temperature=DEFAULT_TEMP_CLASSIFY, timeout=300.0, max_retries=3,
    )

    traffic_for_llm = traffic.get("results") or traffic.get("result") or traffic if isinstance(traffic, dict) else {}
    traffic_payload, traffic_meta = build_payload(
        "traffic", traffic_for_llm, max_bytes=PayloadBudget.CLASSIFY // 3
    )
    routing_payload, routing_meta = build_payload(
        "routing", routing, max_bytes=PayloadBudget.CLASSIFY // 3
    )
    victim_payload, victim_meta = build_payload(
        "generic", victim_traffic, max_bytes=PayloadBudget.CLASSIFY // 6
    )
    prefix_payload, prefix_meta = build_payload(
        "generic", prefix_traffic_results, max_bytes=PayloadBudget.CLASSIFY // 8
    )
    payload = {
        "asn": asn,
        "time_window": f"{start} to {end}",
        "org_name": asn_info.get("org", {}).get("name"),
        "country": asn_info.get("org", {}).get("country"),
        "prefixes": asn_info.get("prefixes", [])[:10],
        "relationships": asn_info.get("relationships", [])[:10],
        "traffic": traffic_payload,
        "routing": routing_payload,
        "victim_traffic": victim_payload,
        "prefix_traffic": prefix_payload,
        "correlation_score": correlation_score_result,
        "as_path_delta": as_path_delta_result,
        "as_relationships": as_relationships_result,
        "probe_reachability": probe_result,
        "roa_validation": roa_validation_result,
        "threat_intel": threat_intel_result,
    }
    payload, payload_cap = cap_payload(payload, max_bytes=PayloadBudget.CLASSIFY)
    logger.info(
        "[reason_and_classify] LLM payload %sB (traffic %sB, routing %sB, "
        "victim %sB, prefix %sB; cap %sB)",
        estimate_bytes(payload), traffic_meta["final_bytes"], routing_meta["final_bytes"],
        victim_meta["final_bytes"], prefix_meta["final_bytes"], payload_cap["max_bytes"],
    )

    prompt = f"""You are a senior BGP routing security analyst. Your job is to reason like a human analyst, not to mechanically map signals to labels.

Use the full evidence set below to form a judgment. Weigh traffic, routing, AS metadata, relationships, and any context that helps explain the incident. If the evidence is mixed, weak, or incomplete, it is acceptable to return "inconclusive" rather than forcing a confident label.

=== DATA ===
{json.dumps(payload, indent=2, ensure_ascii=False, default=_json_serial)}

=== ANALYSIS GUIDELINES ===
- Compare traffic and routing evidence for temporal alignment, magnitude, and consistency.
- Use AS org / country / prefix / relationship data to assess whether the routing event is plausible as a hijack, leak, outage, or benign change.
- If the evidence is insufficient, say so explicitly and explain what evidence would reduce uncertainty.
- Do NOT force a definitive classification when the data does not support it.
- Prefer nuanced judgment over overconfident labeling.
- Think through alternative explanations (e.g. CDN shielding, transient route changes, mitigation, missing visibility).
|- IMPORTANT - Victim AS Traffic Verification: The "victim_traffic" field contains traffic analysis results for ASes discovered from routing events.
|- IMPORTANT - Prefix-level traffic impact: The "prefix_traffic" field shows whether hijacked prefixes had attacker AS in their AS-paths. High "attacker_path_delta_pct" = strong evidence that hijack was effective.
|- IMPORTANT - Quantitative Correlation Score: The "correlation_score" field contains a 0-100 score (L1-L5) from 5 dimensions. Use this to calibrate your confidence rating.
|- IMPORTANT - AS-Path Structural Changes: The "as_path_delta" field contains path length delta, new ASes appearing, loop counts, and traceroute results (for recent events only).
|- IMPORTANT - AS Relationships: The "as_relationships" field shows attacker-victim relationship (provider/peer/customer), blast radius tier, financial impact estimate, and hijack plausibility.
|- IMPORTANT - Prefix Reachability: The "probe_reachability" field shows which AS is currently announcing each prefix (ACTIVE_HIJACK / RESOLVED / MIXED / INCONCLUSIVE). For historical events, uses RIPE RIS and Looking Glass APIs.
|- IMPORTANT - RPKI ROA Validation: The "roa_validation" field contains per-prefix ROV status. INVALID = strong hijack evidence (ROA exists but origin does not match). NOT_FOUND = no ROA coverage.
|- IMPORTANT - Threat Intel: The "threat_intel" field contains attacker AS risk_score (0-100) and threat_level (LOW/MEDIUM/HIGH/CRITICAL). Use this to calibrate incident severity.

=== YOUR TASK ===
1. Classify the incident type: "route_hijack", "route_leak", "network_outage", "traffic_anomaly_only", "normal", or "inconclusive".
2. Rate confidence: "high", "medium", or "low".
3. List 3-6 concrete evidence items from the data above.
4. Write a 2-4 sentence root cause narrative that explicitly mentions uncertainty if present.
5. List 2-4 immediate recommended actions.
6. If the evidence is insufficient or conflicting, include the most useful additional evidence to collect next.
7. For each victim AS in victim_traffic, assess whether its traffic was affected and whether this corroborates or contradicts the routing event.
8. For each prefix in prefix_traffic, cite the attacker_path_delta_pct and verdict to support or refute the hijack effectiveness hypothesis.
9. Cross-check your confidence rating with the "correlation_score.total_score" (0-100) and "correlation_score.correlation_level" (L1-L5). If your confidence diverges significantly from the quantitative score, explain why.
10. If as_path_delta shows high path length delta or new ASes, note how this corroborates or contradicts the hijack hypothesis.
11. If as_relationships is available, use the relationship type (provider/peer/customer), blast_radius.tier, and plausibility.level to assess the realism and severity of the hijack.
12. If probe_reachability is available, use the overall_verdict (ACTIVE_HIJACK/RESOLVED/MIXED/INCONCLUSIVE) to determine whether the hijack is still active.
13. If roa_validation is available, use the per-prefix ROV status. INVALID = strong evidence of intentional hijack. NOT_FOUND = no ROV protection on this prefix.
14. If threat_intel is available, use the risk_score (0-100) and threat_level to calibrate incident severity. CRITICAL/HIGH threat level should override lower confidence ratings.

|=== OUTPUT FORMAT ===
Return ONLY valid JSON:
{{
 "incident_type": "...",
 "confidence": "...",
 "evidence": ["...", "..."],
 "root_cause_narrative": "...",
 "immediate_actions": ["...", "..."],
 "additional_evidence_needed": ["...", "..."],
 "victim_verification": [
 {{"asn": "AS12345", "traffic_anomalous": true/false/null, "verdict": "...", "details": "..."}}
 ],
 "prefix_hijack_effectiveness": [
 {{"prefix": "1.2.3.0/24", "attacker_path_pct": 45.2, "delta_pct": 42.1, "verdict": "STRONG/MODERATE/WEAK", "details": "..."}}
 ],
 "quantitative_correlation": {{
 "total_score": 0-100,
 "level": "L1-L5",
 "dimension_breakdown": {{"temporal": 0-20, "direction": 0-20, "magnitude": 0-20, "victim": 0-20, "prefix": 0-20}}
 }},
 "as_path_analysis": {{
 "path_length_delta": float,
 "new_asns_count": int,
 "verdict": "STRONG/MODERATE/WEAK",
 "traceroute_performed": bool,
 "traceroute_result": "..."
 }},
 "as_relationship_analysis": {{
 "attacker_to_victim": "provider/peer/customer/unknown",
 "blast_radius_tier": "HIGH/MEDIUM/LOW/UNKNOWN",
 "plausibility": "HIGH/MEDIUM/LOW/UNKNOWN",
 "financial_impact_estimate": "...",
 "details": "..."
 }},
 "hijack_status": {{
 "verdict": "ACTIVE_HIJACK/RESOLVED/MIXED/INCONCLUSIVE",
 "probed_prefixes": int,
 "attacker_present_in": "X/Y",
 "probe_method": "live_traceroute/historical_api",
 "details": "..."
 }},
 "roa_validation": {{
 "total_valid": int,
 "total_invalid": int,
 "total_not_found": int,
 "rov_coverage_pct": float,
 "risk_level": "CRITICAL/HIGH/LOW",
 "invalid_prefixes": ["prefix1", "prefix2", ...]
 }},
 "threat_intel": {{
 "attacker_asn": "AS...",
 "risk_score": 0-100,
 "threat_level": "LOW/MEDIUM/HIGH/CRITICAL",
 "threat_signals": ["...", "..."],
 "historical_hijack_count": int
 }}
}}
"""

    try:
        resp = await asyncio.to_thread(llm.complete, prompt)
        raw = resp.text if hasattr(resp, "text") else str(resp)
        result = _parse_json(raw)
        obs = f"LLM classified incident as '{result.get('incident_type','unknown')}' (confidence: {result.get('confidence','unknown')})"
        return {
            "success": True,
            "classification": result,
            "victim_traffic_results": victim_traffic,
            "victim_asns": all_victim_asns,
            "prefix_traffic_results": prefix_traffic_results,
            "correlation_score_result": correlation_score_result,
            "as_path_delta_result": as_path_delta_result,
            "as_relationships_result": as_relationships_result,
            "probe_reachability_result": probe_result,
            "roa_validation_result": roa_validation_result,
            "threat_intel_result": threat_intel_result,
            "causal_evidence": tool_input.get("causal_evidence", {}),
            "observation": obs,
        }
    except Exception as e:
        return {"success": False, "error": str(e), "observation": f"LLM reasoning failed: {e}"}


def _json_serial(obj):
    if hasattr(obj, "isoformat"):
        return obj.isoformat()
    return str(obj)


def _parse_json(raw_text):
    raw = raw_text.strip()
    for fence in ["```json\n", "```json", "```\n", "```"]:
        if raw.startswith(fence):
            raw = raw[len(fence):]
    for fence in ["\n```", "```"]:
        if raw.endswith(fence):
            raw = raw[: -len(fence)]
    raw = raw.strip()
    try:
        return json.loads(raw)
    except Exception:
        # Bug fix 2026-09-13 (BUG-R47): previously the fallback was
        try:
            from utils.helpers import extract_json_object as _safe_extract
            snippet = _safe_extract(raw)
            if snippet is not None:
                return json.loads(snippet)
        except Exception:
            return {}
        return {}


register_tool(
    name="reason_and_classify",
    description="LLM reasoning over traffic, routing, and AS context to produce a nuanced incident assessment, confidence, evidence, and recommendations.",
    parameters=[
        ToolParameter("asn", "AS number", "string"),
        ToolParameter("traffic_result", "Output of analyze_traffic", "object"),
        ToolParameter("routing_result", "Output of analyze_routing", "object"),
        ToolParameter("asn_info", "Output of query_as_info", "object", required=False),
        ToolParameter("start_time", "Time window start", "string"),
        ToolParameter("end_time", "Time window end", "string"),
        ToolParameter("causal_evidence", "Externally verified evidence with provenance. Model-generated assertions are not accepted.", "object", required=False),
    ],
    handler=_reason_and_classify,
)


# ══════════════════════════════════════════════════════════════════════════════
def _inject_traffic_plot_into_file(html_path, traffic_plot_base64):
    """After the HTML is saved, inject the traffic plot if the LLM missed it."""
    import pathlib
    try:
        p = pathlib.Path(html_path)
        if not p.exists():
            return
        html = p.read_text(encoding="utf-8")
        if "data:image/png;base64," in html:
            return  # already embedded

        section = (
            '\n<div class="card" style="margin-top:24px;">'
            '\n    <h2>Traffic Visualization</h2>'
            '\n    <p>Traffic anomaly analysis chart for the analysis window.</p>'
            f'\n    <img src="data:image/png;base64,{traffic_plot_base64}" '
            '\n         alt="Traffic Analysis Plot" '
            '\n         style="max-width:100%; border-radius:8px; border:1px solid #e2e8f0;" />'
            '\n</div>\n'
        )
        if "</body>" in html:
            html = html.replace("</body>", section + "</body>", 1)
        else:
            html = html + section
        p.write_text(html, encoding="utf-8")
    except Exception:
        pass

async def _generate_report(tool_input, session):
    """Generate the final LLM-driven HTML report from all collected evidence.

    Params come from `tool_input` (priority) or `session.evidence` (fallback),
    so the report always has data even when the LLM omits the ASN. Plots are
    embedded as base64.
    """
    import base64 as _b64
    import pathlib

    from utils.logger import logger

    # ── Get run context from session.run_context (explicit param, no global lookup) ──
    rc = getattr(session, "run_context", {}) or {}
    _run_asn = rc.get("asn", "") or ""
    _run_start = rc.get("start_time", "") or ""
    _run_end = rc.get("end_time", "") or ""

    # ── Get the ASN — try in priority order ─────────────────────────────────────
    # Priority: tool_input.asn > session evidence > _RUN_ASN
    asn = tool_input.get("asn")
    if not asn:
        # session.evidence has no asn — use the run context set by ReactAgent.run()
        asn = _run_asn or ""
    asn = str(asn) if asn else "unknown"
    start = tool_input.get("start_time") or _run_start
    end = tool_input.get("end_time") or _run_end

    # ── Resolve traffic_result with plot_path extraction ─────────────────────
    traffic = tool_input.get("traffic_result") or {}
    if not traffic and session is not None:
        ev = getattr(session, "evidence", {}) or {}
        raw = ev.get("analyze_traffic", {})
        if isinstance(raw, dict):
            traffic = raw.get("results", {}) or raw.get("result", {}) or raw
        else:
            traffic = {}

    # Unwrap traffic to a flat "traffic_result.shape = {anomaly_count, percent_change, ...}"
    traffic = _unwrap_traffic_for_payload_standalone(traffic, target_asn=str(asn) if asn else "")

    # Surface `max_severity` at the top level so _substitute_field_references and
    if isinstance(traffic, dict) and "max_severity" not in traffic:
        try:
            from agents.traffic_agent import _to_canonical_severity
            traffic["max_severity"] = _to_canonical_severity(traffic.get("anomalies") or [])
        except Exception:
            pass

    # Extract plot_path from traffic results (search multiple possible locations)
    traffic_plot_path = None
    traffic_plot_base64 = None

    def _search_plot(data, _depth=0):
        """Recursively search for plot_path in a dict."""
        if _depth > 3 or not isinstance(data, dict):
            return
        for k, v in data.items():
            if k in ("plot_path", "traffic_plot_path", "image_path") and isinstance(v, str) and v:
                nonlocal traffic_plot_path
                traffic_plot_path = v
                return
            if isinstance(v, dict):
                _search_plot(v, _depth + 1)

    _search_plot(traffic)

    # Also search the raw _SHARED_EVIDENCE entry for the plot path
    if not traffic_plot_path and session is not None:
        ev = getattr(session, "evidence", {}) or {}
        raw_traffic = ev.get("analyze_traffic", {})
        _search_plot(raw_traffic)

    # Fallback: construct the expected plot path from known conventions
    if not traffic_plot_path:
        from config import PROJECT_ROOT
        _plot_dir = PROJECT_ROOT / "data" / "traffic_plots"
        if _plot_dir.exists():
            _asn_dir = PROJECT_ROOT / "data"
            # Try AS{asn}_{start}_to_{end}.png
            _start_safe = str(start).replace(" ", "_").replace(":", "-") if start else ""
            _end_safe = str(end).replace(" ", "_").replace(":", "-") if end else ""
            for _pat in [f"AS{asn}_{_start_safe}_to_{_end_safe}.png",
                          f"AS{asn}_{_start_safe}_to_{_end_safe}",
                          f"AS{asn}_*.png"]:
                if _pat.endswith(".png"):
                    _matches = list(_plot_dir.glob(_pat))
                else:
                    _matches = list(_plot_dir.glob(_pat + ".png"))
                if _matches:
                    traffic_plot_path = str(_matches[0])
                    break

    if traffic_plot_path:
        p = pathlib.Path(str(traffic_plot_path))
        if p.exists():
            try:
                traffic_plot_base64 = _b64.b64encode(p.read_bytes()).decode("utf-8")
            except Exception as e:
                logger.warning(f"[report_tool] Failed to embed plot {traffic_plot_path}: {e}")

    # ── Resolve routing_result ───────────────────────────────────────────────
    routing = tool_input.get("routing_result") or {}
    if not routing and session is not None:
        ev = getattr(session, "evidence", {}) or {}
        raw = ev.get("analyze_routing", {})
        if isinstance(raw, dict):
            routing = raw.get("result", {}) or raw
        else:
            routing = {}

    # ── Resolve classification ───────────────────────────────────────────────
    classification = tool_input.get("classification") or {}
    if not classification and session is not None:
        ev = getattr(session, "evidence", {}) or {}
        raw = ev.get("reason_and_classify", {})
        if isinstance(raw, dict):
            classification = raw.get("classification", {}) or raw.get("result", {}) or raw
        else:
            classification = {}

    # ── Resolve asn_info ─────────────────────────────────────────────────────
    asn_info = tool_input.get("asn_info") or {}
    if not asn_info and session is not None:
        ev = getattr(session, "evidence", {}) or {}
        raw = ev.get("query_as_info", {})
        if isinstance(raw, dict):
            asn_info = raw.get("info", {}) or raw.get("result", {}) or raw
        else:
            asn_info = {}

    # ── Resolve victim traffic (from reason_and_classify) ──────────────────
    victim_traffic_results = {}
    victim_asns = []
    if session is not None:
        ev = getattr(session, "evidence", {}) or {}
        raw_rc = ev.get("reason_and_classify", {})
        if isinstance(raw_rc, dict):
            victim_traffic_results = raw_rc.get("victim_traffic_results", {}) or {}
            victim_asns = raw_rc.get("victim_asns", []) or []
        # Also check tool_input direct pass
        if not victim_traffic_results:
            victim_traffic_results = tool_input.get("victim_traffic_results", {}) or {}
            victim_asns = tool_input.get("victim_asns", []) or []

    # ── Resolve prefix traffic results (from reason_and_classify) ───────────────
    prefix_traffic_results = {}
    if session is not None:
        ev = getattr(session, "evidence", {}) or {}
        raw_rc = ev.get("reason_and_classify", {})
        if isinstance(raw_rc, dict):
            prefix_traffic_results = raw_rc.get("prefix_traffic_results", {}) or {}
        if not prefix_traffic_results:
            prefix_traffic_results = tool_input.get("prefix_traffic_results", {}) or {}

    # ── Resolve correlation score and as_path_delta (from reason_and_classify) ───
    correlation_score_result = {}
    as_path_delta_result = {}
    as_relationships_result = {}
    probe_reachability_result = {}
    roa_validation_result = {}
    threat_intel_result = {}
    if session is not None:
        ev = getattr(session, "evidence", {}) or {}
        raw_rc = ev.get("reason_and_classify", {})
        if isinstance(raw_rc, dict):
            correlation_score_result = raw_rc.get("correlation_score_result", {}) or {}
            as_path_delta_result = raw_rc.get("as_path_delta_result", {}) or {}
            as_relationships_result = raw_rc.get("as_relationships_result", {}) or {}
            probe_reachability_result = raw_rc.get("probe_reachability_result", {}) or {}
            roa_validation_result = raw_rc.get("roa_validation_result", {}) or {}
            threat_intel_result = raw_rc.get("threat_intel_result", {}) or {}
    if not correlation_score_result:
        correlation_score_result = tool_input.get("correlation_score_result", {}) or {}
    if not as_path_delta_result:
        as_path_delta_result = tool_input.get("as_path_delta_result", {}) or {}
    if not as_relationships_result:
        as_relationships_result = tool_input.get("as_relationships_result", {}) or {}
    if not probe_reachability_result:
        probe_reachability_result = tool_input.get("probe_reachability_result", {}) or {}
    if not roa_validation_result:
        roa_validation_result = tool_input.get("roa_validation_result", {}) or {}
    if not threat_intel_result:
        threat_intel_result = tool_input.get("threat_intel_result", {}) or {}

    logger.info(
        f"[report_tool] Generating report for AS{asn}  {start} → {end}  "
        f"| traffic={'has data' if traffic else 'EMPTY'}  "
        f"| routing={'has data' if routing else 'EMPTY'}  "
        f"| classification={'has data' if classification else 'EMPTY'}  "
        f"| victim_asns={victim_asns}  "
        f"| prefix_traffic={len(prefix_traffic_results)} prefixes  "
        f"| corr_score={correlation_score_result.get('total_score', 'N/A')}  "
        f"| as_rel={as_relationships_result.get('relationship', {}).get('attacker_to_victim', 'N/A')}  "
        f"| probe={probe_reachability_result.get('synthesis', {}).get('overall_verdict', 'N/A')}  "
        f"| roa={roa_validation_result.get('summary', {}).get('risk_level', 'N/A')}  "
        f"| threat={threat_intel_result.get('threat_level', 'N/A')}  "
        f"| plot={'YES ' + traffic_plot_path if traffic_plot_base64 else 'no'}"
    )

    try:
        # When LLM is disabled, skip the LLM-driven path entirely and render
        if os.environ.get("BGP_TRACER_DISABLE_LLM_REPORT", "").strip() in ("1", "true", "yes"):
            from agents.report_agent import generate_report_html as _gen
            # generate_report_html raises on LLM failure but raises RuntimeError.
            # We want a clean fallback; emit a minimal HTML directly.
            _path = os.path.join(
                "results/html",
                f"llm_report_{asn}_{start.replace(' ', '_').replace(':','')}_{end.replace(' ', '_').replace(':','')}.html",
            )
            os.makedirs(os.path.dirname(_path), exist_ok=True)
            # Width-fix CSS for the minimal fallback so the report body is
            # properly constrained (matching the main LLM report width fix).
            _fallback_css = (
                "<style>"
                "html,body{margin:0;padding:0;background:#fafafa;}"
                "body{padding:16px;}"
                ".report-container{max-width:1180px;margin:0 auto;padding:24px 28px;"
                "background:#ffffff;box-shadow:0 1px 4px rgba(0,0,0,0.06);"
                "border-radius:8px;box-sizing:border-box;}"
                "pre{white-space:pre-wrap;word-break:break-word;}"
                "table{table-layout:fixed;width:100%;word-break:break-word;}"
                "</style>"
            )
            html_body = (
                f"<!DOCTYPE html><html><head><meta charset='utf-8'>"
                f"<title>BGP Report AS{asn}</title>"
                f"{_fallback_css}</head><body>"
                f"<div class='report-container'>"
                f"<h1>BGP / Traffic Report — AS{asn}</h1>"
                f"<p><b>Window:</b> {start} → {end}</p>"
                f"<p><b>Mode:</b> deterministic fallback (LLM disabled)</p>"
                f"<h2>Traffic</h2><pre>{json.dumps(traffic, ensure_ascii=False, default=str)[:4000]}</pre>"
                f"<h2>Routing</h2><pre>{json.dumps(routing, ensure_ascii=False, default=str)[:4000]}</pre>"
                f"<h2>Classification</h2><pre>{json.dumps(classification, ensure_ascii=False, default=str)[:4000]}</pre>"
                f"</div></body></html>"
            )
            with open(_path, "w", encoding="utf-8") as f:
                f.write(html_body)
            obs = f"Report generated (fallback) and saved to: {_path}"
            return {
                "success": True,
                "report_path": _path,
                "classification": classification,
                "observation": obs,
            }

        path = await asyncio.to_thread(
            generate_report_html,
            asn=asn,
            start_time=start,
            end_time=end,
            traffic_result=traffic,
            routing_result=routing,
            reasoning_result=classification,
            traffic_plot_path=traffic_plot_path,
            traffic_plot_base64=traffic_plot_base64,
            victim_traffic_results=victim_traffic_results,
            victim_asns=victim_asns,
            prefix_traffic_results=prefix_traffic_results,
            correlation_score_result=correlation_score_result,
            as_path_delta_result=as_path_delta_result,
            as_relationships_result=as_relationships_result,
            probe_reachability_result=probe_reachability_result,
            roa_validation_result=roa_validation_result,
            threat_intel_result=threat_intel_result,
            output_dir=None,
        )

        # ── Post-process: ensure plot is embedded even if LLM missed it ─────
        if traffic_plot_base64 and path:
            _inject_traffic_plot_into_file(path, traffic_plot_base64)

        obs = f"Report generated and saved to: {path}"
        return {
            "success": True,
            "report_path": path,
            "classification": classification,
            "observation": obs,
        }
    except Exception as e:
        logger.error(f"[report_tool] Failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {"success": False, "error": str(e), "observation": f"Report generation failed: {e}"}


# ══════════════════════════════════════════════════════════════════════════════
async def _analyze_prefix_traffic(tool_input, session):
    """
 Analyze traffic impact for specific BGP prefixes involved in routing events.

 Since Cloudflare does not provide prefix-level traffic data, this tool uses
 BGP AS-path distribution changes as a proxy for traffic impact:
 - During hijack: attacker AS appears in AS-paths → traffic redirected
 - After hijack: attacker AS disappears → traffic restored
 - Hijack effectiveness = proportion of paths going through attacker

 Required params:
 prefixes (list[str]): list of BGP prefixes, e.g. ["185.245.181.0/24"]
 hijacker_asn (str): the AS that performed the hijack
 victim_asn (str): the AS that was hijacked
 start_time (str): ISO format
 end_time (str): ISO format
 Optional params:
 routing_result (dict): optional routing result for auto-extracting prefix list
 """
    prefixes = tool_input.get("prefixes", [])
    if isinstance(prefixes, str):
        try:
            prefixes = json.loads(prefixes)
        except Exception:
            prefixes = [prefixes]

    hijacker_asn = str(tool_input.get("hijacker_asn", ""))
    victim_asn = str(tool_input.get("victim_asn", ""))
    start = tool_input.get("start_time", "")
    end = tool_input.get("end_time", "")

    # Allow routing_result to be passed in directly for auto-extraction
    routing = tool_input.get("routing_result", {})
    if isinstance(routing, str):
        try:
            routing = json.loads(routing)
        except Exception:
            routing = {}

    # Auto-extract prefixes + attacker/victim from routing result if not provided
    if not prefixes or not hijacker_asn:
        routing_unwrapped = routing.get("result", routing) if isinstance(routing, dict) else routing
        if not prefixes:
            origin_hijacked = routing_unwrapped.get("origin_hijacked", [])
            prefixes = list({str(ev.get("prefix", "")) for ev in origin_hijacked if ev.get("prefix")})
        if not hijacker_asn:
            attacker_anomalies = routing_unwrapped.get("origin_hijacking", [])
            if attacker_anomalies:
                hijacker_asn = str(attacker_anomalies[0].get("origin_as", ""))

    if not prefixes:
        return {"success": False, "error": "No prefixes provided or found in routing_result",
                "observation": "Cannot analyze prefix traffic without prefix list."}

    # Parse times. Bug fix 2026-09-13 (BUG-R61): the original double
    try:
        start_dt = _parse_dt(start)
    except Exception:
        start_dt = None
    try:
        end_dt = _parse_dt(end)
    except Exception:
        end_dt = None

    # Normal baseline: 2 hours before hijack window
    normal_start_dt = start_dt - timedelta(hours=2) if start_dt else None
    normal_end_dt = start_dt if start_dt else None
    normal_start = normal_start_dt.strftime("%Y-%m-%d %H:%M:%S") if normal_start_dt else None
    normal_end = normal_end_dt.strftime("%Y-%m-%d %H:%M:%S") if normal_end_dt else None

    logger.info(f"[prefix_traffic] {len(prefixes)} prefixes, hijacker=AS{hijacker_asn}, "
                f"victim=AS{victim_asn}, hijack_window={start}→{end}, "
                f"normal_window={normal_start}→{normal_end}")

    # ── Build prefix set for fast lookup ──────────────────────────────────────
    prefix_set = set(prefixes)
    prefix_set_lower = {p.lower() for p in prefix_set}

    # ── Aggregate stats per prefix: {prefix: {normal_count, hijack_count, ...}} ──
    from collections import defaultdict
    stats: dict = {p: {
        "normal_through_attacker": 0, "normal_total": 0,
        "hijack_through_attacker": 0, "hijack_total": 0,
        "normal_origins": [], "hijack_origins": [],
        "normal_samples": 0, "hijack_samples": 0,
    } for p in prefix_set}

    def parse_as_path(raw_text):
        if not raw_text:
            return []
        return [x.strip() for x in str(raw_text).split() if x.strip()]

    def in_window(ts_str, w_start, w_end):
        # Bug fix 2026-09-13 (BUG-R61): the original nested
        try:
            ts = _parse_dt(ts_str)
        except Exception:
            return False
        if w_start and ts < w_start:
            return False
        if w_end and ts > w_end:
            return False
        return True

    # ── Stream BGP updates from the hijack window + normal window ──────────────
    all_start = normal_start or start
    all_end = end
    from data.updates_loader import get_updates_streaming
    import gc

    # Bug fix 2026-09-13 (BUG-R61): the previous code called
    try:
        _all_start_dt = _parse_dt(all_start) if all_start else None
    except Exception:
        _all_start_dt = None
    try:
        _all_end_dt = _parse_dt(all_end) if all_end else None
    except Exception:
        _all_end_dt = None

    processed = 0
    for df_chunk in get_updates_streaming(
        _all_start_dt,
        _all_end_dt,
        workers=8, io_busy_threshold=80, auto_download=True
    ):
        if df_chunk is None or df_chunk.is_empty():
            del df_chunk; gc.collect(); continue

        # Filter to announcements only for target prefixes
        announcements = df_chunk.filter(
            (pl.col("A/W") == "A") & (pl.col("prefix").is_in(list(prefix_set_lower)))
        )
        del df_chunk; gc.collect()

        if announcements.is_empty():
            continue

        # Classify each row: normal vs hijack window
        rows = announcements.iter_rows(named=True)
        for row in rows:
            processed += 1
            prefix = row.get("prefix", "").lower()
            if prefix not in prefix_set_lower:
                continue
            ts = row.get("timestamp", "")
            as_path_raw = row.get("as-path", "") or ""
            as_path = parse_as_path(as_path_raw)

            in_hijack = in_window(ts, start_dt, end_dt)
            in_normal = in_window(ts, normal_start_dt, normal_end_dt)

            if in_hijack:
                s = stats[prefix]
                s["hijack_samples"] += 1
                s["hijack_origins"].append(as_path[-1] if as_path else "")
                if hijacker_asn and hijacker_asn in as_path:
                    s["hijack_through_attacker"] += 1
            elif in_normal:
                s = stats[prefix]
                s["normal_samples"] += 1
                s["normal_origins"].append(as_path[-1] if as_path else "")
                if hijacker_asn and hijacker_asn in as_path:
                    s["normal_through_attacker"] += 1

        del announcements; gc.collect()

    logger.info(f"[prefix_traffic] Processed {processed} BGP messages, building results...")

    # ── Compute metrics per prefix ─────────────────────────────────────────────
    results = {}
    for prefix in prefix_set:
        s = stats.get(prefix, {})
        n_norm = s.get("normal_samples", 0)
        n_hijack = s.get("hijack_samples", 0)

        hijack_pct = (s["hijack_through_attacker"] / n_hijack * 100) if n_hijack > 0 else 0.0
        normal_pct = (s["normal_through_attacker"] / n_norm * 100) if n_norm > 0 else 0.0
        delta_pct = hijack_pct - normal_pct

        norm_origins = list({o for o in s.get("normal_origins", []) if o})
        hijack_origins = list({o for o in s.get("hijack_origins", []) if o})
        origin_changed = norm_origins and hijack_origins and norm_origins != hijack_origins

        if hijack_pct > 50:
            eff = "high"
        elif hijack_pct > 20:
            eff = "medium"
        elif hijack_pct > 0:
            eff = "low"
        else:
            eff = "none"

        results[prefix] = {
            "prefix": prefix,
            "normal_window_samples": n_norm,
            "hijack_window_samples": n_hijack,
            "hijack_through_attacker_count": s["hijack_through_attacker"],
            "hijack_attacker_path_pct": round(hijack_pct, 2),
            "normal_attacker_path_pct": round(normal_pct, 2),
            "attacker_path_delta_pct": round(delta_pct, 2),
            "hijack_effectiveness": eff,
            "origin_as_changed": origin_changed,
            "normal_origin_asns": norm_origins,
            "hijack_origin_asns": hijack_origins,
            "traffic_impact_proxy": round(delta_pct, 2),
            "verdict": _prefix_traffic_verdict(eff, delta_pct, origin_changed),
        }

    total = len(results)
    effective = sum(1 for r in results.values() if r["hijack_effectiveness"] in ("high", "medium"))
    avg_delta = round(sum(r["attacker_path_delta_pct"] for r in results.values()) / max(total, 1), 2) if results else 0.0
    verdict_summary = _summarize_verdicts(results)

    obs = (f"Analyzed {total} prefixes. Effective hijacks: {effective}. "
            f"Avg attacker-path delta: {avg_delta:.1f}%. {verdict_summary}")
    logger.info(f"[prefix_traffic] {obs}")

    return {
        "success": True,
        "prefixes": prefixes,
        "hijacker_asn": hijacker_asn,
        "victim_asn": victim_asn,
        "time_window": f"{start} to {end}",
        "normal_window": f"{normal_start} to {normal_end}",
        "results": results,
        "summary": {
            "total_prefixes_analyzed": total,
            "effective_hijack_count": effective,
            "overall_impact": "significant" if effective > 0 else "limited",
            "avg_attacker_path_delta_pct": avg_delta,
        },
        "observation": obs,
    }


def _prefix_traffic_verdict(effectiveness, path_delta, origin_changed):
    if effectiveness == "high" and path_delta > 30 and origin_changed:
        return "STRONG: attacker captured majority of traffic, origin AS changed"
    elif effectiveness in ("high", "medium") and path_delta > 0:
        return "MODERATE: attacker appears in paths, traffic likely affected"
    elif path_delta < -10:
        return "NEGATIVE: attacker paths decreased (possible mitigation or false positive)"
    else:
        return "WEAK: limited evidence of traffic impact"


def _summarize_verdicts(items):
    # Bug fix 2026-10-13: function parameter is `items` (the dict of
    # verdicts) but the body referenced the undefined name `results`.
    verdicts = [r["verdict"].split(":")[0] for r in items.values()]
    strong = verdicts.count("STRONG")
    moderate = verdicts.count("MODERATE")
    weak = verdicts.count("WEAK")
    parts = []
    if strong:
        parts.append(f"{strong} STRONG")
    if moderate:
        parts.append(f"{moderate} MODERATE")
    if weak:
        parts.append(f"{weak} WEAK")
    return ", ".join(parts) if parts else "no verdict"


register_tool(
    name="analyze_prefix_traffic",
    description="Analyze traffic impact for specific BGP prefixes involved in a hijack event. Uses BGP AS-path distribution changes as a proxy for traffic impact (since Cloudflare does not provide prefix-level traffic). Given prefixes and attacker AS, computes: hijack effectiveness score, attacker-path proportion delta, origin-AS changes, and an overall traffic impact verdict. Call this automatically when routing analysis finds hijack events.",
    parameters=[
        ToolParameter("prefixes", "List of BGP prefixes involved in the hijack, e.g. ['185.245.181.0/24']", "string", required=False),
        ToolParameter("hijacker_asn", "The AS number that performed the hijack", "string", required=False),
        ToolParameter("victim_asn", "The AS number that was hijacked", "string", required=False),
        ToolParameter("start_time", "Hijack window start, ISO format", "string"),
        ToolParameter("end_time", "Hijack window end, ISO format", "string"),
        ToolParameter("normal_start", "Baseline normal period start (optional, defaults to 2h before event)", "string", required=False),
        ToolParameter("normal_end", "Baseline normal period end (optional)", "string", required=False),
        ToolParameter("routing_result", "Routing analysis result (auto-extracts prefixes if not provided)", "object", required=False),
    ],
    handler=_analyze_prefix_traffic,
)


# ══════════════════════════════════════════════════════════════════════════════
async def _classify_traffic_anomaly(tool_input, session):
    """
 Classify the root cause type of a traffic anomaly using LLM reasoning.
 This prevents misattribution: not every traffic drop is a hijack.

 Required params:
 traffic_result (dict): output of analyze_traffic
 routing_result (dict, optional): output of analyze_routing
 victim_prefix_traffic (dict, optional): output of analyze_prefix_traffic
 asn_info (dict, optional): output of query_as_info
 """
    ev = getattr(session, "evidence", {}) or {}

    # Resolve inputs
    traffic = tool_input.get("traffic_result") or {}
    if not traffic:
        raw = ev.get("analyze_traffic", {})
        if isinstance(raw, dict):
            traffic = raw.get("results", {}) or raw.get("result", {}) or raw

    routing = tool_input.get("routing_result") or {}
    if not routing:
        raw = ev.get("analyze_routing", {})
        if isinstance(raw, dict):
            routing = raw.get("result", {}) or raw

    prefix_traffic = tool_input.get("victim_prefix_traffic") or {}
    if not prefix_traffic:
        raw = ev.get("analyze_prefix_traffic", {})
        if isinstance(raw, dict):
            prefix_traffic = raw.get("results", {}) or raw

    asn_info = tool_input.get("asn_info") or {}
    if not asn_info:
        raw = ev.get("query_as_info", {})
        if isinstance(raw, dict):
            asn_info = raw.get("info", {}) or raw.get("result", {}) or {}

    if not traffic:
        return {"success": False, "error": "No traffic data provided",
                "observation": "Cannot classify without traffic analysis data."}

    llm, _ = setup_llm_settings(
        model=MODEL, api_key=API_KEY, base_url=BASE_URL,
        temperature=DEFAULT_TEMP_CLASSIFY, timeout=300.0, max_retries=3,
    )

    payload = {
        "traffic": _slim_traffic(traffic),
        "routing": _slim_routing(routing),
        "prefix_traffic": prefix_traffic,
        "asn_info": _slim_asn_info(asn_info),
    }

    prompt = f"""You are a BGP security analyst. Classify the ROOT CAUSE of the traffic anomaly below.

The classification is NOT simply copying the routing detection result. Many things can cause
traffic anomalies that are NOT BGP hijacks: DDoS attacks, CDN shielding, normal traffic spikes,
upstream provider issues, routing table churn, etc.

=== TRAFFIC DATA ===
{json.dumps(payload, indent=2, ensure_ascii=False, default=_json_serial)}

=== CLASSIFICATION OPTIONS ===
- bgp_hijack_related: Traffic pattern is consistent with a BGP prefix hijack.
 Evidence: routing shows hijack, attacker appears in AS-paths, traffic dropped during hijack window.
- ddos: Sudden traffic spike (not drop), no routing change, traffic returns to normal quickly.
- cdn_shielding: Gradual traffic reduction with no routing change (CDN provider shielding).
- network_outage: Traffic dropped to near-zero for the entire AS, routing outage detected.
- legitimate_spike: Traffic increase with valid business reason (product launch, marketing campaign).
- bgp_churn: Traffic with routing changes but no clear attacker pattern (normal routing churn).
- inconclusive: Insufficient data to determine the cause.
- normal: No real anomaly - statistical variation within normal range.

=== OUTPUT FORMAT ===
Return ONLY valid JSON:
{{
 "anomaly_type": "...",
 "confidence": "high|medium|low",
 "key_evidence": ["...", "..."],
 "ruling_out": ["...", "..."],
 "reasoning": "2-3 sentence explanation of why this classification fits the data"
}}
"""

    try:
        resp = await asyncio.to_thread(llm.complete, prompt)
        raw = resp.text if hasattr(resp, "text") else str(resp)
        result = _parse_json(raw)

        anomaly_type = result.get("anomaly_type", "unknown")
        confidence = result.get("confidence", "unknown")
        obs = f"Anomaly classified as '{anomaly_type}' (confidence: {confidence})"

        return {
            "success": True,
            "classification": result,
            "observation": obs,
        }
    except Exception as e:
        return {"success": False, "error": str(e),
                "observation": f"Classification failed: {e}"}


def _slim_traffic(payload):
    """Extract only the essential fields from traffic result for LLM prompt."""
    if isinstance(traffic, dict) and "asn" in traffic:
        return {
            "anomalies_detected": traffic.get("anomalies_detected", False),
            "anomaly_count": traffic.get("anomaly_count", 0),
            "anomalies": traffic.get("anomalies", [])[:10],
            "percent_change": traffic.get("percent_change", 0),
            "data_points": traffic.get("data_points", 0),
        }
    return traffic if isinstance(traffic, dict) else {}


def _slim_routing(payload):
    """Extract only the essential fields from routing result for LLM prompt."""
    if not routing or not isinstance(routing, dict):
        return {}
    return {
        "origin_hijacked_count": len(routing.get("origin_hijacked", [])),
        "forge_hijacked_count": len(routing.get("forge_hijacked", [])),
        "origin_hijacking_count": len(routing.get("origin_hijacking", [])),
        "route_leak_count": len(routing.get("route_leaks", [])),
        "outage_score": routing.get("outage_analysis", {}).get("outage_score", 0),
        "outage_suspected": routing.get("outage_analysis", {}).get("is_outage_suspected", False),
    }


def _slim_asn_info(payload):
    """Extract essential AS info for LLM prompt."""
    if not isinstance(asn_info, dict):
        return {}
    return {
        "org_name": asn_info.get("org", {}).get("name"),
        "country": asn_info.get("org", {}).get("country"),
        "prefix_count": len(asn_info.get("prefixes", [])),
    }


register_tool(
    name="classify_traffic_anomaly",
    description="Classify the root cause type of a traffic anomaly using LLM reasoning. Returns: anomaly_type (bgp_hijack_related/ddos/cdn_shielding/network_outage/legitimate_spike/bgp_churn/inconclusive/normal), confidence level, key evidence, and what was ruled out. This prevents misattribution — not every traffic drop is a BGP hijack.",
    parameters=[
        ToolParameter("traffic_result", "Output of analyze_traffic", "object"),
        ToolParameter("routing_result", "Output of analyze_routing (optional)", "object", required=False),
        ToolParameter("victim_prefix_traffic", "Output of analyze_prefix_traffic (optional)", "object", required=False),
        ToolParameter("asn_info", "Output of query_as_info (optional)", "object", required=False),
    ],
    handler=_classify_traffic_anomaly,
)


# ══════════════════════════════════════════════════════════════════════════════
async def _compute_traffic_routing_correlation_score(tool_input, session):
    """Quantify traffic-routing correlation as a 0-100 score.

    Sum of 5 dimensions (20 each): temporal overlap, direction consistency,
    magnitude alignment, victim verification, prefix-path delta.
    Required: traffic_result, routing_result. Optional: victim_traffic,
    prefix_traffic.
    """
    ev = getattr(session, "evidence", {}) or {}

    # ── Resolve inputs ────────────────────────────────────────────────────────
    traffic = _resolve_result(tool_input, "traffic_result", ev,
                              ["analyze_traffic"], ["results", "result"])
    routing = _resolve_result(tool_input, "routing_result", ev,
                              ["analyze_routing"], ["result", "origin_hijacked"])

    if not traffic:
        return {"success": False, "error": "No traffic data",
                "observation": "Cannot compute correlation without traffic analysis."}

    traffic_anomalies = traffic.get("anomalies", [])
    if isinstance(traffic_anomalies, list) and traffic_anomalies and isinstance(traffic_anomalies[0], dict):
        pass  # good
    elif isinstance(traffic.get("outage_period_anomalies"), list):
        traffic_anomalies = traffic.get("outage_period_anomalies", [])
    else:
        traffic_anomalies = []

    # ── Basic dimensions ─────────────────────────────────────────────────────
    scores = {}
    details = {}

    # 1. Temporal overlap (max 20)
    routing_window = _extract_routing_window(routing)
    if routing_window and traffic_anomalies:
        anomaly_timestamps = [
            datetime.fromisoformat(a["timestamp"].replace("Z", "+00:00"))
            if "T" in str(a.get("timestamp", ""))
            else _parse_dt(str(a.get("timestamp", "")), "%Y-%m-%d %H:%M:%S")
            for a in traffic_anomalies if a.get("timestamp")
        ]
        if anomaly_timestamps:
            overlap_count = sum(
                1 for ts in anomaly_timestamps
                if routing_window["start"] <= ts <= routing_window["end"]
            )
            overlap_ratio = overlap_count / len(anomaly_timestamps)
            temporal_score = min(20, round(overlap_ratio * 25))  # 80%+ → 20pts
            scores["temporal_overlap"] = temporal_score
            details["temporal_overlap"] = {
                "routing_window": f"{routing_window['start']} to {routing_window['end']}",
                "anomaly_count": len(traffic_anomalies),
                "overlap_count": overlap_count,
                "overlap_ratio_pct": round(overlap_ratio * 100, 1),
            }
        else:
            scores["temporal_overlap"] = 0
            details["temporal_overlap"] = {"error": "no parseable anomaly timestamps"}
    else:
        scores["temporal_overlap"] = 0
        details["temporal_overlap"] = {"error": "no routing window or no anomalies"}

    # 2. Direction consistency (max 20)
    # Hijack: victim AS traffic drops, attacker (if in victim_traffic) traffic may increase
    traffic_pct = traffic.get("percent_change", 0)
    # Positive pct = traffic increase, negative = decrease
    direction_score = 0
    direction_detail = ""
    if traffic_pct < -10:
        # Victim traffic dropped — consistent with hijack
        direction_score = 20
        direction_detail = f"Traffic dropped {abs(traffic_pct):.1f}%, consistent with hijack impact"
    elif traffic_pct < -3:
        direction_score = 12
        direction_detail = f"Traffic dropped {abs(traffic_pct):.1f}%, partially consistent"
    elif traffic_pct > 10:
        # Traffic increased — might be attacker, or DDoS, or legitimate
        direction_score = 5
        direction_detail = f"Traffic increased {traffic_pct:.1f}%, inconsistent with typical hijack pattern"
    else:
        direction_score = 8
        direction_detail = f"Traffic change {traffic_pct:.1f}% is modest, inconclusive"
    scores["direction_consistency"] = direction_score
    details["direction_consistency"] = {"percent_change": traffic_pct, "verdict": direction_detail}

    # 3. Magnitude alignment (max 20)
    hijack_count = len(routing.get("origin_hijacked", [])) if isinstance(routing, dict) else 0
    hijack_score = 0
    if hijack_count >= 5:
        hijack_score = 20
    elif hijack_count >= 2:
        hijack_score = 14
    elif hijack_count == 1:
        hijack_score = 8
    scores["magnitude_alignment"] = hijack_score
    details["magnitude_alignment"] = {"hijack_count": hijack_count, "score": hijack_score}

    # 4. Victim verification score (max 20)
    victim_traffic = tool_input.get("victim_traffic", {})
    if not isinstance(victim_traffic, dict):
        victim_traffic = {}
        raw_ev = ev.get("reason_and_classify", {})
        if isinstance(raw_ev, dict):
            victim_traffic = raw_ev.get("victim_traffic_results", {}) or {}
    if not isinstance(victim_traffic, dict):
        victim_traffic = {}
    victim_anomalous_count = 0
    total_victims = 0
    for vas, vres in (victim_traffic or {}).items():
        if not isinstance(vres, dict):
            continue
        total_victims += 1
        if vres.get("anomalies_detected") or vres.get("success") is False:
            victim_anomalous_count += 1
    if total_victims == 0:
        victim_score = 0
    else:
        ratio = victim_anomalous_count / total_victims
        victim_score = round(min(20, ratio * 25))  # 80%+ → 20pts
    scores["victim_verification"] = victim_score
    details["victim_verification"] = {
        "total_victims": total_victims,
        "anomalous_victims": victim_anomalous_count,
        "ratio_pct": round(victim_score / 25 * 100, 1) if victim_score > 0 else 0,
    }

    # 5. Prefix-path delta from analyze_prefix_traffic (max 20)
    prefix_traffic = tool_input.get("prefix_traffic", {}) or {}
    if not prefix_traffic:
        raw_ev = ev.get("reason_and_classify", {})
        if isinstance(raw_ev, dict):
            prefix_traffic = raw_ev.get("prefix_traffic_results", {}) or {}
    if prefix_traffic and isinstance(prefix_traffic, dict):
        delta_values = [
            r.get("attacker_path_delta_pct", 0)
            for r in prefix_traffic.values()
            if isinstance(r, dict)
        ]
        if delta_values:
            avg_delta = sum(delta_values) / len(delta_values)
            # delta > 30% = 20pts, delta > 20% = 14pts, > 10% = 8pts, > 0 = 4pts
            if avg_delta > 30:
                prefix_score = 20
            elif avg_delta > 20:
                prefix_score = 14
            elif avg_delta > 10:
                prefix_score = 8
            elif avg_delta > 0:
                prefix_score = 4
            else:
                prefix_score = 0
        else:
            prefix_score = 0
    else:
        avg_delta = 0.0
        prefix_score = 0
    scores["prefix_path_delta"] = prefix_score
    details["prefix_path_delta"] = {
        "avg_attacker_path_delta_pct": round(avg_delta, 2) if isinstance(avg_delta, float) else avg_delta,
        "score": prefix_score,
    }

    # ── Overall score ─────────────────────────────────────────────────────────
    total = sum(scores.values())
    level = "EXCEPTIONAL" if total >= 90 else \
            "STRONG"      if total >= 70 else \
            "MODERATE"    if total >= 45 else \
            "WEAK"        if total >= 20 else "NONE"

    obs = (f"Correlation score: {total}/100 ({level}). "
           f"Temporal={scores['temporal_overlap']}, Direction={scores['direction_consistency']}, "
           f"Magnitude={scores['magnitude_alignment']}, Victim={scores['victim_verification']}, "
           f"PrefixPath={scores['prefix_path_delta']}")

    logger.info(f"[correlation_score] {obs}")
    return {
        "success": True,
        "total_score": total,
        "correlation_level": level,
        "dimension_scores": scores,
        "dimension_details": details,
        "observation": obs,
        # ── Cross-validation extras (consumed by report_agent) ──────────────
        "avg_delta_hours": _extract_avg_delta_hours(traffic_anomalies, routing_window),
        "direction_label": direction_detail,
    }


def _extract_avg_delta_hours(
    anomalies: list[dict], routing_window: dict | None
) -> float | None:
    """Compute average |ΔT| in hours between anomalies and routing window center."""
    if not anomalies or not routing_window:
        return None
    try:
        rw_start = routing_window["start"]
        rw_end   = routing_window["end"]
        rw_center = rw_start + (rw_end - rw_start) / 2
        deltas = []
        for a in anomalies:
            ts_str = a.get("timestamp", "")
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")) \
                if "T" in str(ts_str) \
                else _parse_dt(str(ts_str), "%Y-%m-%d %H:%M:%S")
            deltas.append(abs((ts - rw_center).total_seconds() / 3600))
        return round(sum(deltas) / len(deltas), 2) if deltas else None
    except Exception:
        return None


def _resolve_result(tool_input: dict, key: str, ev: dict,
                    ev_keys: list, nested_keys: list) -> dict:
    """Resolve a result dict from tool_input or session evidence."""
    # Direct pass
    val = tool_input.get(key, {})
    if isinstance(val, dict) and val:
        return val
    # From session evidence
    for ev_key in ev_keys:
        raw = ev.get(ev_key, {})
        if isinstance(raw, dict):
            for nk in nested_keys:
                val = raw.get(nk, {})
                if isinstance(val, dict) and val:
                    return val
            if raw and raw not in (None, {}):
                return raw
    return {}


def _extract_routing_window(routing):
    """Extract (start, end) from routing result."""
    if not routing:
        return None
    # Check origin_hijacked first (victim perspective)
    for key in ("origin_hijacked", "forge_hijacked", "origin_hijacking"):
        entries = routing.get(key, []) if isinstance(routing, dict) else []
        if entries and isinstance(entries, list):
            first = entries[0]
            if isinstance(first, dict):
                start = first.get("timestamp", "")
                # Find last entry's timestamp
                last_ts = (entries[-1].get("timestamp", "") if isinstance(entries[-1], dict) else "") or start
                if start:
                    try:
                        start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
                    except Exception:
                        try:
                            start_dt = _parse_dt(start)
                        except Exception:
                            start_dt = None
                    if start_dt:
                        try:
                            end_dt = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
                        except Exception:
                            try:
                                end_dt = _parse_dt(last_ts)
                            except Exception:
                                end_dt = start_dt
                        if end_dt:
                            return {"start": start_dt, "end": end_dt}
    return None


register_tool(
    name="compute_traffic_routing_correlation_score",
    description="Quantify the correlation between traffic anomalies and routing events as a 0-100 score across 5 dimensions: temporal overlap, direction consistency, magnitude alignment, victim verification, and prefix-path delta. Returns: total_score (0-100), correlation_level (L1-L5), per-dimension scores and details. Call this after analyze_traffic + analyze_routing + analyze_prefix_traffic to get an objective correlation score.",
    parameters=[
        ToolParameter("traffic_result", "Output of analyze_traffic", "object"),
        ToolParameter("routing_result", "Output of analyze_routing", "object"),
        ToolParameter("victim_traffic", "Victim AS traffic results (optional)", "object", required=False),
        ToolParameter("prefix_traffic", "Prefix traffic results from analyze_prefix_traffic (optional)", "object", required=False),
    ],
    handler=_compute_traffic_routing_correlation_score,
)


# ══════════════════════════════════════════════════════════════════════════════
async def _analyze_as_path_delta(tool_input, session):
    """Analyze AS-path structural changes during a hijack window.

    Past events: skip traceroute, use BGP archival data. Recent events
    (end_time >= now - 24h): also traceroute to verify current path.
    Reports path-length delta, structural changes, AS-relationship
    inference, and traceroute verification (recent only).
    """
    routing = tool_input.get("routing_result", {})
    if isinstance(routing, str):
        try:
            routing = json.loads(routing)
        except Exception:
            routing = {}
    ev = getattr(session, "evidence", {}) or {}
    if not routing:
        raw = ev.get("analyze_routing", {})
        if isinstance(raw, dict):
            routing = raw.get("result", {}) or raw

    routing = routing.get("result", routing) if isinstance(routing, dict) else routing
    if not routing:
        return {"success": False, "error": "No routing data",
                "observation": "Cannot analyze AS-path without routing result."}

    start = tool_input.get("start_time", "")
    end = tool_input.get("end_time", "")
    normal_start_input = tool_input.get("normal_start", "")
    normal_end_input = tool_input.get("normal_end", "")

    # Parse times. Bug fix 2026-09-13 (BUG-R61): the original double
    try:
        start_dt = _parse_dt(start)
    except Exception:
        start_dt = None
    try:
        end_dt = _parse_dt(end)
    except Exception:
        end_dt = None

    # Normal baseline window
    if normal_start_input and normal_end_input:
        normal_start = normal_start_input
        normal_end = normal_end_input
    elif start_dt:
        normal_end = start
        normal_start = (start_dt - timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")
    else:
        normal_start = normal_end = None

    # ── Time check: is this a recent event? ──────────────────────────────────
    is_recent = False
    traceroute_skipped_reason = ""
    now = datetime.now()
    if end_dt:
        time_diff = now - end_dt
        is_recent = time_diff.total_seconds() <= 24 * 3600
        if not is_recent:
            traceroute_skipped_reason = (
                f"Event ended at {end}, which is {time_diff.days}d {time_diff.seconds//3600}h ago. "
                "Skipping live traceroute — only archival BGP data will be used."
            )
            logger.info(f"[as_path_delta] Historical event ({traceroute_skipped_reason})")
    else:
        traceroute_skipped_reason = "Cannot determine event recency — no end_time provided."

    # ── Extract all AS-path entries from routing result ───────────────────────
    def parse_as_path(raw):
        if not raw:
            return []
        return [x.strip() for x in str(raw).split() if x.strip()]

    all_entries = []
    for key in ("origin_hijacked", "forge_hijacked", "origin_hijacking",
                "forge_hijacking", "victim_anomalies", "attacker_anomalies"):
        entries = routing.get(key, [])
        if isinstance(entries, list):
            all_entries.extend(entries)

    # ── Compute AS-path metrics ───────────────────────────────────────────────
    path_metrics = _compute_path_metrics(all_entries, start_dt, end_dt, normal_start, normal_end)

    # ── Traceroute for recent events only ─────────────────────────────────────
    traceroute_result = {}
    if is_recent:
        traceroute_result = await _do_traceroute_probe(routing, end_dt, tool_input)
    else:
        traceroute_result = {"performed": False, "skipped": True,
                             "reason": traceroute_skipped_reason}

    # ── Combine findings ──────────────────────────────────────────────────────
    overall_verdict = _as_path_verdict(path_metrics, traceroute_result)

    obs = (
        f"AS-path analysis complete. "
        f"Avg path length delta: {path_metrics.get('avg_path_len_delta', 0):+.1f} hops. "
        f"Traceroute: {'performed' if traceroute_result.get('performed') else 'skipped'}. "
        f"Verdict: {overall_verdict.get('level', 'unknown')}"
    )
    logger.info(f"[as_path_delta] {obs}")

    return {
        "success": True,
        "start_time": start,
        "end_time": end,
        "is_recent_event": is_recent,
        "traceroute_skipped": not is_recent,
        "traceroute_skipped_reason": traceroute_skipped_reason if not is_recent else "",
        "path_metrics": path_metrics,
        "traceroute_result": traceroute_result,
        "overall_verdict": overall_verdict,
        "observation": obs,
    }


async def _do_traceroute_probe(routing: dict, end_dt: Optional[datetime],
                               tool_input: dict) -> dict:
    """
 Perform traceroute for recent events to verify current routing path.
 Only proceeds if the event is recent (ended within 24h).
 """
    # Extract a target prefix to probe
    prefixes = []
    for key in ("origin_hijacked", "forge_hijacked"):
        for ev in routing.get(key, []):
            pf = ev.get("prefix", "")
            if pf and pf not in prefixes:
                prefixes.append(pf)
    if not prefixes:
        return {"performed": False, "skipped": True,
                "reason": "No target prefix found in routing result"}

    target_prefix = prefixes[0]

    # Extract attacker AS for path validation
    attacker_asns = []
    for key in ("origin_hijacking", "forge_hijacking", "attacker_anomalies"):
        for ev in routing.get(key, []):
            oas = ev.get("origin_as", "")
            if oas and oas not in attacker_asns:
                attacker_asns.append(oas)
    # Also from origin_hijacked
    for ev in routing.get("origin_hijacked", []):
        ha = ev.get("hijacker_as", "")
        if ha and ha not in attacker_asns:
            attacker_asns.append(ha)

    logger.info(f"[as_path_delta] Probing {target_prefix} via traceroute...")

    # Use system traceroute (or mtr) with max 30 hops, 3 probes per hop
    import subprocess, shlex

    probe_result = {
        "target_prefix": target_prefix,
        "performed": True,
        "skipped": False,
        "probes": [],
        "path": [],
        "attacker_in_path": False,
    }

    try:
        # Try mtr first (richer output), fallback to traceroute
        target_ip = target_prefix.split('/')[0].strip()
        # Minimal sanity-check: refuse anything that isn't an IP or
        import re as _re_probe
        if not _re_probe.match(r'^[A-Za-z0-9.\-:]+$', target_ip):
            raise ValueError(f"unsafe target_prefix {target_ip!r}")
        cmd = ["mtr", "-r", "-c", "3", "-m", "30", target_ip]
        logger.info(f"[as_path_delta] Running: {' '.join(cmd)}")
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60
        )
        output = result.stdout + result.stderr

        # Parse mtr output (Last: 3, Avg: 2.1, Best: 1.8, etc. + hop lines)
        # Simple heuristic: extract IP addresses from each line
        hop_ips = []
        for line in output.splitlines():
            parts = line.strip().split()
            for p in parts:
                # Match IP-like patterns
                if re.match(r"\d+\.\d+\.\d+\.\d+", p) or ":" in p:
                    hop_ips.append(p)

        probe_result["path"] = hop_ips
        probe_result["raw_output"] = output[:500]

        # Try to resolve AS numbers for each hop
        probe_result["attacker_in_path"] = any(
            str(a) in output for a in attacker_asns
        )

    except subprocess.TimeoutExpired:
        probe_result["error"] = "Traceroute timed out after 60s"
        logger.warning("[as_path_delta] Traceroute timed out")
    except FileNotFoundError:
        probe_result["error"] = "mtr/traceroute not installed on this system"
        logger.warning("[as_path_delta] No traceroute tool found")
    except Exception as e:
        probe_result["error"] = str(e)
        logger.warning(f"[as_path_delta] Traceroute failed: {e}")

    # Determine path verdict
    if probe_result.get("attacker_in_path"):
        probe_result["path_verdict"] = "ATTACKER_IN_PATH: attacker AS detected in traceroute path — hijack may still be active"
        probe_result["hijack_active"] = True
    elif probe_result.get("error"):
        probe_result["path_verdict"] = f"Traceroute failed: {probe_result['error']}"
        probe_result["hijack_active"] = None
    else:
        probe_result["path_verdict"] = "ATTACKER_NOT_IN_PATH: hijack path not currently observed — may have been mitigated"
        probe_result["hijack_active"] = False

    return probe_result


def _compute_path_metrics(entries: list, start_dt: Optional[datetime],
                          end_dt: Optional[datetime],
                          normal_start_str: Optional[str],
                          normal_end_str: Optional[str]) -> dict:
    """Compute AS-path length, structural change, and AS appearance metrics."""
    def parse_as_path(raw):
        if not raw:
            return []
        return [x.strip() for x in str(raw).split() if x.strip()]

    def in_window(ts_str, w_start, w_end):
        if not ts_str:
            return False
        # Bug fix 2026-09-13 (BUG-R85): the previous implementation
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            try:
                ts = _parse_dt(ts_str)
            except Exception:
                return False
        if w_start and ts < w_start:
            return False
        if w_end and ts > w_end:
            return False
        return True

    normal_start_dt = None
    normal_end_dt = None
    if normal_start_str:
        try:
            normal_start_dt = _parse_dt(normal_start_str)
        except Exception:
            pass
    if normal_end_str:
        try:
            normal_end_dt = _parse_dt(normal_end_str)
        except Exception:
            pass

    hijack_paths = []
    normal_paths = []
    hijack_as_set = set()
    normal_as_set = set()
    new_asns = []

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        ts = entry.get("timestamp", "")
        as_path_raw = entry.get("as_path", "") or entry.get("as-path", "")
        as_path = parse_as_path(as_path_raw)
        if not as_path:
            continue

        if start_dt and end_dt and in_window(ts, start_dt, end_dt):
            hijack_paths.append(as_path)
            hijack_as_set.update(as_path)
        elif normal_start_dt and normal_end_dt and in_window(ts, normal_start_dt, normal_end_dt):
            normal_paths.append(as_path)
            normal_as_set.update(as_path)

    # AS-path length
    hijack_lens = [len(p) for p in hijack_paths] or [0]
    normal_lens = [len(p) for p in normal_paths] or [0]
    avg_hijack_len = sum(hijack_lens) / len(hijack_lens)
    avg_normal_len = sum(normal_lens) / len(normal_lens)
    path_len_delta = avg_hijack_len - avg_normal_len

    # New ASes appearing during hijack
    new_asns = list(hijack_as_set - normal_as_set)

    # ASes disappearing during hijack
    lost_asns = list(normal_as_set - hijack_as_set)

    # Detect AS-path loops (consecutive duplicate AS)
    def has_loop(path_list):
        return any(path[i] == path[i+1] for i in range(len(path)-1))

    hijack_loops = sum(1 for p in hijack_paths if has_loop(p))
    normal_loops = sum(1 for p in normal_paths if has_loop(p))

    # Path concentration: how many hijack paths go through the first AS (upstream)?
    # A high concentration indicates potential hijack path
    if hijack_paths:
        first_hop_counts = {}
        for p in hijack_paths:
            if p:
                first_as = p[0]
                first_hop_counts[first_as] = first_hop_counts.get(first_as, 0) + 1
        dominant_first_hop = max(first_hop_counts.values()) / len(hijack_paths) if first_hop_counts else 0
    else:
        dominant_first_hop = 0.0

    return {
        "hijack_sample_count": len(hijack_paths),
        "normal_sample_count": len(normal_paths),
        "avg_hijack_path_length": round(avg_hijack_len, 2),
        "avg_normal_path_length": round(avg_normal_len, 2),
        "path_length_delta": round(path_len_delta, 2),
        "new_asns_appearing": new_asns[:20],  # cap to 20
        "asns_disappearing": lost_asns[:20],
        "hijack_loop_count": hijack_loops,
        "normal_loop_count": normal_loops,
        "dominant_first_hop_ratio": round(dominant_first_hop, 3),
        "hijack_first_hop_concentration": "high" if dominant_first_hop > 0.7 else ("medium" if dominant_first_hop > 0.4 else "low"),
    }


def _as_path_verdict(path_metrics, traceroute_result):
    """Determine overall AS-path verdict."""
    score = 0
    reasons = []

    # Path length delta
    delta = path_metrics.get("path_length_delta", 0)
    if delta > 3:
        score += 25
        reasons.append(f"Path significantly elongated by {delta:.1f} hops during hijack")
    elif delta > 1:
        score += 15
        reasons.append(f"Path length increased by {delta:.1f} hops")
    elif delta < -1:
        score += 5
        reasons.append(f"Path shortened unexpectedly by {abs(delta):.1f} hops")

    # New ASes appearing
    new_asns = path_metrics.get("new_asns_appearing", [])
    if len(new_asns) > 5:
        score += 20
        reasons.append(f"{len(new_asns)} new ASes appeared in paths")
    elif len(new_asns) > 0:
        score += 10
        reasons.append(f"{len(new_asns)} new ASes appeared in paths")

    # Path loops
    loop_delta = path_metrics.get("hijack_loop_count", 0) - path_metrics.get("normal_loop_count", 0)
    if loop_delta > 2:
        score += 15
        reasons.append(f"{loop_delta} extra path loops during hijack")
    elif loop_delta > 0:
        score += 8
        reasons.append(f"{loop_delta} extra path loops during hijack")

    # Traceroute evidence
    if traceroute_result.get("performed") and not traceroute_result.get("skipped"):
        if traceroute_result.get("hijack_active") is True:
            score += 25
            reasons.append("Traceroute confirms attacker in current path — hijack may be ACTIVE")
        elif traceroute_result.get("hijack_active") is False:
            reasons.append("Traceroute shows normal path — hijack likely mitigated or expired")
        # If None (error), no score added

    level = "STRONG" if score >= 60 else ("MODERATE" if score >= 30 else "WEAK")

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
        "summary": f"AS-path score {score}/85 — {level}. " + " ".join(reasons[:3]),
    }


register_tool(
    name="analyze_as_path_delta",
    description="Analyze AS-path structural changes during a hijack window (path length, new ASes, loops). For RECENT events (ended within 24h), also attempts traceroute to verify current routing path. For HISTORICAL events (ended >24h ago), skips traceroute and only uses archival BGP data. Returns: path_length_delta, new_asns_appearing, path loop counts, traceroute result, and overall AS-path verdict.",
    parameters=[
        ToolParameter("routing_result", "Output of analyze_routing", "object"),
        ToolParameter("start_time", "Hijack window start, ISO format", "string"),
        ToolParameter("end_time", "Hijack window end, ISO format", "string"),
        ToolParameter("normal_start", "Baseline normal period start (optional, default: 2h before hijack)", "string", required=False),
        ToolParameter("normal_end", "Baseline normal period end (optional)", "string", required=False),
    ],
    handler=_analyze_as_path_delta,
)


# ══════════════════════════════════════════════════════════════════════════════
async def _analyze_as_relationships(tool_input, session):
    """Analyze AS-level relationship between attacker and victim.

    Uses CAIDA as-rel (priority 1), then AS-path structure (priority 2),
    then unknown. Returns provider/peer/customer relationship, blast
    radius, and proportion of victim traffic through the attacker.
    """
    attacker_asn = str(tool_input.get("attacker_asn", "") or tool_input.get("hijacker_asn", ""))
    victim_asn = str(tool_input.get("victim_asn", ""))
    start = tool_input.get("start_time", "")
    routing = tool_input.get("routing_result", {})
    asn_info = tool_input.get("asn_info", {})

    ev = getattr(session, "evidence", {}) or {}
    if not routing:
        raw = ev.get("analyze_routing", {})
        if isinstance(raw, dict):
            routing = raw.get("result", {}) or raw
    if not asn_info:
        raw_asn = ev.get("query_as_info", {})
        if isinstance(raw_asn, dict):
            asn_info = raw_asn.get("info", {}) or raw_asn.get("result", {}) or raw_asn

    if not attacker_asn or not victim_asn:
        return {"success": False, "error": "attacker_asn and victim_asn are required",
                "observation": "Cannot analyze AS relationships without both AS numbers."}

    logger.info(f"[as_relationships] Attacker=AS{attacker_asn}, Victim=AS{victim_asn}")

    # ── Load CAIDA AS Relationship data ─────────────────────────────────────
    from data.asrel_loader import process_asrel
    try:
        lookup_time = _parse_dt(start) if start else datetime(2025, 1, 1)
    except Exception:
        lookup_time = datetime(2025, 1, 1)
    asrel_file = process_asrel(lookup_time)
    asrel = _load_asrel_json(asrel_file)

    # ── Query direct relationship ─────────────────────────────────────────────
    direct_rel = _query_as_relationship(asrel, attacker_asn, victim_asn)

    # ── Infer from AS-path structure ─────────────────────────────────────────
    inferred_rel = _infer_relationship_from_path(routing, attacker_asn, victim_asn)

    # ── Determine final relationship ─────────────────────────────────────────
    if direct_rel != "unknown":
        final_rel = direct_rel
        rel_source = "caida_as_rel"
    else:
        final_rel = inferred_rel
        rel_source = "inferred_from_as_path"

    # ── Blast radius estimation ───────────────────────────────────────────────
    blast_radius = _estimate_blast_radius(asrel, attacker_asn, victim_asn, final_rel)

    # ── Financial impact estimation ─────────────────────────────────────────
    victim_country = asn_info.get("org", {}).get("country") if isinstance(asn_info, dict) else ""
    financial_impact = _estimate_financial_impact(
        final_rel, attacker_asn, victim_asn, victim_country, blast_radius
    )

    # ── Hijack plausibility ─────────────────────────────────────────────────
    plausibility = _relationship_plausibility(final_rel, attacker_asn, victim_asn)

    obs = (
        f"Attacker (AS{attacker_asn}) is {final_rel} of victim (AS{victim_asn}). "
        f"Blast radius: {blast_radius['tier']}. Plausibility: {plausibility['level']}. "
        f"Source: {rel_source}."
    )
    logger.info(f"[as_relationships] {obs}")

    return {
        "success": True,
        "attacker_asn": attacker_asn,
        "victim_asn": victim_asn,
        "relationship": {
            "attacker_to_victim": final_rel,
            "source": rel_source,
            "direct_caida": direct_rel,
            "inferred_from_path": inferred_rel,
        },
        "blast_radius": blast_radius,
        "financial_impact": financial_impact,
        "plausibility": plausibility,
        "observation": obs,
    }


def _load_asrel_json(filepath_str):
    """Load and parse CAIDA AS Relationship JSON file.

 Bug fix 2026-09-13 (BUG-R50): previously the bare ``open(filepath, "r")``
 call had no encoding and silently swallowed the loader error, returning
 an empty ``{"providers": {}, "peers": {}}`` shape. Downstream callers
 could not distinguish "data file is missing" from "AS has no recorded
 relationships" and would silently emit ``unknown`` for every pair - a
 mask on real config / data path bugs.

 Now we return ``None`` when the file cannot be read, and ``None`` for
 empty / malformed JSON, so callers can surface the data error.
 """
    try:
        # Bug fix 2026-10-13: parameter is ``filepath_str`` but body
        # referenced the undefined name ``filepath``.
        with open(filepath_str, "r", encoding="utf-8", errors="ignore") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    except Exception:
        return None


def _query_as_relationship(asrel, as1, as2):
    """
 Query the direct CAIDA AS relationship between as1 and as2.
 Returns: "provider" | "customer" | "peer" | "unknown"
 """
    if not asrel or not isinstance(asrel, dict):
        return "unknown"
    providers = asrel.get("providers", {})
    peers = asrel.get("peers", {})
    # as1 is provider of as2?
    if as2 in providers and as1 in providers[as2]:
        return "provider"
    # as1 is customer of as2?
    if as1 in providers and as2 in providers[as1]:
        return "customer"
    # as1 and as2 are peers?
    if as1 in peers and as2 in peers[as1]:
        return "peer"
    return "unknown"


def _infer_relationship_from_path(routing: dict, attacker_asn: str,
                                  victim_asn: str) -> str:
    """
 Infer attacker-victim relationship from AS-path structure.

 In a hijack AS_PATH:
 - Attacker appearing before victim → attacker is upstream (provider)
 - Attacker appearing after victim → attacker is downstream (customer)
 - Mixed positions → peer-level hijack
 """
    if not routing:
        return "unknown"
    all_entries = []
    for key in ("origin_hijacked", "origin_hijacking", "victim_anomalies", "attacker_anomalies"):
        entries = routing.get(key, [])
        if isinstance(entries, list):
            all_entries.extend(entries)
    if not all_entries:
        return "unknown"

    attacker_before = attacker_after = 0
    for entry in all_entries:
        if not isinstance(entry, dict):
            continue
        as_path_raw = entry.get("as_path", "") or entry.get("as-path", "")
        if not as_path_raw:
            continue
        as_path = [x.strip() for x in str(as_path_raw).split() if x.strip()]
        try:
            ai = as_path.index(attacker_asn)
        except ValueError:
            continue
        try:
            vi = as_path.index(victim_asn)
            if ai < vi:
                attacker_before += 1
            else:
                attacker_after += 1
        except ValueError:
            pass

    total = attacker_before + attacker_after
    if total == 0:
        return "unknown"
    before_ratio = attacker_before / total
    if before_ratio > 0.6:
        return "provider"
    elif attacker_after / total > 0.6:
        return "customer"
    elif before_ratio + attacker_after / total > 0.3:
        return "peer"
    return "unknown"


def _estimate_blast_radius(asrel: dict, attacker_asn: str,
                           victim_asn: str, relationship: str) -> dict:
    """
 Estimate the blast radius of the hijack based on AS relationship.

 Provider hijack: HIGH blast radius (all upstream traffic routes through attacker)
 Peer hijack: MEDIUM blast radius (only shared peering links affected)
 Customer hijack: LOW blast radius (limited to customer's own traffic)
 """
    providers = asrel.get("providers", {})
    peers = asrel.get("peers", {})

    # Count attacker's downstream customers
    attacker_customers = [cust for cust, provs in providers.items() if attacker_asn in provs]
    # Count victim's upstream providers
    victim_providers = providers.get(victim_asn, [])
    # Count victim's peers
    victim_peers = peers.get(victim_asn, [])

    if relationship == "provider":
        tier, tier_score = "HIGH", 3
        tier_desc = "Attacker is upstream — all traffic routes through attacker"
    elif relationship == "peer":
        tier, tier_score = "MEDIUM", 2
        tier_desc = f"Attacker is peer ({len(victim_peers)} shared peers) — partial interception"
    elif relationship == "customer":
        tier, tier_score = "LOW", 1
        tier_desc = "Attacker is downstream — limited to customer's own traffic"
    else:
        tier, tier_score = "UNKNOWN", 0
        tier_desc = "Cannot determine blast radius — unknown relationship"

    return {
        "tier": tier,
        "tier_score": tier_score,
        "tier_description": tier_desc,
        "attacker_customers_count": len(attacker_customers),
        "victim_provider_count": len(victim_providers),
        "victim_peer_count": len(victim_peers),
        "attacker_is_provider_for": attacker_customers[:10],
        "victim_providers": victim_providers[:5],
        "victim_peers": victim_peers[:5],
    }


def _estimate_financial_impact(relationship: str, attacker_asn: str,
                                victim_asn: str, victim_country: str,
                                blast_radius: dict) -> dict:
    """Rough financial impact estimation based on relationship and blast radius."""
    country_risk = {
        "US": 1.0, "CN": 0.9, "DE": 0.85, "JP": 0.85, "GB": 0.8,
        "IN": 0.6, "BR": 0.5, "RU": 0.4, "NG": 0.3,
    }
    country_mult = country_risk.get(victim_country, 0.5)
    tier_base = {"HIGH": 1_000_000, "MEDIUM": 500_000, "LOW": 100_000, "UNKNOWN": 250_000}
    base = tier_base.get(blast_radius.get("tier", "UNKNOWN"), 250_000)
    estimated = round(base * country_mult, -3)

    impact_level_map = {"HIGH": "CRITICAL", "MEDIUM": "HIGH", "LOW": "MEDIUM", "UNKNOWN": "UNKNOWN"}
    return {
        "estimated_daily_impact_usd": estimated,
        "impact_level": impact_level_map.get(blast_radius.get("tier", "UNKNOWN"), "UNKNOWN"),
        "description": f"Estimated ${estimated:,}/day for {blast_radius.get('tier', 'UNKNOWN').lower()} blast radius",
        "country_multiplier": country_mult,
        "note": "Rough estimate — not financial advice",
    }


def _relationship_plausibility(relationship: str, attacker_asn: str,
                               victim_asn: str) -> dict:
    """Assess how plausible the hijack is, given the relationship."""
    if relationship == "provider":
        return {"level": "HIGH",
                "reason": "Attacker is victim's upstream provider — can legitimately announce victim's prefix"}
    elif relationship == "peer":
        return {"level": "MEDIUM",
                "reason": "Attacker is victim's peer — hijack possible via route leak or false announcement"}
    elif relationship == "customer":
        return {"level": "LOW",
                "reason": "Attacker is victim's customer — false announcement of victim's prefix is suspicious"}
    return {"level": "UNKNOWN", "reason": "Cannot assess — unknown relationship"}


register_tool(
    name="analyze_as_relationships",
    description="Analyze the business relationship (provider/peer/customer/unknown) between attacker and victim AS using CAIDA AS Relationship data and AS-path inference. Returns: relationship type, blast radius tier (HIGH/MEDIUM/LOW), financial impact estimate, and hijack plausibility. Use this to assess how realistic the hijack scenario is and its potential scope.",
    parameters=[
        ToolParameter("attacker_asn", "AS number of the hijacker", "string"),
        ToolParameter("victim_asn", "AS number of the hijacked AS", "string"),
        ToolParameter("start_time", "Event start time (ISO format, for selecting correct as-rel data)", "string"),
        ToolParameter("hijacker_asn", "Alias for attacker_asn (for backward compat)", "string", required=False),
        ToolParameter("routing_result", "Output of analyze_routing (for AS-path inference)", "object", required=False),
        ToolParameter("asn_info", "Output of query_as_info", "object", required=False),
    ],
    handler=_analyze_as_relationships,
)


# ══════════════════════════════════════════════════════════════════════════════
async def _probe_prefix_reachability(tool_input, session):
    """
 Verify prefix reachability and hijack effectiveness.

 Time-aware probe selection:
 - RECENT event (ended within 24h): live traceroute/mtr
 - HISTORICAL event (ended > 24h ago): RIPE RIS API + BGPView.io + RIPE Looking Glass

 Required params:
 prefixes (list[str]): prefixes to probe, e.g. ["185.245.181.0/24"]
 start_time (str): hijack window start
 end_time (str): hijack window end
 Optional params:
 attacker_asn (str): hijacker AS for path validation
 victim_asn (str): victim AS for expected origin comparison
 routing_result (dict): routing result for target prefix extraction
 """
    prefixes = tool_input.get("prefixes", [])
    if isinstance(prefixes, str):
        try:
            prefixes = json.loads(prefixes)
        except Exception:
            prefixes = [prefixes]

    start = tool_input.get("start_time", "")
    end = tool_input.get("end_time", "")
    attacker_asn = str(tool_input.get("attacker_asn", ""))
    victim_asn = str(tool_input.get("victim_asn", ""))

    ev = getattr(session, "evidence", {}) or {}

    # Resolve routing result
    routing = tool_input.get("routing_result", {})
    if not routing:
        raw = ev.get("analyze_routing", {})
        if isinstance(raw, dict):
            routing = raw.get("result", {}) or raw
    routing = routing.get("result", routing) if isinstance(routing, dict) else routing

    # Auto-extract from routing result
    if not prefixes:
        origin_hijacked = routing.get("origin_hijacked", []) if isinstance(routing, dict) else []
        prefixes = list({str(ev.get("prefix", "")) for ev in origin_hijacked if ev.get("prefix")})
    if not attacker_asn:
        attacker_anomalies = routing.get("origin_hijacking", []) if isinstance(routing, dict) else []
        if attacker_anomalies:
            attacker_asn = str(attacker_anomalies[0].get("origin_as", ""))

    if not prefixes:
        return {"success": False, "error": "No prefixes provided or found",
                "observation": "Cannot probe reachability without prefixes."}

    # ── Time check ───────────────────────────────────────────────────────
    try:
        end_dt = _parse_dt(end)
    except Exception:
        try:
            end_dt = _parse_dt(end)
        except Exception:
            end_dt = None

    now = datetime.now()
    is_recent = bool(end_dt and (now - end_dt).total_seconds() <= 24 * 3600)
    time_label = "RECENT" if is_recent else "HISTORICAL"

    logger.info(f"[probe_reachability] {time_label} event. {len(prefixes)} prefixes. end={end}")

    # ── Run probes ────────────────────────────────────────────────────────
    results = {}
    methods_used = []

    if is_recent:
        for prefix in prefixes:
            results[prefix] = await _live_traceroute_probe(prefix, attacker_asn, victim_asn)
            methods_used.append("live_traceroute_mtr")
    else:
        for prefix in prefixes:
            results[prefix] = await _historical_prefix_probe(prefix, start, end, attacker_asn, victim_asn)
        methods_used.extend(["ripe_ris_api", "bgpview_io", "ripe_looking_glass"])

    synthesize = _synthesize_probe_results(results, attacker_asn, victim_asn)

    obs = (f"Probed {len(prefixes)} prefixes ({time_label}, ended {end}). "
           f"Methods: {', '.join(set(methods_used))}. "
           f"Verdict: {synthesize['overall_verdict']}")
    logger.info(f"[probe_reachability] {obs}")

    return {
        "success": True,
        "time_label": time_label,
        "is_recent": is_recent,
        "end_time": end,
        "probed_prefixes": prefixes,
        "attacker_asn": attacker_asn,
        "victim_asn": victim_asn,
        "probe_methods_used": list(set(methods_used)),
        "per_prefix_results": results,
        "synthesis": synthesize,
        "observation": obs,
    }


async def _live_traceroute_probe(prefix, attacker_asn, victim_asn):
    """Run live traceroute using scapy (no root required) or system binary."""
    target_ip = prefix.split("/")[0]

    # Try our scapy-based TracerouteProbe first (no root required)
    try:
        from tools.probing_tools import TracerouteProbe
        probe = TracerouteProbe(max_hops=15, timeout=3.0, retries=1)
        result = await probe.probe(target_ip)
        output = result.raw_output
        hop_ips = [h.get("ip") for h in result.hops if h.get("ip") and h.get("ip") != "*"]
        probe_method = result.probe_type
    except Exception:
        # Fallback: try system mtr/traceroute binary
        import subprocess, shlex
        output = ""
        # Bug fix 2026-09-13 (BUG-R86): the previous code used
        import re as _re_probe2
        if not _re_probe2.match(r'^[A-Za-z0-9.\-:]+$', target_ip):
            logger.warning(f"[probe_prefix_reachability] unsafe target_ip {target_ip!r}; skipping fallback probe")
            target_ip = ""
        for cmd_tmpl in [["mtr", "-r", "-c", "3", "-m", "30", target_ip],
                         ["traceroute", "-m", "30", "-w", "3", target_ip]]:
            if not target_ip:
                break
            try:
                res = subprocess.run(cmd_tmpl, capture_output=True, text=True, timeout=60)
                output = res.stdout + res.stderr
                if res.returncode == 0 and output.strip():
                    break
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
            except Exception:
                continue

        hop_ips = []
        for line in output.splitlines():
            for p in line.strip().split():
                if re.match(r"\d+\.\d+\.\d+\.\d+", p) or ":" in p:
                    if p not in hop_ips:
                        hop_ips.append(p)
        probe_method = "live_traceroute"

    attacker_in_path = attacker_asn in output if attacker_asn else False

    return {
        "prefix": prefix,
        "target_ip": target_ip,
        "probe_method": probe_method,
        "hops": hop_ips,
        "hop_count": len(hop_ips),
        "raw_output": output[:800] if output else "",
        "attacker_in_path": attacker_in_path,
        "verdict": "ATTACKER_DETECTED" if attacker_in_path else "ATTACKER_NOT_DETECTED",
    }


async def _historical_prefix_probe(prefix: str, start: str, end: str,
                                   attacker_asn: str, victim_asn: str) -> dict:
    """Probe a prefix for historical events using RIPE RIS + BGPView + Looking Glass."""
    import requests

    results_by_method = {}

    # Helper: fetch URL on a worker thread, return ``(status_code, body)``
    def _sync_get(url, want_json=True):
        try:
            r = requests.get(url, timeout=15)
            if want_json:
                try:
                    return r.status_code, r.json()
                except Exception:
                    return r.status_code, None
            return r.status_code, r.text
        except Exception:
            return 0, None

    # Method 1: RIPE RIS REST API
    try:
        url = f"https://ris.ripe.net/api/v1/prefix/lookup?prefix={prefix}"
        status_code, data = await asyncio.to_thread(_sync_get, url)
        if status_code == 200 and isinstance(data, dict):
            prefixes_data = data.get("data", {}).get("prefixes", [])
            for pf in prefixes_data:
                if pf.get("prefix") == prefix:
                    results_by_method["ripe_ris"] = {
                        "current_origin_as": pf.get("origin", "unknown"),
                        "path_count": pf.get("path_count", 0),
                        "source": "ripe_ris"
                    }
                    break
            if "ripe_ris" not in results_by_method:
                results_by_method["ripe_ris"] = {"error": "prefix not in RIS data", "source": "ripe_ris"}
        else:
            results_by_method["ripe_ris"] = {"error": f"HTTP {status_code}", "source": "ripe_ris"}
    except Exception as e:
        results_by_method["ripe_ris"] = {"error": str(e), "source": "ripe_ris"}

    # Method 2: BGPView.io (free, no auth)
    try:
        bv_url = f"https://api.bgpview.io/prefix/{prefix}"
        status_code, data = await asyncio.to_thread(_sync_get, bv_url)
        if status_code == 200 and isinstance(data, dict):
            if data.get("status") == "ok":
                for pf in data.get("data", {}).get("prefixes", []):
                    if pf.get("prefix") == prefix:
                        results_by_method["bgpview_io"] = {
                            "announced_by_asns": [str(o.get("asn")) for o in pf.get("ownership_prefixes", [])],
                            "source": "bgpview_io"
                        }
                        break
                if "bgpview_io" not in results_by_method:
                    results_by_method["bgpview_io"] = {"error": "no data for prefix", "source": "bgpview_io"}
    except Exception as e:
        results_by_method["bgpview_io"] = {"error": str(e), "source": "bgpview_io"}

    # Method 3: RIPE RIS Whois (Looking Glass)
    try:
        lg_url = f"https://riswhois.ripe.net/Routing?KEY={prefix}&TYPE=prefix"
        status_code, text = await asyncio.to_thread(_sync_get, lg_url, False)
        if status_code == 200 and isinstance(text, str):
            origin_match = re.search(r"origin:\s*(AS?\d+)", text, re.IGNORECASE)
            if origin_match:
                results_by_method["ripe_looking_glass"] = {
                    "origin_as_from_lg": origin_match.group(1).upper(),
                    "raw_snippet": text[:500],
                    "source": "ripe_looking_glass"
                }
            else:
                results_by_method["ripe_looking_glass"] = {"error": "no origin in output", "source": "ripe_looking_glass"}
    except Exception as e:
        results_by_method["ripe_looking_glass"] = {"error": str(e), "source": "ripe_looking_glass"}

    # Synthesize declared origins
    current_origins = set()
    for mres in results_by_method.values():
        if isinstance(mres, dict):
            oas = mres.get("current_origin_as") or mres.get("origin_as_from_lg", "")
            if oas:
                oas = re.sub(r"^AS", "", oas, flags=re.IGNORECASE)
                current_origins.add(oas)
            for asn in mres.get("announced_by_asns", []):
                current_origins.add(str(asn))

    attacker_present = attacker_asn in current_origins if attacker_asn else False
    victim_present = victim_asn in current_origins if victim_asn else False

    return {
        "prefix": prefix,
        "probe_method": "historical_api",
        "methods_results": results_by_method,
        "current_declared_origins": list(current_origins),
        "attacker_present": attacker_present,
        "victim_present": victim_present,
        "verdict": _historical_verdict(attacker_present, victim_present, current_origins, attacker_asn, victim_asn),
    }


def _historical_verdict(attacker_present: bool, victim_present: bool,
                       current_origins: set, attacker_asn: str,
                       victim_asn: str) -> str:
    """Determine verdict from historical probe results."""
    if attacker_present and not victim_present:
        return "ATTACKER_CURRENTLY_ANNOUNCING: hijack may still be active"
    elif victim_present and not attacker_present:
        return "VICTIM_RECOVERED: hijack resolved"
    elif attacker_present and victim_present:
        return "CONFLICTING_ANNOUNCEMENTS: both attacker and victim are announcing"
    elif not current_origins:
        return "PREFIX_WITHDRAWN: no AS is declaring this prefix"
    return "UNKNOWN_ORIGIN: neither attacker nor victim in current declarations"


def _synthesize_probe_results(results: dict, attacker_asn: str,
                               victim_asn: str) -> dict:
    """Synthesize per-prefix probe results into overall verdict."""
    total = len(results)
    if total == 0:
        return {"overall_verdict": "NO_PREFIXES_PROBED", "attacker_presence_count": 0,
                "victim_recovery_count": 0, "details": []}

    attacker_count = victim_count = active = resolved = 0
    details = []

    for prefix, res in results.items():
        if not isinstance(res, dict):
            continue
        verdict = res.get("verdict", "")
        details.append({"prefix": prefix, "verdict": verdict})
        if "ATTACKER_DETECTED" in verdict or "ATTACKER_CURRENTLY_ANNOUNCING" in verdict or "CONFLICTING" in verdict:
            attacker_count += 1
            active += 1
        elif "VICTIM_RECOVERED" in verdict or "ATTACKER_NOT_DETECTED" in verdict:
            victim_count += 1
            resolved += 1

    if active == total:
        overall = "ACTIVE_HIJACK"
    elif resolved == total:
        overall = "RESOLVED"
    elif attacker_count > 0:
        overall = f"MIXED: {attacker_count}/{total} prefixes show attacker presence"
    else:
        overall = "INCONCLUSIVE"

    return {
        "overall_verdict": overall,
        "attacker_presence_count": attacker_count,
        "victim_recovery_count": victim_count,
        "active_hijack_count": active,
        "resolved_count": resolved,
        "total_prefixes": total,
        "details": details,
    }


register_tool(
    name="probe_prefix_reachability",
    description="Verify prefix reachability and hijack effectiveness. Time-aware: for RECENT events (ended within 24h), runs live traceroute/mtr. For HISTORICAL events (ended >24h ago), queries RIPE RIS API, BGPView.io, and RIPE Looking Glass to determine which AS is currently announcing each prefix. Returns per-prefix verdict and overall synthesis.",
    parameters=[
        ToolParameter("prefixes", "List of prefixes to probe, e.g. ['185.245.181.0/24']", "string"),
        ToolParameter("start_time", "Hijack window start (ISO format)", "string"),
        ToolParameter("end_time", "Hijack window end (ISO format)", "string"),
        ToolParameter("attacker_asn", "Hijacker AS number (for path validation)", "string", required=False),
        ToolParameter("victim_asn", "Victim AS number (for expected origin comparison)", "string", required=False),
        ToolParameter("routing_result", "Output of analyze_routing (auto-extracts prefixes)", "object", required=False),
    ],
    handler=_probe_prefix_reachability,
)


# ══════════════════════════════════════════════════════════════════════════════
async def _validate_roa_status(tool_input, session):
    """Validate hijacked prefix+origin pairs against RPKI ROA.

    Sources: Cloudflare RPKI API (live, 5-min cache), RIPE NCC archive
    (historical). Per-prefix status: VALID / INVALID / NOT_FOUND /
    EXPIRED. INVALID is strong hijack evidence.
    """
    announcements = tool_input.get("announcements", [])
    routing = tool_input.get("routing_result", {})
    start = tool_input.get("start_time", "")
    end = tool_input.get("end_time", "")

    ev = getattr(session, "evidence", {}) or {}

    # Auto-extract from routing result if not provided
    if not announcements and routing:
        # routing may be a stringified summary; only proceed when it's a dict
        if isinstance(routing, dict):
            routing = routing.get("result", routing) if isinstance(routing, dict) else routing
            origin_hijacked = routing.get("origin_hijacked", []) or []
            for ev_entry in origin_hijacked:
                if not isinstance(ev_entry, dict):
                    continue
                pf = ev_entry.get("prefix", "")
                oas = ev_entry.get("origin_as", "")
                ts = ev_entry.get("timestamp", "")
                if pf and oas:
                    announcements.append({
                        "prefix": pf,
                        "origin_asn": str(oas),
                        "timestamp": ts,
                    })
    if not announcements:
        return {"success": False, "error": "No announcements to validate",
                "observation": "Cannot validate ROA without hijacked prefix+origin pairs."}

    # ── Load ROA data ───────────────────────────────────────────────────────
    # Use Cloudflare RPKI API for live validation
    roa_data = {}
    roa_source = ""

    try:
        roa_data, roa_source = await _fetch_cloudflare_roa()
    except Exception as e:
        logger.warning(f"[roa_validation] Cloudflare ROA fetch failed: {e}")

    # ── Validate each announcement ────────────────────────────────────────────
    results = []
    for ann in announcements:
        pf = ann.get("prefix", "")
        oas = ann.get("origin_asn", "")
        ts = ann.get("timestamp", "")
        status, roa_info = _check_roa_single(roa_data, pf, oas)
        results.append({
            "prefix": pf,
            "origin_asn": oas,
            "timestamp": ts,
            "status": status,
            "roa_info": roa_info,
        })

    # ── Summarize ─────────────────────────────────────────────────────────────
    total = len(results)
    valid_count = sum(1 for r in results if r["status"] == "VALID")
    invalid_count = sum(1 for r in results if r["status"] == "INVALID")
    not_found_count = sum(1 for r in results if r["status"] == "NOT_FOUND")

    # ROV protection assessment
    rov_coverage_pct = round((total - not_found_count) / total * 100, 1) if total > 0 else 0

    # High-risk: INVALID + no ROA count
    high_risk = invalid_count + not_found_count
    risk_level = "CRITICAL" if invalid_count > 0 else ("HIGH" if not_found_count > total * 0.5 else "LOW")

    # Extract invalid events with details
    invalid_events = [
        {"prefix": r["prefix"], "origin_asn": r["origin_asn"],
         "declared_in_roa": r["roa_info"].get("valid_origins", []) if r["roa_info"] else [],
         "reason": "ROA exists but origin does not match"}
        for r in results if r["status"] == "INVALID"
    ]

    # Per-prefix ROV details
    per_prefix_rov = {
        r["prefix"]: {
            "status": r["status"],
            "covered_by_roa": r["status"] in ("VALID", "INVALID"),
            "protected": r["status"] == "VALID",
            "invalid_reason": r["roa_info"] if r["status"] == "INVALID" else None,
        }
        for r in results
    }

    obs = (f"ROA validation: {valid_count}/{total} VALID, {invalid_count}/{total} INVALID, "
           f"{not_found_count}/{total} NOT_FOUND. ROV coverage: {rov_coverage_pct}%. "
           f"Risk level: {risk_level}. Source: {roa_source or 'unavailable'}.")
    logger.info(f"[roa_validation] {obs}")

    return {
        "success": True,
        "roa_source": roa_source,
        "validation_results": results,
        "summary": {
            "total": total,
            "valid_count": valid_count,
            "invalid_count": invalid_count,
            "not_found_count": not_found_count,
            "rov_coverage_pct": rov_coverage_pct,
            "risk_level": risk_level,
        },
        "invalid_events": invalid_events,
        "per_prefix_rov": per_prefix_rov,
        "observation": obs,
    }


# ── ROA data cache (5-minute TTL) ────────────────────────────────────────────
_roa_cache: dict = {"data": None, "fetched_at": None}


async def _fetch_cloudflare_roa():
    """
 Fetch ROA data from Cloudflare RPKI Validator API.
 Caches result for 5 minutes to avoid hammering the API.

 Uses ``asyncio.to_thread`` so the blocking ``requests.get`` does not
 freeze the event loop - running this synchronously inside an async
 function would stall every other concurrent tool/agent.
 """
    import requests
    import time

    now = time.time()
    if _roa_cache["data"] is not None and (now - _roa_cache["fetched_at"]) < 300:
        return _roa_cache["data"], "cloudflare_rpki_api (cached)"

    url = "https://rpki.cloudflare.com/rpki.json"

    def _do_request():
        return requests.get(url, timeout=20)

    try:
        resp = await asyncio.to_thread(_do_request)
    except Exception as e:
        logger.warning(f"_fetch_cloudflare_roa network error: {e}")
        return _roa_cache.get("data") or {}, "cloudflare_rpki_api (network error)"
    try:
        resp.raise_for_status()
    except Exception as e:
        logger.warning(f"_fetch_cloudflare_roa non-200: {e}")
        return _roa_cache.get("data") or {}, "cloudflare_rpki_api (non-200)"
    raw_roas = resp.json().get("roas", [])

    # Build lookup: prefix -> list of valid (origin_asn, max_length)
    roa_data: dict = {}
    for roa in raw_roas:
        prefix = roa.get("prefix", "")
        if not prefix:
            continue
        if prefix not in roa_data:
            roa_data[prefix] = []
        roa_data[prefix].append({
            "origin": str(roa.get("asn", "")),
            "max_length": roa.get("maxLength", 32),
        })

    _roa_cache["data"] = roa_data
    _roa_cache["fetched_at"] = now
    return roa_data, "cloudflare_rpki_api"


def _check_roa_single(roa_data, prefix, origin_asn):
    """
 Check if (prefix, origin_asn) is covered by a valid ROA.

 Returns: (status: str, roa_info: dict or None)
 - VALID: prefix has ROA and origin is in the valid list
 - INVALID: prefix has ROA but origin is NOT in the valid list
 - NOT_FOUND: no ROA for this prefix
 """
    if not roa_data or not prefix:
        return "NOT_FOUND", None

    # Exact prefix match first
    if prefix in roa_data:
        valid_origins = roa_data[prefix]
        matching_origin = next(
            (o for o in valid_origins if o["origin"] == str(origin_asn)), None
        )
        if matching_origin:
            return "VALID", {"valid_origins": valid_origins}
        else:
            return "INVALID", {"valid_origins": valid_origins, "declared_origin": str(origin_asn)}

    # Try less-specific prefix match (e.g., /24 -> /22)
    prefix_parts = prefix.split("/")
    if len(prefix_parts) == 2:
        base_ip, length = prefix_parts
        prefix_int = _ip_to_int(base_ip)
        for mask_len in range(int(length) - 1, 0, -1):
            parent_net = _int_to_ip(prefix_int & (0xFFFFFFFF << (32 - mask_len)))
            parent_prefix = f"{parent_net}/{mask_len}"
            if parent_prefix in roa_data:
                valid_origins = roa_data[parent_prefix]
                matching_origin = next(
                    (o for o in valid_origins if o["origin"] == str(origin_asn)), None
                )
                if matching_origin:
                    return "VALID", {"valid_origins": valid_origins, "matched_prefix": parent_prefix}
                else:
                    return "INVALID", {
                        "valid_origins": valid_origins,
                        "declared_origin": str(origin_asn),
                        "matched_prefix": parent_prefix,
                    }

    return "NOT_FOUND", None


def _ip_to_int(ip_str):
    parts = ip_str.split(".")
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])


def _int_to_ip(n):
    return f"{(n >> 24) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"


register_tool(
    name="validate_roa_status",
    description="Validate hijacked prefix+origin pairs against RPKI ROA (Route Origin Attestation) using Cloudflare RPKI API (5-min cache). Returns per-prefix status: VALID (covered by ROA, origin matches), INVALID (ROA exists but origin does NOT match — strong hijack evidence), NOT_FOUND (no ROA for this prefix), EXPIRED. Also computes ROV coverage percentage, risk level, and lists invalid events.",
    parameters=[
        ToolParameter("announcements", "List of {prefix, origin_asn, timestamp} to validate", "object"),
        ToolParameter("routing_result", "Output of analyze_routing (auto-extracts origin_hijacked)", "object", required=False),
        ToolParameter("start_time", "Analysis window start (ISO format)", "string", required=False),
        ToolParameter("end_time", "Analysis window end (ISO format)", "string", required=False),
    ],
    handler=_validate_roa_status,
)


# ══════════════════════════════════════════════════════════════════════════════
async def _lookup_as_threat_intel(tool_input, session):
    """
 Gather threat intelligence on attacker AS(es): BGP history, known hijack
 activity, AS relationship, and external threat signals.

 Sources queried (in priority order):
 1. BGPView.io (free): prefix list, announced origins, neighbors
 2. Circl.lu Passive DNS (passive DNS for AS contact domain)
 3. Manual ASN abuse contact lookup (via bgpview contacts endpoint)
 4. Historical hijack events from routing_result

 Required params:
 attacker_asn (str): the AS number to investigate
 Optional params:
 routing_result (dict): for extracting historical hijack evidence
 victim_asn (str): victim AS (for correlation)
 start_time (str): analysis window start
 """
    attacker_asn = str(tool_input.get("attacker_asn", ""))
    victim_asn = str(tool_input.get("victim_asn", ""))
    routing = tool_input.get("routing_result", {})
    start = tool_input.get("start_time", "")

    ev = getattr(session, "evidence", {}) or {}
    if not routing:
        raw = ev.get("analyze_routing", {})
        if isinstance(raw, dict):
            routing = raw.get("result", {}) or raw
    routing = routing.get("result", routing) if isinstance(routing, dict) else routing

    if not attacker_asn:
        return {"success": False, "error": "attacker_asn is required",
                "observation": "Cannot lookup threat intel without attacker AS number."}

    logger.info(f"[threat_intel] Gathering intel on AS{attacker_asn}")

    # ── Parallel API lookups ─────────────────────────────────────────────────
    bgpview_info, bgpview_prefixes, bgpview_neighbors, bgpview_contacts = \
        await asyncio.gather(
            _bgpview_as_info(attacker_asn),
            _bgpview_prefixes(attacker_asn),
            _bgpview_neighbors(attacker_asn),
            _bgpview_contacts(attacker_asn),
        )

    # ── Historical hijack evidence from routing data ─────────────────────────
    historical_events = _extract_historical_hijacks(routing, attacker_asn, victim_asn)

    # ── Risk scoring ─────────────────────────────────────────────────────────
    risk_score = _compute_attacker_risk_score(
        attacker_asn, bgpview_info, bgpview_prefixes,
        bgpview_neighbors, historical_events
    )

    # ── Threat assessment ────────────────────────────────────────────────────
    threat_level = "LOW"
    threat_signals = []
    if risk_score >= 60:
        threat_level = "CRITICAL"
        threat_signals.append("High historical hijack frequency or confirmed hijack activity")
    elif risk_score >= 40:
        threat_level = "HIGH"
        threat_signals.append("Multiple suspicious AS-paths or prefix announcements")
    elif risk_score >= 20:
        threat_level = "MEDIUM"
        threat_signals.append("Some anomalous behavior detected")
    else:
        threat_signals.append("No strong threat signals detected")

    if bgpview_info and bgpview_info.get("country_code") in ("IR", "RU", "CN", "KP", "CU"):
        threat_signals.append(f"AS operates in high-risk jurisdiction: {bgpview_info.get('country_code')}")
        threat_level = "HIGH" if threat_level == "LOW" else threat_level

    if bgpview_prefixes and bgpview_prefixes.get("is_allocated", False):
        # AS has very few allocated prefixes — possible transient/hijack AS
        if bgpview_prefixes.get("prefix_count", 999) < 3:
            threat_signals.append("AS has very few allocated prefixes — possible transient actor")
            threat_level = "HIGH" if threat_level == "MEDIUM" else threat_level

    obs = (f"Threat intel for AS{attacker_asn}: level={threat_level}, risk_score={risk_score}/100. "
           f"Historical hijack events: {len(historical_events)}. "
           f"BGPView data: {'found' if bgpview_info else 'not found'}.")
    logger.info(f"[threat_intel] {obs}")

    return {
        "success": True,
        "attacker_asn": attacker_asn,
        "victim_asn": victim_asn,
        "bgpview": {
            "info": bgpview_info,
            "prefixes": bgpview_prefixes,
            "neighbors": bgpview_neighbors,
            "contacts": bgpview_contacts,
        },
        "historical_hijack_evidence": historical_events,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "threat_signals": threat_signals,
        "observation": obs,
    }


async def _bgpview_as_info(asn_id):
    # Bug fix 2026-10-13: function parameter is `asn_id` but the body
    # referenced the undefined name `asn`.
    data = await _async_get_json(f"https://api.bgpview.io/asn/{asn_id}/info")
    if isinstance(data, dict) and data.get("status") == "ok":
        return data.get("data", {}) or {}
    return {}


async def _bgpview_prefixes(asn_id):
    # Bug fix 2026-10-13: function parameter is ``asn_id`` but body
    # referenced the undefined name ``asn``.
    data = await _async_get_json(f"https://api.bgpview.io/asn/{asn_id}/prefixes")
    if isinstance(data, dict) and data.get("status") == "ok":
        prefixes_data = data.get("data", {}) or {}
        return {
            "ipv4_prefixes": prefixes_data.get("ipv4_prefixes", []),
            "ipv6_prefixes": prefixes_data.get("ipv6_prefixes", []),
            "prefix_count": len(prefixes_data.get("ipv4_prefixes", [])) + len(prefixes_data.get("ipv6_prefixes", [])),
            "is_allocated": len(prefixes_data.get("ipv4_prefixes", [])) > 0,
        }
    return {}


async def _bgpview_neighbors(asn_id):
    # Bug fix 2026-10-13: see above.
    data = await _async_get_json(f"https://api.bgpview.io/asn/{asn_id}/neighbours")
    if isinstance(data, dict) and data.get("status") == "ok":
        neighbors = data.get("data", {}).get("neighbours", []) or []
        # Bug fix 2026-10-14: BGPView returns ``asn`` as either an int
        # (e.g. ``3356``) or a string (e.g. ``"2001:db8::1"``). Coerce
        # to string before substring check to avoid ``TypeError`` on int.
        def _asn_str(n):
            v = n.get("asn", "")
            return str(v) if v is not None else ""

        return {
            "ipv4_neighbors": [n for n in neighbors if ":" not in _asn_str(n)],
            "ipv6_neighbors": [n for n in neighbors if ":" in _asn_str(n)],
            "neighbor_count": len(neighbors),
        }
    return {}


async def _bgpview_contacts(asn_id):
    # Bug fix 2026-10-13: see above.
    data = await _async_get_json(f"https://api.bgpview.io/asn/{asn_id}/contacts")
    if isinstance(data, dict) and data.get("status") == "ok":
        return data.get("data", {}) or {}
    return {}


def _extract_historical_hijacks(routing: dict, attacker_asn: str,
                                victim_asn: str) -> list:
    """Extract historical hijack events for this attacker from routing result."""
    if not routing:
        return []

    events = []
    for key in ("origin_hijacking", "forge_hijacking", "origin_hijacked",
                "forge_hijacked", "victim_anomalies", "attacker_anomalies"):
        entries = routing.get(key, [])
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            oas = str(entry.get("origin_as", "") or entry.get("hijacker_as", ""))
            if oas == attacker_asn:
                events.append({
                    "type": key,
                    "timestamp": entry.get("timestamp", ""),
                    "prefix": entry.get("prefix", ""),
                    "victim_as": victim_asn,
                    "as_path": entry.get("as_path", "") or entry.get("as-path", ""),
                    "confidence": entry.get("confidence", "unknown"),
                })

    # Deduplicate by (timestamp, prefix)
    seen = set()
    deduped = []
    for e in events:
        key = (e["timestamp"], e["prefix"])
        if key not in seen:
            seen.add(key)
            deduped.append(e)
    return sorted(deduped, key=lambda x: x.get("timestamp", ""))[:20]


def _compute_attacker_risk_score(asn: str, bgpview_info: dict,
                                 bgpview_prefixes: dict,
                                 bgpview_neighbors: dict,
                                 historical_events: list) -> int:
    """
 Compute a 0-100 risk score for the attacker AS.

 Scoring:
 - Historical hijack events: +5 per event (max +30)
 - Short prefix list (< 5): +15 (possible transient AS)
 - Large number of neighbors (> 500): +10 (IXP/big tier-1)
 - Very few neighbors (< 3): +10 (small/transient AS)
 - Known in high-risk country: +15
 - AS age < 2 years (if available): +10
 - Multiple prefix hijacks: +10
 """
    score = 0

    # Historical hijack events
    hijack_count = len(historical_events)
    score += min(30, hijack_count * 5)

    # Prefix count signal
    prefix_count = bgpview_prefixes.get("prefix_count", 0) if bgpview_prefixes else 0
    if prefix_count == 0:
        score += 20  # no allocated prefixes — suspicious
    elif prefix_count < 3:
        score += 15
    elif prefix_count < 5:
        score += 8

    # Neighbor count signal
    neighbor_count = bgpview_neighbors.get("neighbor_count", 0) if bgpview_neighbors else 0
    if neighbor_count == 0:
        score += 10
    elif neighbor_count < 3:
        score += 10
    elif neighbor_count > 500:
        score += 5  # large AS, less suspicious

    # Country risk
    country = bgpview_info.get("country_code", "") if bgpview_info else ""
    if country in ("IR", "KP", "CU"):
        score += 20
    elif country in ("RU", "CN"):
        score += 10

    # Multiple prefix hijacks from same AS
    prefixes_hijacked = set(e["prefix"] for e in historical_events)
    if len(prefixes_hijacked) > 3:
        score += 15
    elif len(prefixes_hijacked) > 1:
        score += 8

    return min(100, score)


register_tool(
    name="lookup_as_threat_intel",
    description="Gather threat intelligence on an attacker AS: BGPView.io AS info/prefixes/neighbors/contacts, historical hijack evidence from routing data, and risk scoring (0-100). Returns: bgpview data, historical hijack events, risk_score, threat_level (LOW/MEDIUM/HIGH/CRITICAL), threat_signals. Use this to assess how credible and dangerous the attacker AS is.",
    parameters=[
        ToolParameter("attacker_asn", "AS number of the hijacker", "string"),
        ToolParameter("victim_asn", "Victim AS number (optional)", "string", required=False),
        ToolParameter("routing_result", "Output of analyze_routing (for historical hijack evidence)", "object", required=False),
        ToolParameter("start_time", "Analysis window start (ISO format)", "string", required=False),
    ],
    handler=_lookup_as_threat_intel,
)


register_tool(
    name="generate_report",
    description="Generate the final LLM-driven HTML analysis report and save it to disk. Returns the file path.",
    parameters=[
        ToolParameter("asn", "AS number", "string"),
        ToolParameter("start_time", "Analysis window start", "string"),
        ToolParameter("end_time", "Analysis window end", "string"),
        ToolParameter("traffic_result", "Output of analyze_traffic", "object"),
        ToolParameter("routing_result", "Output of analyze_routing", "object"),
        ToolParameter("classification", "Output of reason_and_classify", "object", required=False),
        ToolParameter("asn_info", "Output of query_as_info", "object", required=False),
    ],
    handler=_generate_report,
)
