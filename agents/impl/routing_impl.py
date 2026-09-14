"""
Routing Agent Implementation
Core logic extracted from original routing_agent.py.
"""

import os
import sys
import json
import gc
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from detectors.hijack.hijack_detector import detect_hijacks
from detectors.leak.leak_detector import analyze_leak_surface
from utils.logger import logger
from utils.helpers import extract_json_object as _extract_json_object
from llm.llm_factory import setup_llm_settings, DEFAULT_TEMP_REASONING
from config import BASE_URL, API_KEY, MODEL, MAX_WORKERS, IO_BUSY_THRESHOLD


def get_outage_detector():
    from detectors.outage.outage_detector import RouteOutageDetector
    return RouteOutageDetector()


class LLMEnhancedRoutingAgent:
    def __init__(self, model, api_key, base_url):
        self.model = model; self.api_key = api_key; self.base_url = base_url; self.llm = None

    async def setup_llm(self):
        self.llm, _ = setup_llm_settings(model=self.model, api_key=self.api_key, base_url=self.base_url,
                                          temperature=DEFAULT_TEMP_REASONING, timeout=300.0, max_retries=2)

    async def analyze_routing_with_llm(self, routing_results, asn, start_time, end_time):
        await self.setup_llm()
        data = {
            "asn": asn,
            "time_period": f"{start_time} to {end_time}",
            # AS834 was a VICTIM: its legitimately-owned prefixes were announced by others
            "victim_events": {
                "origin_hijacked": routing_results.get("origin_hijacked", []),
                "forge_hijacked":  routing_results.get("forge_hijacked",  []),
            },
            # AS834 was an ATTACKER: it announced prefixes belonging to other ASes
            "attacker_events": {
                "origin_hijacking": routing_results.get("origin_hijacking", []),
                "forge_hijacking":  routing_results.get("forge_hijacking",  []),
            },
            # Summary counts
            "summary": {
                "victim_of_origin_hijack_count":  len(routing_results.get("origin_hijacked", [])),
                "victim_of_forge_hijack_count":   len(routing_results.get("forge_hijacked",  [])),
                "origin_hijacking_count":          len(routing_results.get("origin_hijacking", [])),
                "forge_hijacking_count":           len(routing_results.get("forge_hijacking",  [])),
                "mitm_alerts":                    len(routing_results.get("mitm_alerts", [])),
                "route_leak_count":               routing_results.get("leak_count", 0),
                "outage_score":                   routing_results.get("outage_score", 0),
            }
        }
        insights = await self._generate_llm_insights(data)
        return {**routing_results, "llm_enhanced": True, "llm_insights": insights,
                "analysis_timestamp": datetime.now().isoformat()}

    async def _generate_llm_insights(self, data):
        victim = data["victim_events"]
        attacker = data["attacker_events"]
        s = data["summary"]
        # Truncate long lists for the prompt
        def _cap(lst, n=5):
            return lst[:n] if len(lst) > n else lst

        prompt = f"""You are a BGP routing security expert. Analyze detection results for AS{data['asn']}
during the period {data['time_period']}.

IMPORTANT — Two distinct roles must always be distinguished:
  1. "VICTIM" — AS{data['asn']} was the TARGET of the attack (attackers announced AS{data['asn']}'s legitimately-owned prefixes)
  2. "ATTACKER" — AS{data['asn']} was the PERPETRATOR (AS{data['asn']} itself announced prefixes belonging to other ASes)

=== ROLE SUMMARY ===
  - AS{data['asn']} is a VICTIM of {s['victim_of_origin_hijack_count']} origin-hijack event(s) and {s['victim_of_forge_hijack_count']} forge-hijack event(s)
  - AS{data['asn']} is an ATTACKER in {s['origin_hijacking_count']} origin-hijack event(s) and {s['forge_hijacking_count']} forge-hijack event(s)
  - MITM alerts: {s['mitm_alerts']}
  - Route leaks: {s['route_leak_count']}
  - Outage score: {s['outage_score']}

=== VICTIM ALERTS (AS{data['asn']}'s prefixes were hijacked) ===
Origin hijacked (top {min(5, s['victim_of_origin_hijack_count'])} examples):
{json.dumps(_cap(victim['origin_hijacked']), indent=2, ensure_ascii=False)}

Forge hijacked / MITM (top {min(5, s['victim_of_forge_hijack_count'])} examples):
{json.dumps(_cap(victim['forge_hijacked']), indent=2, ensure_ascii=False)}

=== ATTACKER ALERTS (AS{data['asn']} hijacked others' prefixes) ===
Origin hijacking (AS{data['asn']} announced prefixes it does not own):
{json.dumps(_cap(attacker['origin_hijacking']), indent=2, ensure_ascii=False)}

Forge hijacking / MITM (AS{data['asn']} performed path manipulation):
{json.dumps(_cap(attacker['forge_hijacking']), indent=2, ensure_ascii=False)}

Return JSON with these exact keys (use English only):
- role_analysis: string describing AS{data['asn']}'s role (victim, attacker, both, or none)
- victim_of_hijack: bool — True if AS{data['asn']} was a victim
- attacker_of_hijack: bool — True if AS{data['asn']} was an attacker
- attack_pattern_analysis: string — description of the attack pattern
- victim_impact: string — impact on AS{data['asn']} when it was a victim
- attacker_behavior: string — description of AS{data['asn']}'s malicious behavior when it was an attacker
- victim_attribution: list — victim prefixes and their legitimate owners (if AS{data['asn']} was a victim)
- attacker_attribution: list — victim prefixes and victim ASes (if AS{data['asn']} was an attacker)
- correlation_with_traffic: string — how routing anomalies relate to any traffic anomalies
- mitigation_recommendations: list of strings
- risk_assessment: string
- confidence_level: float between 0.0 and 1.0
- key_findings: list of important findings
"""
        try:
            resp = self.llm.complete(prompt)
            raw = resp.text if hasattr(resp, "text") else str(resp)
            try:
                return json.loads(raw)
            except Exception:
                # Brace-balanced extraction (handles nested {} in string values)
                snippet = _extract_json_object(raw)
                if snippet is not None:
                    return json.loads(snippet)
        except Exception as e:
            logger.error(f"LLM routing analysis failed: {e}")
        return {"error": "LLM unavailable"}


async def run_routing_agent_async(asn, start_time, end_time, use_llm=True,
                                  periodicity=None, periodicity_confidence=0.0, enable_mitm=True,
                                  skip_leak=False, skip_forge=None, skip_outage=False,
                                  skip_hijack_streaming=False):
    """Run the routing agent.

    Args:
        skip_forge: if True, force-skip forge detection regardless of enable_mitm.
                    If None (default), use ``not enable_mitm`` for backward compatibility.
        skip_outage: if True, skip the slow 24h-baseline outage detector. Default False
                     (kept for backward compat with one-phase legacy mode).
        skip_hijack_streaming: if True, skip the chunked streaming hijack detector.
                    Caller is responsible for filling origin_hijacked / origin_hijacking
                    in the result (e.g. the Phase-1 quick path uses a single-pass
                    vectorized detector instead).
    """
    if skip_forge is None:
        skip_forge = not enable_mitm

    # NOTE (2026-09-14, reverting BUG-R134 fallback):
    # ``start_time`` / ``end_time`` must always be supplied by the caller
    # (UI / CLI / chief_agent / reasoning_agent). An empty string here
    # means a bug upstream — the UI never lets users submit an empty
    # window. Swallowing the bug behind a silent 24-hour fallback would
    # hide real defects and produce misleading "no anomaly" reports.
    # If the parser cannot resolve the window, fail loudly with a
    # structured error dict (see BUG-R110 below).

    try:
        # Bug fix 2026-09-13 (BUG-R110): the previous implementation tried
        # to parse ``start_time`` and ``end_time`` *together* in a single
        # loop: each iteration attempted ``datetime.strptime(start_time, fmt)``
        # AND ``datetime.strptime(end_time, fmt)``, breaking on the first
        # iteration where BOTH succeeded. When the caller supplied
        # differently-formatted strings (e.g. ``"2024-01-15 00:00"`` and
        # ``"2024-01-15T00:30:00Z"``), no single format matched both and the
        # code fell through to ``datetime.fromisoformat(...)``. ``fromisoformat``
        # only handles ISO 8601 strings, so a plain date like ``"2024-01-15"``
        # produced a ``datetime.date`` (not ``datetime.datetime``), and an
        # empty string raised ``ValueError`` that propagated as a 500-style
        # error in callers that already did ``if start is None: start = ""``
        # (see ``tools/tool_implementations._analyze_routing``).
        #
        # Parse each timestamp independently with a shared helper that
        # tries the same format list, then falls back to ``fromisoformat``,
        # then to a last-ditch ``datetime.combine(date, time.min)`` for
        # plain dates.
        def _parse_ts(value, label):
            if value is None:
                return None
            if isinstance(value, datetime):
                return value
            if not isinstance(value, str):
                return None
            s = value.strip()
            if not s:
                return None
            for fmt in (
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S%z",
            ):
                try:
                    return datetime.strptime(s.replace("Z", "+0000") if s.endswith("Z") else s, fmt)
                except ValueError:
                    continue
            # ISO 8601 fallback (handles "2024-01-15T00:30:00+00:00" and similar)
            try:
                return datetime.fromisoformat(s.replace("Z", "+00:00"))
            except ValueError:
                pass
            # Last resort: plain date "YYYY-MM-DD" → midnight
            try:
                d = datetime.strptime(s, "%Y-%m-%d")
                return datetime.combine(d.date(), datetime.min.time())
            except ValueError:
                logger.warning(
                    f"[routing_impl] could not parse {label}={value!r}; "
                    f"returning None and relying on caller-provided defaults."
                )
                return None

        start_dt = _parse_ts(start_time, "start_time")
        end_dt = _parse_ts(end_time, "end_time")
        if start_dt is None or end_dt is None:
            logger.warning(
                f"[routing_impl] routing analysis aborted — "
                f"start_dt={start_dt}, end_dt={end_dt}, "
                f"raw start_time={start_time!r}, end_time={end_time!r}"
            )
            return {
                "success": False,
                "error": (
                    f"Cannot parse time window: start_time={start_time!r}, "
                    f"end_time={end_time!r}"
                ),
                "origin_hijacked": [],
                "origin_hijacking": [],
                "forge_hijacked": [],
                "forge_hijacking": [],
                "route_leaks": [],
                "mitm_alerts": [],
            }

        logger.info(f"Routing analysis AS{asn}: {start_time}→{end_time} (MITM={enable_mitm}, skip_forge={skip_forge})")

        if skip_hijack_streaming:
            hijack_results = {
                "success": True,
                "error": None,
                "origin_hijacked": [],
                "forge_hijacked": [],
                "origin_hijacking": [],
                "forge_hijacking": [],
                "mitm_alerts": [],
                "as_rel_file": None,
                "prefix2as_file": None,
                "asorg_file": None,
                "skipped": True,
                "reason": "light_mode_single_pass",
            }
            logger.info("Hijack streaming skipped (light mode single-pass)")
        else:
            hijack_results = detect_hijacks(start_dt, end_dt, asn, validate_with_updates=False,
                                           skip_forge_detection=skip_forge)
            if not hijack_results.get("success"):
                logger.warning(
                    f"Hijack detection failed for AS{asn}: {hijack_results.get('error', 'unknown')}. "
                    f"Proceeding with leak/outage detection."
                )
                hijack_results = {
                    "success": False,
                    "error": hijack_results.get("error"),
                    "origin_hijacked": [],
                    "forge_hijacked": [],
                    "origin_hijacking": [],
                    "forge_hijacking": [],
                    "mitm_alerts": [],
                    "as_rel_file": None,
                    "prefix2as_file": None,
                    "asorg_file": None,
                }

        if skip_leak:
            leak_result = {"success": True, "route_leaks": [], "leak_count": 0, "skipped": True, "reason": "light_mode"}
            logger.info("Leak detection skipped in light mode")
        else:
            # Use default threshold from config (DEFAULT_LEAK_THRESHOLD = 0.4)
            leak_result = analyze_leak_surface(asn, start_time, end_time)

        if skip_outage:
            outage_result = {
                "success": True,
                "is_outage_suspected": False,
                "outage_score": 0.0,
                "skipped": True,
                "reason": "light_mode",
            }
            logger.info("Outage detection skipped in light mode")
        else:
            try:
                outage_detector = get_outage_detector()
                outage_result = outage_detector.analyze(asn, start_time, end_time,
                                                       periodicity=periodicity, periodicity_confidence=periodicity_confidence)
            except Exception as e:
                logger.error(f"Outage detector error: {e}")
                outage_result = {"success": False, "is_outage_suspected": False, "outage_score": 0.0, "error": str(e)}

        if not isinstance(outage_result, dict):
            outage_result = {"success": False, "is_outage_suspected": False, "outage_score": 0.0}

        _outage_score = float(outage_result.get("outage_score") or 0.0) if outage_result.get("success") else 0.0
        if leak_result is None:
            leak_result = {"success": False, "route_leaks": [], "leak_count": 0}

        _origin_h = hijack_results.get("origin_hijacked", [])
        _forge_h = hijack_results.get("forge_hijacked", [])

        combined = {
            "success": True, "asn": asn,
            "analysis_period": f"{start_time} to {end_time}",
            "analysis_timestamp": datetime.now().isoformat(),
            "origin_hijacked": _origin_h,
            "forge_hijacked": _forge_h,
            "origin_hijacking": hijack_results.get("origin_hijacking", []),
            "forge_hijacking": hijack_results.get("forge_hijacking", []),
            "mitm_alerts": hijack_results.get("mitm_alerts", []),
            "leak_analysis": leak_result if isinstance(leak_result, dict) else {},
            "route_leaks": leak_result.get("route_leaks", []) if isinstance(leak_result, dict) else [],
            "leak_count": leak_result.get("leak_count", 0) if isinstance(leak_result, dict) else 0,
            "outage_analysis": outage_result,
            "as_rel_file": hijack_results.get("as_rel_file"),
            "prefix2as_file": hijack_results.get("prefix2as_file"),
            "asorg_file": hijack_results.get("asorg_file"),
            "total_prefix_hijacks": len(_origin_h) + len(_forge_h),
            "outage_suspected": bool(outage_result.get("is_outage_suspected", False)),
            "outage_score": _outage_score,
        }

        if use_llm:
            llm_agent = LLMEnhancedRoutingAgent(model=MODEL, api_key=API_KEY, base_url=BASE_URL)
            combined = await llm_agent.analyze_routing_with_llm(combined, asn, start_time, end_time)

        return combined
    except Exception as e:
        logger.error(f"Routing agent error: {e}")
        return {"success": False, "error": str(e), "asn": asn}
