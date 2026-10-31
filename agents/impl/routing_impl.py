"""
Routing Agent Implementation
Core logic extracted from original routing_agent.py.
"""

import os
import sys
import json
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from detectors.hijack.hijack_detector import detect_hijacks
from detectors.leak.leak_detector import analyze_leak_surface
from utils.logger import logger
from utils.helpers import extract_json_object as _extract_json_object
from llm.llm_factory import setup_llm_settings, DEFAULT_TEMP_REASONING
from config import BASE_URL, API_KEY, MODEL


def get_outage_detector():
    from detectors.outage.outage_detector import RouteOutageDetector
    return RouteOutageDetector()


def outage_baseline_start(start_dt, end_dt, periodicity):
    """The start of the baseline the outage detector needs.

    The outage detector compares the event window against a baseline that
    starts before the event, so the shared scan has to read that far
    back.  The detector's own baseline-period logic is the reference; a
    periodic event reaches further back than a single one.
    """
    try:
        detector = get_outage_detector()
        periods = detector.get_baseline_periods(start_dt, end_dt, periodicity)
        if periods:
            return min(p["start"] for p in periods)
    except (AttributeError, TypeError, ValueError) as exc:
        logger.debug(f"[routing_impl] could not derive the baseline start: {exc!r}")
    try:
        return start_dt - timedelta(hours=get_outage_detector().baseline_hours)
    except (AttributeError, TypeError):
        return start_dt


def hijack_from_shared(shared, asn, start_dt, end_dt, skip_forge):
    """Shape the shared scan's hijack output like the detector's own."""
    result = (shared or {}).get("hijack")
    if not result:
        return {
            "success": False,
            "error": "hijack detection produced no result",
            "origin_hijacked": [],
            "forge_hijacked": [],
            "origin_hijacking": [],
            "forge_hijacking": [],
            "mitm_alerts": [],
            "as_rel_file": None,
            "prefix2as_file": None,
            "asorg_file": None,
        }

    entry = result.get(str(asn)) or {}
    return {
        "success": True,
        "error": None,
        "origin_hijacked": entry.get("origin_hijacked", []),
        "forge_hijacked": entry.get("forge_hijack", []),
        "origin_hijacking": entry.get("origin_hijacking", []),
        "forge_hijacking": entry.get("forge_hijacking", []),
        "mitm_alerts": [],
        "as_rel_file": None,
        "prefix2as_file": None,
        "asorg_file": None,
    }


def leak_from_shared(shared, asn, start_time, end_time):
    """Shape the shared scan's leak output like the detector's own."""
    result = (shared or {}).get("leak")
    if result is None:
        # The shared scan could not run the leak detector at all (no
        # PathProb table, say).  Fall back to the standalone detector so
        # the event still gets a leak answer.
        try:
            return analyze_leak_surface(asn, start_time, end_time, target_asns=[str(asn)])
        except TypeError:
            return analyze_leak_surface(asn, start_time, end_time)
        except (AttributeError) as exc:
            logger.error(f"Leak detector error: {exc}")
            return {"success": False, "route_leaks": [], "leak_count": 0}

    out = dict(result)
    out.setdefault("success", True)
    out.setdefault("asn", str(asn))
    out.setdefault("analysis_period", f"{start_time} to {end_time}")
    out.setdefault("data_available", True)
    out.setdefault("no_data_reason", "")
    out.setdefault("anomalies_detected", bool(result.get("total_detected", 0)))
    out.setdefault("anomaly_count", result.get("total_detected", 0))
    out.setdefault("data_source", "shared_scan")
    return out


class LLMEnhancedRoutingAgent:
    def __init__(self, model, api_key, base_url):
        self.model = model; self.api_key = api_key; self.base_url = base_url; self.llm = None

    async def setup_llm(self):
        self.llm, _ = setup_llm_settings(model=self.model, api_key=self.api_key, base_url=self.base_url,
                                          temperature=DEFAULT_TEMP_REASONING, timeout=600.0, max_retries=2)

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
                # True count + truncation state, so the prompt and the rendered
                # report never present max_leaks as if it were the measurement.
                "route_leak_count_total":         routing_results.get("leak_count_total",
                                                                       routing_results.get("leak_count", 0)),
                "route_leak_results_truncated":   bool(routing_results.get("leak_results_truncated", False)),
                "route_leak_truncation_limit":    routing_results.get("leak_truncation_limit"),
                "route_leak_analysis_skipped":    bool(routing_results.get("leak_analysis_skipped", False)),
                "outage_score":                   routing_results.get("outage_score", 0),
            }
        }
        insights = await self.generate_llm_insights(data)
        return {**routing_results, "llm_enhanced": True, "llm_insights": insights,
                "analysis_timestamp": datetime.now().isoformat()}

    async def generate_llm_insights(self, data):
        victim = data["victim_events"]
        attacker = data["attacker_events"]
        s = data["summary"]
        # Truncate long lists for the prompt
        def cap(lst, n=5):
            return lst[:n] if len(lst) > n else lst

        def safe_json(obj, **kwargs):
            from dataclasses import asdict, is_dataclass
            return json.dumps(obj, default=lambda o: asdict(o) if is_dataclass(o) else str(o), **kwargs)

        prompt = f"""You are a BGP routing security expert. Analyze detection results for AS{data['asn']}
during the period {data['time_period']}.

IMPORTANT — Two distinct roles must always be distinguished:
  1. "VICTIM" — AS{data['asn']} was the TARGET of the attack (attackers announced AS{data['asn']}'s legitimately-owned prefixes)
  2. "ATTACKER" — AS{data['asn']} was the PERPETRATOR (AS{data['asn']} itself announced prefixes belonging to other ASes)

=== ROLE SUMMARY ===
  - AS{data['asn']} is a VICTIM of {s['victim_of_origin_hijack_count']} origin-hijack event(s) and {s['victim_of_forge_hijack_count']} forge-hijack event(s)
  - AS{data['asn']} is an ATTACKER in {s['origin_hijacking_count']} origin-hijack event(s) and {s['forge_hijacking_count']} forge-hijack event(s)
  - MITM alerts: {s['mitm_alerts']}
  - Route leaks: {s['route_leak_count']}{" (SKIPPED — leak detection did not run; this is NOT a measurement and no route-leak conclusion may be drawn)" if s.get('route_leak_analysis_skipped') else ""}{" (TRUNCATED: at least " + str(s['route_leak_count_total']) + " actually detected; results were capped at the detector limit of " + str(s['route_leak_truncation_limit']) + ", so the per-event list below is NOT exhaustive)" if s.get('route_leak_results_truncated') else ""}
  - Outage score: {s['outage_score']}

=== VICTIM ALERTS (AS{data['asn']}'s prefixes were hijacked) ===
Origin hijacked (top {min(5, s['victim_of_origin_hijack_count'])} examples):
{safe_json(cap(victim['origin_hijacked']), indent=2, ensure_ascii=False)}

Forge hijacked / MITM (top {min(5, s['victim_of_forge_hijack_count'])} examples):
{safe_json(cap(victim['forge_hijacked']), indent=2, ensure_ascii=False)}

=== ATTACKER ALERTS (AS{data['asn']} hijacked others' prefixes) ===
Origin hijacking (AS{data['asn']} announced prefixes it does not own):
{safe_json(cap(attacker['origin_hijacking']), indent=2, ensure_ascii=False)}

Forge hijacking / MITM (AS{data['asn']} performed path manipulation):
{safe_json(cap(attacker['forge_hijacking']), indent=2, ensure_ascii=False)}

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
        except (AttributeError) as e:
            logger.error(f"LLM routing analysis failed: {e}")
        return {"error": "LLM unavailable"}


async def run_routing_agent_async(asn, start_time, end_time, use_llm=True,
                                  periodicity=None, periodicity_confidence=0.0, enable_mitm=True,
                                  skip_leak=False, skip_forge=None, skip_outage=False,
                                  skip_hijack_streaming=False):
    """Run the routing agent."""
    if skip_forge is None:
        skip_forge = not enable_mitm

    # NOTE (2026-09-14, reverting BUG-R134 fallback):
    try:
        def parse_ts(value, label):
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

        start_dt = parse_ts(start_time, "start_time")
        end_dt = parse_ts(end_time, "end_time")
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

        # ── One read, three detectors ──────────────────────────────────
        # The hijack detector, the leak detector and the outage detector
        # used to open the update stream each on their own, so an event
        # read the same window three times.  A shared scan reads it once
        # and dispatches every chunk.
        #
        # The outage detector needs a baseline that may start a day
        # earlier, so the scan reads the union of the windows and routes
        # the baseline chunks to the outage detector alone.
        requested = []
        if not skip_hijack_streaming:
            requested.append("hijack")
        if not skip_leak:
            requested.append("leak")
        if not skip_outage:
            requested.append("outage")

        baseline_start = None
        if "outage" in requested:
            baseline_start = outage_baseline_start(start_dt, end_dt, periodicity)

        shared = {}
        if requested:
            from detectors.shared_scan import SharedUpdateScan

            scan = SharedUpdateScan(
                start=start_dt,
                end=end_dt,
                target_asns=[str(asn)],
                detectors=requested,
                baseline_start=baseline_start,
            )
            shared = scan.run() or {}

        if skip_hijack_streaming:
            # Same placeholder problem as the leak/outage branches: an empty
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
                "data_available": False,
                "skipped": True,
                "reason": "light_mode_single_pass",
                "no_data_reason": "hijack streaming skipped in light mode",
            }
            logger.info("Hijack streaming skipped (light mode single-pass)")
        else:
            hijack_results = hijack_from_shared(shared, asn, start_dt, end_dt, skip_forge)
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
            # BUG (2026-10-05): this placeholder reported `success: True` with
            leak_result = {
                "success": True,
                "route_leaks": [],
                "leak_count": None,
                "leak_count_total": None,
                "truncated": False,
                "data_available": False,
                "skipped": True,
                "reason": "light_mode",
                "no_data_reason": "leak detection skipped in light mode",
            }
            logger.info("Leak detection skipped in light mode")
        else:
            leak_result = leak_from_shared(shared, asn, start_time, end_time)

        if skip_outage:
            # Same placeholder problem as the leak branch above: a skipped
            # detector must not look like a measured 0.0 score.
            outage_result = {
                "success": True,
                "is_outage_suspected": None,
                "outage_score": None,
                "data_available": False,
                "skipped": True,
                "reason": "light_mode",
                "no_data_reason": "outage detection skipped in light mode",
            }
            logger.info("Outage detection skipped in light mode")
        else:
            try:
                outage_detector = get_outage_detector()
                outage_result = outage_detector.analyze(
                    asn, start_time, end_time,
                    periodicity=periodicity,
                    periodicity_confidence=periodicity_confidence,
                    timeseries=(shared.get("outage") or {}).get(str(asn)),
                )
            except (AttributeError) as e:
                logger.error(f"Outage detector error: {e}")
                outage_result = {"success": False, "is_outage_suspected": False, "outage_score": 0.0, "error": str(e)}

        if not isinstance(outage_result, dict):
            outage_result = {"success": False, "is_outage_suspected": False, "outage_score": 0.0}

        _outage_score = float(outage_result.get("outage_score") or 0.0) if outage_result.get("success") else 0.0
        if leak_result is None:
            leak_result = {"success": False, "route_leaks": [], "leak_count": 0}

        _origin_h = hijack_results.get("origin_hijacked", [])
        _forge_h = hijack_results.get("forge_hijacked", [])

        # `leak_count` is the length of the returned list, which the detector
        _leak_skipped = bool(leak_result.get("skipped")) if isinstance(leak_result, dict) else False
        _leak_count = leak_result.get("leak_count") if isinstance(leak_result, dict) else 0
        _leak_count = 0 if _leak_count is None else int(_leak_count)
        _leak_total = leak_result.get("total_detected") if isinstance(leak_result, dict) else None
        if _leak_total is None:
            _leak_total = _leak_count

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
            "leak_count": _leak_count,
            "leak_count_total": _leak_total,
            "leak_origin_announcements": leak_result.get("leak_origin_announcements") if isinstance(leak_result, dict) else None,
            "leak_results_truncated": bool(leak_result.get("truncated", False)) if isinstance(leak_result, dict) else False,
            "leak_truncation_limit": leak_result.get("truncation_limit") if isinstance(leak_result, dict) else None,
            "leak_analysis_skipped": _leak_skipped,
            "outage_analysis": outage_result,
            "outage_analysis_skipped": bool(outage_result.get("skipped")) if isinstance(outage_result, dict) else False,
            "as_rel_file": hijack_results.get("as_rel_file"),
            "prefix2as_file": hijack_results.get("prefix2as_file"),
            "asorg_file": hijack_results.get("asorg_file"),
            "total_prefix_hijacks": len(_origin_h) + len(_forge_h),
            "hijack_analysis_skipped": bool(hijack_results.get("skipped")) if isinstance(hijack_results, dict) else False,
            "outage_suspected": bool(outage_result.get("is_outage_suspected", False)),
            "outage_score": _outage_score,
        }

        if use_llm:
            llm_agent = LLMEnhancedRoutingAgent(model=MODEL, api_key=API_KEY, base_url=BASE_URL)
            combined = await llm_agent.analyze_routing_with_llm(combined, asn, start_time, end_time)

        return combined
    except (AttributeError) as e:
        logger.error(f"Routing agent error: {e}")
        return {"success": False, "error": str(e), "asn": asn}