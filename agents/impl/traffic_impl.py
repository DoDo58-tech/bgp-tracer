"""
Traffic Agent Implementation
Core logic extracted from original traffic_agent.py to avoid circular imports.
"""

import os
import re
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from detectors.traffic.traffic_detector import CloudflareRadarAPI
from utils.logger import logger
from utils.helpers import extract_json_object as _extract_json_object
from llm.llm_factory import setup_llm_settings, DEFAULT_TEMP_REASONING
from config import BASE_URL, API_KEY, MODEL


class LLMEnhancedTrafficAgent:
    def __init__(self, model=MODEL, api_key=API_KEY, base_url=BASE_URL):
        self.model = model
        self.api_key = api_key
        self.base_url = base_url
        self.llm = None
        self.cloudflare_api = CloudflareRadarAPI()

    async def setup_llm(self):
        self.llm, _ = setup_llm_settings(
            model=self.model, api_key=self.api_key, base_url=self.base_url,
            temperature=DEFAULT_TEMP_REASONING, timeout=300.0, max_retries=2,
        )

    async def analyze_traffic_with_llm(self, asn, start_time, end_time, routing_analysis=None,
                                       original_start_time=None, original_end_time=None):
        await self.setup_llm()
        traffic_result = self.cloudflare_api.detect_anomalies(
            asn=asn, start_time=start_time, end_time=end_time, plot_result=True,
            event_start_time=original_start_time, event_end_time=original_end_time,
        )
        if not traffic_result.get("success"):
            return traffic_result

        analysis_data = {
            "asn": asn, "time_period": f"{start_time} to {end_time}",
            "traffic_metrics": {
                "anomaly_count": traffic_result.get("anomaly_count", 0),
                "data_points": traffic_result.get("data_points", 0),
                "percent_change": traffic_result.get("percent_change", 0),
                "current_avg": traffic_result.get("current_avg", 0),
                "historical_avg": traffic_result.get("historical_avg", 0),
            },
            "anomalies": traffic_result.get("anomalies", []),
            "routing_context": routing_analysis or {},
        }

        llm_insights = await self._generate_llm_insights(analysis_data)
        return {
            **traffic_result,
            "llm_enhanced": True,
            "llm_insights": llm_insights,
            "analysis_timestamp": datetime.now().isoformat(),
        }

    async def analyze_traffic_no_llm(self, asn, start_time, end_time,
                                     original_start_time=None, original_end_time=None):
        """Phase-1 light version: skip LLM insights, just return CloudflareRadar facts.

        Same anomaly detection + plot as analyze_traffic_with_llm, but without
        the ~10s LLM round-trip. Used by the two-phase diagnosis quick phase
        to keep wall time under 60 s.
        """
        traffic_result = self.cloudflare_api.detect_anomalies(
            asn=asn, start_time=start_time, end_time=end_time, plot_result=True,
            event_start_time=original_start_time, event_end_time=original_end_time,
        )
        if not traffic_result.get("success"):
            return traffic_result
        return {
            **traffic_result,
            "llm_enhanced": False,
            "llm_insights": None,
            "analysis_timestamp": datetime.now().isoformat(),
        }

    async def _generate_llm_insights(self, analysis_data):
        routing_context = (
            json.dumps(analysis_data.get("routing_context", {}), indent=2, ensure_ascii=False)
            if analysis_data.get("routing_context") else "No routing analysis data"
        )

        # Pre-compute role summary
        rc = analysis_data.get("routing_context") or {}
        victim_origin  = len(rc.get("origin_hijacked",  []) or [])
        victim_forge   = len(rc.get("forge_hijacked",   []) or [])
        atk_origin    = len(rc.get("origin_hijacking", []) or [])
        atk_forge     = len(rc.get("forge_hijacking",  []) or [])
        is_victim   = (victim_origin + victim_forge) > 0
        is_attacker = (atk_origin + atk_forge) > 0
        if is_attacker and not is_victim:
            role_note = (
                f"WARNING: The target AS (AS{analysis_data['asn']}) is an ATTACKER. "
                f"It announced prefixes belonging to other ASes (origin_hijacking={atk_origin}). "
                f"Traffic anomalies on this AS are NOT caused by the hijacking it performed. "
                f"Do NOT attribute this AS's traffic anomalies to routing anomalies."
            )
        elif is_victim and not is_attacker:
            role_note = (
                f"INFO: The target AS (AS{analysis_data['asn']}) is a VICTIM of hijacking. "
                f"It was targeted by origin_hijacked={victim_origin} event(s). "
                f"Traffic anomalies on this AS are CONSISTENT with being a victim."
            )
        elif is_victim and is_attacker:
            role_note = (
                f"INFO: The target AS (AS{analysis_data['asn']}) shows both victim and attacker behavior. "
                f"Review traffic anomalies carefully — some may be caused by being a victim, others may be unrelated."
            )
        else:
            role_note = "No hijacking events detected for the target AS."

        prompt = f"""You are a network traffic analysis expert. Review AS traffic data and provide professional insights.

AS: {analysis_data['asn']} | Period: {analysis_data['time_period']}
Anomaly count: {analysis_data['traffic_metrics']['anomaly_count']}
Traffic change: {analysis_data['traffic_metrics']['percent_change']:.2f}%
Top anomalies: {json.dumps(analysis_data['anomalies'][:5], indent=2, ensure_ascii=False)}

=== Role Determination ===
{role_note}

=== Routing Context (for reference) ===
{routing_context}

Return JSON with: traffic_pattern_analysis, root_cause_analysis (IMPORTANT: respect the role determination above),
impact_assessment, recommendations (IMPORTANT: if target AS is an ATTACKER, recommendations should address
investigating the AS itself, not attributing the traffic anomaly to routing issues),
risk_assessment, confidence_level (0-1), key_findings (list).
Use English only.
"""
        try:
            response = self.llm.complete(prompt)
            raw = response.text if hasattr(response, "text") else str(response)
            try:
                return json.loads(raw)
            except Exception:
                # Brace-balanced extraction (handles nested {} in string values)
                snippet = _extract_json_object(raw)
                if snippet is not None:
                    return json.loads(snippet)
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
        return {"error": "LLM analysis unavailable"}


def lookup_as_by_country(country_name, asorg_file=None):
    try:
        if not asorg_file or not Path(asorg_file).exists():
            return []
        with open(asorg_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        asn_to_org_id = data.get("asn_to_org_id", {})
        asn_to_name = data.get("asn_to_name", {})
        org_id_to_info = data.get("org_id_to_info", {})
        cl = country_name.lower()
        results = []
        for asn, org_id in asn_to_org_id.items():
            info = org_id_to_info.get(org_id, {})
            if cl in info.get("country", "").lower() or cl in info.get("name", "").lower():
                results.append({"asn": asn, "as_name": asn_to_name.get(asn, "Unknown"),
                                "org_name": info.get("name", "Unknown"), "country": info.get("country", "Unknown")})
        return results
    except Exception as e:
        logger.error(f"Error looking up AS by country: {e}")
        return []


def parse_traffic_outage_input(user_input):
    asn_match = re.search(r"AS(\d+)", user_input, re.IGNORECASE)
    if not asn_match:
        return None, None, None
    asn = asn_match.group(1)
    for pattern in [
        r"(\d{4})-(\d{1,2})-(\d{1,2})\s+(\d{1,2}):(\d{2})\s+to\s+(\d{4})-(\d{1,2})-(\d{1,2})\s+(\d{1,2}):(\d{2})",
        r"(\d{4}):(\d{1,2}):(\d{1,2})\s+(\d{1,2}):(\d{2})\s+to\s+(\d{4}):(\d{1,2}):(\d{1,2})\s+(\d{1,2}):(\d{2})",
    ]:
        m = re.search(pattern, user_input)
        if m:
            g = m.groups()
            start = f"{g[0]}-{g[1].zfill(2)}-{g[2].zfill(2)} {g[3].zfill(2)}:{g[4]}"
            end = f"{g[5]}-{g[6].zfill(2)}-{g[7].zfill(2)} {g[8].zfill(2)}:{g[9]}"
            return asn, start, end
    return asn, None, None


def parse_multiple_as_input(user_input):
    as_list = list(dict.fromkeys(re.findall(r"AS(\d+)", user_input, re.IGNORECASE)))
    for pattern in [
        r"(\d{4})-(\d{1,2})-(\d{1,2})\s+(\d{1,2}):(\d{2})\s+to\s+(\d{4})-(\d{1,2})-(\d{1,2})\s+(\d{1,2}):(\d{2})",
    ]:
        m = re.search(pattern, user_input)
        if m:
            g = m.groups()
            start = f"{g[0]}-{g[1].zfill(2)}-{g[2].zfill(2)} {g[3].zfill(2)}:{g[4]}"
            end = f"{g[5]}-{g[6].zfill(2)}-{g[7].zfill(2)} {g[8].zfill(2)}:{g[9]}"
            return as_list if as_list else None, start, end
    return None, None, None


def parse_country_region_input(user_input):
    asn_match = re.search(r"AS(\d+)", user_input, re.IGNORECASE)
    asn = asn_match.group(1) if asn_match else None
    for pattern in [
        r"(\d{4})-(\d{1,2})-(\d{1,2})\s+(\d{1,2}):(\d{2})\s+to\s+(\d{4})-(\d{1,2})-(\d{1,2})\s+(\d{1,2}):(\d{2})",
    ]:
        m = re.search(pattern, user_input)
        if m:
            g = m.groups()
            start = f"{g[0]}-{g[1].zfill(2)}-{g[2].zfill(2)} {g[3].zfill(2)}:{g[4]}"
            end = f"{g[5]}-{g[6].zfill(2)}-{g[7].zfill(2)} {g[8].zfill(2)}:{g[9]}"
            country_m = re.search(r"in\s+([A-Za-z\s]+?)\s+(?:from|between|during)", user_input, re.IGNORECASE)
            return country_m.group(1).strip() if country_m else None, start, end, asn
    return None, None, None, asn


async def _analyze_single_as_traffic(asn, start_time, end_time, routing_analysis=None, use_llm=True):
    # Bug fix 2026-09-13 (BUG-R111): the previous implementation only
    # tried two human-readable formats (``"%Y-%m-%d %H:%M:%S"`` and
    # ``"%Y-%m-%d %H:%M"``) for both ``start_time`` and ``end_time``
    # independently. When the caller supplied ISO 8601 strings like
    # ``"2024-01-15T00:30:00"`` (very common when callers pass through
    # the React agent's run_context, or when chief_agent's
    # ``_extract_anomaly_times`` returns ISO strings), both formats
    # failed and the function returned
    # ``{"success": False, "error": "Invalid time: ..."}`` —
    # silently aborting the analysis with a confusing error message
    # that the LLM caller could not recover from. The fix mirrors the
    # one applied to ``routing_impl.run_routing_agent_async`` (BUG-R110):
    # try the human-readable formats first, then ``fromisoformat``,
    # then a plain-date fallback.

    # ── Default-window fallback (BUG-R134, 2026-09-14) ───────────────────────
    # Same logic as ``run_routing_agent_async``: when callers accidentally
    # pass ``None`` or an empty string for ``start_time`` / ``end_time``,
    # fall back to a 24-hour window ending now rather than aborting
    # analysis and silently emitting a "no anomaly" report.
    if not start_time or not end_time:
        from datetime import datetime as _dt, timedelta as _td
        _now = _dt.utcnow()
        if not start_time:
            start_time = (_now - _td(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
            logger.warning(
                f"[traffic_impl] start_time missing/empty; "
                f"defaulting to 24h-ago: {start_time}"
            )
        if not end_time:
            end_time = _now.strftime("%Y-%m-%dT%H:%M:%SZ")
            logger.warning(
                f"[traffic_impl] end_time missing/empty; "
                f"defaulting to now: {end_time}"
            )

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
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S%z",
        ):
            try:
                return datetime.strptime(s.replace("Z", "+0000") if s.endswith("Z") else s, fmt)
            except ValueError:
                continue
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            pass
        # Last-ditch: plain date "YYYY-MM-DD" → midnight
        try:
            d = datetime.strptime(s, "%Y-%m-%d")
            return datetime.combine(d.date(), datetime.min.time())
        except ValueError:
            return None

    try:
        start_dt = _parse_ts(start_time, "start_time")
        end_dt = _parse_ts(end_time, "end_time")
        if start_dt is None or end_dt is None:
            return {
                "success": False,
                "error": (
                    f"Invalid time: start_time={start_time!r}, end_time={end_time!r}"
                ),
            }
        # Normalise to naive UTC so the downstream subtraction
        # ``end_dt - start_dt`` (used for ``duration_hours``) cannot
        # raise ``TypeError: can't subtract offset-naive and
        # offset-aware datetimes`` when the caller mixed a tz-aware
        # ISO string with a tz-naive human-readable one. The raw
        # strings are still passed to the LLM call unchanged so
        # downstream display formats are preserved.
        if start_dt.tzinfo is not None:
            start_dt = start_dt.astimezone(timezone.utc).replace(tzinfo=None)
        if end_dt.tzinfo is not None:
            end_dt = end_dt.astimezone(timezone.utc).replace(tzinfo=None)
    except Exception as e:
        return {"success": False, "error": f"Invalid time: {e}"}

    llm_agent = LLMEnhancedTrafficAgent()
    if use_llm:
        result = await llm_agent.analyze_traffic_with_llm(
            asn=asn, start_time=start_time, end_time=end_time,
            routing_analysis=routing_analysis,
            original_start_time=start_time, original_end_time=end_time,
        )
    else:
        result = await llm_agent.analyze_traffic_no_llm(
            asn=asn, start_time=start_time, end_time=end_time,
            original_start_time=start_time, original_end_time=end_time,
        )
    if result.get("success"):
        result["original_outage_period"] = {
            "start_time": start_time, "end_time": end_time,
            "duration_hours": (end_dt - start_dt).total_seconds() / 3600,
        }
        # Filter anomalies within the outage window
        start_d = start_dt; end_d = end_dt
        within = []
        for a in result.get("anomalies", []):
            try:
                t = datetime.strptime(a["timestamp"], "%Y-%m-%dT%H:%M:%SZ")
                if start_d <= t <= end_d:
                    within.append(a)
            except Exception:
                pass
        result["outage_period_anomalies"] = within
        result["outage_period_anomaly_count"] = len(within)

    # Ensure unified schema fields are present so the evaluator can distinguish
    # "no data" from "no anomaly".  The detector already writes these, but
    # wrap them explicitly here so callers that receive the outer result
    # (rather than result["result"]) also see them.
    if "data_available" not in result:
        result["data_available"] = result.get("data_points", 0) > 0
    if "no_data_reason" not in result:
        result["no_data_reason"] = (
            "" if result.get("data_available")
            else result.get("no_data_reason", "unknown")
        )
    return result


async def run_traffic_agent_batch(
    as_list,
    start_time,
    end_time,
    max_concurrent: int = 4,
):
    """
    修 P2-Fix1：原 reasoning_agent.run_reasoning_agent_batch 试图 import 这个
    函数但从未实现，调用时会 ImportError。
    新增：并行对多个 AS 调用 analyze_traffic，汇总异常 AS 列表。

    Args:
        as_list: 待分析的 AS 列表
        start_time: 起始时间字符串
        end_time: 结束时间字符串
        max_concurrent: 最大并发数

    Returns:
        {
            "success": bool,
            "batch_mode": True,
            "as_count": int,
            "results_by_as": {asn: traffic_result},
            "anomaly_as_list": [asn, ...],
            "error": str (optional)
        }
    """
    import asyncio
    from datetime import datetime

    try:
        # 解析时间为 datetime 对象
        try:
            start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M")
        try:
            end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M")

        semaphore = asyncio.Semaphore(max_concurrent)

        async def _one(asn):
            async with semaphore:
                try:
                    r = await run_traffic_agent_async(
                        asn=str(asn),
                        start_time=start_dt.strftime("%Y-%m-%d %H:%M"),
                        end_time=end_dt.strftime("%Y-%m-%d %H:%M"),
                    )
                    return asn, r
                except Exception as exc:
                    return asn, {"success": False, "error": str(exc), "asn": str(asn)}

        tasks = [_one(a) for a in as_list]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        results_by_as: dict = {}
        anomaly_as_list = []
        errors = []
        for item in results:
            if isinstance(item, Exception):
                errors.append(str(item))
                continue
            asn, r = item
            results_by_as[str(asn)] = r if isinstance(r, dict) else {"success": False, "error": str(r)}
            if r.get("anomalies_detected") or r.get("anomaly_count", 0) > 0:
                anomaly_as_list.append(str(asn))

        return {
            "success": True,
            "batch_mode": True,
            "as_count": len(as_list),
            "results_by_as": results_by_as,
            "anomaly_as_list": anomaly_as_list,
            "errors": errors if errors else None,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "batch_mode": True,
            "as_count": len(as_list) if as_list else 0,
            "results_by_as": {},
            "anomaly_as_list": [],
        }


async def run_traffic_agent_async(user_input=None, asn=None, start_time=None,
                                  end_time=None, asorg_file=None, routing_analysis=None,
                                  use_llm=True):
    try:
        if user_input and not all([asn, start_time, end_time]):
            country, parsed_start, parsed_end, parsed_asn = parse_country_region_input(user_input)
            if country and not parsed_asn:
                matches = lookup_as_by_country(country, asorg_file)
                if not matches:
                    return {"success": False, "error": f"No AS found for: {country}"}
                if len(matches) > 5:
                    return {"success": False, "error": f"Too many AS ({len(matches)}). Max 5."}
                results = []
                for info in matches:
                    r = await _analyze_single_as_traffic(info["asn"], parsed_start, parsed_end, routing_analysis, use_llm=use_llm)
                    if r.get("success"):
                        r["as_info"] = info; results.append(r)
                return {"success": True, "country_region": country, "analysis_type": "multi_as_country_analysis",
                        "total_as_analyzed": len(results), "results": results}
            elif parsed_asn:
                asn, start_time, end_time = parsed_asn, parsed_start, parsed_end
            else:
                parsed_asn, parsed_start, parsed_end = parse_traffic_outage_input(user_input)
                if not parsed_asn:
                    return {"success": False, "error": "Could not extract ASN"}
                if not parsed_start or not parsed_end:
                    return {"success": False, "error": "Could not extract time period"}
                asn, start_time, end_time = parsed_asn, parsed_start, parsed_end

        if not all([asn, start_time, end_time]):
            return {"success": False, "error": "Missing required parameters"}
        return await _analyze_single_as_traffic(asn, start_time, end_time, routing_analysis, use_llm=use_llm)
    except Exception as e:
        logger.error(f"Traffic agent error: {e}")
        return {"success": False, "error": str(e)}


def run_traffic_agent(user_input=None, asn=None, start_time=None, end_time=None,
                      asorg_file=None, routing_analysis=None, use_llm=True):
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import nest_asyncio; nest_asyncio.apply()
            return loop.run_until_complete(run_traffic_agent_async(user_input, asn, start_time, end_time, asorg_file, routing_analysis, use_llm=use_llm))
        return loop.run_until_complete(run_traffic_agent_async(user_input, asn, start_time, end_time, asorg_file, routing_analysis, use_llm=use_llm))
    except (RuntimeError, AssertionError):
        return asyncio.run(run_traffic_agent_async(user_input, asn, start_time, end_time, asorg_file, routing_analysis, use_llm=use_llm))
