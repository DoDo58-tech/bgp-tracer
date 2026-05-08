import os
import sys
import re
import json
from datetime import datetime, timedelta
from pathlib import Path

sys.path.append((os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from detectors.traffic.traffic_detector import CloudflareRadarAPI
from utils.logger import logger
from llm.llm_factory import setup_llm_settings
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
            model=self.model,
            api_key=self.api_key,
            base_url=self.base_url,
            temperature=0.3,
            timeout=300.0,
            max_retries=2,
        )

    async def analyze_traffic_with_llm(self, asn, start_time, end_time, routing_analysis, original_start_time=None, original_end_time=None):
        await self.setup_llm()

        traffic_result = self.cloudflare_api.detect_anomalies(
            asn=asn,
            start_time=start_time,
            end_time=end_time,
            plot_result=True,
            event_start_time=original_start_time,
            event_end_time=original_end_time,
        )

        if not traffic_result.get("success"):
            return traffic_result

        analysis_data = {
            "asn": asn,
            "time_period": f"{start_time} to {end_time}",
            "traffic_metrics": {
                "anomaly_count": traffic_result.get("anomaly_count", 0),
                "data_points": traffic_result.get("data_points", 0),
                "percent_change": traffic_result.get("percent_change", 0),
                "current_avg": traffic_result.get("current_avg", 0),
                "historical_avg": traffic_result.get("historical_avg", 0),
            },
            "anomalies": traffic_result.get("anomalies", []),
            "routing_context": routing_analysis,
        }

        llm_insights = await self._generate_llm_insights(analysis_data)

        enhanced_result = {
            **traffic_result,
            "llm_enhanced": True,
            "llm_insights": llm_insights,
            "analysis_timestamp": datetime.now().isoformat(),
        }

        return enhanced_result

    async def _generate_llm_insights(self, analysis_data):
        routing_context = (
            json.dumps(analysis_data.get("routing_context", {}), indent=2, ensure_ascii=False)
            if analysis_data.get("routing_context")
            else "No routing analysis data"
        )

        prompt = f"""
You are a network traffic analysis expert. Review the following AS traffic data and provide professional insights.

AS Information:
- ASN: {analysis_data['asn']}
- Analysis period: {analysis_data['time_period']}

Traffic Metrics:
- Anomaly count: {analysis_data['traffic_metrics']['anomaly_count']}
- Sample count: {analysis_data['traffic_metrics']['data_points']}
- Traffic change: {analysis_data['traffic_metrics']['percent_change']:.2f}%
- Current average traffic: {analysis_data['traffic_metrics']['current_avg']:.4f}
- Historical average traffic: {analysis_data['traffic_metrics']['historical_avg']:.4f}

Top anomalies (max 5):
{json.dumps(analysis_data['anomalies'][:5], indent=2, ensure_ascii=False)}

Routing context:
{routing_context}

Provide analysis for:
1. Traffic pattern analysis
2. Root cause analysis
3. Impact assessment
4. Recommendations
5. Risk assessment

Return JSON with fields:
- traffic_pattern_analysis
- root_cause_analysis
- impact_assessment
- recommendations
- risk_assessment
- confidence_level (0-1)
- key_findings (list)
"""

        try:
            response = self.llm.complete(prompt)
            raw = response.text if hasattr(response, "text") else str(response)
            try:
                insights = json.loads(raw)
            except Exception:
                start = raw.find("{")
                end = raw.rfind("}")
                if start != -1 and end != -1 and end > start:
                    candidate = raw[start : end + 1]
                    try:
                        insights = json.loads(candidate)
                    except Exception:
                        candidate2 = re.sub(r"'", '"', candidate)
                        insights = json.loads(candidate2)
                else:
                    raise ValueError("No JSON object found in LLM response")
            return insights
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return {
                "error": f"LLM analysis failed: {str(e)}",
                "fallback_analysis": self._generate_fallback_analysis(analysis_data),
            }

    def _generate_fallback_analysis(self, analysis_data):
        anomaly_count = analysis_data["traffic_metrics"]["anomaly_count"]
        percent_change = analysis_data["traffic_metrics"]["percent_change"]

        if anomaly_count > 10:
            risk_level = "high"
            recommendation = "Investigate immediately; large anomaly volume suggests severe instability."
        elif anomaly_count > 5:
            risk_level = "medium"
            recommendation = "Increase monitoring frequency and prepare mitigation steps."
        else:
            risk_level = "low"
            recommendation = "Maintain routine monitoring; traffic is largely within expectations."

        return {
            "traffic_pattern_analysis": f"{anomaly_count} anomalies detected with {percent_change:.2f}% deviation.",
            "root_cause_analysis": "Additional evidence is required to isolate the exact trigger.",
            "impact_assessment": f"Impact level inferred as {risk_level} based on anomaly density.",
            "recommendations": [recommendation],
            "risk_assessment": risk_level,
            "confidence_level": 0.5,
            "key_findings": [
                f"Anomaly count: {anomaly_count}",
                f"Traffic change: {percent_change:.2f}%",
            ],
        }


def _compute_extended_window(start_time, end_time):
    try:
        start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M")

    try:
        end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M")

    extended_start_dt = start_dt - timedelta(days=1)
    extended_end_dt = end_dt + timedelta(hours=6)

    return (
        extended_start_dt.strftime("%Y-%m-%d %H:%M"),
        extended_end_dt.strftime("%Y-%m-%d %H:%M"),
    )


def lookup_as_by_country(country_name, asorg_file=None):
    try:
        if not asorg_file or not Path(asorg_file).exists():
            logger.warning("AS organization file not available")
            return []

        with open(asorg_file, 'r', encoding='utf-8') as f:
            asorg_data = json.load(f)

        asn_to_org_id = asorg_data.get("asn_to_org_id", {})
        asn_to_name = asorg_data.get("asn_to_name", {})
        org_id_to_info = asorg_data.get("org_id_to_info", {})

        country_lower = country_name.lower()
        matching_asns = []

        for asn, org_id in asn_to_org_id.items():
            org_info = org_id_to_info.get(org_id, {})
            org_country = org_info.get("country", "").lower()
            org_name = org_info.get("name", "").lower()
            as_name = asn_to_name.get(asn, "").lower()

            if (country_lower in org_country or country_lower in org_name or country_lower in as_name):
                matching_asns.append({
                    "asn": asn,
                    "as_name": asn_to_name.get(asn, "Unknown"),
                    "org_name": org_info.get("name", "Unknown"),
                    "country": org_info.get("country", "Unknown"),
                    "source": org_info.get("source", "Unknown")
                })

        return matching_asns

    except Exception as e:
        logger.error(f"Error looking up AS by country: {str(e)}")
        return []


def parse_country_region_input(user_input):
    asn_pattern = r'AS(\d+)'
    asn_match = re.search(asn_pattern, user_input, re.IGNORECASE)
    asn = asn_match.group(1) if asn_match else None

    time_patterns = [
        r'(\d{4}):(\d{1,2}):(\d{1,2})\s+(\d{1,2}):(\d{2})\s+to\s+(\d{4}):(\d{1,2}):(\d{1,2})\s+(\d{1,2}):(\d{2})',
        r'(\d{4})-(\d{1,2})-(\d{1,2})\s+(\d{1,2}):(\d{2})\s+to\s+(\d{4})-(\d{1,2})-(\d{1,2})\s+(\d{1,2}):(\d{2})',
        r'(\d{4})/(\d{1,2})/(\d{1,2})\s+(\d{1,2}):(\d{2})\s+to\s+(\d{4})/(\d{1,2})/(\d{1,2})\s+(\d{1,2}):(\d{2})',
    ]

    start_time = None
    end_time = None

    for pattern in time_patterns:
        match = re.search(pattern, user_input)
        if match:
            groups = match.groups()
            if len(groups) >= 10:
                start_time = f"{groups[0]}-{groups[1].zfill(2)}-{groups[2].zfill(2)} {groups[3].zfill(2)}:{groups[4]}"
                end_time = f"{groups[5]}-{groups[6].zfill(2)}-{groups[7].zfill(2)} {groups[8].zfill(2)}:{groups[9]}"
                break

    country_patterns = [
        r'in\s+([A-Za-z\s]+?)\s+(?:from|between|during)',
        r'in\s+([A-Za-z\s]+?)\s+from',
        r'in\s+([A-Za-z\s]+?)\s+between',
        r'in\s+([A-Za-z\s]+?)\s+during',
        r'([A-Za-z\s]+?)\s+network\s+outage',
        r'([A-Za-z\s]+?)\s+traffic\s+outage',
        r'([A-Za-z\s]+?)\s+internet\s+outage',
    ]

    country_region = None
    for pattern in country_patterns:
        match = re.search(pattern, user_input, re.IGNORECASE)
        if match:
            country_region = match.group(1).strip()
            break

    return country_region, start_time, end_time, asn


def parse_traffic_outage_input(user_input):
    asn_pattern = r'AS(\d+)'
    asn_match = re.search(asn_pattern, user_input, re.IGNORECASE)
    if not asn_match:
        return None, None, None

    asn = asn_match.group(1)

    time_patterns = [
        r'(\d{4}):(\d{1,2}):(\d{1,2})\s+(\d{1,2}):(\d{2})\s+to\s+(\d{4}):(\d{1,2}):(\d{1,2})\s+(\d{1,2}):(\d{2})',
        r'(\d{4})-(\d{1,2})-(\d{1,2})\s+(\d{1,2}):(\d{2})\s+to\s+(\d{4})-(\d{1,2})-(\d{1,2})\s+(\d{1,2}):(\d{2})',
        r'(\d{4})/(\d{1,2})/(\d{1,2})\s+(\d{1,2}):(\d{2})\s+to\s+(\d{4})/(\d{1,2})/(\d{1,2})\s+(\d{1,2}):(\d{2})',
    ]

    for pattern in time_patterns:
        match = re.search(pattern, user_input)
        if match:
            groups = match.groups()
            if len(groups) >= 10:
                start_time = f"{groups[0]}-{groups[1].zfill(2)}-{groups[2].zfill(2)} {groups[3].zfill(2)}:{groups[4]}"
                end_time = f"{groups[5]}-{groups[6].zfill(2)}-{groups[7].zfill(2)} {groups[8].zfill(2)}:{groups[9]}"
                return asn, start_time, end_time

    return asn, None, None


def parse_multiple_as_input(user_input):
    """
    Parse user input to extract multiple AS numbers and a shared time period.
    Used for batch analysis of multiple ASes simultaneously.
    
    Returns:
        tuple: (as_list, start_time, end_time)
            - as_list: list of AS numbers as strings, or None
            - start_time: start time string in format "YYYY-MM-DD HH:MM"
            - end_time: end time string in format "YYYY-MM-DD HH:MM"
    """
    time_patterns = [
        r'(\d{4}):(\d{1,2}):(\d{1,2})\s+(\d{1,2}):(\d{2})\s+to\s+(\d{4}):(\d{1,2}):(\d{1,2})\s+(\d{1,2}):(\d{2})',
        r'(\d{4})-(\d{1,2})-(\d{1,2})\s+(\d{1,2}):(\d{2})\s+to\s+(\d{4})-(\d{1,2})-(\d{1,2})\s+(\d{1,2}):(\d{2})',
        r'(\d{4})/(\d{1,2})/(\d{1,2})\s+(\d{1,2}):(\d{2})\s+to\s+(\d{4})/(\d{1,2})/(\d{1,2})\s+(\d{1,2}):(\d{2})',
    ]
    
    as_pattern = r'AS(\d+)'
    
    start_time = None
    end_time = None
    
    for pattern in time_patterns:
        match = re.search(pattern, user_input)
        if match:
            groups = match.groups()
            if len(groups) >= 10:
                start_time = f"{groups[0]}-{groups[1].zfill(2)}-{groups[2].zfill(2)} {groups[3].zfill(2)}:{groups[4]}"
                end_time = f"{groups[5]}-{groups[6].zfill(2)}-{groups[7].zfill(2)} {groups[8].zfill(2)}:{groups[9]}"
                break
    
    as_list = re.findall(as_pattern, user_input, re.IGNORECASE)
    as_list = list(set(as_list))
    
    if not as_list:
        return None, start_time, end_time
    
    return as_list, start_time, end_time


async def _analyze_single_as_traffic(asn, start_time, end_time, routing_analysis=None):
    try:
        try:
            start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M")

        try:
            end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M")
    except Exception as e:
        return {"success": False, "error": f"Invalid time format. Error: {str(e)}"}

    llm_agent = LLMEnhancedTrafficAgent()
    result = await llm_agent.analyze_traffic_with_llm(
        asn=asn,
        start_time=start_time,
        end_time=end_time,
        routing_analysis=routing_analysis,
        original_start_time=start_time,
        original_end_time=end_time,
    )

    if result.get("success"):
        result["original_outage_period"] = {
            "start_time": start_time,
            "end_time": end_time,
            "duration_hours": (end_dt - start_dt).total_seconds() / 3600,
        }

        original_outage_anomalies = []
        if result.get("anomalies"):
            for anomaly in result["anomalies"]:
                try:
                    anomaly_time = datetime.strptime(anomaly["timestamp"], "%Y-%m-%dT%H:%M:%SZ")
                    if start_dt <= anomaly_time <= end_dt:
                        original_outage_anomalies.append(anomaly)
                except Exception:
                    continue

        result["outage_period_anomalies"] = original_outage_anomalies
        result["outage_period_anomaly_count"] = len(original_outage_anomalies)

    return result


async def run_traffic_agent_async(user_input=None, asn=None, start_time=None, end_time=None, asorg_file=None, routing_analysis=None):
    try:
        if user_input and not (asn and start_time and end_time):
            country_region, parsed_start, parsed_end, parsed_asn = parse_country_region_input(user_input)

            if country_region and not parsed_asn:
                matching_asns = lookup_as_by_country(country_region, asorg_file)

                if not matching_asns:
                    return {"success": False, "error": f"No AS numbers found for: {country_region}", "user_input": user_input, "country_region": country_region}

                if len(matching_asns) <= 5:
                    results = []
                    for as_info in matching_asns:
                        asn = as_info["asn"]
                        result = await _analyze_single_as_traffic(asn=asn, start_time=parsed_start, end_time=parsed_end, routing_analysis=routing_analysis)
                        if result.get("success"):
                            result["as_info"] = as_info
                            results.append(result)

                    return {"success": True, "country_region": country_region, "analysis_type": "multi_as_country_analysis", "total_as_analyzed": len(results), "results": results, "user_input": user_input}
                else:
                    return {"success": False, "error": f"Too many AS numbers found ({len(matching_asns)}). Max 5 allowed.", "user_input": user_input, "country_region": country_region}

            elif parsed_asn:
                asn = parsed_asn
                start_time = parsed_start
                end_time = parsed_end
            else:
                parsed_asn, parsed_start, parsed_end = parse_traffic_outage_input(user_input)
                if not parsed_asn:
                    return {"success": False, "error": "Could not extract ASN from input", "user_input": user_input}
                if not parsed_start or not parsed_end:
                    return {"success": False, "error": "Could not extract time period from input", "user_input": user_input, "parsed_asn": parsed_asn}
                asn = parsed_asn
                start_time = parsed_start
                end_time = parsed_end

        if not all([asn, start_time, end_time]):
            return {"success": False, "error": "Missing required parameters: asn, start_time, end_time"}

        return await _analyze_single_as_traffic(asn=asn, start_time=start_time, end_time=end_time, routing_analysis=routing_analysis)

    except Exception as e:
        logger.error(f"Traffic agent error: {str(e)}")
        return {"success": False, "error": str(e)}


def run_traffic_agent(user_input=None, asn=None, start_time=None, end_time=None, asorg_file=None, routing_analysis=None):
    import asyncio
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            try:
                import nest_asyncio
                nest_asyncio.apply()
                return loop.run_until_complete(run_traffic_agent_async(user_input, asn, start_time, end_time, asorg_file, routing_analysis))
            except ImportError:
                import concurrent.futures
                new_loop = asyncio.new_event_loop()
                def run_in_thread():
                    asyncio.set_event_loop(new_loop)
                    return new_loop.run_until_complete(run_traffic_agent_async(user_input, asn, start_time, end_time, asorg_file, routing_analysis))
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(run_in_thread)
                    return future.result()
        else:
            return loop.run_until_complete(run_traffic_agent_async(user_input, asn, start_time, end_time, asorg_file, routing_analysis))
    except RuntimeError:
        return asyncio.run(run_traffic_agent_async(user_input, asn, start_time, end_time, asorg_file, routing_analysis))


def run_traffic_agent_batch(as_list, start_time, end_time, asorg_file=None, fast_mode=None, historical_weeks=None):
    logger.info(f"Batch traffic analysis for {len(as_list)} AS from {start_time} to {end_time}")

    cloudflare_api = CloudflareRadarAPI()

    if fast_mode is None:
        fast_mode = os.getenv("TRAFFIC_FAST_MODE", "true").lower() == "true"

    weeks_override = None
    env_weeks = os.getenv("TRAFFIC_HISTORICAL_WEEKS", "")
    if historical_weeks:
        weeks_override = historical_weeks
    elif env_weeks:
        try:
            weeks_override = [int(w.strip()) for w in env_weeks.split(",") if w.strip()]
        except Exception:
            weeks_override = None

    batch_results = {}
    anomaly_as_list = []

    for idx, asn in enumerate(as_list, 1):
        try:
            result = cloudflare_api.detect_anomalies(
                asn=asn,
                start_time=start_time,
                end_time=end_time,
                plot_result=True,
                event_start_time=start_time,
                event_end_time=end_time,
                fast_mode=fast_mode,
                historical_weeks=weeks_override,
                anomaly_method="combined",
                auto_expand_boundaries=True,
            )

            batch_results[asn] = result

            if result.get("success") and result.get("anomalies_detected"):
                anomaly_as_list.append(asn)
        except Exception as e:
            logger.error(f"AS{asn}: Traffic analysis failed - {str(e)}")
            batch_results[asn] = {"success": False, "asn": asn, "error": str(e), "anomalies_detected": False}

    return {
        "success": True,
        "batch_mode": True,
        "as_count": len(as_list),
        "success_count": sum(1 for r in batch_results.values() if r.get("success")),
        "anomaly_count": len(anomaly_as_list),
        "anomaly_as_list": anomaly_as_list,
        "results_by_as": batch_results,
        "analysis_period": f"{start_time} to {end_time}",
        "analysis_timestamp": datetime.now().isoformat()
    }


__all__ = [
    "run_traffic_agent",
    "run_traffic_agent_async",
    "run_traffic_agent_batch",
    "LLMEnhancedTrafficAgent",
    "lookup_as_by_country",
    "parse_country_region_input",
    "parse_traffic_outage_input"
]
