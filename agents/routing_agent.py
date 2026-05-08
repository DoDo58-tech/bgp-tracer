import os
import sys
import json
import gc
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.append((os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from detectors.hijack.hijack_detector import detect_hijacks
from detectors.leak.leak_detector import analyze_leak_surface
from utils.logger import logger
from llm.llm_factory import setup_llm_settings
from config import BASE_URL, API_KEY, MODEL, MAX_WORKERS, IO_BUSY_THRESHOLD


def _get_outage_detector():
    from detectors.outage.outage_detector import RouteOutageDetector
    return RouteOutageDetector()


class LLMEnhancedRoutingAgent:
    def __init__(self, model, api_key, base_url):
        self.model = model
        self.api_key = api_key
        self.base_url = base_url
        self.llm = None
    
    async def setup_llm(self):
        self.llm, _ = setup_llm_settings(
            model=self.model,
            api_key=self.api_key,
            base_url=self.base_url,
            temperature=0.3,
            timeout=300.0,
            max_retries=2
        )
    
    async def analyze_routing_with_llm(self, routing_results, asn, start_time, end_time):
        await self.setup_llm()

        analysis_data = {
            "asn": asn,
            "time_period": f"{start_time} to {end_time}",
            "routing_events": {
                "origin_hijacked": len(routing_results.get("origin_hijacked", [])),
                "forge_hijacked": len(routing_results.get("forge_hijacked", [])),
                "origin_hijacking": len(routing_results.get("origin_hijacking", [])),
                "forge_hijacking": len(routing_results.get("forge_hijacking", [])),
                "mitm_alerts": len(routing_results.get("mitm_alerts", []))
            },
            "detailed_events": {
                "origin_hijacked_samples": routing_results.get("origin_hijacked", [])[:5],
                "forge_hijacked_samples": routing_results.get("forge_hijacked", [])[:5],
                "origin_hijacking_samples": routing_results.get("origin_hijacking", [])[:5],
                "mitm_alerts_samples": routing_results.get("mitm_alerts", [])[:5]
            }
        }

        llm_insights = await self._generate_llm_insights(analysis_data)

        enhanced_result = {
            **routing_results,
            "llm_enhanced": True,
            "llm_insights": llm_insights,
            "analysis_timestamp": datetime.now().isoformat()
        }

        return enhanced_result

    async def _generate_llm_insights(self, analysis_data):
        import re

        prompt = f"""
As a BGP routing security expert, analyze the following routing detection results and provide professional insights. Use English only.

AS Information:
- AS Number: {analysis_data['asn']}
- Analysis Period: {analysis_data['time_period']}

Routing Events Detected:
- Origin Hijacked (AS being attacked): {analysis_data['routing_events']['origin_hijacked']}
- Forge Hijacked (MITM attacks detected): {analysis_data['routing_events']['forge_hijacked']}
- Origin Hijacking (AS attacking others): {analysis_data['routing_events']['origin_hijacking']}
- Forge Hijacking (AS performing MITM): {analysis_data['routing_events']['forge_hijacking']}
- MITM Alerts: {analysis_data['routing_events']['mitm_alerts']}

Detailed Event Samples:
{json.dumps(analysis_data['detailed_events'], indent=2, ensure_ascii=False)}

Provide analysis for:
1. Attack Pattern Analysis
2. Attack Correlation
3. Impact Assessment
4. Attacker Attribution
5. Mitigation Recommendations
6. Risk Assessment

Return JSON with fields:
- attack_pattern_analysis
- attack_correlation
- impact_assessment
- attacker_attribution
- mitigation_recommendations
- risk_assessment
- confidence_level (0-1)
- key_findings (list)
"""

        try:
            response = self.llm.complete(prompt)
            raw = response.text if hasattr(response, 'text') else str(response)
            try:
                insights = json.loads(raw)
            except Exception:
                start = raw.find('{')
                end = raw.rfind('}')
                if start != -1 and end != -1 and end > start:
                    candidate = raw[start:end+1]
                    try:
                        insights = json.loads(candidate)
                    except Exception:
                        candidate2 = re.sub(r"'", '"', candidate)
                        insights = json.loads(candidate2)
                else:
                    raise ValueError("No JSON object found in LLM response")
            return insights
        except Exception as e:
            logger.error(f"LLM routing analysis failed: {e}")
            return {
                "error": f"LLM analysis failed: {str(e)}",
                "fallback_analysis": self._generate_fallback_analysis(analysis_data)
            }

    def _generate_fallback_analysis(self, analysis_data):
        total_attacks = sum([
            analysis_data['routing_events']['origin_hijacked'],
            analysis_data['routing_events']['forge_hijacked'],
            analysis_data['routing_events']['origin_hijacking'],
            analysis_data['routing_events']['forge_hijacking'],
            analysis_data['routing_events']['mitm_alerts']
        ])

        if total_attacks > 10:
            risk_level = "High"
            recommendation = "Immediate action required: Multiple BGP attacks detected"
        elif total_attacks > 5:
            risk_level = "Medium"
            recommendation = "Monitor closely and prepare response actions"
        elif total_attacks > 0:
            risk_level = "Low"
            recommendation = "Continue monitoring for potential escalation"
        else:
            risk_level = "Very Low"
            recommendation = "No attacks detected, maintain normal monitoring"

        return {
            "attack_pattern_analysis": f"Detected {total_attacks} routing security events",
            "attack_correlation": "Requires further investigation to determine correlations",
            "impact_assessment": f"Based on {total_attacks} events, impact level is {risk_level}",
            "attacker_attribution": "Attribution requires additional investigation",
            "mitigation_recommendations": [recommendation],
            "risk_assessment": risk_level,
            "confidence_level": 0.5,
            "key_findings": [
                f"Total routing events: {total_attacks}",
                f"Risk level: {risk_level}"
            ]
        }


def detect_mitm_with_asrel_validation(asn, start_time, end_time, asrel_data):
    try:
        start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M")
        end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M")

        from data.updates_loader import get_updates_streaming

        fake_connection_alerts = []
        connection_frequency_map = {}

        for updates_df in get_updates_streaming(start_dt, end_dt, workers=MAX_WORKERS, io_busy_threshold=IO_BUSY_THRESHOLD, auto_download=True):
            if updates_df.empty:
                continue

            from utils.bgp_utils import check_fake_connections_in_df

            as_relationships = {}
            providers = asrel_data.get("providers", {})
            peers = asrel_data.get("peers", {})

            for asn_str, provider_list in providers.items():
                as_relationships[asn_str] = {
                    "providers": set(provider_list),
                    "peers": set(peers.get(asn_str, [])),
                    "customers": set()
                }

            for customer_asn, customer_providers in providers.items():
                for provider_asn in customer_providers:
                    if provider_asn in as_relationships:
                        as_relationships[provider_asn]["customers"].add(customer_asn)

            if 'timestamp' in updates_df.columns:
                updates_df['timestamp'] = updates_df['timestamp'].astype(str)

            updates_df = check_fake_connections_in_df(updates_df, as_relationships)
            fake_connection_messages = updates_df[updates_df['has_fake_connect'] == True]

            for _, row in fake_connection_messages.iterrows():
                as_path = row.get('as-path', '')
                exact_fake_connections = row.get('exact_fake_connect', '')
                timestamp_raw = row.get('timestamp', '')
                prefix = row.get('prefix', '')

                try:
                    if isinstance(timestamp_raw, (int, float)) or (isinstance(timestamp_raw, str) and timestamp_raw.isdigit()):
                        timestamp_dt = datetime.fromtimestamp(float(timestamp_raw), tz=timezone.utc)
                        timestamp_str = timestamp_dt.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        timestamp_str = str(timestamp_raw)
                        timestamp_dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                except Exception as e:
                    logger.warning(f"Error parsing timestamp '{timestamp_raw}': {e}")
                    continue

                if exact_fake_connections:
                    fake_connections = exact_fake_connections.split(';')
                    for fake_conn in fake_connections:
                        if fake_conn:
                            if fake_conn not in connection_frequency_map:
                                connection_frequency_map[fake_conn] = []
                            connection_frequency_map[fake_conn].append({
                                'timestamp': timestamp_str,
                                'timestamp_dt': timestamp_dt,
                                'prefix': prefix,
                                'as_path': as_path
                            })

            del updates_df, fake_connection_messages, as_relationships
            gc.collect()

        week_ago = start_dt - timedelta(days=7)

        legitimate_connections = set()
        suspicious_connections = set()

        def parse_timestamp(ts_str):
            try:
                if isinstance(ts_str, datetime):
                    return ts_str
                return datetime.strptime(str(ts_str), "%Y-%m-%d %H:%M:%S")
            except Exception:
                try:
                    return datetime.fromtimestamp(float(ts_str), tz=timezone.utc)
                except Exception:
                    return None

        for connection, occurrences in connection_frequency_map.items():
            week_occurrences = []
            for occ in occurrences:
                ts_dt = occ.get('timestamp_dt') or parse_timestamp(occ['timestamp'])
                if ts_dt and ts_dt >= week_ago:
                    week_occurrences.append(occ)

            if len(week_occurrences) >= 5:
                legitimate_connections.add(connection)
            else:
                suspicious_connections.add(connection)

        for connection in suspicious_connections:
            occurrences = connection_frequency_map[connection]
            recent_occurrences = []
            for occ in occurrences:
                ts_dt = occ.get('timestamp_dt') or parse_timestamp(occ['timestamp'])
                if ts_dt and ts_dt >= start_dt:
                    recent_occurrences.append(occ)

            if recent_occurrences:
                aggregated_prefixes = set()
                aggregated_paths = []

                for occ in recent_occurrences:
                    aggregated_prefixes.add(occ['prefix'])
                    aggregated_paths.append(occ['as_path'])

                week_freq = 0
                for occ in occurrences:
                    ts_dt = occ.get('timestamp_dt') or parse_timestamp(occ['timestamp'])
                    if ts_dt and ts_dt >= week_ago:
                        week_freq += 1

                alert = {
                    'type': 'mitm_hijack',
                    'fake_connection': connection,
                    'timestamp': recent_occurrences[0]['timestamp'],
                    'affected_prefixes': list(aggregated_prefixes),
                    'affected_paths': aggregated_paths[:5],
                    'occurrence_count': len(recent_occurrences),
                    'week_frequency': week_freq,
                    'confidence': 'high' if len(recent_occurrences) > 3 else 'medium'
                }
                fake_connection_alerts.append(alert)

        return {
            'success': True,
            'mitm_alerts': fake_connection_alerts,
            'legitimate_connections': list(legitimate_connections),
            'suspicious_connections': list(suspicious_connections),
            'total_fake_connections_analyzed': len(connection_frequency_map),
            'analysis_period': f"{start_time} to {end_time}",
            'asn': asn
        }

    except Exception as e:
        logger.error(f"MITM detection error: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'mitm_alerts': [],
            'asn': asn
        }


def run_routing_agent(asn, start_time, end_time, target_asns=None, periodicity=None, periodicity_confidence=0.0):
    try:
        try:
            start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M")

        try:
            end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M")

        logger.info(f"Routing analysis for AS{asn}: {start_time} to {end_time}")

        hijack_results = detect_hijacks(
            start_dt,
            end_dt,
            asn,
            validate_with_updates=False
        )

        if not hijack_results.get("success"):
            return hijack_results

        mitm_results = {
            'success': True,
            'mitm_alerts': [],
            'note': 'MITM detection integrated into hijack detection'
        }

        leak_result = analyze_leak_surface(asn, start_time, end_time, target_asns=target_asns)

        logger.info("Running outage detector...")
        outage_result = _get_outage_detector().analyze(asn, start_time, end_time, periodicity=periodicity, periodicity_confidence=periodicity_confidence)

        if hijack_results.get("batch_mode") and hijack_results.get("results_by_as"):
            results_by_as = hijack_results.get("results_by_as", {})
            as_key = int(asn) if asn not in results_by_as else asn
            if as_key in results_by_as:
                as_result = results_by_as[as_key]
                _origin_hijacked = as_result.get("origin_hijacked", [])
                _forge_hijacked = as_result.get("forge_hijacked", [])
            else:
                as_result = results_by_as.get(str(asn), {})
                _origin_hijacked = as_result.get("origin_hijacked", [])
                _forge_hijacked = as_result.get("forge_hijacked", [])
        else:
            _origin_hijacked = hijack_results.get("origin_hijacked", [])
            _forge_hijacked = hijack_results.get("forge_hijacked", [])

        combined_results = {
            "success": True,
            "asn": asn,
            "analysis_period": f"{start_time} to {end_time}",
            "analysis_timestamp": datetime.now().isoformat(),
            "origin_hijacked": _origin_hijacked,
            "forge_hijacked": _forge_hijacked,
            "origin_hijacking": hijack_results.get("origin_hijacking", []),
            "forge_hijacking": hijack_results.get("forge_hijacking", []),
            "aggregated_alerts": hijack_results.get("aggregated_alerts", []),
            "mitm_alerts": mitm_results.get("mitm_alerts", []),
            "mitm_detection_success": mitm_results.get("success", False),
            "mitm_detection_error": mitm_results.get("error"),
            "route_leaks": leak_result.get("route_leaks", []),
            "leak_count": leak_result.get("leak_count", 0),
            "leak_detection_success": leak_result.get("success", False),
            "leak_detection_error": leak_result.get("error"),
            "leak_data_source": leak_result.get("data_source", "csv_streaming") if leak_result else "no_data",
            "outage_analysis": outage_result,
            "as_rel_file": hijack_results.get("as_rel_file"),
            "prefix2as_file": hijack_results.get("prefix2as_file"),
            "asorg_file": hijack_results.get("asorg_file"),
            "total_prefix_hijacks": len(_origin_hijacked) + len(_forge_hijacked),
            "total_prefix_hijacking": len(hijack_results.get("origin_hijacking", [])) + len(hijack_results.get("forge_hijacking", [])),
            "total_mitm_alerts": len(mitm_results.get("mitm_alerts", [])),
            "outage_suspected": bool(outage_result.get("is_outage_suspected", False)),
            "outage_score": float(outage_result.get("outage_score", 0.0)) if outage_result.get("success") else 0.0,
        }

        return combined_results

    except Exception as e:
        logger.error(f"Routing agent error: {str(e)}")
        return {"success": False, "error": str(e), "asn": asn}


async def run_routing_agent_async(
    asn, 
    start_time, 
    end_time, 
    use_llm=True, 
    periodicity=None, 
    periodicity_confidence=0.0,
    enable_mitm: bool = True
):
    """
    Run routing agent asynchronously.
    
    Args:
        asn: Target AS number
        start_time: Start time
        end_time: End time
        use_llm: Whether to use LLM for analysis
        periodicity: Periodicity parameter for outage detection
        periodicity_confidence: Periodicity confidence threshold
        enable_mitm: Whether to enable MITM (中间人劫持) detection (default: True)
                     When False, skips forge hijack detection and ES usage
    """
    try:
        if isinstance(start_time, str):
            try:
                start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M")
        else:
            start_dt = start_time

        if isinstance(end_time, str):
            try:
                end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M")
        else:
            end_dt = end_time

        logger.info(f"Routing analysis for AS{asn}: {start_time} to {end_time} (MITM detection: {'enabled' if enable_mitm else 'disabled'})")

        # Hijack detection with MITM control
        hijack_results = detect_hijacks(
            start_dt, 
            end_dt, 
            asn, 
            validate_with_updates=False,
            skip_forge_detection=not enable_mitm  # 控制是否跳过forge hijack检测
        )

        if not hijack_results.get("success"):
            return hijack_results

        # Only run MITM detection if enabled
        if enable_mitm:
            mitm_results = {'success': True, 'mitm_alerts': []}
            logger.info("MITM detection enabled - forge hijack detection active")
        else:
            mitm_results = {
                'success': True, 
                'mitm_alerts': [], 
                'note': 'MITM detection disabled by user'
            }
            logger.info("MITM detection disabled - skipping forge hijack detection")

        leak_result = analyze_leak_surface(asn, start_time, end_time, pathprob_file=None, threshold=None)

        try:
            outage_detector = _get_outage_detector()
            outage_result = outage_detector.analyze(asn, start_time, end_time, periodicity=periodicity, periodicity_confidence=periodicity_confidence)
        except Exception as e:
            logger.error(f"Outage detector error: {e}")
            outage_result = {"success": False, "is_outage_suspected": False, "outage_score": 0.0, "error": str(e)}

        if outage_result is None:
            outage_result = {"success": False, "is_outage_suspected": False, "outage_score": 0.0}
        if not isinstance(outage_result, dict):
            outage_result = {"success": False, "is_outage_suspected": False, "outage_score": 0.0}

        _outage_score = float(outage_result.get("outage_score") or 0.0) if outage_result.get("success") else 0.0

        if leak_result is None:
            leak_result = {"success": False, "route_leaks": [], "leak_count": 0, "error": "No result"}

        if hijack_results.get("batch_mode") and hijack_results.get("results_by_as"):
            results_by_as = hijack_results.get("results_by_as", {})
            as_key = int(asn) if asn not in results_by_as else asn
            if as_key in results_by_as:
                as_result = results_by_as[as_key]
                _origin_hijacked = as_result.get("origin_hijacked", [])
                _forge_hijacked = as_result.get("forge_hijacked", [])
            else:
                as_result = results_by_as.get(str(asn), {})
                _origin_hijacked = as_result.get("origin_hijacked", [])
                _forge_hijacked = as_result.get("forge_hijacked", [])
        else:
            _origin_hijacked = hijack_results.get("origin_hijacked", [])
            _forge_hijacked = hijack_results.get("forge_hijacked", [])

        combined_results = {
            "success": True,
            "asn": asn,
            "analysis_period": f"{start_time} to {end_time}",
            "analysis_timestamp": datetime.now().isoformat(),
            "origin_hijacked": _origin_hijacked,
            "forge_hijacked": _forge_hijacked,
            "origin_hijacking": hijack_results.get("origin_hijacking", []),
            "forge_hijacking": hijack_results.get("forge_hijacking", []),
            "mitm_alerts": mitm_results.get("mitm_alerts", []),
            "mitm_detection_success": mitm_results.get("success", False),
            "mitm_detection_error": mitm_results.get("error"),
            "leak_analysis": leak_result if isinstance(leak_result, dict) else {"success": False},
            "route_leaks": leak_result.get("route_leaks", []) if isinstance(leak_result, dict) else [],
            "leak_count": leak_result.get("leak_count", 0) if isinstance(leak_result, dict) else 0,
            "leak_detection_success": leak_result.get("success", False) if isinstance(leak_result, dict) else False,
            "leak_detection_error": leak_result.get("error") if isinstance(leak_result, dict) else None,
            "leak_data_source": leak_result.get("data_source", "csv_streaming") if isinstance(leak_result, dict) else "no_data",
            "outage_analysis": outage_result,
            "as_rel_file": hijack_results.get("as_rel_file"),
            "prefix2as_file": hijack_results.get("prefix2as_file"),
            "asorg_file": hijack_results.get("asorg_file"),
            "total_prefix_hijacks": len(_origin_hijacked) + len(_forge_hijacked),
            "total_prefix_hijacking": len(hijack_results.get("origin_hijacking", [])) + len(hijack_results.get("forge_hijacking", [])),
            "total_mitm_alerts": len(mitm_results.get("mitm_alerts", [])),
            "outage_suspected": bool(outage_result.get("is_outage_suspected", False)),
            "outage_score": _outage_score,
        }

        if use_llm:
            llm_agent = LLMEnhancedRoutingAgent(model=MODEL, api_key=API_KEY, base_url=BASE_URL)
            combined_results = await llm_agent.analyze_routing_with_llm(combined_results, asn, start_time, end_time)

        return combined_results

    except Exception as e:
        logger.error(f"Routing agent error: {str(e)}")
        return {"success": False, "error": str(e), "asn": asn}


def run_routing_agent_with_llm(asn, start_time, end_time):
    import asyncio
    return asyncio.run(run_routing_agent_async(asn, start_time, end_time, use_llm=True))


__all__ = ["run_routing_agent", "run_routing_agent_async", "run_routing_agent_with_llm", "LLMEnhancedRoutingAgent"]
