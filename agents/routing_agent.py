import os
import sys
import json
from typing import Dict, Any, List
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.append((os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from tools.hijack_detector import detect_hijacks
from tools.leak_detector import analyze_leak_surface
from tools.outage_detector import RouteOutageDetector
from utils.logger import logger
from llm.llm_factory import setup_llm_settings
from config import BASE_URL, API_KEY, MODEL


OUTAGE_DETECTOR = RouteOutageDetector()


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
            timeout=60.0,
            max_retries=2
        )
    
    async def analyze_routing_with_llm(
        self,
        routing_results,
        asn,
        start_time,
        end_time
    ):
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
        
        # Generate LLM insights
        llm_insights = await self._generate_llm_insights(analysis_data)
        
        # Enhance result with LLM analysis
        enhanced_result = {
            **routing_results,
            "llm_enhanced": True,
            "llm_insights": llm_insights,
            "analysis_timestamp": datetime.now().isoformat()
        }
        
        return enhanced_result
    
    async def _generate_llm_insights(self, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
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

Please provide the following analysis:

1. **Attack Pattern Analysis**:
   - Describe the types of attacks detected
   - Identify any patterns in the attack methods
   - Assess the sophistication of the attacks

2. **Attack Correlation**:
   - Analyze relationships between different attack types
   - Identify if there are coordinated attacks
   - Determine the scope and scale of the attacks

3. **Impact Assessment**:
   - Evaluate the impact on network security
   - Assess potential data breach risks
   - Estimate service disruption impact

4. **Attacker Attribution**:
   - Analyze the source of attacks
   - Identify suspicious AS patterns
   - Provide attribution insights

5. **Mitigation Recommendations**:
   - Provide specific security recommendations
   - Suggest immediate response actions
   - Recommend long-term preventive measures

6. **Risk Assessment**:
   - Assess the risk level of current situation
   - Predict potential future attacks
   - Provide threat intelligence insights

Please return the analysis result in JSON format with the following fields:
- attack_pattern_analysis: Attack pattern description
- attack_correlation: Attack correlation analysis
- impact_assessment: Impact evaluation
- attacker_attribution: Attribution insights
- mitigation_recommendations: Specific recommendations
- risk_assessment: Risk level and threat intelligence
- confidence_level: Analysis confidence level (0-1)
- key_findings: List of key findings
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
            try:
                preview = (raw[:500] if 'raw' in locals() else '')
            except Exception:
                preview = ''
            logger.error(f"LLM routing analysis failed: {e}. Raw preview: {preview}")
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
        
        for updates_df in get_updates_streaming(start_dt, end_dt):
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
            
            # Ensure timestamp column is string to avoid pandas auto-parsing issues
            if 'timestamp' in updates_df.columns:
                updates_df['timestamp'] = updates_df['timestamp'].astype(str)
            
            # Check for fake connections
            updates_df = check_fake_connections_in_df(updates_df, as_relationships)
            
            # Process messages with fake connections
            fake_connection_messages = updates_df[updates_df['has_fake_connect'] == True]
            
            for _, row in fake_connection_messages.iterrows():
                as_path = row.get('as-path', '')
                exact_fake_connections = row.get('exact_fake_connect', '')
                timestamp_raw = row.get('timestamp', '')
                prefix = row.get('prefix', '')
                
                # Convert timestamp to datetime object (handle both Unix timestamp and formatted string)
                try:
                    if isinstance(timestamp_raw, (int, float)) or (isinstance(timestamp_raw, str) and timestamp_raw.isdigit()):
                        # Unix timestamp (seconds)
                        timestamp_dt = datetime.fromtimestamp(float(timestamp_raw), tz=timezone.utc)
                        timestamp_str = timestamp_dt.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        # Already formatted string
                        timestamp_str = str(timestamp_raw)
                        timestamp_dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                except Exception as e:
                    logger.warning(f"Error parsing timestamp '{timestamp_raw}': {e}")
                    continue
                
                if exact_fake_connections:
                    # Parse fake connections
                    fake_connections = exact_fake_connections.split(';')
                    for fake_conn in fake_connections:
                        if fake_conn:
                            # Track connection frequency
                            if fake_conn not in connection_frequency_map:
                                connection_frequency_map[fake_conn] = []
                            connection_frequency_map[fake_conn].append({
                                'timestamp': timestamp_str,
                                'timestamp_dt': timestamp_dt,
                                'prefix': prefix,
                                'as_path': as_path
                            })
        
        # Analyze connection frequency over the past week
        week_ago = start_dt - timedelta(days=7)
        
        legitimate_connections = set()
        suspicious_connections = set()
        
        def parse_timestamp(ts_str):
            """Helper to parse timestamp string to datetime"""
            try:
                if isinstance(ts_str, datetime):
                    return ts_str
                return datetime.strptime(str(ts_str), "%Y-%m-%d %H:%M:%S")
            except Exception:
                # Try Unix timestamp
                try:
                    return datetime.fromtimestamp(float(ts_str), tz=timezone.utc)
                except Exception:
                    logger.warning(f"Failed to parse timestamp: {ts_str}")
                    return None
        
        for connection, occurrences in connection_frequency_map.items():
            # Count occurrences in the past week
            week_occurrences = []
            for occ in occurrences:
                ts_dt = occ.get('timestamp_dt') or parse_timestamp(occ['timestamp'])
                if ts_dt and ts_dt >= week_ago:
                    week_occurrences.append(occ)
            
            if len(week_occurrences) >= 5:  # Threshold for legitimate connection
                legitimate_connections.add(connection)
            else:
                suspicious_connections.add(connection)
        
        # Generate alerts for suspicious connections
        for connection in suspicious_connections:
            occurrences = connection_frequency_map[connection]
            recent_occurrences = []
            for occ in occurrences:
                ts_dt = occ.get('timestamp_dt') or parse_timestamp(occ['timestamp'])
                if ts_dt and ts_dt >= start_dt:
                    recent_occurrences.append(occ)
            
            if recent_occurrences:
                # Aggregate messages with this fake connection
                aggregated_prefixes = set()
                aggregated_paths = []
                
                for occ in recent_occurrences:
                    aggregated_prefixes.add(occ['prefix'])
                    aggregated_paths.append(occ['as_path'])
                
                # Count week frequency
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
                    'affected_paths': aggregated_paths[:5],  # Limit to first 5 paths
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


def run_routing_agent(asn, start_time, end_time, target_asns: List[str] | None = None):
    """
    Run routing analysis for specified AS and time period.
    
    Args:
        asn: Primary AS number
        start_time: Start time string (format: "YYYY-MM-DD HH:MM")
        end_time: End time string (format: "YYYY-MM-DD HH:MM")
        target_asns: List of AS numbers to filter route leak detection.
                    Only messages containing these ASNs will be analyzed for leaks.
                    If None, analyzes all messages (backward compatibility).
    
    Returns:
        Dictionary with routing analysis results
    """
    try:
        start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M")
        end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M")
        
        logger.info(f"🔍 Starting routing analysis for AS{asn} from {start_time} to {end_time}")
        if target_asns:
            logger.info(f"   Filtering route leak detection for AS paths containing: {target_asns}")
        
        hijack_results = detect_hijacks(
            start_dt,
            end_dt,
            asn,
            validate_with_updates=False  # disable historical validation for performance
        )
        
        if not hijack_results.get("success"):
            return hijack_results
        
        mitm_results = {
            'success': True,
            'mitm_alerts': [],
            'note': 'MITM detection integrated into hijack detection process'
        }
        
        # 2. Route leak detection (PathProb-based) - only analyze messages containing target ASNs
        leak_result = analyze_leak_surface(asn, start_time, end_time, target_asns=target_asns)
        
        # 3. Outage detection (timeseries-based BGP outage detector)
        logger.info("🔍 Running outage detector module...")
        outage_result = OUTAGE_DETECTOR.analyze(asn, start_time, end_time)
        logger.info(
            "📊 Outage detector result: success=%s, is_outage_suspected=%s, score=%s",
            outage_result.get("success", False),
            outage_result.get("is_outage_suspected"),
            outage_result.get("outage_score"),
        )
        
        # Combine results from three independent modules
        combined_results = {
            "success": True,
            "asn": asn,
            "analysis_period": f"{start_time} to {end_time}",
            "analysis_timestamp": datetime.now().isoformat(),
            
            # 1. Hijack detection results
            "origin_hijacked": hijack_results.get("origin_hijacked", []),
            "forge_hijacked": hijack_results.get("forge_hijacked", []),
            "origin_hijacking": hijack_results.get("origin_hijacking", []),
            "forge_hijacking": hijack_results.get("forge_hijacking", []),
            
            # MITM detection results (integrated in hijack detection)
            "mitm_alerts": mitm_results.get("mitm_alerts", []),
            "mitm_detection_success": mitm_results.get("success", False),
            "mitm_detection_error": mitm_results.get("error"),
            
            # 2. Route leak detection results (independent module)
            "route_leaks": leak_result.get("route_leaks", []),
            "leak_count": leak_result.get("leak_count", 0),
            "leak_detection_success": leak_result.get("success", False),
            "leak_detection_error": leak_result.get("error"),
            
            # 3. Outage detection results (independent module)
            "outage_analysis": outage_result,
            
            # Data file paths
            "as_rel_file": hijack_results.get("as_rel_file"),
            "prefix2as_file": hijack_results.get("prefix2as_file"),
            "asorg_file": hijack_results.get("asorg_file"),
            
            # Summary statistics
            "total_prefix_hijacks": len(hijack_results.get("origin_hijacked", [])) + len(hijack_results.get("forge_hijacked", [])),
            "total_prefix_hijacking": len(hijack_results.get("origin_hijacking", [])) + len(hijack_results.get("forge_hijacking", [])),
            "total_mitm_alerts": len(mitm_results.get("mitm_alerts", [])),
            # Normalize outage fields so they are never None for downstream HTML/report logic
            "outage_suspected": bool(outage_result.get("is_outage_suspected", False)),
            "outage_score": float(outage_result.get("outage_score", 0.0)) if outage_result.get("success") else 0.0,
        }
        
        logger.info(
            "✅ Routing analysis completed: %s prefix hijacks, %s MITM alerts, %s route leaks, outage=%s",
            combined_results["total_prefix_hijacks"],
            combined_results["total_mitm_alerts"],
            combined_results["leak_count"],
            combined_results["outage_suspected"],
        )
        
        return combined_results
        
    except Exception as e:
        logger.error(f"Routing agent error: {str(e)}")
        return {"success": False, "error": str(e), "asn": asn}

async def run_routing_agent_async(asn, start_time, end_time, use_llm = True):

    try:
        start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M")
        end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M")
        
        logger.info(f"Starting routing analysis for AS{asn} from {start_time} to {end_time}")
        
        hijack_results = detect_hijacks(
            start_dt,
            end_dt,
            asn,
            validate_with_updates=False  # enable historical validation
        )
        
        if not hijack_results.get("success"):
            return hijack_results
        
        mitm_results = {
            'success': True,
            'mitm_alerts': [],
            'note': 'MITM detection integrated into hijack detection process'
        }
        leak_result = analyze_leak_surface(asn, start_time, end_time)
        outage_result = OUTAGE_DETECTOR.analyze(asn, start_time, end_time)
        
        # Combine basic results
        combined_results = {
            "success": True,
            "asn": asn,
            "analysis_period": f"{start_time} to {end_time}",
            "analysis_timestamp": datetime.now().isoformat(),
            "origin_hijacked": hijack_results.get("origin_hijacked", []),
            "forge_hijacked": hijack_results.get("forge_hijacked", []),
            "origin_hijacking": hijack_results.get("origin_hijacking", []),
            "forge_hijacking": hijack_results.get("forge_hijacking", []),
            "mitm_alerts": mitm_results.get("mitm_alerts", []),
            "mitm_detection_success": mitm_results.get("success", False),
            "mitm_detection_error": mitm_results.get("error"),
            "leak_analysis": leak_result,
            "outage_analysis": outage_result,
            "as_rel_file": hijack_results.get("as_rel_file"),
            "prefix2as_file": hijack_results.get("prefix2as_file"),
            "asorg_file": hijack_results.get("asorg_file"),
            "total_prefix_hijacks": len(hijack_results.get("origin_hijacked", [])) + len(hijack_results.get("forge_hijacked", [])),
            "total_prefix_hijacking": len(hijack_results.get("origin_hijacking", [])) + len(hijack_results.get("forge_hijacking", [])),
            "total_mitm_alerts": len(mitm_results.get("mitm_alerts", [])),
            "outage_suspected": outage_result.get("is_outage_suspected", False),
            "outage_score": outage_result.get("outage_score"),
        }
        
        # Apply LLM enhancement if requested
        if use_llm:
            logger.info("Enhancing routing analysis with LLM insights")
            llm_agent = LLMEnhancedRoutingAgent()
            combined_results = await llm_agent.analyze_routing_with_llm(
                combined_results, asn, start_time, end_time
            )
        
        logger.info(f"Routing analysis completed")
        return combined_results
        
    except Exception as e:
        logger.error(f"Routing agent error: {str(e)}")
        return {"success": False, "error": str(e), "asn": asn}


def run_routing_agent_with_llm(asn: str, start_time: str, end_time: str) -> Dict[str, Any]:
    """Synchronous wrapper for LLM-enhanced routing agent"""
    import asyncio
    return asyncio.run(run_routing_agent_async(asn, start_time, end_time, use_llm=True))


__all__ = ["run_routing_agent", "run_routing_agent_async", "run_routing_agent_with_llm", "LLMEnhancedRoutingAgent"]


