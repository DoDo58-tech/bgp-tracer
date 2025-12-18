import os
import sys
import json
import asyncio
import re
from datetime import datetime
from time import perf_counter
from pathlib import Path
from typing import Dict, Any, List

from agents.reasoning_agent import run_reasoning_agent
from agents.analysis_agent import run_analysis_agent
from data.asorg_loader import process_asorg
from llm.llm_factory import setup_llm_settings
from llama_index.core.agent.workflow import ReActAgent, AgentStream, ToolCallResult
from llama_index.core.tools import FunctionTool

sys.path.append((os.path.dirname(os.path.abspath(__file__))))
from utils.logger import logger
from utils.helpers import make_json_safe
from utils.report_generator import generate_comprehensive_report, generate_batch_html_report
from config import BASE_URL, API_KEY, MODEL, LOG_FILE, USE_DIRECT_MODE
from agents.coordination_utils import (
    lookup_org_info,
    normalize_time,
    query_as_relationships as util_query_as_relationships,
    query_as_prefixes as util_query_as_prefixes,
    generate_integrated_report as util_generate_integrated_report,
)

PROJECT_ROOT = Path(os.path.dirname(os.path.abspath(__file__)))


class ChiefExpertAgent:
    def __init__(self, model, api_key, base_url):
        self.model = model
        self.api_key = api_key
        self.base_url = base_url
        self.llm = None
        self.token_counter = None
        self.reasoning_trace = []
        self.asrel_file = None
        self.prefix2as_file = None
        self.asorg_file = None
        self.tool_call_counts = {
            'invoke_reasoning_expert': 0
        }
        
    def _wrapped_reasoning_agent(self, asn, start_time, end_time, user_input, **kwargs):
        if self.tool_call_counts['invoke_reasoning_expert'] > 0:
            return {
                "success": False,
                "error": "Reasoning analysis already completed. Do not call this tool again.",
                "asn": asn,
                "analysis_period": f"{start_time} to {end_time}"
            }
        
        self.tool_call_counts['invoke_reasoning_expert'] += 1
        logger.info(f"🔧 Executing reasoning analysis (call #{self.tool_call_counts['invoke_reasoning_expert']})")
        
        if hasattr(self, '_current_asn') and hasattr(self, '_current_start_time') and hasattr(self, '_current_end_time'):
            asn = self._current_asn
            start_time = self._current_start_time
            end_time = self._current_end_time
            logger.info(f"🔧 Using parsed parameters: AS{asn} from {start_time} to {end_time}")
            return run_reasoning_agent(asn, start_time, end_time)
        else:
            if user_input and not (asn and start_time and end_time):
                return run_reasoning_agent(user_input=user_input)
            else:
                return run_reasoning_agent(asn, start_time, end_time)
    
    def _wrapped_analysis_agent(self, traffic_analysis: Dict[str, Any], routing_analysis: Dict[str, Any], user_input: str = None, **kwargs) -> Dict[str, Any]:
        logger.info(f"🔧 Executing comprehensive analysis agent")
        return run_analysis_agent(traffic_analysis, routing_analysis, user_input)
        
    async def setup_llm(self):
        self.llm, self.token_counter = setup_llm_settings(
            model=self.model,
            api_key=self.api_key,
            base_url=self.base_url,
            temperature=0.1, 
            timeout=120.0,
            max_retries=2
        )
        
    def create_agent_tools(self):
        return [
            FunctionTool.from_defaults(
                fn=self._wrapped_reasoning_agent,
                name="invoke_reasoning_expert",
                description="Invoke multi-round reasoning expert for comprehensive BGP analysis. Performs traffic analysis first, then routing analysis to determine if traffic changes are related to routing issues (CALL ONCE ONLY)"
            ),
            FunctionTool.from_defaults(
                fn=self._wrapped_analysis_agent,
                name="invoke_analysis_expert",
                description="Invoke comprehensive analysis expert to generate final report integrating traffic and routing analysis"
            ),
            FunctionTool.from_defaults(
                fn=self._query_as_organization,
                name="query_as_organization",
                description="Query organization information for any ASN using the asorg data file"
            ),
            FunctionTool.from_defaults(
                fn=self._query_as_relationships,
                name="query_as_relationships",
                description="Query provider/peer/customer relationships for any ASN using the asrel data file"
            ),
            FunctionTool.from_defaults(
                fn=self._query_as_prefixes,
                name="query_as_prefixes",
                description="Query legal prefixes owned by any ASN using the prefix2as data file"
            ),
            FunctionTool.from_defaults(
                fn=self._generate_integrated_report,
                name="generate_final_report",
                description="Generate comprehensive integrated analysis report from all expert inputs"
            )
        ]
    
    def _load_data_from_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load data from {file_path}: {e}")
            return {}
    
    def _query_as_organization(self, asn):
        logger.info(f"🔍 query_as_organization called for ASN {asn}")
        logger.info(f"📁 Current asorg_file: {self.asorg_file}")
        if not self.asorg_file:
            return {"success": False, "error": "AS organization data file not available", "asn": asn}
        return lookup_org_info(str(asn), self.asorg_file)
    
    def _query_as_relationships(self, asn):
        return util_query_as_relationships(str(asn), self.asrel_file)
    
    def _query_as_prefixes(self, asn):
        return util_query_as_prefixes(str(asn), self.prefix2as_file)
    
    async def _generate_integrated_report(
        self,
        routing_analysis,
        traffic_analysis,
        law_analysis,
        start_time,
        reasoning_analysis,
        asn,
        output_dir,
        org_name,
        **kwargs,
    ):
        if output_dir is None:
            output_dir = PROJECT_ROOT / "results" / "html"
        
        # If org_name was not passed in, try to resolve it from AS-org data.
        if org_name is None:
            try:
                asn_info = (
                    asn
                    or getattr(self, "_current_asn", None)
                    or (routing_analysis or {}).get("asn")
                    or (traffic_analysis or {}).get("asn")
                    or (reasoning_analysis or {}).get("asn")
                )
                logger.info(
                    f"🔧 ASN extraction debug: asn={asn}, "
                    f"_current_asn={getattr(self, '_current_asn', None)}, "
                    f"asn_info={asn_info}"
                )
                if asn_info and self.asorg_file:
                    org_info = lookup_org_info(str(asn_info), self.asorg_file)
                    if org_info.get("success"):
                        org_name = org_info.get("org_name")
            except Exception:
                # Non-fatal: org name is optional for report generation.
                pass

        actual_reasoning_analysis = reasoning_analysis or getattr(
            self, "reasoning_analysis_result", None
        )
        
        if isinstance(actual_reasoning_analysis, str):
            try:
                actual_reasoning_analysis = json.loads(actual_reasoning_analysis)
            except Exception:
                try:
                    actual_reasoning_analysis = eval(actual_reasoning_analysis)
                except Exception:
                    logger.warning(
                        "🔍 Could not parse reasoning_analysis_result string, using None"
                    )
                    actual_reasoning_analysis = None
        
        if self.llm is None:
            await self.setup_llm()
        
        asn_info = (
            asn
            or getattr(self, "_current_asn", None)
            or (routing_analysis or {}).get("asn")
            or (traffic_analysis or {}).get("asn")
            or (reasoning_analysis or {}).get("asn")
        )
        
        return await generate_comprehensive_report(
            llm=self.llm,
            routing_analysis=routing_analysis,
            traffic_analysis=traffic_analysis,
            law_analysis=law_analysis,
            reasoning_analysis=actual_reasoning_analysis,
            start_time=start_time,
            output_dir=output_dir,
            org_name=org_name,
            asn=asn_info,
            fallback_report_func=util_generate_integrated_report,
        )
    
    
    
    async def coordinate_analysis(self, user_input, asn, start_time, end_time) -> Dict[str, Any]:
        logger.info(f"🎯 Chief Expert Agent starting coordination for traffic outage analysis")
        _t0 = perf_counter()
        event_start_time = datetime.now()
        
        if user_input and not (asn and start_time and end_time):
            from agents.traffic_agent import (
                parse_traffic_outage_input,
                parse_country_region_input,
                parse_multiple_as_input,
                lookup_as_by_country,
            )
            from agents.reasoning_agent import run_reasoning_agent_batch
            
            # Try parsing multiple AS first
            as_list, multi_start, multi_end = parse_multiple_as_input(user_input)
            
            # If multiple AS found, enter batch mode
            if as_list and len(as_list) > 1:
                logger.info(f"Detected multiple AS input: {', '.join([f'AS{a}' for a in as_list])}")
                
                if len(as_list) > 10:
                    return {
                        "success": False,
                        "error": f"Too many AS numbers ({len(as_list)}). Please select up to 10 AS for batch analysis.",
                        "user_input": user_input,
                        "detected_as_list": as_list
                    }
                
                if not (multi_start and multi_end):
                    return {
                        "success": False,
                        "error": "Time period required for batch analysis. Please provide start and end times.",
                        "user_input": user_input,
                        "detected_as_list": as_list
                    }
                
                # Execute batch analysis
                logger.info(f"Entering BATCH ANALYSIS mode for {len(as_list)} AS")
                batch_result = run_reasoning_agent_batch(
                    as_list=as_list,
                    start_time=normalize_time(multi_start),
                    end_time=normalize_time(multi_end)
                )
                
                # Generate single batch HTML report
                html_report_path = None
                if batch_result.get("success"):
                    logger.info("Generating batch HTML report...")
                    try:
                        from utils.report_generator import generate_batch_html_report
                        html_report_path = generate_batch_html_report(
                            batch_result={"batch_result": batch_result},
                            start_time=normalize_time(multi_start),
                            end_time=normalize_time(multi_end),
                            output_dir=PROJECT_ROOT / "results"
                        )
                        if html_report_path:
                            logger.info(f"✅ Generated batch HTML report: {html_report_path}")
                    except Exception as e:
                        logger.warning(f"Failed to generate batch HTML report: {e}")
                
                return {
                    "success": True,
                    "batch_mode": True,
                    "analysis_type": "multi_as_batch_analysis",
                    "as_count": len(as_list),
                    "as_list": as_list,
                    "batch_result": batch_result,
                    "html_report_path": html_report_path,
                    "user_input": user_input
                }
            
            # Fall back to single AS parsing
            parsed_asn, parsed_start, parsed_end = parse_traffic_outage_input(user_input)

            if parsed_asn:
                if not parsed_start or not parsed_end:
                    return {
                        "success": False,
                        "error": "Could not extract time period from input. Please provide start and end times explicitly.",
                        "user_input": user_input,
                        "parsed_asn": parsed_asn,
                    }
                asn = parsed_asn
                start_time = normalize_time(parsed_start)
                end_time = normalize_time(parsed_end)
            else:
                country_region, c_start, c_end, c_asn = parse_country_region_input(user_input)
                if c_asn:
                    asn = c_asn
                    start_time = normalize_time(c_start) if c_start else c_start
                    end_time = normalize_time(c_end) if c_end else c_end
                else:
                    try:
                        target_dt = None
                        if c_start:
                            try:
                                target_dt = datetime.strptime(normalize_time(c_start), "%Y-%m-%d %H:%M")
                            except Exception:
                                target_dt = datetime.now()
                        else:
                            target_dt = datetime.now()
                        asorg_parsed_path = process_asorg(target_dt)
                        if asorg_parsed_path:
                            self.asorg_file = asorg_parsed_path
                            logger.info(f"📁 Prepared AS-ORG file for country lookup: {self.asorg_file}")
                        else:
                            logger.warning("AS-ORG preparation returned empty path; country lookup may fail.")
                    except Exception as e:
                        logger.warning(f"Failed to prepare AS-ORG data: {e}")

                    start_time = c_start or start_time
                    end_time = c_end or end_time

                    try:
                        if self.asorg_file and country_region:
                            matches = lookup_as_by_country(country_region, self.asorg_file)
                            
                            if matches:
                                as_count = len(matches)
                                logger.info(f"Found {as_count} AS for {country_region}")
                                
                                # Batch analysis mode: handle up to 10 AS automatically
                                if as_count <= 10:
                                    logger.info(f"Entering BATCH ANALYSIS mode for {as_count} AS")
                                    as_list = [m['asn'] for m in matches]
                                    
                                    # Normalize time format
                                    if c_start and c_end:
                                        batch_start = normalize_time(c_start)
                                        batch_end = normalize_time(c_end)
                                    else:
                                        return {
                                            "success": False,
                                            "error": "Time period required for batch analysis",
                                            "country_region": country_region,
                                            "matching_asns": matches
                                        }
                                    
                                    # Execute batch analysis
                                    logger.info(f"Executing batch reasoning analysis for: {', '.join([f'AS{a}' for a in as_list])}")
                                    batch_result = run_reasoning_agent_batch(
                                        as_list=as_list,
                                        start_time=batch_start,
                                        end_time=batch_end
                                    )
                                    
                                    # Generate single batch HTML report
                                    html_report_path = None
                                    if batch_result.get("success"):
                                        logger.info("Generating batch HTML report...")
                                        try:
                                            from utils.report_generator import generate_batch_html_report
                                            html_report_path = generate_batch_html_report(
                                                batch_result={"batch_result": batch_result},
                                                start_time=batch_start,
                                                end_time=batch_end,
                                                output_dir=PROJECT_ROOT / "results"
                                            )
                                            if html_report_path:
                                                logger.info(f"✅ Generated batch HTML report: {html_report_path}")
                                        except Exception as e:
                                            logger.warning(f"Failed to generate batch HTML report: {e}")
                                    
                                    # Return batch results
                                    return {
                                        "success": True,
                                        "batch_mode": True,
                                        "analysis_type": "country_batch_analysis",
                                        "country_region": country_region,
                                        "as_count": as_count,
                                        "batch_result": batch_result,
                                        "html_report_path": html_report_path,
                                        "user_input": user_input
                                    }
                                
                                # Too many AS: prompt user to select
                                else:
                                    as_list = [
                                        f"AS{m['asn']} ({m.get('as_name','Unknown')})"
                                        for m in matches[:20]
                                    ]
                                return {
                                    "success": False,
                                        "error": (
                                            f"Too many AS numbers found for {country_region} "
                                            f"({as_count} AS). Please select up to 10 AS for batch analysis. "
                                            "Top 20: " + ", ".join(as_list)
                                        ),
                                    "user_input": user_input,
                                    "country_region": country_region,
                                    "matching_asns": matches,
                                        "total_count": as_count,
                                    "requires_user_selection": True,
                                        "hint": (
                                            "You can provide specific AS numbers like: "
                                            "'analyze AS13335, AS16010 for ...'"
                                        ),
                                }
                    except Exception as e:
                        logger.warning(f"Early country lookup failed (non-fatal): {e}")
        
        if user_input:
            if not (start_time and end_time):
                return {
                    "success": False,
                    "error": "Missing required parameters: start_time, end_time",
                    "hint": "Provide time period in the input or via --start/--end",
                }
        else:
            if not all([asn, start_time, end_time]):
                return {
                    "success": False,
                    "error": "Missing required parameters: asn, start_time, end_time"
                }
        
        logger.info(f"🎯 Analyzing traffic outage for AS{asn} from {start_time} to {end_time}")
        
        self._current_asn = asn
        self._current_start_time = start_time
        self._current_end_time = end_time
        
        # Use direct analysis flow (streaming mode is disabled)
        # Direct flow ensures outage detection is called via run_reasoning_agent -> run_routing_agent
        if USE_DIRECT_MODE:
            logger.info("📊 Using direct analysis flow: Direct function calls")
            result = await self._direct_analysis_flow(asn, start_time, end_time, user_input)
        else:
            logger.info("🤔 Attempting ReActAgent coordination mode: LLM autonomous decision making")
            try:
                result = await self._react_agent_flow(asn, start_time, end_time, user_input)
            except RuntimeError as e:
                if "Streaming coordination mode is disabled" in str(e):
                    logger.warning("⚠️  ReActAgent mode disabled, falling back to direct analysis flow")
                    result = await self._direct_analysis_flow(asn, start_time, end_time, user_input)
                else:
                    raise
        
        # Calculate and log total execution time
        _t1 = perf_counter()
        total_elapsed = _t1 - _t0
        event_end_time = datetime.now()
        total_duration = (event_end_time - event_start_time).total_seconds()
        
        logger.info(f"⏱️  Total event execution time: {total_duration:.2f} seconds ({total_duration/60:.2f} minutes)")
        logger.info(f"⏱️  Total coordination time: {total_elapsed:.2f} seconds ({total_elapsed/60:.2f} minutes)")
        
        # Add timing information to result
        if isinstance(result, dict):
            result["execution_time_seconds"] = total_duration
            result["execution_time_minutes"] = total_duration / 60
            result["coordination_time_seconds"] = total_elapsed
            result["event_start_time"] = event_start_time.isoformat()
            result["event_end_time"] = event_end_time.isoformat()
        
        return result
    
    async def _direct_analysis_flow(self, asn: str, start_time: str, end_time: str, user_input: str = None) -> Dict[str, Any]:
        _t0 = perf_counter()
        
        try:
            # Step 1: Directly call reasoning_agent to execute detection
            logger.info("📊 Step 1: Executing traffic and routing detection...")
            reasoning_result = run_reasoning_agent(
                asn=asn,
                start_time=start_time,
                end_time=end_time,
                user_input=user_input
            )
            
            self.reasoning_analysis_result = reasoning_result
            
            if isinstance(reasoning_result, dict):
                self.asrel_file = reasoning_result.get("as_rel_file")
                self.prefix2as_file = reasoning_result.get("prefix2as_file")
                self.asorg_file = reasoning_result.get("asorg_file")
            
            logger.info(f"✅ Detection completed: {reasoning_result.get('success', False)}")
            
            if not reasoning_result.get("success", False):
                error_msg = reasoning_result.get("error", "Unknown error")
                logger.error(f"❌ Reasoning agent failed: {error_msg}")
                raise RuntimeError(f"Reasoning agent detection failed: {error_msg}")
            
            # Step 2: Query AS organization information (optional)
            logger.info("📋 Step 2: Querying AS organization information...")
            org_info = {}
            if self.asorg_file:
                org_info = lookup_org_info(str(asn), self.asorg_file)
            
            relationships = {}
            prefixes = {}
            if self.asrel_file:
                relationships = util_query_as_relationships(str(asn), self.asrel_file)
            if self.prefix2as_file:
                prefixes = util_query_as_prefixes(str(asn), self.prefix2as_file)
            
            # Step 3: Use LLM to analyze results and generate report
            logger.info("🧠 Step 3: LLM analyzing results and generating report...")
            await self.setup_llm()
            
            evidence_summary = reasoning_result.get("evidence_summary", {})
            traffic_data = evidence_summary.get("traffic_data", {})
            routing_data = evidence_summary.get("routing_data", {})
            
            report_result = await self._generate_integrated_report(
                routing_analysis=routing_data,
                traffic_analysis=traffic_data,
                law_analysis=None,
                reasoning_analysis=reasoning_result,
                start_time=start_time,
                output_dir=PROJECT_ROOT / "results" / "html",
                org_name=org_info.get("org_name") if org_info.get("success") else None,
                asn=asn,
            )
            
            _elapsed = perf_counter() - _t0
            
            tokens_used = 0
            try:
                # 1. Get token usage from reasoning_result
                reasoning_token_usage = reasoning_result.get("token_usage", {})
                if isinstance(reasoning_token_usage, dict):
                    if "total_across_agents" in reasoning_token_usage:
                        tokens_used += reasoning_token_usage["total_across_agents"]
                        logger.info(f"📊 Token from reasoning_result: {tokens_used} (total_across_agents)")
                    else:
                        reasoning_agent_tokens = reasoning_token_usage.get("reasoning_agent", {})
                        if isinstance(reasoning_agent_tokens, dict):
                            tokens_used += reasoning_agent_tokens.get("total", 0)
                        elif isinstance(reasoning_agent_tokens, int):
                            tokens_used += reasoning_agent_tokens
                        
                        routing_agent_tokens = reasoning_token_usage.get("routing_agent", {})
                        if isinstance(routing_agent_tokens, dict):
                            tokens_used += routing_agent_tokens.get("total_tokens", 0)
                        elif isinstance(routing_agent_tokens, int):
                            tokens_used += routing_agent_tokens
                        
                        traffic_agent_tokens = reasoning_token_usage.get("traffic_agent", {})
                        if isinstance(traffic_agent_tokens, dict):
                            tokens_used += traffic_agent_tokens.get("total_tokens", 0)
                        elif isinstance(traffic_agent_tokens, int):
                            tokens_used += traffic_agent_tokens
                
                # 2. Get current LLM token usage from token_counter (used for report generation)
                if self.token_counter:
                    try:
                        current_tokens = self.token_counter.total_llm_token_count
                        if current_tokens > 0:
                            if tokens_used == 0 or current_tokens > tokens_used:
                                tokens_used = max(tokens_used, current_tokens)
                    except Exception as e:
                        logger.debug(f"Failed to get token_counter: {e}")
                
                if tokens_used == 0:
                    logger.warning("⚠️ Cannot get accurate token usage")
                else:
                    logger.info(f"✅ Token usage statistics completed: Total={tokens_used}")
                
            except Exception as e:
                logger.warning(f"⚠️ Token counting failed: {e}", exc_info=True)
            
            formatted_trace = []
            reasoning_trace_entries = reasoning_result.get("reasoning_trace", [])
            if isinstance(reasoning_trace_entries, list) and reasoning_trace_entries:
                for idx, entry in enumerate(reasoning_trace_entries):
                    formatted_trace.append({
                        "step": idx,
                        "action": "reasoning_agent",
                        "observation": entry,
                        "timestamp": datetime.now().isoformat()
                    })
            else:
                formatted_trace.append({
                    "step": 0,
                    "action": "DirectCall",
                    "observation": "Directly called reasoning_agent to execute detection",
                    "timestamp": datetime.now().isoformat()
                })
            
            return {
                "chief_expert_analysis": {
                    "coordination_summary": "Direct call mode: Detection completed, LLM analysis completed",
                    "analysis_method": "Direct Analysis Flow (No ReActAgent)",
                    "target_as": asn,
                    "time_range": f"{start_time} to {end_time}",
                    "analysis_timestamp": datetime.now().isoformat(),
                    "llm_model": self.model,
                    "coordination_strategy": "Direct function calls + LLM result analysis",
                    "elapsed_seconds": round(_elapsed, 3),
                },
                "token_count": tokens_used,
                "reasoning_result": reasoning_result,
                # For CLI and downstream tools, expose the integrated report as analysis_report
                "analysis_report": report_result,
                # Keep original key for backward compatibility
                "report_result": report_result,
                "org_info": org_info,
                "relationships": relationships,
                "prefixes": prefixes,
                "reasoning_trace": formatted_trace,
            }
            
        except Exception as e:
            logger.error(f"❌ Direct analysis flow failed: {e}", exc_info=True)
            raise RuntimeError(f"Direct analysis flow failed: {str(e)}")
    
    async def _react_agent_flow(self, asn: str, start_time: str, end_time: str, user_input: str = None) -> Dict[str, Any]:
        logger.debug("setup_llm start")
        await self.setup_llm()
        logger.debug("setup_llm done")
        
        logger.debug("create_agent_tools start")
        tools = self.create_agent_tools()
        logger.debug("create_agent_tools done")
        from llm.prompt import build_react_system_prompt
        system_prompt_template = build_react_system_prompt()
        system_prompt_str = system_prompt_template.template if hasattr(system_prompt_template, 'template') else str(system_prompt_template)
        
        logger.debug("ReActAgent initialization start")
        coordination_agent = ReActAgent(
            tools=tools,
            llm=self.llm,
            max_iterations=25,
            verbose=False, 
            system_prompt=system_prompt_str
        )
        logger.debug("ReActAgent initialization done")
        
        if user_input:
            mission_prompt = f"""Analyze a traffic outage incident based on user input: "{user_input}"

MANDATORY EXECUTION ORDER (DO NOT REPEAT ANY STEP):
1. FIRST: Call invoke_reasoning_expert with user_input="{user_input}" (ONCE ONLY)
   - This will perform multi-round reasoning analysis including LLM-enhanced traffic and routing analysis
   - The reasoning agent will first analyze traffic patterns with LLM insights, then routing security
   - This follows the project motivation: determine if traffic changes are related to routing issues
2. SECOND: After reasoning analysis completes, use query_as_organization, query_as_relationships, and query_as_prefixes for additional investigation
3. THIRD: Generate comprehensive HTML report with traffic diagrams and root cause analysis using generate_final_report

CRITICAL RULES:
- Call invoke_reasoning_expert EXACTLY ONCE
- Do NOT call individual traffic or routing experts separately
- The reasoning expert will handle the complete analysis workflow with LLM enhancements
- The reasoning expert will determine if traffic anomalies are related to routing issues (hijacking, MITM attacks)
- The final report will include traffic diagrams, routing analysis, and root cause analysis

OBJECTIVE: Use multi-round reasoning with LLM insights to determine if the traffic outage is related to routing issues or other factors.

Start with reasoning analysis now."""
        else:
            mission_prompt = f"""Analyze a traffic outage incident for AS{asn} from {start_time} to {end_time}.

MANDATORY EXECUTION ORDER (DO NOT REPEAT ANY STEP):
1. FIRST: Call invoke_reasoning_expert for AS{asn} from {start_time} to {end_time} (ONCE ONLY)
   - This will perform multi-round reasoning analysis including traffic and routing analysis
   - The reasoning agent will first analyze traffic patterns, then routing security
   - This follows the project motivation: determine if traffic changes are related to routing issues
2. SECOND: After reasoning analysis completes, use query_as_organization, query_as_relationships, and query_as_prefixes for additional investigation
3. THIRD: Generate final HTML report using generate_final_report

CRITICAL RULES:
- Call invoke_reasoning_expert EXACTLY ONCE
- Do NOT call individual traffic or routing experts separately
- The reasoning expert will handle the complete analysis workflow
- The reasoning expert will determine if traffic anomalies are related to routing issues (hijacking, MITM attacks)

OBJECTIVE: Use multi-round reasoning to determine if the traffic outage is related to routing issues or other factors.

Start with reasoning analysis now."""

        coordination_timeout = int(os.environ.get("CHIEF_COORDINATION_TIMEOUT", "900"))
        try:
            return await asyncio.wait_for(
                self._coordinate_with_streaming(coordination_agent, mission_prompt, asn, start_time, end_time),
                timeout=coordination_timeout
            )
        except asyncio.TimeoutError:
            logger.error(f"❌ Coordination timed out after {coordination_timeout} seconds")
            raise RuntimeError(
                f"Chief Expert coordination exceeded timeout ({coordination_timeout}s). "
                "Consider reducing mission complexity or increasing CHIEF_COORDINATION_TIMEOUT."
            )

    async def _coordinate_with_streaming(
        self,
        coordination_agent,
        mission_prompt: str,
        asn: str,
        start_time: str,
        end_time: str,
    ) -> Dict[str, Any]:
        """
        Streaming coordination path (ReAct-style agent).

        To simplify this build and avoid complex async event handling bugs,
        we currently do not support the streaming coordination mode.
        The project is configured to use direct mode (USE_DIRECT_MODE=True),
        so this function should not be invoked in normal workflows.
        """
        logger.error(
            "Streaming coordination mode (_coordinate_with_streaming) is disabled in this build. "
            "Set USE_DIRECT_MODE=True to rely on the direct analysis flow."
        )
        raise RuntimeError(
            "Streaming coordination mode is disabled in this build; "
            "use direct analysis flow instead."
        )


async def analyze_traffic_outage_async(user_input, asn, start_time, end_time):
    output_dir = PROJECT_ROOT / "results"
    output_dir.mkdir(exist_ok=True, parents=True)
    
    if asn and start_time:
        analysis_file = output_dir / "json" / f"traffic_outage_analysis_{asn}_{start_time.replace(' ', '_')}.json"
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        analysis_file = output_dir / "json" / f"traffic_outage_analysis_{timestamp}.json"
    
    logger.info(f"🎯 Starting Traffic Outage Analysis")
    if user_input:
        logger.info(f"📝 User Input: {user_input}")
    if asn:
        logger.info(f"🎯 Target ASN: AS{asn}")
    if start_time and end_time:
        logger.info(f"⏰ Time Period: {start_time} to {end_time}")
    
    try:
        chief_expert = ChiefExpertAgent(MODEL, API_KEY, BASE_URL)
        result = await chief_expert.coordinate_analysis(user_input, asn, start_time, end_time)
        
        result = make_json_safe(result)
        
        with open(analysis_file, "w", encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        logger.info(f"📄 Chief Expert analysis saved: {analysis_file}")
        
        return result
        
    except Exception as e:
        # Log full stack trace and re-raise original error so the real root cause is visible
        logger.error(f"Chief Expert analysis failed: {e}", exc_info=True)
        raise


def analyze_traffic_outage(user_input, asn, start_time, end_time) -> Dict[str, Any]:
    return asyncio.run(analyze_traffic_outage_async(user_input, asn, start_time, end_time))


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Traffic Outage Analysis - Chief Expert Agent Coordination")
    parser.add_argument("--user-input", help="Natural language input describing the traffic outage")
    parser.add_argument("--asn", help="AS number (overrides user input parsing)")
    parser.add_argument("--start", help="Start time (YYYY-MM-DD HH:MM) (overrides user input parsing)")
    parser.add_argument("--end", help="End time (YYYY-MM-DD HH:MM) (overrides user input parsing)")
    
    args = parser.parse_args()
    
    print(f"🎯 Traffic Outage Analysis")
    if args.user_input:
        print(f"User Input: {args.user_input}")
    if args.asn:
        print(f"Target: AS{args.asn}")
    if args.start and args.end:
        print(f"Time Period: {args.start} to {args.end}")
    print(f"LLM Model: {MODEL}")
    print("=" * 80)
    
    result = analyze_traffic_outage(args.user_input, args.asn, args.start, args.end)
    
    print(f"\n🧠 Traffic Outage Analysis Results:")
    print("=" * 80)
    
    if result.get('batch_mode'):
        # Batch analysis mode
        print(f"✅ Batch Analysis Mode: {result.get('analysis_type', 'Unknown')}")
        print(f"AS Count: {result.get('as_count', 0)}")
        if result.get('as_list'):
            print(f"AS List: {', '.join([f'AS{a}' for a in result['as_list'][:10]])}")
            if len(result['as_list']) > 10:
                print(f"  ... and {len(result['as_list']) - 10} more AS")
        if result.get('batch_result'):
            batch_result = result['batch_result']
            if isinstance(batch_result, dict):
                print(f"Batch Analysis Success: {batch_result.get('success', False)}")
                if batch_result.get('anomaly_count'):
                    print(f"Total Anomalies Detected: {batch_result.get('anomaly_count', 0)}")
                if batch_result.get('reasoning_results'):
                    print(f"Individual AS Results: {len(batch_result['reasoning_results'])} AS analyzed")
        if result.get('html_report_path'):
            print(f"\n📄 Batch HTML Report Generated: {result['html_report_path']}")
    elif result.get('chief_expert_analysis'):
        # Single AS analysis mode
        analysis_result = result['chief_expert_analysis']
        print(f"Analysis Time: {analysis_result.get('analysis_timestamp', 'Unknown')}")
        print(f"Tokens Used: {result.get('token_count', 'N/A')}")
        if result.get('token_count', 0) == 0:
            print("ℹ️  Token usage not available or reported as 0 by backend.")
        else:
            print("🎯 Chief Expert successfully coordinated multi-agent analysis")
            
        if result.get("analysis_report"):
            print(f"📊 Comprehensive Analysis Report Generated")
            if result["analysis_report"].get("html_report_path"):
                print(f"📄 HTML Report: {result['analysis_report']['html_report_path']}")
        
        print(f"\n🔍 Analysis completed with {len(result.get('reasoning_trace', []))} reasoning steps")
    elif result.get('success') is False:
        print(f"❌ Analysis failed: {result.get('error', 'Unknown error')}")
    else:
        print(f"⚠️  Unexpected result format. Keys: {list(result.keys())[:10]}")
        if result.get('error'):
            print(f"Error: {result.get('error')}")