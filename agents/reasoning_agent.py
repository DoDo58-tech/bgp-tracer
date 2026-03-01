import os
import sys
import json
from datetime import datetime, timedelta

sys.path.append((os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from llm.llm_factory import setup_llm_settings
from llm.prompt import build_multi_agent_coordination_prompt, get_reasoning_laws
from agents.routing_agent import run_routing_agent, run_routing_agent_async
from agents.traffic_agent import run_traffic_agent
from utils.logger import logger
from config import BASE_URL, API_KEY, MODEL


class ReasoningAgent:
    def __init__(self, asn, start_time, end_time, model = "deepseek-chat", uuid = ""):
        self.asn = asn
        self.start_time = start_time
        self.end_time = end_time
        self.model = model
        self.uuid = uuid
        
        self.llm, self.token_counter = setup_llm_settings(
            model=self.model,
            api_key=API_KEY,
            base_url=BASE_URL,
            temperature=0.2
        )
        
        
        self.reasoning_trace = []
        self.evidence_pool = {}
        self.confidence_scores = {}
        self.round_count = 0
    
    def perform_multi_round_analysis(self, max_rounds = 3):
        try:
            self.reasoning_trace.append(f"Starting multi-round analysis for ASN {self.asn}")
            self.reasoning_trace.append(f"Time range: {self.start_time} to {self.end_time}")
            
            initial_data = self.phase1_data_collection()
            
            if not initial_data.get("success", False):
                return {
                    "success": False,
                    "error": "Data collection failed",
                    "reasoning_trace": self.reasoning_trace
                }
            
            for round_num in range(1, max_rounds + 1):
                self.round_count = round_num
                self.reasoning_trace.append(f"\n=== ROUND {round_num} REASONING ===")
                
                round_result = self._perform_reasoning_round(initial_data, round_num)
                
                if self._should_conclude_analysis():
                    self.reasoning_trace.append(f"Analysis concluded after {round_num} rounds with sufficient confidence")
                    break
            
            final_result = self._phase3_final_integration()
            
            return final_result
            
        except Exception as e:
            return {
                "success": False, 
                "error": str(e),
                "reasoning_trace": self.reasoning_trace
            }
    
    def parse_anomaly_timestamp(self, timestamp_str):
        if not timestamp_str:
            return None
        
        try:
            if "T" in timestamp_str and "Z" in timestamp_str:
                return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%SZ")
            elif "T" in timestamp_str:
                try:
                    return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
                except:
                    return datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M")
            else:
                try:
                    return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                except:
                    return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M")
        except Exception as e:
            logger.warning(f"Failed to parse anomaly timestamp {timestamp_str}: {e}")
            return None
    
    def _identify_consecutive_anomaly_periods(
        self, 
        anomalies, 
        min_consecutive_count = 3,
        max_gap_minutes = 60
    ):
        if not anomalies:
            return []
        
        anomaly_times = []
        for anomaly in anomalies:
            timestamp_str = anomaly.get("timestamp", "")
            if not timestamp_str:
                continue
            
            anomaly_time = self.parse_anomaly_timestamp(timestamp_str)
            if anomaly_time:
                anomaly_times.append(anomaly_time)
        
        if not anomaly_times:
            return []
        
        anomaly_times.sort()
        
        consecutive_periods = []
        current_period_start = None
        current_period_end = None
        current_count = 0
        
        for i, current_time in enumerate(anomaly_times):
            if current_period_start is None:
                current_period_start = current_time
                current_period_end = current_time
                current_count = 1
            else:
                time_gap = (current_time - current_period_end).total_seconds() / 60
                
                if time_gap <= max_gap_minutes:
                    current_period_end = current_time
                    current_count += 1
                else:
                    if current_count >= min_consecutive_count:
                        consecutive_periods.append((current_period_start, current_period_end))
                    
                    current_period_start = current_time
                    current_period_end = current_time
                    current_count = 1
        
        if current_period_start is not None and current_count >= min_consecutive_count:
            consecutive_periods.append((current_period_start, current_period_end))
        
        return consecutive_periods
    
    def extract_anomaly_time_range(
        self, 
        anomalies, 
        buffer_hours = 2,
        use_consecutive_periods = True,
        min_consecutive_count = 3,
        max_gap_minutes = 60
    ) :
        if not anomalies:
            return None, None
        
        if use_consecutive_periods:
            consecutive_periods = self._identify_consecutive_anomaly_periods(
                anomalies, 
                min_consecutive_count=min_consecutive_count,
                max_gap_minutes=max_gap_minutes
            )
            
            if not consecutive_periods:
                logger.info(
                    f"No consecutive anomaly periods found (requires at least {min_consecutive_count} consecutive anomalies, "
                    f"max gap {max_gap_minutes} minutes). Total anomalies: {len(anomalies)}"
                )
                return None, None
            
            longest_period = max(
                consecutive_periods, 
                key=lambda p: (p[1] - p[0]).total_seconds()
            )
            
            start_time, end_time = longest_period
            
            logger.info(
                f"Identified {len(consecutive_periods)} consecutive anomaly periods; "
                f"selected longest period: {start_time.strftime('%Y-%m-%d %H:%M')} to {end_time.strftime('%Y-%m-%d %H:%M')}"
            )
        else:
            anomaly_times = []
            for anomaly in anomalies:
                timestamp_str = anomaly.get("timestamp", "")
                if not timestamp_str:
                    continue
                
                anomaly_time = self.parse_anomaly_timestamp(timestamp_str)
                if anomaly_time:
                    anomaly_times.append(anomaly_time)
            
            if not anomaly_times:
                return None, None
            
            start_time = min(anomaly_times)
            end_time = max(anomaly_times)
        
        start_time = start_time - timedelta(hours=buffer_hours)
        end_time = end_time + timedelta(hours=buffer_hours)
        
        logger.info(
            f"Extracted anomaly time range (with {buffer_hours}h buffer): "
            f"{start_time.strftime('%Y-%m-%d %H:%M')} to {end_time.strftime('%Y-%m-%d %H:%M')}"
        )
        
        return start_time, end_time
    
    def phase1_data_collection(self):
        self.reasoning_trace.append("Phase 1: Data Collection")
        
        try:
            self.reasoning_trace.append("- Activating TrafficAgent with LLM enhancement...")
            traffic_result = run_traffic_agent(
                asn=self.asn,
                start_time=self.start_time.strftime('%Y-%m-%d %H:%M'),
                end_time=self.end_time.strftime('%Y-%m-%d %H:%M')
            )
            
            traffic_anomaly_detected = traffic_result.get("success") and traffic_result.get("anomalies_detected", False)
            
            extended_analysis_start = self.start_time
            extended_analysis_end = self.end_time
            
            if traffic_anomaly_detected:
                self.reasoning_trace.append("- Traffic anomalies confirmed. Identifying consecutive anomaly periods for routing analysis...")
                
                # Extract anomaly time range using consecutive period detection
                anomalies = traffic_result.get("anomalies", [])
                anomaly_start, anomaly_end = self.extract_anomaly_time_range(
                    anomalies,
                    use_consecutive_periods=True,
                    min_consecutive_count=3,
                    max_gap_minutes=60
                )
                
                if anomaly_start and anomaly_end:
                        # count consecutive anomalies within the longest period
                    consecutive_periods = self._identify_consecutive_anomaly_periods(
                        anomalies, min_consecutive_count=3, max_gap_minutes=60
                    )
                    total_consecutive_anomalies = 0
                    if consecutive_periods:
                        # select the longest period
                        longest_period = max(
                            consecutive_periods, 
                            key=lambda p: (p[1] - p[0]).total_seconds()
                        )
                        period_start, period_end = longest_period
                        for anomaly in anomalies:
                            anomaly_time = self.parse_anomaly_timestamp(anomaly.get("timestamp", ""))
                            if anomaly_time and period_start <= anomaly_time <= period_end:
                                total_consecutive_anomalies += 1
                    
                    self.reasoning_trace.append(
                        f"- Identified consecutive anomaly period: {anomaly_start.strftime('%Y-%m-%d %H:%M')} to {anomaly_end.strftime('%Y-%m-%d %H:%M')} "
                        f"(total anomalies: {len(anomalies)}, consecutive anomalies: {total_consecutive_anomalies})"
                    )
                    routing_start = anomaly_start.strftime('%Y-%m-%d %H:%M')
                    routing_end = anomaly_end.strftime('%Y-%m-%d %H:%M')
                    # Store extended time range for report
                    extended_analysis_start = anomaly_start
                    extended_analysis_end = anomaly_end
                else:
                    # if no consecutive period found, log and skip routing analysis
                    self.reasoning_trace.append(
                        f"- No sufficient consecutive anomaly period found (requires at least 3 consecutive anomalies, max gap 60 minutes)."
                        f" Total anomalies: {len(anomalies)}. Skipping routing analysis."
                    )
                    routing_result = {
                        "success": False,
                        "asn": self.asn,
                        "analysis_period": f"{self.start_time} to {self.end_time}",
                        "skipped": True,
                        "skip_reason": f"No sufficient consecutive anomaly period found. Total anomalies: {len(anomalies)}; did not meet consecutive anomaly conditions (>=3 anomalies, max gap 60 minutes)."
                    }
                    data_quality = self._assess_data_quality(routing_result, traffic_result)
                    self.evidence_pool = {
                        "routing_data": routing_result,
                        "traffic_data": traffic_result,
                        "data_quality": data_quality,
                        "extended_analysis_start": extended_analysis_start,
                        "extended_analysis_end": extended_analysis_end
                    }
                    self.reasoning_trace.append(f"- Data quality assessment: {data_quality}")
                    return {
                        "success": True,
                        "routing_success": False,
                        "traffic_success": traffic_result.get("success", False),
                        "data_quality": data_quality,
                        "extended_analysis_start": extended_analysis_start.strftime('%Y-%m-%d %H:%M'),
                        "extended_analysis_end": extended_analysis_end.strftime('%Y-%m-%d %H:%M')
                    }
                
                self.reasoning_trace.append(f"- Using consecutive anomaly period for routing analysis: {routing_start} to {routing_end}")
                
                # Extract target ASNs for route leak detection (only analyze messages containing these ASNs)
                target_asns = [self.asn]  # Always include primary ASN
                
                routing_result = run_routing_agent(
                    asn=self.asn,
                    start_time=routing_start,
                    end_time=routing_end,
                    target_asns=target_asns
                )
            else:
                self.reasoning_trace.append("- Traffic anomalies were not confirmed. Skipping routing analysis by design.")
                routing_result = {
                    "success": False,
                    "asn": self.asn,
                    "analysis_period": f"{self.start_time} to {self.end_time}",
                    "skipped": True,
                    "skip_reason": "Traffic API did not confirm anomalies, routing analysis skipped per workflow."
                }
            
            data_quality = self._assess_data_quality(routing_result, traffic_result)
            
            self.evidence_pool = {
                "routing_data": routing_result,
                "traffic_data": traffic_result,
                "data_quality": data_quality,
                "extended_analysis_start": extended_analysis_start,
                "extended_analysis_end": extended_analysis_end
            }
            
            self.reasoning_trace.append(f"- Data quality assessment: {data_quality}")
            self.reasoning_trace.append(f"- Extended analysis time range for report: {extended_analysis_start.strftime('%Y-%m-%d %H:%M')} to {extended_analysis_end.strftime('%Y-%m-%d %H:%M')}")
            
            return {
                "success": True,
                "routing_success": routing_result.get("success", False),
                "traffic_success": traffic_result.get("success", False),
                "data_quality": data_quality,
                "extended_analysis_start": extended_analysis_start.strftime('%Y-%m-%d %H:%M'),
                "extended_analysis_end": extended_analysis_end.strftime('%Y-%m-%d %H:%M')
            }
            
        except Exception as e:
            self.reasoning_trace.append(f"- Data collection failed: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def _perform_reasoning_round(self, initial_data, round_num):
        
        try:
            evidence_analysis = self._analyze_evidence_state()
            self.reasoning_trace.append(f"Evidence state: {evidence_analysis['summary']}")
            
            # Identify knowledge gaps
            knowledge_gaps = self._identify_knowledge_gaps()
            if knowledge_gaps:
                self.reasoning_trace.append(f"Knowledge gaps identified: {knowledge_gaps}")
            
            # In later rounds, perform deeper analysis using LLM if gaps exist
            if round_num > 1 and knowledge_gaps:
                self._perform_deeper_analysis(round_num, knowledge_gaps)
            
            # Apply reasoning laws to current evidence
            law_application = self._apply_reasoning_laws()
            self.reasoning_trace.append(f"Reasoning law application: {law_application['classification']}")
            
            # Update confidence scores with round-specific refinement
            self._update_confidence_scores(law_application, round_num)
            
            # Check for conflicts between agent findings
            conflicts = self._detect_agent_conflicts()
            if conflicts:
                self.reasoning_trace.append(f"Agent conflicts detected: {conflicts}")
                resolution = self._resolve_conflicts(conflicts)
                self.reasoning_trace.append(f"Conflict resolution: {resolution}")
            
            # Determine if additional rounds are needed
            need_more_rounds = self._assess_analysis_completeness()
            
            return {
                "round_num": round_num,
                "evidence_analysis": evidence_analysis,
                "law_application": law_application,
                "conflicts": conflicts if conflicts else None,
                "need_more_rounds": need_more_rounds,
                "confidence_scores": self.confidence_scores.copy()
            }
            
        except Exception as e:
            self.reasoning_trace.append(f"Round {round_num} failed: {str(e)}")
            return {"round_num": round_num, "error": str(e)}
    
    def _phase3_final_integration(self):
        self.reasoning_trace.append("\nPhase 3: Final Integration and Decision")
        
        try:
            # Generate final coordination prompt
            coordination_prompt = self._build_coordination_prompt()
            
            # Get LLM coordination decision
            response = self.llm.complete(coordination_prompt)
            coordination_result = self._parse_coordination_response(response.text)
            
            # Generate comprehensive report
            final_report = self._generate_final_report(coordination_result)
            
            self.reasoning_trace.append("Analysis completed successfully")
            
            # Extract file paths from routing analysis for chief_agent
            routing_data = self.evidence_pool.get("routing_data", {})
            
            return {
                "success": True,
                "analysis_type": "multi-round_reasoning",
                "asn": self.asn,
                "time_range": f"{self.start_time} to {self.end_time}",
                "rounds_performed": self.round_count,
                "final_classification": coordination_result.get("integrated_findings", {}),
                "recommendations": coordination_result.get("recommendations", {}),
                "confidence_assessment": self._get_final_confidence(),
                "reasoning_trace": self.reasoning_trace,
                "evidence_summary": self._summarize_evidence(),
                "token_usage": self.get_total_token_usage(),
                "as_rel_file": routing_data.get("as_rel_file"),
                "prefix2as_file": routing_data.get("prefix2as_file"),
                "asorg_file": routing_data.get("asorg_file")
            }
            
        except Exception as e:
            self.reasoning_trace.append(f"Final integration failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "reasoning_trace": self.reasoning_trace
            }
    
    def _assess_data_quality(self, routing_result, traffic_result):
        quality_factors = []
        
        if routing_result.get("success", False):
            has_anomalies = any([
                routing_result.get("origin_hijacked"),
                routing_result.get("forge_hijacked"),
                routing_result.get("origin_hijacking"),
                routing_result.get("forge_hijacking")
            ])
            quality_factors.append("routing_available")
            if has_anomalies:
                quality_factors.append("routing_anomalies_detected")
        
        if traffic_result.get("success", False):
            quality_factors.append("traffic_available")
            if traffic_result.get("anomalies_detected", False):
                quality_factors.append("traffic_anomalies_detected")
        
        if len(quality_factors) >= 3:
            return "High"
        elif len(quality_factors) >= 2:
            return "Medium"
        else:
            return "Low"
    
    def _analyze_evidence_state(self):
        """Analyze current state of evidence"""
        routing_data = self.evidence_pool.get("routing_data", {})
        traffic_data = self.evidence_pool.get("traffic_data", {})
        
        evidence_types = []
        
        if routing_data.get("origin_hijacked") or routing_data.get("origin_hijacking"):
            evidence_types.append("origin_hijack")
        
        if routing_data.get("forge_hijacked") or routing_data.get("forge_hijacking"):
            evidence_types.append("path_forgery")
        
        if traffic_data.get("anomalies_detected", False):
            evidence_types.append("traffic_anomalies")
        
        return {
            "evidence_types": evidence_types,
            "evidence_count": len(evidence_types),
            "summary": f"Found {len(evidence_types)} types of evidence: {', '.join(evidence_types) if evidence_types else 'None'}"
        }
    
    def _identify_knowledge_gaps(self):
        """Identify gaps in current knowledge"""
        gaps = []
        
        routing_data = self.evidence_pool.get("routing_data", {})
        traffic_data = self.evidence_pool.get("traffic_data", {})
        
        if not routing_data.get("as_rel_data"):
            gaps.append("missing_as_relationships")
        
        if not routing_data.get("as_prefixes_data"):
            gaps.append("missing_prefix_mappings")
        
        if routing_data.get("success") and not routing_data.get("llm_analysis"):
            gaps.append("missing_routing_analysis")
        
        if traffic_data.get("success") and not traffic_data.get("llm_analysis"):
            gaps.append("missing_traffic_analysis")
        
        return gaps
    
    def _perform_deeper_analysis(self, round_num, knowledge_gaps):
        """Perform deeper analysis in later rounds to refine understanding"""
        self.reasoning_trace.append(f"Round {round_num}: Performing deeper analysis for gaps: {knowledge_gaps}")
        
        routing_data = self.evidence_pool.get("routing_data", {})
        traffic_data = self.evidence_pool.get("traffic_data", {})
        
        # Re-analyze evidence with more context from previous rounds
        if round_num == 2:
            # Round 2: Cross-validate findings between routing and traffic
            self.reasoning_trace.append("Cross-validating routing and traffic findings...")
            # Check temporal alignment
            routing_events = []
            for key in ["origin_hijacked", "forge_hijacked", "origin_hijacking", "forge_hijacking"]:
                events = routing_data.get(key, []) or []
                routing_events.extend(events)
            
            traffic_anomalies = traffic_data.get("anomalies", []) or []
            
            if routing_events and traffic_anomalies:
                # Check if routing events and traffic anomalies overlap in time
                routing_times = set()
                for event in routing_events:
                    ts = event.get("timestamp") or event.get("first_seen")
                    if ts:
                        try:
                            dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                            routing_times.add(dt)
                        except:
                            pass
                
                anomaly_times = set()
                for anomaly in traffic_anomalies:
                    ts = anomaly.get("timestamp")
                    if ts:
                        try:
                            dt = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
                            anomaly_times.add(dt)
                        except:
                            pass
                
                # Check temporal overlap (within 1 hour)
                overlap_count = 0
                for rt in routing_times:
                    for at in anomaly_times:
                        if abs((rt - at).total_seconds()) < 3600:
                            overlap_count += 1
                            break
                
                if overlap_count > 0:
                    self.reasoning_trace.append(
                        f"Temporal correlation found: {overlap_count} routing events align with traffic anomalies"
                    )
                    # Store this insight for confidence calculation
                    self.evidence_pool["temporal_correlation"] = {
                        "overlap_count": overlap_count,
                        "routing_events": len(routing_times),
                        "traffic_anomalies": len(anomaly_times)
                    }
                else:
                    self.reasoning_trace.append("No temporal correlation between routing events and traffic anomalies")
        
        elif round_num == 3:
            # Round 3: Final synthesis and confidence refinement
            self.reasoning_trace.append("Final synthesis: aggregating all evidence...")
            # Review all previous rounds' findings
            if len(self.confidence_scores) >= 2:
                round1_conf = self.confidence_scores.get("round_1", {}).get("overall_confidence", 0.0)
                round2_conf = self.confidence_scores.get("round_2", {}).get("overall_confidence", 0.0)
                
                # If confidence is stable across rounds, it's more reliable
                if abs(round1_conf - round2_conf) < 0.1:
                    self.reasoning_trace.append("Confidence stable across rounds, increasing reliability")
                    self.evidence_pool["confidence_stability"] = True
                else:
                    self.reasoning_trace.append("Confidence varies across rounds, maintaining conservative estimate")
                    self.evidence_pool["confidence_stability"] = False
    
    def _apply_reasoning_laws(self):
        """Apply BGP reasoning laws to current evidence"""
        routing_data = self.evidence_pool.get("routing_data", {})
        traffic_data = self.evidence_pool.get("traffic_data", {})
        
        # Apply classification laws (1-3)
        classification = self._classify_incident_type(routing_data)
        
        # Apply traffic correlation laws (4)
        traffic_correlation = self._assess_traffic_correlation(routing_data, traffic_data)
        
        # Apply severity assessment laws (6)
        severity = self._assess_incident_severity(routing_data, traffic_data)
        
        return {
            "classification": classification,
            "traffic_correlation": traffic_correlation,
            "severity": severity,
            "laws_applied": ["1-3: Classification", "4: Traffic Correlation", "6: Severity Assessment"]
        }
    
    def _classify_incident_type(self, routing_data):
        """Apply reasoning laws 1-3 for incident classification"""
        if routing_data.get("origin_hijacked") or routing_data.get("origin_hijacking"):
            return "Origin Hijacking"
        elif routing_data.get("forge_hijacked") or routing_data.get("forge_hijacking"):
            return "Path Forgery"
        else:
            return "No BGP Anomaly Detected"
    
    def _assess_traffic_correlation(self, routing_data, traffic_data):
        """Apply reasoning law 4 for traffic correlation"""
        has_bgp_anomaly = any([
            routing_data.get("origin_hijacked"),
            routing_data.get("forge_hijacked"),
            routing_data.get("origin_hijacking"),
            routing_data.get("forge_hijacking")
        ])
        
        has_traffic_anomaly = traffic_data.get("anomalies_detected", False)
        
        if has_bgp_anomaly and has_traffic_anomaly:
            return "Correlated BGP and Traffic Anomalies"
        elif has_bgp_anomaly and not has_traffic_anomaly:
            return "BGP Anomaly Without Traffic Impact"
        elif not has_bgp_anomaly and has_traffic_anomaly:
            return "Traffic Anomaly Without BGP Events"
        else:
            return "No Anomalies Detected"
    
    def _assess_incident_severity(self, routing_data, traffic_data):
        """Apply reasoning law 6 for severity assessment"""
        duration_minutes = (self.end_time - self.start_time).total_seconds() / 60
        
        if duration_minutes > 120:  # > 2 hours
            return "High"
        elif duration_minutes > 10:  # 10 minutes - 2 hours
            return "Medium"
        else:  # < 10 minutes
            return "Low"
    
    def _update_confidence_scores(self, law_application, round_num=None):
        """Update confidence scores based on reasoning results with iterative refinement"""
        if round_num is None:
            round_num = self.round_count
        
        # Calculate confidence based on evidence consistency
        evidence_consistency = self._calculate_evidence_consistency()
        
        # Update confidence for current round
        classification_confidence = self._get_classification_confidence(law_application)
        classification_confidence = self._apply_small_bgp_penalty(classification_confidence)
        
        # Apply iterative refinement: confidence should improve with more rounds (up to a point)
        # Round 1: base confidence
        # Round 2: slight improvement if evidence is consistent
        # Round 3: further refinement or stabilization
        refinement_factor = 1.0
        if round_num > 1:
            # If previous rounds had consistent results, increase confidence slightly
            prev_round_key = f"round_{round_num - 1}"
            if prev_round_key in self.confidence_scores:
                prev_confidence = self.confidence_scores[prev_round_key].get("overall_confidence", 0.0)
                # If evidence consistency is high, allow small improvement
                if evidence_consistency >= 0.8:
                    refinement_factor = min(1.15, 1.0 + (round_num - 1) * 0.05)
                # If previous round had low confidence, check if we're converging
                elif prev_confidence < 0.5 and round_num == 3:
                    # Final round: stabilize at current level
                    refinement_factor = 1.0
        
        adjusted_classification_confidence = min(0.95, classification_confidence * refinement_factor)
        
        self.confidence_scores[f"round_{round_num}"] = {
            "evidence_consistency": evidence_consistency,
            "classification_confidence": adjusted_classification_confidence,
            "overall_confidence": min(evidence_consistency, adjusted_classification_confidence)
        }
    
    def _calculate_evidence_consistency(self):
        """Calculate how consistent the evidence is across agents with round-specific refinement"""
        routing_data = self.evidence_pool.get("routing_data", {})
        traffic_data = self.evidence_pool.get("traffic_data", {})
        
        # Check for consistency between routing and traffic findings
        has_routing_anomalies = any([
            routing_data.get("origin_hijacked"),
            routing_data.get("forge_hijacked"),
            routing_data.get("origin_hijacking"),
            routing_data.get("forge_hijacking")
        ])
        
        has_traffic_anomalies = traffic_data.get("anomalies_detected", False)
        
        # Base consistency score
        if has_routing_anomalies == has_traffic_anomalies:
            base_consistency = 0.9
        else:
            base_consistency = 0.6
        
        # Refine based on deeper analysis in later rounds
        if self.round_count > 1:
            # Check temporal correlation if available
            temporal_corr = self.evidence_pool.get("temporal_correlation")
            if temporal_corr:
                overlap_ratio = temporal_corr.get("overlap_count", 0) / max(
                    temporal_corr.get("routing_events", 1),
                    temporal_corr.get("traffic_anomalies", 1)
                )
                # Boost consistency if temporal correlation is strong
                if overlap_ratio > 0.5:
                    base_consistency = min(0.95, base_consistency + 0.1)
                elif overlap_ratio > 0.2:
                    base_consistency = min(0.9, base_consistency + 0.05)
            
            # In round 3, consider confidence stability
            if self.round_count == 3:
                if self.evidence_pool.get("confidence_stability", False):
                    base_consistency = min(0.95, base_consistency + 0.05)
        
        return base_consistency
    
    def _get_classification_confidence(self, law_application):
        """Get confidence level for classification"""
        classification = law_application.get("classification", "")
        
        if classification in ["Origin Hijacking", "Path Forgery"]:
            return 0.8
        elif classification == "No BGP Anomaly Detected":
            return 0.7
        else:
            return 0.5
    
    def _apply_small_bgp_penalty(self, base_confidence):
        """Reduce confidence when routing impact is small compared to traffic anomaly severity"""
        routing_impact = self._get_routing_impact_score()
        traffic_severity = self._get_traffic_severity_score()
        
        # Only penalize when traffic impact is significant but routing impact is minimal
        if traffic_severity >= 0.6 and routing_impact < 0.3:
            penalty = min(0.4, (traffic_severity - routing_impact))
            adjusted = max(0.1, base_confidence - penalty)
            self.reasoning_trace.append(
                f"Confidence penalty applied: routing impact {routing_impact:.2f} is much smaller than traffic severity {traffic_severity:.2f}"
            )
            return adjusted
        return base_confidence
    
    def _get_routing_impact_score(self):
        """Estimate how wide the routing anomaly spreads based on events and affected prefixes"""
        routing_data = self.evidence_pool.get("routing_data", {})
        event_keys = ["origin_hijacked", "forge_hijacked", "origin_hijacking", "forge_hijacking"]
        event_count = 0
        affected_prefixes = set()
        
        for key in event_keys:
            events = routing_data.get(key, []) or []
            event_count += len(events)
            for event in events:
                prefix = event.get("prefix")
                if prefix:
                    affected_prefixes.add(prefix)
        
        event_factor = min(1.0, event_count / 5.0)  # Full score if >=5 events
        prefix_factor = min(1.0, len(affected_prefixes) / 3.0)  # Full score if >=3 prefixes
        return max(event_factor, prefix_factor)
    
    def _get_traffic_severity_score(self):
        """Estimate traffic anomaly severity using percent change and anomaly count"""
        traffic_data = self.evidence_pool.get("traffic_data", {})
        percent_change = abs(traffic_data.get("percent_change", 0.0) or 0.0)
        anomaly_count = traffic_data.get("anomaly_count", 0) or 0
        
        change_factor = min(1.0, percent_change / 40.0)  # 40%+ treated as severe
        anomaly_factor = min(1.0, anomaly_count / 3.0)  # >=3 anomalies considered severe
        return max(change_factor, anomaly_factor)
    
    def _detect_agent_conflicts(self):
        """Detect conflicts between agent findings"""
        conflicts = []
        
        routing_data = self.evidence_pool.get("routing_data", {})
        traffic_data = self.evidence_pool.get("traffic_data", {})
        
        # Check for conflicting evidence
        has_routing_issues = any([
            routing_data.get("origin_hijacked"),
            routing_data.get("forge_hijacked")
        ])
        
        no_traffic_impact = not traffic_data.get("anomalies_detected", False)
        
        if has_routing_issues and no_traffic_impact:
            conflicts.append("BGP anomalies detected but no traffic impact observed")
        
        return conflicts if conflicts else None
    
    def _resolve_conflicts(self, conflicts):
        """Resolve conflicts between agent findings"""
        # Simple conflict resolution - in production this would be more sophisticated
        if "BGP anomalies detected but no traffic impact observed" in conflicts:
            return "BGP anomaly may be inactive or traffic data incomplete"
        
        return "Conflicts require manual review"
    
    def _should_conclude_analysis(self):
        """Determine if analysis should conclude"""
        if not self.confidence_scores:
            return False
        
        # Get latest round confidence
        latest_round = f"round_{self.round_count}"
        latest_confidence = self.confidence_scores.get(latest_round, {})
        overall_confidence = latest_confidence.get("overall_confidence", 0.0)
        
        # Conclude if confidence is high enough or max rounds reached
        return overall_confidence >= 0.8 or self.round_count >= 3
    
    def _assess_analysis_completeness(self):
        """Assess if more analysis rounds are needed"""
        return not self._should_conclude_analysis()
    
    def _build_coordination_prompt(self):
        """Build prompt for final coordination"""
        prompt_template = build_multi_agent_coordination_prompt()
        
        # Summarize agent results
        routing_summary = self._summarize_routing_results()
        traffic_summary = self._summarize_traffic_results()
        
        return prompt_template.format(
            routing_results=routing_summary,
            traffic_results=traffic_summary,
            reasoning_trace="\n".join(self.reasoning_trace[-10:]),  # Last 10 trace entries
            confidence_scores=json.dumps(self.confidence_scores, indent=2)
        )
    
    def _summarize_routing_results(self):
        """Summarize routing agent results"""
        routing_data = self.evidence_pool.get("routing_data", {})
        
        if not routing_data.get("success", False):
            return "Routing analysis failed"
        
        summary_parts = [
            f"Origin hijacked: {len(routing_data.get('origin_hijacked', []))} events",
            f"Forge hijacked: {len(routing_data.get('forge_hijacked', []))} events",
            f"LLM analysis: {'Available' if routing_data.get('llm_analysis') else 'Not available'}"
        ]
        
        return "; ".join(summary_parts)
    
    def _summarize_traffic_results(self):
        """Summarize traffic agent results"""
        traffic_data = self.evidence_pool.get("traffic_data", {})
        
        if not traffic_data.get("success", False):
            return "Traffic analysis failed"
        
        summary_parts = [
            f"Anomalies detected: {traffic_data.get('anomalies_detected', False)}",
            f"Anomaly count: {traffic_data.get('anomaly_count', 0)}",
            f"LLM analysis: {'Available' if traffic_data.get('llm_analysis') else 'Not available'}"
        ]
        
        return "; ".join(summary_parts)
    
    def _parse_coordination_response(self, response_text):
        """Parse LLM coordination response"""
        try:
            # Extract JSON from response
            json_start = response_text.find("{")
            json_end = response_text.rfind("}") + 1
            
            if json_start >= 0 and json_end > json_start:
                json_text = response_text[json_start:json_end]
                return json.loads(json_text)
            
            # Fallback to simple parsing
            return {"integrated_findings": {"incident_type": "Unknown", "confidence_level": "Low"}}
            
        except json.JSONDecodeError:
            return {"integrated_findings": {"incident_type": "Parse Error", "confidence_level": "Low"}}
    
    def _generate_final_report(self, coordination_result):
        """Generate comprehensive final report"""
        return {
            "analysis_metadata": {
                "asn": self.asn,
                "time_range": f"{self.start_time} to {self.end_time}",
                "analysis_timestamp": datetime.now().isoformat(),
                "rounds_performed": self.round_count,
                "uuid": self.uuid
            },
            "coordination_result": coordination_result,
            "agent_results": {
                "routing": self.evidence_pool.get("routing_data", {}),
                "traffic": self.evidence_pool.get("traffic_data", {})
            },
            "confidence_progression": self.confidence_scores,
            "reasoning_trace": self.reasoning_trace
        }
    
    def _get_final_confidence(self):
        """Get final confidence assessment"""
        if not self.confidence_scores:
            return {"overall": "Low", "details": "No confidence data available"}
        
        # Get the latest round confidence
        latest_round = f"round_{self.round_count}"
        latest_confidence = self.confidence_scores.get(latest_round, {})
        
        overall = latest_confidence.get("overall_confidence", 0.0)
        
        if overall >= 0.8:
            level = "High"
        elif overall >= 0.6:
            level = "Medium"
        else:
            level = "Low"
        
        return {
            "overall": level,
            "score": overall,
            "details": f"Based on {self.round_count} rounds of analysis",
            "progression": self.confidence_scores
        }
    
    def _summarize_evidence(self):
        """Summarize all collected evidence"""
        # Convert pandas Timestamps to strings to ensure JSON serialization
        routing_data = self.evidence_pool.get("routing_data", {})
        traffic_data = self.evidence_pool.get("traffic_data", {})
        
        # Clean routing data
        cleaned_routing_data = self._clean_timestamps(routing_data)
        cleaned_traffic_data = self._clean_timestamps(traffic_data)
        
        # Get extended time range for report generation
        extended_start = self.evidence_pool.get("extended_analysis_start")
        extended_end = self.evidence_pool.get("extended_analysis_end")
        extended_time_range = None
        if extended_start and extended_end:
            extended_time_range = {
                "start": extended_start.strftime('%Y-%m-%d %H:%M') if hasattr(extended_start, 'strftime') else str(extended_start),
                "end": extended_end.strftime('%Y-%m-%d %H:%M') if hasattr(extended_end, 'strftime') else str(extended_end)
            }
        
        return {
            "data_quality": self.evidence_pool.get("data_quality", "Unknown"),
            "routing_data": cleaned_routing_data,  # Return cleaned routing data
            "traffic_data": cleaned_traffic_data,   # Return cleaned traffic data
            "routing_evidence": self._count_routing_evidence(),
            "traffic_evidence": self._count_traffic_evidence(),
            "correlation_assessment": self._assess_final_correlation(),
            "extended_analysis_time_range": extended_time_range  # Include extended time range for report
        }
    
    def _clean_timestamps(self, data):
        """Recursively clean pandas Timestamps from data structure"""
        if isinstance(data, dict):
            return {k: self._clean_timestamps(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._clean_timestamps(item) for item in data]
        elif hasattr(data, 'strftime'):  # pandas Timestamp or datetime object
            return str(data)
        else:
            return data
    
    def _count_routing_evidence(self):
        """Count routing evidence"""
        routing_data = self.evidence_pool.get("routing_data", {})
        
        return {
            "origin_hijacked_count": len(routing_data.get("origin_hijacked", [])),
            "forge_hijacked_count": len(routing_data.get("forge_hijacked", [])),
            "origin_hijacking_count": len(routing_data.get("origin_hijacking", [])),
            "forge_hijacking_count": len(routing_data.get("forge_hijacking", []))
        }
    
    def _count_traffic_evidence(self):
        """Count traffic evidence"""
        traffic_data = self.evidence_pool.get("traffic_data", {})
        
        return {
            "anomalies_detected": traffic_data.get("anomalies_detected", False),
            "anomaly_count": traffic_data.get("anomaly_count", 0),
            "has_baseline_data": bool(traffic_data.get("baseline_metrics"))
        }
    
    def _assess_final_correlation(self):
        """Assess final correlation between routing and traffic"""
        routing_evidence = self._count_routing_evidence()
        traffic_evidence = self._count_traffic_evidence()
        
        has_routing_anomalies = sum(routing_evidence.values()) > 0
        has_traffic_anomalies = traffic_evidence.get("anomalies_detected", False)
        
        if has_routing_anomalies and has_traffic_anomalies:
            return "Strong correlation between BGP and traffic anomalies"
        elif has_routing_anomalies and not has_traffic_anomalies:
            return "BGP anomalies without observable traffic impact"
        elif not has_routing_anomalies and has_traffic_anomalies:
            return "Traffic anomalies without BGP routing issues"
        else:
            return "No significant anomalies detected"
    
    def get_total_token_usage(self):
        total_tokens = self.token_counter.total_llm_token_count
        prompt_tokens = self.token_counter.prompt_llm_token_count
        completion_tokens = self.token_counter.completion_llm_token_count
        
        routing_data = self.evidence_pool.get("routing_data", {})
        routing_tokens = routing_data.get("token_usage", {})
        
        # Add traffic agent tokens
        traffic_data = self.evidence_pool.get("traffic_data", {})
        traffic_tokens = traffic_data.get("token_usage", {})
        
        return {
            "reasoning_agent": {
                "total": total_tokens,
                "prompt": prompt_tokens,
                "completion": completion_tokens
            },
            "routing_agent": routing_tokens,
            "traffic_agent": traffic_tokens,
            "total_across_agents": (
                total_tokens + 
                routing_tokens.get("total_tokens", 0) + 
                traffic_tokens.get("total_tokens", 0)
            )
        }


def run_reasoning_agent(asn = None, start_time = None, end_time = None, 
                       user_input = None, max_rounds = 3):
    try:
        if user_input and not (asn and start_time and end_time):
            from agents.traffic_agent import parse_traffic_outage_input, normalize_time
            parsed_asn, parsed_start, parsed_end = parse_traffic_outage_input(user_input)
            
            if not parsed_asn or not parsed_start or not parsed_end:
                return {
                    "success": False,
                    "error": "Could not extract ASN and time period from user input",
                    "user_input": user_input
                }
            
            asn = parsed_asn
            start_time = normalize_time(parsed_start)
            end_time = normalize_time(parsed_end)
        else:
            # Normalize time format for direct parameters
            if start_time:
                try:
                    from agents.traffic_agent import normalize_time
                    start_time = normalize_time(str(start_time))
                except Exception:
                    pass
            if end_time:
                try:
                    from agents.traffic_agent import normalize_time
                    end_time = normalize_time(str(end_time))
                except Exception:
                    pass
        
        # Validate required parameters
        if not all([asn, start_time, end_time]):
            return {
                "success": False,
                "error": "Missing required parameters: asn, start_time, end_time"
            }
        
        # Parse time strings
        start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M")
        end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M")
        
        # Create and run reasoning agent
        agent = ReasoningAgent(asn, start_dt, end_dt)
        return agent.perform_multi_round_analysis(max_rounds)
        
    except Exception as e:
        return {"success": False, "error": str(e)}


def run_reasoning_agent_batch(
    as_list,
    start_time,
    end_time,
    max_rounds = 3
):
    from agents.traffic_agent import run_traffic_agent_batch
    from detectors.hijack.hijack_detector import detect_hijacks_batch, detect_hijacks
    
    try:
        logger.info(f"Starting BATCH reasoning analysis for {len(as_list)} AS")
        logger.info(f"Time range: {start_time} to {end_time}")
        
        start_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M")
        end_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M")
        
        logger.info(f"Step 1: Batch traffic analysis for {len(as_list)} AS...")
        traffic_batch_result = run_traffic_agent_batch(
            as_list=as_list,
            start_time=start_time,
            end_time=end_time
        )
        
        if not traffic_batch_result.get("success"):
            return {
                "success": False,
                "error": "Batch traffic analysis failed",
                "traffic_result": traffic_batch_result
            }
        
        anomaly_as_list = traffic_batch_result.get("anomaly_as_list", [])
        logger.info(f"Step 2: Identified {len(anomaly_as_list)} AS with traffic anomalies: {anomaly_as_list}")
        
        if not anomaly_as_list:
            logger.info("No traffic anomalies detected. Skipping routing analysis.")
            return {
                "success": True,
                "batch_mode": True,
                "as_count": len(as_list),
                "anomaly_count": 0,
                "traffic_batch_result": traffic_batch_result,
                "routing_batch_result": None,
                "message": "No traffic anomalies detected across all AS"
            }
        
        logger.info(f"Step 2.5: Extracting anomaly time ranges for routing analysis (per AS)...")
        per_as_windows = {}
        for asn in anomaly_as_list:
            traffic_data = traffic_batch_result.get("results_by_as", {}).get(asn, {})
            anomalies = traffic_data.get("anomalies", [])
            
            if anomalies:
                temp_agent = ReasoningAgent(str(asn), start_dt, end_dt)
                anomaly_start, anomaly_end = temp_agent.extract_anomaly_time_range(
                    anomalies,
                    use_consecutive_periods=True,
                    min_consecutive_count=3,
                    max_gap_minutes=60
                )
                
                if anomaly_start and anomaly_end:
                    per_as_windows[asn] = (anomaly_start, anomaly_end)
                    logger.info(f"  AS{asn}: anomaly range {anomaly_start.strftime('%Y-%m-%d %H:%M')} to {anomaly_end.strftime('%Y-%m-%d %H:%M')}")
        
        logger.info(f"Step 3: Per-AS routing analysis for {len(anomaly_as_list)} anomaly AS using individual anomaly windows...")
        routing_results_by_as = {}
        routing_failures = []
        
        for asn in anomaly_as_list:
            if asn not in per_as_windows:
                logger.info(f"  Routing analysis AS{asn} skipped (no traffic anomalies)")
                routing_results_by_as[str(asn)] = {
                    "success": True,
                    "skipped": True,
                    "reason": "no_traffic_anomaly",
                    "asn": asn,
                }
        
        as_with_windows = [asn for asn in anomaly_as_list if asn in per_as_windows]
        if not as_with_windows:
            logger.info("No AS with valid anomaly windows for routing analysis")
        else:
            window_to_as = {}
            for asn in as_with_windows:
                r_start, r_end = per_as_windows[asn]
                window_key = (r_start, r_end)
                if window_key not in window_to_as:
                    window_to_as[window_key] = []
                window_to_as[window_key].append(asn)
            
            logger.info(f"Grouped {len(as_with_windows)} AS into {len(window_to_as)} unique time windows")
            for (w_start, w_end), as_group in window_to_as.items():
                logger.info(f"  Window {w_start.strftime('%Y-%m-%d %H:%M')} to {w_end.strftime('%Y-%m-%d %H:%M')}: {len(as_group)} AS ({', '.join([f'AS{a}' for a in as_group])})")
            
            for (r_start, r_end), as_group in window_to_as.items():
                window_start_str = r_start.strftime('%Y-%m-%d %H:%M')
                window_end_str = r_end.strftime('%Y-%m-%d %H:%M')
                
                logger.info(
                    f"  Processing time window [{window_start_str} to {window_end_str}] for {len(as_group)} AS: {', '.join([f'AS{a}' for a in as_group])}"
                )
                
                if len(as_group) > 1:
                    logger.info(f"    Using BATCH hijack detection (read data once for {len(as_group)} AS)")
                    from detectors.hijack.hijack_detector import detect_hijacks_batch
                    from detectors.leak.leak_detector import analyze_leak_surface
                    from detectors.outage.outage_detector import OUTAGE_DETECTOR
                    
                    batch_hijack_results = detect_hijacks_batch(
                        start_time=r_start,
                        end_time=r_end,
                        target_as_list=[str(asn) for asn in as_group],
                        validate_with_updates=False,
                        save_alerts=False  # Don't save individual alerts in batch mode
                    )
                    
                    for asn in as_group:
                        try:
                            asn_str = str(asn)
                            hijack_data = batch_hijack_results.get(asn_str, {})
                            
                            leak_result = analyze_leak_surface(asn_str, window_start_str, window_end_str, target_asns=[asn_str])
                            
                            outage_result = OUTAGE_DETECTOR.analyze(asn_str, window_start_str, window_end_str)
                            
                            result = {
                                "success": True,
                                "asn": asn_str,
                                "analysis_period": f"{window_start_str} to {window_end_str}",
                                "analysis_timestamp": datetime.now().isoformat(),
                                
                                "origin_hijacked": hijack_data.get("origin_hijacked", []),
                                "forge_hijacked": hijack_data.get("forge_hijacked", []),
                                "origin_hijacking": hijack_data.get("origin_hijacking", []),
                                "forge_hijacking": hijack_data.get("forge_hijacking", []),
                                
                                "route_leaks": leak_result.get("route_leaks", []),
                                "leak_count": leak_result.get("leak_count", 0),
                                "leak_detection_success": leak_result.get("success", False),
                                "leak_detection_error": leak_result.get("error"),
                                
                                "outage_analysis": outage_result,
                                "outage_suspected": bool(outage_result.get("is_outage_suspected", False)),
                                "outage_score": float(outage_result.get("outage_score", 0.0)) if outage_result.get("success") else 0.0,
                                
                                "total_prefix_hijacks": len(hijack_data.get("origin_hijacked", [])) + len(hijack_data.get("forge_hijacked", [])),
                                "total_prefix_hijacking": len(hijack_data.get("origin_hijacking", [])) + len(hijack_data.get("forge_hijacking", [])),
                            }
                        except Exception as exc:
                            logger.error(f"Routing analysis failed for AS{asn}: {exc}")
                            result = {
                                "success": False,
                                "error": str(exc),
                                "asn": asn,
                            }
                        
                        if not result.get("success"):
                            routing_failures.append(asn)
                        routing_results_by_as[str(asn)] = result
                        
                        logger.info(
                            f"    ✅ AS{asn}: {result.get('total_prefix_hijacks', 0)} hijacks, "
                            f"{result.get('leak_count', 0)} leaks, "
                            f"outage={result.get('outage_suspected', False)}"
                        )
                else:
                    asn = as_group[0]
                    try:
                        result = run_routing_agent(
                            asn=str(asn),
                            start_time=window_start_str,
                            end_time=window_end_str,
                            target_asns=[str(asn)]
                        )
                    except Exception as exc:
                        logger.error(f"Routing analysis failed for AS{asn}: {exc}")
                        result = {
                            "success": False,
                            "error": str(exc),
                            "asn": asn,
                        }
                    
                    if not result.get("success"):
                        routing_failures.append(asn)
                    routing_results_by_as[str(asn)] = result
                    
                    logger.info(
                        f"    ✅ AS{asn}: {result.get('total_prefix_hijacks', 0)} hijacks, "
                        f"{result.get('leak_count', 0)} leaks, "
                        f"outage={result.get('outage_suspected', False)}"
                    )
        
        routing_batch_result = {
            "success": len(routing_failures) == 0,
            "batch_mode": True,
            "as_count": len(anomaly_as_list),
            "results_by_as": routing_results_by_as,
            "analysis_timestamp": datetime.now().isoformat(),
            "failed_as": routing_failures,
        }
        
        if routing_failures:
            logger.warning(f"Routing analysis failed for AS: {routing_failures}")

        logger.info(f"Step 4: Generating reasoning analysis for {len(anomaly_as_list)} anomaly AS (parallelized)...")
        reasoning_results = {}
        
        def process_single_as_reasoning(asn):
            """Process reasoning analysis for a single AS"""
            logger.info(f"Reasoning analysis for AS{asn}...")
            
            traffic_data = traffic_batch_result["results_by_as"].get(asn, {})
            routing_data = routing_batch_result["results_by_as"].get(asn, {})
            
            # Create a mini reasoning agent for this AS
            agent = ReasoningAgent(asn, start_dt, end_dt)
            
            # Inject pre-computed results into evidence pool
            agent.evidence_pool = {
                "routing_data": routing_data,
                "traffic_data": traffic_data,
                "data_quality": agent._assess_data_quality(routing_data, traffic_data)
            }
            
            # Perform multi-round reasoning analysis
            for round_num in range(1, max_rounds + 1):
                agent.round_count = round_num
                agent.reasoning_trace.append(f"\n=== ROUND {round_num} REASONING ===")
                
                round_result = agent._perform_reasoning_round({"success": True}, round_num)
                
                if agent._should_conclude_analysis():
                    agent.reasoning_trace.append(f"Analysis concluded after {round_num} rounds")
                    break
            
            # Generate final integration
            reasoning_result = agent._phase3_final_integration()
            return asn, reasoning_result
        
        # Parallelize reasoning analysis using ThreadPoolExecutor (I/O bound, not CPU bound)
        from concurrent.futures import ThreadPoolExecutor, as_completed
        max_workers = min(len(anomaly_as_list), 4)  # Limit to 4 concurrent LLM calls
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(process_single_as_reasoning, asn): asn for asn in anomaly_as_list}
            
            for future in as_completed(futures):
                try:
                    asn, reasoning_result = future.result()
                    reasoning_results[asn] = reasoning_result
                    logger.info(f"✅ Completed reasoning analysis for AS{asn}")
                except Exception as e:
                    asn = futures[future]
                    logger.error(f"❌ Failed reasoning analysis for AS{asn}: {e}")
                    reasoning_results[asn] = {
                        "success": False,
                        "error": str(e),
                        "asn": asn
                    }
        
        # Summary
        logger.info(f"Batch reasoning analysis completed for {len(as_list)} AS")
        logger.info(f"  - Total AS analyzed: {len(as_list)}")
        logger.info(f"  - AS with traffic anomalies: {len(anomaly_as_list)}")
        logger.info(f"  - AS with routing anomalies: {sum(1 for asn in anomaly_as_list if reasoning_results[asn].get('success'))}")
        
        return {
            "success": True,
            "batch_mode": True,
            "analysis_type": "batch_multi-round_reasoning",
            "as_count": len(as_list),
            "anomaly_count": len(anomaly_as_list),
            "time_range": f"{start_time} to {end_time}",
            "traffic_batch_result": traffic_batch_result,
            "routing_batch_result": routing_batch_result,
            "reasoning_results": reasoning_results,
            "anomaly_as_list": anomaly_as_list,
            "analysis_timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Batch reasoning analysis failed: {str(e)}", exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "batch_mode": True
        }


__all__ = ["ReasoningAgent", "run_reasoning_agent", "run_reasoning_agent_batch"] 