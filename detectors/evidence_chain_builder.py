"""
(LLM )
========================

. 

: 
- LLM 
- LLM 
- , LLM 
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Any, List, Dict
import json

from utils.logger import logger
from utils.helpers import extract_json_object


# ============================================================
@dataclass
class Evidence:
    """"""
    id: str
    source: str
    type: str
    timestamp: Optional[str] = None
    content: str = ""
    strength: float = 0.5
    reliability: float = 0.5
    supports: list = field(default_factory=list)
    contradicts: list = field(default_factory=list)
    raw_data: dict = field(default_factory=dict)


@dataclass
class EvidenceChain:
    """"""
    verdict: str
    confidence: float
    hypothesis: str
    reasoning_steps: list
    evidence_chain: list
    assumptions: list
    limitations: list
    evidence_gaps: list
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    llm_analysis: Optional[Dict] = None  # LLM 


# ============================================================
class LLMHypothesisIdentifier:
    """
 LLM 
 
 . 
 """

    SYSTEM_PROMPT = """You are a BGP security expert specializing in evidence analysis and hypothesis generation.

Given observed evidence from multiple data sources, your task is to:
1. Identify which assumptions are most relevant given the evidence
2. Identify limitations that apply to this specific case
3. Identify gaps in the evidence that need to be addressed
4. Generate contextual explanations for the observations

Output MUST be valid JSON:
{
 "assumptions": [
 {
 "assumption": "assumption text",
 "relevance": "high/medium/low",
 "reasoning": "why this assumption is relevant"
 }
 ],
 "limitations": [
 {
 "limitation": "limitation text",
 "impact": "high/medium/low",
 "reasoning": "how this limitation affects the analysis"
 }
 ],
 "evidence_gaps": [
 {
 "gap": "gap description",
 "priority": "high/medium/low",
 "how_to_address": "suggestion to fill the gap"
 }
 ],
 "contextual_insights": [
 "insight1",
 "insight2"
 ]
}"""

    USER_PROMPT_TEMPLATE = """## Evidence Collected

### Traffic Evidence
{traffic_evidence}

### Routing Evidence
{routing_evidence}

### Multi-scale Analysis
{multi_scale_evidence}

### Causal Analysis
{causal_evidence}

## Available Data Sources
- Routing data available: {has_routing}
- Traffic data available: {has_traffic}
- Multi-scale analysis available: {has_multi_scale}
- Causal analysis available: {has_causal}

## Context
- Target AS: {asn}
- Analysis time range: {time_range}

## Task

Based on the evidence collected, identify:
1. Which assumptions are most relevant to this analysis?
2. What limitations should be considered?
3. What evidence gaps exist?
4. Any contextual insights from combining the evidence?
"""

    def __init__(self, llm=None):
        self.llm = llm
        self._llm_initialized = False

    def _ensure_llm(self):
        """ LLM"""
        if not self._llm_initialized:
            try:
                from config import API_KEY, BASE_URL, MODEL
                from llm.llm_factory import DEFAULT_TEMP_REASONING, setup_llm_settings
                self.llm, _ = setup_llm_settings(
                    model=MODEL,
                    api_key=API_KEY,
                    base_url=BASE_URL,
                    temperature=DEFAULT_TEMP_REASONING
                )
                self._llm_initialized = True
            except Exception as e:
                logger.warning(f"Failed to initialize LLM for hypothesis identification: {e}")
                self._llm_initialized = True

    def identify_hypotheses(
        self,
        traffic_result: dict,
        routing_result: dict,
        causal_analysis: Optional[dict],
        multi_scale_analysis: Optional[dict],
        asn: str = "unknown",
        time_range: str = "unknown",
    ) -> Dict[str, Any]:
        """
 
 
 Returns:
 {
 "assumptions": [...],
 "limitations": [...],
 "evidence_gaps": [...],
 "contextual_insights": [...],
 "source": "llm" or "default"
 }
 """
        self._ensure_llm()

        if self.llm is None:
            return self._get_default_identification(traffic_result, routing_result)

        try:
            # 
            traffic_evidence = self._format_traffic_evidence(traffic_result)
            routing_evidence = self._format_routing_evidence(routing_result)
            multi_scale_evidence = self._format_multi_scale_evidence(multi_scale_analysis)
            causal_evidence = self._format_causal_evidence(causal_analysis)

            user_prompt = self.USER_PROMPT_TEMPLATE.format(
                traffic_evidence=traffic_evidence,
                routing_evidence=routing_evidence,
                multi_scale_evidence=multi_scale_evidence,
                causal_evidence=causal_evidence,
                has_routing=bool(routing_result and routing_result.get("success")),
                has_traffic=bool(traffic_result and traffic_result.get("success")),
                has_multi_scale=bool(multi_scale_analysis),
                has_causal=bool(causal_analysis),
                asn=asn,
                time_range=time_range,
            )

            response = self.llm.complete(
                f"System: {self.SYSTEM_PROMPT}\n\nUser: {user_prompt}"
            )

            return self._parse_llm_response(response.text)

        except Exception as e:
            logger.warning(f"LLM hypothesis identification failed: {e}, using defaults")
            return self._get_default_identification(traffic_result, routing_result)

    def _format_traffic_evidence(self, traffic_result: dict) -> str:
        """"""
        if not traffic_result:
            return "No traffic data available"
        
        anomaly_count = traffic_result.get("anomaly_count", 0) or 0
        percent_change = traffic_result.get("percent_change", 0) or 0
        
        if anomaly_count > 0:
            direction = "decrease" if percent_change < 0 else "increase"
            return f"Traffic anomaly detected: {anomaly_count} anomalies, {abs(percent_change):.1f}% {direction}"
        else:
            return "No traffic anomalies detected"

    def _format_routing_evidence(self, routing_result: dict) -> str:
        """"""
        if not routing_result:
            return "No routing data available"
        
        if not routing_result.get("success"):
            return f"Routing analysis failed: {routing_result.get('error', 'Unknown error')}"
        
        origin_hijacked = routing_result.get("origin_hijacked", []) or routing_result.get("origin_hijack", []) or []
        forge_hijacked = routing_result.get("forge_hijacked", []) or routing_result.get("forge_hijack", []) or []
        leaks = routing_result.get("route_leaks", []) or []
        
        parts = []
        if origin_hijacked:
            parts.append(f"{len(origin_hijacked)} origin hijack events")
        if forge_hijacked:
            parts.append(f"{len(forge_hijacked)} path forgery events")
        if leaks:
            parts.append(f"{len(leaks)} route leak events")
        
        return ", ".join(parts) if parts else "No routing anomalies detected"

    def _format_multi_scale_evidence(self, multi_scale: Optional[dict]) -> str:
        """"""
        if not multi_scale:
            return "Multi-scale analysis not available"
        
        is_anomaly = multi_scale.get("is_anomaly")
        reasoning = multi_scale.get("reasoning", "")
        
        if is_anomaly is None:
            return "Multi-scale analysis not available"
        
        return f"Multi-scale anomaly: {is_anomaly}. {reasoning}" if reasoning else f"Multi-scale anomaly: {is_anomaly}"

    def _format_causal_evidence(self, causal: Optional[dict]) -> str:
        """"""
        if not causal:
            return "Causal analysis not available"

        # Bug fix 2026-09-13 (BUG-R80): the previous implementation
        has_link = causal.get("has_association", False) or causal.get("has_causal_link", False)
        score = causal.get("association_score")
        if score is None:
            score = causal.get("causal_score", 0)

        if has_link:
            return f"Causal link confirmed with score {score:.2f}"
        else:
            return "No causal link detected"

    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """ LLM """
        try:
            # Use brace-balanced extraction to avoid the previous
            snippet = extract_json_object(response or "")
            if snippet is not None:
                data = json.loads(snippet)

                return {
                    "assumptions": data.get("assumptions", []),
                    "limitations": data.get("limitations", []),
                    "evidence_gaps": data.get("evidence_gaps", []),
                    "contextual_insights": data.get("contextual_insights", []),
                    "source": "llm"
                }
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to parse LLM hypothesis response: {e}")

        return self._get_default_identification({}, {})

    def _get_default_identification(
        self, 
        traffic_result: dict, 
        routing_result: dict
    ) -> Dict[str, Any]:
        """"""
        assumptions = [
            {
                "assumption": "BGP ",
                "relevance": "high",
                "reasoning": "BGP  15-30 "
            },
            {
                "assumption": "Cloudflare ",
                "relevance": "medium",
                "reasoning": " API"
            },
            {
                "assumption": "",
                "relevance": "high",
                "reasoning": ""
            },
        ]

        limitations = [
            {
                "limitation": "BGP  15-30 ",
                "impact": "medium",
                "reasoning": ""
            },
            {
                "limitation": " API，",
                "impact": "low",
                "reasoning": "API "
            },
            {
                "limitation": "",
                "impact": "medium",
                "reasoning": "CDN-related traffic drop"
            },
        ]

        evidence_gaps = []
        if not traffic_result:
            evidence_gaps.append({
                "gap": "",
                "priority": "high",
                "how_to_address": " API "
            })
        if not routing_result:
            evidence_gaps.append({
                "gap": " BGP ",
                "priority": "high",
                "how_to_address": " MRT  BGP "
            })

        return {
            "assumptions": assumptions,
            "limitations": limitations,
            "evidence_gaps": evidence_gaps,
            "contextual_insights": [],
            "source": "default"
        }


# ============================================================
class EvidenceChainBuilder:
    """
 (LLM )
 
 . 
 LLM . 
 """

    SOURCE_PRIORITY = {
        "bgp": 0.9,
        "cloudflare": 0.85,
        "causal_analysis": 0.8,
        "bayesian": 0.75,
        "multi_scale": 0.7,
        "external": 0.6,
    }

    def __init__(self, use_llm: bool = False):
        """
 Args:
 use_llm: LLM 
 """
        self.use_llm = use_llm
        self.hypothesis_identifier = LLMHypothesisIdentifier() if use_llm else None

    def build(
        self,
        traffic_result: dict,
        routing_result: dict,
        causal_analysis: Optional[dict] = None,
        bayesian_result: Optional[dict] = None,
        # LLM 
        asn: str = "unknown",
        time_range: str = "unknown",
    ) -> EvidenceChain:
        """
 
 
 Args:
 traffic_result: 
 routing_result: 
 causal_analysis: 
 bayesian_result: 
 asn: AS 
 time_range: 
 
 Returns:
 EvidenceChain: 
 """
        evidence_chain = []
        reasoning_steps = []
        llm_analysis = None

        # 
        routing_evidence = self._extract_routing_evidence(routing_result)
        evidence_chain.extend(routing_evidence)

        # 
        traffic_evidence = self._extract_traffic_evidence(traffic_result)
        evidence_chain.extend(traffic_evidence)

        # 
        multi_scale_evidence = self._extract_multi_scale_evidence(traffic_result)
        evidence_chain.extend(multi_scale_evidence)

        # 
        causal_evidence = self._extract_causal_evidence(causal_analysis)
        evidence_chain.extend(causal_evidence)

        # LLM-assisted hypothesis generation path.
        if self.use_llm and self.hypothesis_identifier:
            llm_analysis = self.hypothesis_identifier.identify_hypotheses(
                traffic_result=traffic_result,
                routing_result=routing_result,
                causal_analysis=causal_analysis,
                multi_scale_analysis=traffic_result.get("multi_scale_analysis"),
                asn=asn,
                time_range=time_range,
            )
            assumptions = [a["assumption"] for a in llm_analysis.get("assumptions", [])]
            limitations = [l["limitation"] for l in llm_analysis.get("limitations", [])]
            evidence_gaps = [g["gap"] for g in llm_analysis.get("evidence_gaps", [])]
            contextual_insights = llm_analysis.get("contextual_insights", [])
        else:
            assumptions = self._identify_assumptions(traffic_result, routing_result, evidence_chain)
            limitations = self._identify_limitations(evidence_chain, traffic_result, routing_result)
            # Bug fix 2026-09-13 (BUG-R45): pass causal_analysis through
            evidence_gaps = self._identify_evidence_gaps(
                traffic_result, routing_result, causal_analysis,
            )
            contextual_insights = []
            llm_analysis = {"source": "default"}

        # 
        reasoning_steps = self._build_reasoning_steps(
            traffic_result, routing_result, causal_analysis, bayesian_result
        )

        # 
        verdict = self._determine_verdict(
            traffic_result, routing_result, causal_analysis, bayesian_result
        )
        confidence = self._compute_confidence(
            evidence_chain, bayesian_result
        )
        hypothesis = self._get_hypothesis(
            traffic_result, routing_result, bayesian_result
        )

        return EvidenceChain(
            verdict=verdict,
            confidence=confidence,
            hypothesis=hypothesis,
            reasoning_steps=reasoning_steps,
            evidence_chain=evidence_chain,
            assumptions=assumptions,
            limitations=limitations,
            evidence_gaps=evidence_gaps,
            llm_analysis=llm_analysis,
        )

    def _extract_routing_evidence(self, routing_result: dict) -> list:
        """"""
        evidence = []
        if not routing_result or not routing_result.get("data_available", routing_result.get("success", False)):
            reason = (routing_result or {}).get("no_data_reason") or (routing_result or {}).get("error")
            evidence.append(Evidence(
                id="routing_no_data",
                source="system",
                type="absence",
                content=f"{f'：{reason}' if reason else ''}",
                strength=0.0,
                reliability=0.5,
            ))
            return evidence

        hijacks = (
            routing_result.get("origin_hijacked", []) or routing_result.get("origin_hijack", []) or []
        ) + (
            routing_result.get("forge_hijacked", []) or routing_result.get("forge_hijack", []) or []
        )

        if hijacks:
            evidence.append(Evidence(
                id="routing_hijack_detected",
                source="bgp",
                type="anomaly",
                content=f" {len(hijacks)}  BGP ",
                strength=0.9,
                reliability=self.SOURCE_PRIORITY["bgp"],
                raw_data={"count": len(hijacks), "events": hijacks[:3]},
            ))
        else:
            evidence.append(Evidence(
                id="routing_no_hijack",
                source="bgp",
                type="normal",
                content=" BGP ",
                strength=0.6,
                reliability=self.SOURCE_PRIORITY["bgp"],
            ))

        leaks = routing_result.get("route_leaks", []) or []
        outage = routing_result.get("outage_analysis") or {}

        if leaks:
            evidence.append(Evidence(
                id="routing_leak_detected",
                source="bgp",
                type="anomaly",
                content=f" {len(leaks)} ",
                strength=0.8,
                reliability=self.SOURCE_PRIORITY["bgp"],
                raw_data={"count": len(leaks), "events": leaks[:3]},
            ))
        if outage.get("is_outage_suspected"):
            evidence.append(Evidence(
                id="routing_outage_detected",
                source="bgp",
                type="anomaly",
                content="",
                # A skipped outage detector reports outage_score=None; float(None)
                # would raise. Default to 0.0 rather than the old 0.6 so a missing
                # score is never inflated into apparent evidence strength.
                strength=min(1.0, float(outage.get("outage_score") or 0.0)),
                reliability=self.SOURCE_PRIORITY["bgp"],
                raw_data=outage,
            ))

        return evidence

    def _extract_traffic_evidence(self, traffic_result: dict) -> list:
        """"""
        evidence = []
        if not traffic_result or not traffic_result.get("data_available", True):
            evidence.append(Evidence(
                id="traffic_no_data",
                source="system",
                type="absence",
                content="",
                strength=0.0,
                reliability=0.5,
            ))
            return evidence

        anomaly_count = traffic_result.get("anomaly_count", 0) or 0
        percent_change = traffic_result.get("percent_change", 0) or 0

        if anomaly_count > 0:
            direction = "" if percent_change < 0 else ""
            evidence.append(Evidence(
                id="traffic_anomaly_detected",
                source="cloudflare",
                type="anomaly",
                content=f" {anomaly_count} ， {direction} {abs(percent_change):.1f}%",
                strength=min(1.0, anomaly_count / 5),
                reliability=self.SOURCE_PRIORITY["cloudflare"],
                raw_data={
                    "anomaly_count": anomaly_count,
                    "percent_change": percent_change,
                },
            ))
        else:
            evidence.append(Evidence(
                id="traffic_no_anomaly",
                source="cloudflare",
                type="normal",
                content="",
                strength=0.6,
                reliability=self.SOURCE_PRIORITY["cloudflare"],
            ))

        return evidence

    def _extract_multi_scale_evidence(self, traffic_result: dict) -> list:
        """"""
        evidence = []
        multi_scale = traffic_result.get("multi_scale_analysis")
        if not multi_scale:
            evidence.append(Evidence(
                id="multi_scale_not_available",
                source="system",
                type="absence",
                content="",
                strength=0.0,
                reliability=0.5,
            ))
            return evidence

        is_anomaly = multi_scale.get("is_anomaly")
        if is_anomaly is not None:
            consensus = multi_scale.get("consensus_count", 0)
            score = multi_scale.get("weighted_score", 0)
            reasoning = multi_scale.get("reasoning", "")

            evidence.append(Evidence(
                id="multi_scale_analysis",
                source="multi_scale",
                type="anomaly" if is_anomaly else "normal",
                content=f"：{reasoning}",
                strength=0.8 if is_anomaly else 0.5,
                reliability=self.SOURCE_PRIORITY["multi_scale"],
                raw_data=multi_scale,
            ))

        return evidence

    def _extract_causal_evidence(self, causal_analysis: dict) -> list:
        """"""
        evidence = []
        if not causal_analysis:
            evidence.append(Evidence(
                id="causal_not_available",
                source="system",
                type="absence",
                content="",
                strength=0.0,
                reliability=0.5,
            ))
            return evidence

        has_association = causal_analysis.get("has_association", False)
        association_score = causal_analysis.get("association_score", causal_analysis.get("causal_score", 0))
        temporal = causal_analysis.get("temporal_alignment", 0)
        semantic = causal_analysis.get("semantic_alignment", 0)

        if has_association:
            evidence.append(Evidence(
                id="routing_traffic_association",
                source="causal_analysis",
                type="correlation",
                content=f"（：{association_score:.2f}），",
                strength=association_score,
                reliability=self.SOURCE_PRIORITY["causal_analysis"],
                raw_data=causal_analysis,
            ))
            if temporal >= 0.7:
                evidence.append(Evidence(
                    id="association_temporal_strong",
                    source="causal_analysis",
                    type="support",
                    content="： 60 ",
                    strength=temporal,
                    reliability=self.SOURCE_PRIORITY["causal_analysis"],
                ))
            if semantic >= 0.7:
                evidence.append(Evidence(
                    id="association_semantic_strong",
                    source="causal_analysis",
                    type="support",
                    content="： AS ",
                    strength=semantic,
                    reliability=self.SOURCE_PRIORITY["causal_analysis"],
                ))
        else:
            evidence.append(Evidence(
                id="routing_traffic_not_associated",
                source="causal_analysis",
                type="negative",
                content=" AS ",
                strength=0.4,
                reliability=self.SOURCE_PRIORITY["causal_analysis"],
            ))

        return evidence

    def _build_reasoning_steps(
        self,
        traffic_result: dict,
        routing_result: dict,
        causal_analysis: Optional[dict],
        bayesian_result: Optional[dict],
    ) -> list:
        """"""
        steps = []

        traffic_anomaly = (traffic_result or {}).get("anomaly_count", 0) > 0
        routing_anomaly = self._has_routing_anomaly(routing_result)

        steps.append({
            "step": 1,
            "type": "observation",
            "content": "：",
            "sub_steps": [
                f"{'' if traffic_anomaly else ''}",
                f"{'' if routing_anomaly else ''}",
            ]
        })

        if causal_analysis:
            has_association = causal_analysis.get("has_association", False)
            if has_association:
                steps.append({
                    "step": 2,
                    "type": "correlation",
                    "content": "，",
                    "confidence": causal_analysis.get("association_score", causal_analysis.get("causal_score", 0)),
                })
            else:
                steps.append({
                    "step": 2,
                    "type": "correlation",
                    "content": "， AS ",
                    "confidence": 0.2,
                })

        if bayesian_result:
            best = bayesian_result.get("best_hypothesis", "unknown")
            confidence = bayesian_result.get("confidence", 0)
            steps.append({
                "step": 3,
                "type": "hypothesis",
                "content": f"[{best}]",
                "confidence": confidence,
            })

        steps.append({
            "step": 4,
            "type": "conclusion",
            "content": "，",
        })

        return steps

    def _identify_assumptions(
        self,
        traffic_result: dict,
        routing_result: dict,
        evidence_chain: list,
    ) -> list:
        """()"""
        assumptions = [
            "BGP ",
            "Cloudflare ",
            "",
            "（）",
        ]

        if not evidence_chain:
            assumptions.append("")

        return assumptions

    def _identify_limitations(
        self, 
        evidence_chain: list,
        traffic_result: dict,
        routing_result: dict
    ) -> list:
        """"""
        limitations = [
            "BGP feed lag 15-30 minutes",
            "CDN/RIS API rate limit",
            "Client connectivity restored (e.g. CDN edge back online)",
            "",
        ]

        has_routing = any(e.type in ["anomaly", "normal"] and e.source == "bgp" for e in evidence_chain)
        if not has_routing:
            limitations.append("")

        has_traffic = any(e.type in ["anomaly", "normal"] and e.source == "cloudflare" for e in evidence_chain)
        if not has_traffic:
            limitations.append("")

        return limitations

    def _identify_evidence_gaps(
        self,
        traffic_result: dict,
        routing_result: dict,
        causal_analysis: Optional[dict] = None,
    ) -> list:
        """"""
        gaps = []

        if not traffic_result or not traffic_result.get("data_available", True):
            gaps.append("，")

        if not routing_result or not routing_result.get("success", True):
            gaps.append(" BGP ，")

        multi_scale = (traffic_result or {}).get("multi_scale_analysis")
        if not multi_scale:
            gaps.append("，")

        # Bug fix 2026-09-13 (BUG-R45): previously this branch incorrectly
        causal_present = bool(causal_analysis)
        has_association_flag = bool(
            causal_analysis.get("has_association")
        ) if causal_present else False
        has_association_score = bool(
            causal_analysis.get("association_score")
        ) if causal_present else False
        if not causal_present and not (has_association_flag or has_association_score):
            gaps.append("")

        return gaps

    def _has_routing_anomaly(self, routing_result: dict) -> bool:
        routing_result = routing_result or {}
        return any([
            bool(routing_result.get("origin_hijacked") or routing_result.get("origin_hijack")),
            bool(routing_result.get("forge_hijacked") or routing_result.get("forge_hijack")),
            bool(routing_result.get("route_leaks")),
            bool((routing_result.get("outage_analysis") or {}).get("is_outage_suspected")),
        ])

    def _determine_verdict(
        self,
        traffic_result: dict,
        routing_result: dict,
        causal_analysis: Optional[dict],
        bayesian_result: Optional[dict],
    ) -> str:
        """"""
        if bayesian_result:
            return bayesian_result.get("verdict", "inconclusive")
        if not traffic_result or not traffic_result.get("data_available", True):
            return "inconclusive_missing_traffic"
        if not routing_result or not routing_result.get("success", True):
            return "inconclusive_missing_routing"

        traffic_anomaly = (traffic_result or {}).get("anomaly_count", 0) > 0
        routing_anomaly = self._has_routing_anomaly(routing_result)
        correlation = (causal_analysis or {}).get("has_association", False)

        if traffic_anomaly and routing_anomaly and correlation:
            return "correlated_observations"
        elif traffic_anomaly and routing_anomaly:
            return "cooccurring_anomalies"
        elif traffic_anomaly:
            return "traffic_only_anomaly"
        elif routing_anomaly:
            return "routing_only_anomaly"
        else:
            return "verified_normal"

    def _compute_confidence(
        self,
        evidence_chain: list,
        bayesian_result: Optional[dict],
    ) -> float:
        """"""
        if bayesian_result:
            return bayesian_result.get("confidence", 0.5)

        if not evidence_chain:
            return 0.0

        total_weight = 0.0
        weighted_sum = 0.0

        for e in evidence_chain:
            weight = e.strength * e.reliability
            weighted_sum += weight
            total_weight += 1.0

        if total_weight == 0:
            return 0.0

        return min(1.0, weighted_sum / total_weight)

    def _get_hypothesis(
        self,
        traffic_result: dict,
        routing_result: dict,
        bayesian_result: Optional[dict],
    ) -> str:
        """"""
        if bayesian_result:
            return bayesian_result.get("best_hypothesis", "unknown")

        traffic_anomaly = (traffic_result or {}).get("anomaly_count", 0) > 0
        routing_anomaly = self._has_routing_anomaly(routing_result)

        if traffic_anomaly and routing_anomaly:
            return "observationally_associated"
        elif traffic_anomaly:
            return "traffic_only"
        elif routing_anomaly:
            return "routing_only"
        else:
            return "no_anomaly"

    def to_dict(self, chain: EvidenceChain) -> dict:
        """"""
        return {
            "verdict": chain.verdict,
            "confidence": chain.confidence,
            "hypothesis": chain.hypothesis,
            "generated_at": chain.generated_at,
            "reasoning_steps": chain.reasoning_steps,
            "evidence_chain": [
                {
                    "id": e.id,
                    "source": e.source,
                    "type": e.type,
                    "content": e.content,
                    "strength": e.strength,
                    "reliability": e.reliability,
                }
                for e in chain.evidence_chain
            ],
            "assumptions": chain.assumptions,
            "limitations": chain.limitations,
            "evidence_gaps": chain.evidence_gaps,
            "llm_analysis_source": chain.llm_analysis.get("source") if chain.llm_analysis else "none",
        }

    def to_natural_language(self, chain: EvidenceChain) -> str:
        """"""
        lines = []

        lines.append("## ")
        lines.append("")

        lines.append(f"****: {self._format_verdict(chain.verdict)}")
        lines.append(f"****: {chain.confidence:.1%}")
        lines.append(f"****: {self._format_hypothesis(chain.hypothesis)}")
        lines.append("")

        lines.append("### ")
        for e in chain.evidence_chain:
            icon = self._get_evidence_icon(e.type)
            lines.append(f"{icon} **{e.source}**: {e.content}")
        lines.append("")

        if chain.reasoning_steps:
            lines.append("### ")
            for step in chain.reasoning_steps:
                if step["type"] == "observation":
                    lines.append(f"** {step['step']}: {step['content']}**")
                    for sub in step.get("sub_steps", []):
                        lines.append(f"  - {sub}")
                else:
                    conf = step.get("confidence", 0)
                    conf_str = f" ( {conf:.1%})" if conf else ""
                    lines.append(f"** {step['step']}**: {step['content']}{conf_str}")
            lines.append("")

        if chain.assumptions:
            lines.append("### ")
            for a in chain.assumptions:
                lines.append(f"- {a}")
            lines.append("")

        if chain.limitations:
            lines.append("### ")
            for l in chain.limitations:
                lines.append(f"- {l}")
            lines.append("")

        if chain.evidence_gaps:
            lines.append("### ")
            for g in chain.evidence_gaps:
                lines.append(f"- {g}")
            lines.append("")

        return "\n".join(lines)

    def _format_verdict(self, verdict: str) -> str:
        """"""
        formats = {
            "correlated_observations": "",
            "cooccurring_anomalies": "，",
            "inconclusive_missing_traffic": "，",
            "inconclusive_missing_routing": "，",
            "routing_only_anomaly": "",
            "verified_normal": "",
            "contested": "",
            "inconclusive": "",
        }
        return formats.get(verdict, verdict)

    def _format_hypothesis(self, hypothesis: str) -> str:
        """"""
        formats = {
            "correlated": "",
            "observationally_associated": "",
            "routing_only": "",
            "no_anomaly": "",
            "unknown": "",
        }
        return formats.get(hypothesis, hypothesis)

    def _get_evidence_icon(self, evidence_type: str) -> str:
        """"""
        icons = {
            "anomaly": "[!]",
            "normal": "[OK]",
            "correlation": "[→]",
            "support": "[+]",
            "negative": "[-]",
            "absence": "[?]",
        }
        return icons.get(evidence_type, "[*]")
