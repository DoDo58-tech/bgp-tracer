"""
证据链构建器（LLM 驱动版本）
========================

将多源检测结果构建为可解释的证据链。

核心改进：
- LLM 根据证据内容动态生成假设和限制条件
- LLM 根据上下文信息生成更准确的假设识别
- 保留证据链结构，但用 LLM 提供领域知识
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Any, List, Dict
import json

from utils.logger import logger
from utils.helpers import extract_json_object


# ============================================================
# 数据结构
# ============================================================

@dataclass
class Evidence:
    """单个证据"""
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
    """证据链"""
    verdict: str
    confidence: float
    hypothesis: str
    reasoning_steps: list
    evidence_chain: list
    assumptions: list
    limitations: list
    evidence_gaps: list
    generated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    llm_analysis: Optional[Dict] = None  # LLM 生成的额外分析


# ============================================================
# LLM 假设识别器
# ============================================================

class LLMHypothesisIdentifier:
    """
    LLM 驱动的假设识别器
    
    根据证据内容动态识别相关的假设和限制条件。
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
        """延迟初始化 LLM"""
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
        识别假设、限制条件和证据缺口
        
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
            # 构建证据文本
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
        """格式化流量证据"""
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
        """格式化路由证据"""
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
        """格式化多尺度证据"""
        if not multi_scale:
            return "Multi-scale analysis not available"
        
        is_anomaly = multi_scale.get("is_anomaly")
        reasoning = multi_scale.get("reasoning", "")
        
        if is_anomaly is None:
            return "Multi-scale analysis not available"
        
        return f"Multi-scale anomaly: {is_anomaly}. {reasoning}" if reasoning else f"Multi-scale anomaly: {is_anomaly}"

    def _format_causal_evidence(self, causal: Optional[dict]) -> str:
        """格式化因果证据"""
        if not causal:
            return "Causal analysis not available"

        # Bug fix 2026-09-13 (BUG-R80): the previous implementation
        # looked up ``has_causal_link`` and ``causal_score``. The
        # ``multi_scale_baseline`` scorer (the source of this dict)
        # explicitly sets ``has_causal_link=False`` and emits the real
        # association signal under ``has_association`` /
        # ``association_score`` (see ``multi_scale_baseline.py`` line
        # 619-628). The old key read therefore *always* reported "No
        # causal link detected" even when the data showed a strong
        # association, biasing the LLM-driven hypothesis identification
        # toward "no causality" and suppressing the contextual insights
        # that would otherwise be produced.
        has_link = causal.get("has_association", False) or causal.get("has_causal_link", False)
        score = causal.get("association_score")
        if score is None:
            score = causal.get("causal_score", 0)

        if has_link:
            return f"Causal link confirmed with score {score:.2f}"
        else:
            return "No causal link detected"

    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """解析 LLM 响应"""
        try:
            # Use brace-balanced extraction to avoid the previous
            # ``find("{") + rfind("}")`` trap where nested braces in
            # string values (e.g. ``"note": "{foo}"``) would cause the
            # parser to truncate the JSON early.
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
        """获取默认识别结果"""
        assumptions = [
            {
                "assumption": "BGP 数据采集延迟在可接受范围内",
                "relevance": "high",
                "reasoning": "BGP 数据通常有 15-30 分钟采集延迟"
            },
            {
                "assumption": "Cloudflare 流量数据能反映真实流量变化",
                "relevance": "medium",
                "reasoning": "流量数据来自第三方 API"
            },
            {
                "assumption": "路由异常会导致流量下降",
                "relevance": "high",
                "reasoning": "这是核心假设"
            },
        ]

        limitations = [
            {
                "limitation": "BGP 数据可能存在 15-30 分钟采集延迟",
                "impact": "medium",
                "reasoning": "可能导致时间对齐不准确"
            },
            {
                "limitation": "流量数据来自第三方 API，可能存在采样偏差",
                "impact": "low",
                "reasoning": "API 采样可能不完全代表所有流量"
            },
            {
                "limitation": "无法完全排除所有混淆变量",
                "impact": "medium",
                "reasoning": "CDN 切换、备用路由等因素"
            },
        ]

        evidence_gaps = []
        if not traffic_result:
            evidence_gaps.append({
                "gap": "缺少流量监测数据",
                "priority": "high",
                "how_to_address": "检查 API 连接或使用备用数据源"
            })
        if not routing_result:
            evidence_gaps.append({
                "gap": "缺少 BGP 路由数据",
                "priority": "high",
                "how_to_address": "检查 MRT 文件或 BGP 数据源"
            })

        return {
            "assumptions": assumptions,
            "limitations": limitations,
            "evidence_gaps": evidence_gaps,
            "contextual_insights": [],
            "source": "default"
        }


# ============================================================
# 证据链构建器（LLM 驱动）
# ============================================================

class EvidenceChainBuilder:
    """
    证据链构建器（LLM 驱动版本）
    
    将检测结果转换为结构化的证据链。
    支持 LLM 动态生成假设、限制条件和证据缺口。
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
            use_llm: 是否使用 LLM 生成假设和限制条件
        """
        self.use_llm = use_llm
        self.hypothesis_identifier = LLMHypothesisIdentifier() if use_llm else None

    def build(
        self,
        traffic_result: dict,
        routing_result: dict,
        causal_analysis: Optional[dict] = None,
        bayesian_result: Optional[dict] = None,
        # LLM 参数
        asn: str = "unknown",
        time_range: str = "unknown",
    ) -> EvidenceChain:
        """
        构建证据链
        
        Args:
            traffic_result: 流量检测结果
            routing_result: 路由检测结果
            causal_analysis: 因果分析结果
            bayesian_result: 贝叶斯分析结果
            asn: AS 号码
            time_range: 分析时间范围
        
        Returns:
            EvidenceChain: 证据链对象
        """
        evidence_chain = []
        reasoning_steps = []
        llm_analysis = None

        # 收集路由证据
        routing_evidence = self._extract_routing_evidence(routing_result)
        evidence_chain.extend(routing_evidence)

        # 收集流量证据
        traffic_evidence = self._extract_traffic_evidence(traffic_result)
        evidence_chain.extend(traffic_evidence)

        # 收集多尺度基线证据
        multi_scale_evidence = self._extract_multi_scale_evidence(traffic_result)
        evidence_chain.extend(multi_scale_evidence)

        # 收集因果关联证据
        causal_evidence = self._extract_causal_evidence(causal_analysis)
        evidence_chain.extend(causal_evidence)

        # LLM 动态生成假设、限制条件和证据缺口
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
            # so the gap detector can correctly decide whether the
            # causal-association evidence is genuinely missing.
            evidence_gaps = self._identify_evidence_gaps(
                traffic_result, routing_result, causal_analysis,
            )
            contextual_insights = []
            llm_analysis = {"source": "default"}

        # 构建推理步骤
        reasoning_steps = self._build_reasoning_steps(
            traffic_result, routing_result, causal_analysis, bayesian_result
        )

        # 确定判决
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
        """提取路由证据"""
        evidence = []
        if not routing_result or not routing_result.get("data_available", routing_result.get("success", False)):
            reason = (routing_result or {}).get("no_data_reason") or (routing_result or {}).get("error")
            evidence.append(Evidence(
                id="routing_no_data",
                source="system",
                type="absence",
                content=f"无可用路由数据{f'：{reason}' if reason else ''}",
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
                content=f"检测到 {len(hijacks)} 个 BGP 劫持事件",
                strength=0.9,
                reliability=self.SOURCE_PRIORITY["bgp"],
                raw_data={"count": len(hijacks), "events": hijacks[:3]},
            ))
        else:
            evidence.append(Evidence(
                id="routing_no_hijack",
                source="bgp",
                type="normal",
                content="未检测到 BGP 劫持事件",
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
                content=f"检测到 {len(leaks)} 个路由泄漏事件",
                strength=0.8,
                reliability=self.SOURCE_PRIORITY["bgp"],
                raw_data={"count": len(leaks), "events": leaks[:3]},
            ))
        if outage.get("is_outage_suspected"):
            evidence.append(Evidence(
                id="routing_outage_detected",
                source="bgp",
                type="anomaly",
                content="检测到疑似路由中断",
                strength=min(1.0, float(outage.get("outage_score", 0.6))),
                reliability=self.SOURCE_PRIORITY["bgp"],
                raw_data=outage,
            ))

        return evidence

    def _extract_traffic_evidence(self, traffic_result: dict) -> list:
        """提取流量证据"""
        evidence = []
        if not traffic_result or not traffic_result.get("data_available", True):
            evidence.append(Evidence(
                id="traffic_no_data",
                source="system",
                type="absence",
                content="没有可用于判断影响的流量数据",
                strength=0.0,
                reliability=0.5,
            ))
            return evidence

        anomaly_count = traffic_result.get("anomaly_count", 0) or 0
        percent_change = traffic_result.get("percent_change", 0) or 0

        if anomaly_count > 0:
            direction = "下降" if percent_change < 0 else "上升"
            evidence.append(Evidence(
                id="traffic_anomaly_detected",
                source="cloudflare",
                type="anomaly",
                content=f"检测到 {anomaly_count} 个流量异常，流量 {direction} {abs(percent_change):.1f}%",
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
                content="未检测到流量异常",
                strength=0.6,
                reliability=self.SOURCE_PRIORITY["cloudflare"],
            ))

        return evidence

    def _extract_multi_scale_evidence(self, traffic_result: dict) -> list:
        """提取多尺度基线证据"""
        evidence = []
        multi_scale = traffic_result.get("multi_scale_analysis")
        if not multi_scale:
            evidence.append(Evidence(
                id="multi_scale_not_available",
                source="system",
                type="absence",
                content="多尺度基线分析不可用",
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
                content=f"多尺度基线检测结果：{reasoning}",
                strength=0.8 if is_anomaly else 0.5,
                reliability=self.SOURCE_PRIORITY["multi_scale"],
                raw_data=multi_scale,
            ))

        return evidence

    def _extract_causal_evidence(self, causal_analysis: dict) -> list:
        """提取因果关联证据"""
        evidence = []
        if not causal_analysis:
            evidence.append(Evidence(
                id="causal_not_available",
                source="system",
                type="absence",
                content="因果关联分析不可用",
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
                content=f"路由事件与流量异常存在时间和语义关联（分数：{association_score:.2f}），但观测数据不足以单独证明因果关系",
                strength=association_score,
                reliability=self.SOURCE_PRIORITY["causal_analysis"],
                raw_data=causal_analysis,
            ))
            if temporal >= 0.7:
                evidence.append(Evidence(
                    id="association_temporal_strong",
                    source="causal_analysis",
                    type="support",
                    content="时间关联强：匹配的流量异常发生在路由事件后的 60 分钟内",
                    strength=temporal,
                    reliability=self.SOURCE_PRIORITY["causal_analysis"],
                ))
            if semantic >= 0.7:
                evidence.append(Evidence(
                    id="association_semantic_strong",
                    source="causal_analysis",
                    type="support",
                    content="语义一致：路由事件角色与目标 AS 的流量影响相符",
                    strength=semantic,
                    reliability=self.SOURCE_PRIORITY["causal_analysis"],
                ))
        else:
            evidence.append(Evidence(
                id="routing_traffic_not_associated",
                source="causal_analysis",
                type="negative",
                content="没有足够的时间和语义证据将路由事件与目标 AS 的流量异常关联起来",
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
        """构建推理步骤"""
        steps = []

        traffic_anomaly = (traffic_result or {}).get("anomaly_count", 0) > 0
        routing_anomaly = self._has_routing_anomaly(routing_result)

        steps.append({
            "step": 1,
            "type": "observation",
            "content": "首先观察到以下事实：",
            "sub_steps": [
                f"{'检测到流量异常' if traffic_anomaly else '流量无异常'}",
                f"{'检测到路由异常' if routing_anomaly else '路由无异常'}",
            ]
        })

        if causal_analysis:
            has_association = causal_analysis.get("has_association", False)
            if has_association:
                steps.append({
                    "step": 2,
                    "type": "correlation",
                    "content": "时间与事件角色支持路由事件和流量异常之间的观测关联，尚不能单独证明因果关系",
                    "confidence": causal_analysis.get("association_score", causal_analysis.get("causal_score", 0)),
                })
            else:
                steps.append({
                    "step": 2,
                    "type": "correlation",
                    "content": "时间或事件角色证据不足，未建立路由事件与目标 AS 流量异常的关联",
                    "confidence": 0.2,
                })

        if bayesian_result:
            best = bayesian_result.get("best_hypothesis", "unknown")
            confidence = bayesian_result.get("confidence", 0)
            steps.append({
                "step": 3,
                "type": "hypothesis",
                "content": f"贝叶斯分析支持「{best}」假设",
                "confidence": confidence,
            })

        steps.append({
            "step": 4,
            "type": "conclusion",
            "content": "综合以上证据，得出最终判决",
        })

        return steps

    def _identify_assumptions(
        self,
        traffic_result: dict,
        routing_result: dict,
        evidence_chain: list,
    ) -> list:
        """识别假设（默认版本）"""
        assumptions = [
            "BGP 数据采集延迟在可接受范围内",
            "Cloudflare 流量数据能反映真实流量变化",
            "历史同期的流量模式具有参考价值",
            "路由异常会导致流量下降（而非其他复杂因果）",
        ]

        if not evidence_chain:
            assumptions.append("检测数据来源可靠")

        return assumptions

    def _identify_limitations(
        self, 
        evidence_chain: list,
        traffic_result: dict,
        routing_result: dict
    ) -> list:
        """识别限制"""
        limitations = [
            "BGP 数据可能存在 15-30 分钟采集延迟",
            "流量数据来自第三方 API，可能存在采样偏差",
            "无法完全排除所有混淆变量（如 CDN 切换、备用路由）",
            "多尺度历史数据可能不可用或质量不佳",
        ]

        has_routing = any(e.type in ["anomaly", "normal"] and e.source == "bgp" for e in evidence_chain)
        if not has_routing:
            limitations.append("缺乏路由数据支撑")

        has_traffic = any(e.type in ["anomaly", "normal"] and e.source == "cloudflare" for e in evidence_chain)
        if not has_traffic:
            limitations.append("缺乏流量数据支撑")

        return limitations

    def _identify_evidence_gaps(
        self,
        traffic_result: dict,
        routing_result: dict,
        causal_analysis: Optional[dict] = None,
    ) -> list:
        """识别证据缺口"""
        gaps = []

        if not traffic_result or not traffic_result.get("data_available", True):
            gaps.append("缺少可用流量监测数据，无法判断流量影响")

        if not routing_result or not routing_result.get("success", True):
            gaps.append("缺少可用 BGP 路由数据，无法确认路由异常")

        multi_scale = (traffic_result or {}).get("multi_scale_analysis")
        if not multi_scale:
            gaps.append("缺少多尺度基线对比，历史参考有限")

        # Bug fix 2026-09-13 (BUG-R45): previously this branch incorrectly
        # read ``traffic_result["multi_scale_analysis"]["is_anomaly"]`` and
        # named the local variable ``causal``. Two problems:
        #   (1) The name shadowed the function's intent — the variable
        #       wasn't about causal association at all, but about multi-scale
        #       anomaly detection. So when multi-scale ran and returned
        #       is_anomaly=False, the gap "缺少因果关联分析" was silently
        #       omitted even if causal_analysis was absent.
        #   (2) The function signature didn't accept ``causal_analysis`` so
        #       the caller in ``build()`` (line 449) silently dropped it on
        #       the floor — ``identify_hypotheses`` got it but
        #       ``_identify_evidence_gaps`` did not.
        # Now we honour the optional ``causal_analysis`` parameter and only
        # raise the gap when causal_analysis is genuinely missing/empty.
        # Bug fix 2026-09-13 (BUG-R96): the original BUG-R45 fix was
        # written without parentheses around the disjunction:
        #     if not A or not B and not C:
        # which Python parses as ``if not A or (not B and not C)`` —
        # i.e. the gap is reported whenever ``causal_analysis`` exists
        # but the LLM decided ``has_association`` is False (regardless
        # of whether a real analysis ran). The intended semantic is
        # "analysis missing", not "analysis ran but found nothing",
        # so we now wrap the disjunction explicitly and require
        # BOTH absence indicators before flagging the gap.
        causal_present = bool(causal_analysis)
        has_association_flag = bool(
            causal_analysis.get("has_association")
        ) if causal_present else False
        has_association_score = bool(
            causal_analysis.get("association_score")
        ) if causal_present else False
        if not causal_present and not (has_association_flag or has_association_score):
            gaps.append("缺少因果关联分析")

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
        """确定判决"""
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
        """计算置信度"""
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
        """获取假设"""
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
        """转换为字典"""
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
        """生成自然语言报告"""
        lines = []

        lines.append("## 证据链分析报告")
        lines.append("")

        lines.append(f"**判决**: {self._format_verdict(chain.verdict)}")
        lines.append(f"**置信度**: {chain.confidence:.1%}")
        lines.append(f"**假设**: {self._format_hypothesis(chain.hypothesis)}")
        lines.append("")

        lines.append("### 证据链")
        for e in chain.evidence_chain:
            icon = self._get_evidence_icon(e.type)
            lines.append(f"{icon} **{e.source}**: {e.content}")
        lines.append("")

        if chain.reasoning_steps:
            lines.append("### 推理过程")
            for step in chain.reasoning_steps:
                if step["type"] == "observation":
                    lines.append(f"**步骤 {step['step']}: {step['content']}**")
                    for sub in step.get("sub_steps", []):
                        lines.append(f"  - {sub}")
                else:
                    conf = step.get("confidence", 0)
                    conf_str = f" (置信度 {conf:.1%})" if conf else ""
                    lines.append(f"**步骤 {step['step']}**: {step['content']}{conf_str}")
            lines.append("")

        if chain.assumptions:
            lines.append("### 假设条件")
            for a in chain.assumptions:
                lines.append(f"- {a}")
            lines.append("")

        if chain.limitations:
            lines.append("### 已知限制")
            for l in chain.limitations:
                lines.append(f"- {l}")
            lines.append("")

        if chain.evidence_gaps:
            lines.append("### 证据缺口")
            for g in chain.evidence_gaps:
                lines.append(f"- {g}")
            lines.append("")

        return "\n".join(lines)

    def _format_verdict(self, verdict: str) -> str:
        """格式化判决"""
        formats = {
            "correlated_observations": "路由与流量观测存在关联",
            "cooccurring_anomalies": "路由与流量均异常，但关联尚未建立",
            "inconclusive_missing_traffic": "缺少可用流量数据，无法判断实际影响",
            "inconclusive_missing_routing": "缺少可用路由数据，无法判断告警真实性",
            "routing_only_anomaly": "仅路由异常",
            "verified_normal": "验证为正常",
            "contested": "争议事件",
            "inconclusive": "无法确定",
        }
        return formats.get(verdict, verdict)

    def _format_hypothesis(self, hypothesis: str) -> str:
        """格式化假设"""
        formats = {
            "correlated": "路由异常与流量异常相关",
            "observationally_associated": "路由与流量观测同时异常",
            "routing_only": "仅路由异常",
            "no_anomaly": "无异常",
            "unknown": "未知",
        }
        return formats.get(hypothesis, hypothesis)

    def _get_evidence_icon(self, evidence_type: str) -> str:
        """获取证据图标"""
        icons = {
            "anomaly": "[!]",
            "normal": "[OK]",
            "correlation": "[→]",
            "support": "[+]",
            "negative": "[-]",
            "absence": "[?]",
        }
        return icons.get(evidence_type, "[*]")
