"""
LLM 增强推理模块
================

用 LLM 替代硬编码的事件分类、严重性评估等。

核心改进：
- LLM 根据上下文动态评估事件类型
- LLM 根据证据动态计算严重性
- LLM 提供更准确的分类置信度
"""

from __future__ import annotations

import json
from typing import Optional, Any, Dict, List
from llm.llm_factory import setup_llm_settings, DEFAULT_TEMP_REASONING
from config import MODEL, API_KEY, BASE_URL
from utils.logger import logger
from utils.helpers import extract_json_object as _extract_json_object


# LLM 事件分类器

class LLMIncidentClassifier:
    """
    LLM 驱动的事件分类器
    
    根据路由和流量数据，动态评估事件类型。
    """

    SYSTEM_PROMPT = """You are a BGP security expert specializing in incident classification.

Given evidence from BGP routing and traffic analysis, classify the type of incident.

Consider:
1. Origin hijacking: Unauthorized AS announces victim's prefix
2. Path forgery: AS_PATH is manipulated to create false paths
3. Route leak: Routes propagate beyond intended boundaries
4. Outage: Routes disappear without replacement
5. Traffic-only anomaly: Traffic changes without clear routing cause

Output MUST be valid JSON:
{
    "incident_type": "type name",
    "confidence": 0.0-1.0,
    "sub_type": "optional sub-type",
    "reasoning": "explanation of classification",
    "alternative_types": [
        {"type": "alternative", "confidence": 0.0-1.0, "reasoning": "why this could be it"}
    ]
}"""

    USER_PROMPT_TEMPLATE = """## Routing Evidence

### Origin Hijack Events
- Count: {origin_hijack_count}
- Events: {origin_hijack_events}

### Path Forgery Events
- Count: {forge_hijack_count}
- Events: {forge_hijack_events}

### Route Leak Events
- Count: {leak_count}
- Events: {leak_events}

### Outage Analysis
- Outage suspected: {outage_suspected}
- Outage score: {outage_score}

## Traffic Evidence

### Anomalies
- Anomaly detected: {traffic_anomaly}
- Anomaly count: {traffic_count}
- Percent change: {percent_change}%

## Context

- Target AS: {asn}
- Time range: {time_range}
- Analysis duration: {duration_minutes} minutes

## Task

Based on the evidence, classify the incident type.
If multiple types are possible, provide alternative classifications with confidence.
"""

    def __init__(self, llm=None):
        self.llm = llm
        # 已显式传入 LLM（例如被注入的 BadLLM / mock）→ 跳过 ensure_llm
        self._llm_initialized = llm is not None

    def ensure_llm(self):
        """延迟初始化 LLM；初始化失败时抛出异常，不静默回退。"""
        if not self._llm_initialized:
            self.llm, _ = setup_llm_settings(
                model=MODEL,
                api_key=API_KEY,
                base_url=BASE_URL,
                temperature=DEFAULT_TEMP_REASONING
            )
            self._llm_initialized = True

    def classify(
        self,
        routing_data: Dict[str, Any],
        traffic_data: Dict[str, Any],
        asn: str = "unknown",
        time_range: str = "unknown",
        duration_minutes: float = 0.0,
        run_id: str = "",
    ) -> Dict[str, Any]:
        """
        分类事件类型
        
        Returns:
            {
                "incident_type": str,
                "confidence": float,
                "sub_type": str,
                "reasoning": str,
                "alternative_types": [...],
                "source": "llm" or "rule"
            }
        """
        self.ensure_llm()

        # 提取数据
        origin_hijacked = routing_data.get("origin_hijacked", []) or routing_data.get("origin_hijack", []) or []
        forge_hijacked = routing_data.get("forge_hijacked", []) or routing_data.get("forge_hijack", []) or []
        leaks = routing_data.get("route_leaks", []) or []
        outage = routing_data.get("outage_analysis", {}) or {}
        
        traffic_anomaly = traffic_data.get("anomalies_detected", False)
        traffic_count = traffic_data.get("anomaly_count", 0) or 0
        percent_change = traffic_data.get("percent_change", 0.0) or 0.0

        # 如果没有异常，用规则快速判断
        if not (origin_hijacked or forge_hijacked or leaks or traffic_anomaly):
            return {
                "incident_type": "No Anomaly Detected",
                "confidence": 0.9,
                "sub_type": None,
                "reasoning": "No significant anomalies detected in routing or traffic data",
                "alternative_types": [],
                "source": "rule"
            }

        self.ensure_llm()

        try:
            # 限制事件数量避免 token 过多
            origin_sample = origin_hijacked[:2] if origin_hijacked else []
            forge_sample = forge_hijacked[:2] if forge_hijacked else []
            leak_sample = leaks[:2] if leaks else []

            user_prompt = self.USER_PROMPT_TEMPLATE.format(
                origin_hijack_count=len(origin_hijacked),
                origin_hijack_events=str(origin_sample)[:500],
                forge_hijack_count=len(forge_hijacked),
                forge_hijack_events=str(forge_sample)[:500],
                leak_count=len(leaks),
                leak_events=str(leak_sample)[:500],
                outage_suspected=outage.get("is_outage_suspected", False),
                outage_score=outage.get("outage_score", 0.0),
                traffic_anomaly=traffic_anomaly,
                traffic_count=traffic_count,
                percent_change=percent_change,
                asn=asn,
                time_range=time_range,
                duration_minutes=duration_minutes,
            )

            from agents.llm_wrapper import llm_complete
            response = llm_complete(
                self.llm,
                f"System: {self.SYSTEM_PROMPT}\n\nUser: {user_prompt}",
                run_id=run_id,
                agent_name="LLMIncidentClassifier",
                json_mode=True,
                max_retries=2,
            )

            return self.parse_llm_response(response.text)

        except Exception as e:
            raise RuntimeError(
                f"LLMIncidentClassifier: LLM call failed ({type(e).__name__}): {e}"
            ) from e

    def classify_by_rule(
        self,
        origin_hijacked: List,
        forge_hijacked: List,
        leaks: List,
        outage: Dict,
        traffic_anomaly: bool,
        traffic_count: int,
    ) -> Dict[str, Any]:
        """规则-based 分类（备用）"""
        if origin_hijacked:
            return {
                "incident_type": "Origin Hijacking",
                "confidence": 0.85,
                "sub_type": "victim_hijack",
                "reasoning": "Detected unauthorized prefix announcements",
                "alternative_types": [],
                "source": "rule"
            }
        elif forge_hijacked:
            return {
                "incident_type": "Path Forgery",
                "confidence": 0.8,
                "sub_type": "mitm",
                "reasoning": "Detected AS_PATH manipulation",
                "alternative_types": [],
                "source": "rule"
            }
        elif leaks:
            return {
                "incident_type": "Route Leak",
                "confidence": 0.75,
                "sub_type": None,
                "reasoning": "Detected route propagation beyond boundaries",
                "alternative_types": [],
                "source": "rule"
            }
        elif outage.get("is_outage_suspected"):
            return {
                "incident_type": "Route Outage",
                "confidence": 0.7,
                "sub_type": None,
                "reasoning": f"Route disappearance detected (score: {outage.get('outage_score', 0):.2f})",
                "alternative_types": [],
                "source": "rule"
            }
        elif traffic_anomaly:
            return {
                "incident_type": "Traffic-Only Anomaly",
                "confidence": 0.6,
                "sub_type": None,
                "reasoning": "Traffic anomalies without clear routing cause",
                "alternative_types": [],
                "source": "rule"
            }
        else:
            return {
                "incident_type": "Unknown",
                "confidence": 0.3,
                "sub_type": None,
                "reasoning": "Unable to determine incident type",
                "alternative_types": [],
                "source": "rule"
            }

    def parse_llm_response(self, response: str) -> Dict[str, Any]:
        """解析 LLM 响应"""
        try:
            # Use brace-balanced extraction so values containing
            # literal ``{...}`` substrings don't truncate the JSON.
            snippet = _extract_json_object(response)
            if snippet is not None:
                data = json.loads(snippet)

                return {
                    "incident_type": data.get("incident_type", "Unknown"),
                    "confidence": float(data.get("confidence", 0.5)),
                    "sub_type": data.get("sub_type"),
                    "reasoning": data.get("reasoning", ""),
                    "alternative_types": data.get("alternative_types", []),
                    "source": "llm"
                }
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to parse LLM classification response: {e}")

        return {
            "incident_type": "Parse Error",
            "confidence": 0.3,
            "sub_type": None,
            "reasoning": "Failed to parse LLM response",
            "alternative_types": [],
            "source": "llm"
        }


# LLM 严重性评估器

class LLMSeverityAssessor:
    """
    LLM 驱动的严重性评估器
    
    根据事件特征动态评估严重性。
    """

    SYSTEM_PROMPT = """You are a BGP security expert specializing in incident severity assessment.

Given incident details and evidence, assess the severity level.

Consider:
1. Duration: How long did the incident last?
2. Scope: How many prefixes/ASes were affected?
3. Impact: What was the traffic impact?
4. Persistence: Is it ongoing or resolved?
5. Context: Is this a critical infrastructure?

Output MUST be valid JSON:
{
    "severity": "High/Medium/Low",
    "confidence": 0.0-1.0,
    "score": 0-100,
    "factors": {
        "duration": {"level": "High/Medium/Low", "reasoning": "..."},
        "scope": {"level": "High/Medium/Low", "reasoning": "..."},
        "impact": {"level": "High/Medium/Low", "reasoning": "..."},
        "persistence": {"level": "High/Medium/Low", "reasoning": "..."}
    },
    "reasoning": "overall reasoning"
}"""

    USER_PROMPT_TEMPLATE = """## Incident Details

### Event Counts
- Origin hijacks: {origin_hijack_count}
- Path forgeries: {forge_hijack_count}
- Route leaks: {leak_count}

### Affected Prefixes
- Unique prefixes affected: {prefix_count}

### Traffic Impact
- Traffic anomaly: {traffic_anomaly}
- Percent change: {percent_change}%
- Anomaly count: {traffic_count}

### Duration
- Analysis window: {duration_minutes} minutes

### Context
- Target AS: {asn}
- Time range: {time_range}

## Task

Assess the severity of this incident based on:
1. How long did the incident last?
2. How many prefixes/ASes were affected?
3. What was the traffic impact?
4. Is it ongoing or resolved?
"""

    def __init__(self, llm=None):
        self.llm = llm
        # 已显式传入 LLM（例如被注入的 BadLLM / mock）→ 跳过 ensure_llm
        self._llm_initialized = llm is not None

    def ensure_llm(self):
        """延迟初始化 LLM；初始化失败时抛出异常，不静默回退。"""
        if not self._llm_initialized:
            self.llm, _ = setup_llm_settings(
                model=MODEL,
                api_key=API_KEY,
                base_url=BASE_URL,
                temperature=DEFAULT_TEMP_REASONING
            )
            self._llm_initialized = True

    def assess(
        self,
        routing_data: Dict[str, Any],
        traffic_data: Dict[str, Any],
        duration_minutes: float,
        asn: str = "unknown",
        time_range: str = "unknown",
        run_id: str = "",
    ) -> Dict[str, Any]:
        """
        评估严重性
        
        Returns:
            {
                "severity": "High/Medium/Low",
                "confidence": float,
                "score": int,
                "factors": {...},
                "reasoning": str,
                "source": "llm" or "rule"
            }
        """
        self.ensure_llm()

        # 提取数据
        origin_hijacked = routing_data.get("origin_hijacked", []) or routing_data.get("origin_hijack", []) or []
        forge_hijacked = routing_data.get("forge_hijacked", []) or routing_data.get("forge_hijack", []) or []
        leaks = routing_data.get("route_leaks", []) or []
        
        # 统计唯一前缀
        prefixes = set()
        for event in origin_hijacked + forge_hijacked + leaks:
            prefix = event.get("prefix")
            if prefix:
                prefixes.add(prefix)
        
        traffic_anomaly = traffic_data.get("anomalies_detected", False)
        traffic_count = traffic_data.get("anomaly_count", 0) or 0
        percent_change = abs(traffic_data.get("percent_change", 0.0) or 0.0)

        # 如果没有事件，快速返回低严重性
        if not (origin_hijacked or forge_hijacked or leaks) and not traffic_anomaly:
            return {
                "severity": "Low",
                "confidence": 0.9,
                "score": 10,
                "factors": {},
                "reasoning": "No significant anomalies detected",
                "source": "rule"
            }

        self.ensure_llm()

        try:
            user_prompt = self.USER_PROMPT_TEMPLATE.format(
                origin_hijack_count=len(origin_hijacked),
                forge_hijack_count=len(forge_hijacked),
                leak_count=len(leaks),
                prefix_count=len(prefixes),
                traffic_anomaly=traffic_anomaly,
                percent_change=percent_change,
                traffic_count=traffic_count,
                duration_minutes=duration_minutes,
                asn=asn,
                time_range=time_range,
            )

            from agents.llm_wrapper import llm_complete
            response = llm_complete(
                self.llm,
                f"System: {self.SYSTEM_PROMPT}\n\nUser: {user_prompt}",
                run_id=run_id,
                agent_name="LLMSeverityAssessor",
                json_mode=True,
                max_retries=2,
            )

            return self.parse_llm_response(response.text)

        except Exception as e:
            raise RuntimeError(
                f"LLMSeverityAssessor: LLM call failed ({type(e).__name__}): {e}"
            ) from e

    def assess_by_rule(
        self,
        origin_count: int,
        forge_count: int,
        leak_count: int,
        prefix_count: int,
        traffic_anomaly: bool,
        percent_change: float,
        duration_minutes: float,
    ) -> Dict[str, Any]:
        """规则-based 严重性评估（备用）"""
        score = 0
        
        # 事件数量
        event_count = origin_count + forge_count + leak_count
        if event_count >= 5:
            score += 30
        elif event_count >= 3:
            score += 20
        elif event_count >= 1:
            score += 10
        
        # 影响范围
        if prefix_count >= 5:
            score += 25
        elif prefix_count >= 3:
            score += 15
        elif prefix_count >= 1:
            score += 5
        
        # 流量影响
        if traffic_anomaly and percent_change >= 50:
            score += 30
        elif traffic_anomaly and percent_change >= 20:
            score += 20
        elif traffic_anomaly:
            score += 10
        
        # 持续时间
        if duration_minutes > 120:
            score += 15
        elif duration_minutes > 30:
            score += 10
        elif duration_minutes > 10:
            score += 5
        
        # 确定严重性级别
        if score >= 70:
            severity = "High"
        elif score >= 40:
            severity = "Medium"
        else:
            severity = "Low"

        return {
            "severity": severity,
            "confidence": 0.7,
            "score": min(100, score),
            "factors": {
                "event_count": {"level": "High" if event_count >= 5 else "Medium" if event_count >= 2 else "Low"},
                "scope": {"level": "High" if prefix_count >= 5 else "Medium" if prefix_count >= 2 else "Low"},
                "traffic_impact": {"level": "High" if percent_change >= 50 else "Medium" if percent_change >= 20 else "Low"},
                "duration": {"level": "High" if duration_minutes > 120 else "Medium" if duration_minutes > 30 else "Low"},
            },
            "reasoning": f"Rule-based assessment: score={score}",
            "source": "rule"
        }

    def parse_llm_response(self, response: str) -> Dict[str, Any]:
        """解析 LLM 响应"""
        try:
            snippet = _extract_json_object(response)
            if snippet is not None:
                data = json.loads(snippet)

                return {
                    "severity": data.get("severity", "Medium"),
                    "confidence": float(data.get("confidence", 0.5)),
                    "score": int(data.get("score", 50)),
                    "factors": data.get("factors", {}),
                    "reasoning": data.get("reasoning", ""),
                    "source": "llm"
                }
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to parse LLM severity response: {e}")

        return {
            "severity": "Medium",
            "confidence": 0.3,
            "score": 50,
            "factors": {},
            "reasoning": "Failed to parse LLM response",
            "source": "llm"
        }


# LLM 流量关联评估器

class LLMTrafficCorrelator:
    """
    LLM 驱动的流量关联评估器
    
    评估路由异常与流量异常之间的关联性。
    """

    SYSTEM_PROMPT = """You are a BGP security expert specializing in causal correlation analysis.

Given routing anomalies and traffic anomalies, assess whether they are correlated.

Consider:
1. Temporal alignment: Did they happen at similar times?
2. Intensity correlation: Is the traffic impact proportional to routing events?
3. Mechanism plausibility: Could routing changes cause traffic changes?
4. Alternative explanations: Could traffic changes have other causes?

Output MUST be valid JSON:
{
    "has_correlation": true/false,
    "confidence": 0.0-1.0,
    "correlation_type": "direct/indirect/unclear/none",
    "reasoning": "explanation",
    "temporal_alignment": 0.0-1.0,
    "intensity_correlation": 0.0-1.0,
    "alternative_explanations": ["explanation1", "explanation2"]
}"""

    USER_PROMPT_TEMPLATE = """## Routing Anomalies

- Origin hijacks: {origin_hijack_count}
- Path forgeries: {forge_hijack_count}
- Route leaks: {leak_count}

### Event Details
{routing_details}

## Traffic Anomalies

- Anomalies detected: {traffic_anomaly}
- Anomaly count: {traffic_count}
- Percent change: {percent_change}%

### Anomaly Timestamps
{anomaly_timestamps}

## Temporal Information

- Routing events time range: {routing_time_range}
- Traffic anomalies time range: {traffic_time_range}
- Time offset: {time_offset_minutes} minutes

## Task

Assess whether the routing anomalies and traffic anomalies are correlated.
Consider timing, intensity, and possible alternative explanations.
"""

    def __init__(self, llm=None):
        self.llm = llm
        # 已显式传入 LLM（例如被注入的 BadLLM / mock）→ 跳过 ensure_llm
        self._llm_initialized = llm is not None

    def ensure_llm(self):
        """延迟初始化 LLM；初始化失败时抛出异常，不静默回退。"""
        if not self._llm_initialized:
            self.llm, _ = setup_llm_settings(
                model=MODEL,
                api_key=API_KEY,
                base_url=BASE_URL,
                temperature=DEFAULT_TEMP_REASONING
            )
            self._llm_initialized = True

    def assess_correlation(
        self,
        routing_data: Dict[str, Any],
        traffic_data: Dict[str, Any],
        run_id: str = "",
    ) -> Dict[str, Any]:
        """
        评估关联性
        
        Returns:
            {
                "has_correlation": bool,
                "confidence": float,
                "correlation_type": str,
                "reasoning": str,
                "temporal_alignment": float,
                "intensity_correlation": float,
                "alternative_explanations": [...],
                "source": "llm" or "rule"
            }
        """
        self.ensure_llm()

        # 提取数据
        origin_hijacked = routing_data.get("origin_hijacked", []) or routing_data.get("origin_hijack", []) or []
        forge_hijacked = routing_data.get("forge_hijacked", []) or routing_data.get("forge_hijack", []) or []
        leaks = routing_data.get("route_leaks", []) or []
        
        traffic_anomaly = traffic_data.get("anomalies_detected", False)
        traffic_count = traffic_data.get("anomaly_count", 0) or 0
        percent_change = traffic_data.get("percent_change", 0.0) or 0.0

        # 快速检查
        routing_count = len(origin_hijacked) + len(forge_hijacked) + len(leaks)
        if routing_count == 0 and not traffic_anomaly:
            return {
                "has_correlation": False,
                "confidence": 0.9,
                "correlation_type": "none",
                "reasoning": "No anomalies to correlate",
                "temporal_alignment": 0.0,
                "intensity_correlation": 0.0,
                "alternative_explanations": [],
                "source": "rule"
            }
        elif routing_count == 0 and traffic_anomaly:
            return {
                "has_correlation": False,
                "confidence": 0.7,
                "correlation_type": "none",
                "reasoning": "Traffic anomalies without routing anomalies",
                "temporal_alignment": 0.0,
                "intensity_correlation": 0.0,
                "alternative_explanations": ["CDN issues", "DDoS attack", "Application-level issues"],
                "source": "rule"
            }
        elif routing_count > 0 and not traffic_anomaly:
            return {
                "has_correlation": False,
                "confidence": 0.6,
                "correlation_type": "unclear",
                "reasoning": "Routing anomalies without traffic impact",
                "temporal_alignment": 0.5,
                "intensity_correlation": 0.0,
                "alternative_explanations": ["Backup routes activated", "Attack was mitigated", "Data collection gap"],
                "source": "rule"
            }

        self.ensure_llm()

        try:
            # 构建事件详情（限制数量）
            routing_details = []
            for event in (origin_hijacked + forge_hijacked + leaks)[:3]:
                ts = event.get("timestamp") or event.get("first_seen", "unknown")
                prefix = event.get("prefix", "unknown")
                routing_details.append(f"- {ts}: {prefix}")
            
            traffic_timestamps = []
            anomalies = traffic_data.get("anomalies", []) or []
            for anomaly in anomalies[:5]:
                ts = anomaly.get("timestamp", "unknown")
                traffic_timestamps.append(f"- {ts}")

            user_prompt = self.USER_PROMPT_TEMPLATE.format(
                origin_hijack_count=len(origin_hijacked),
                forge_hijack_count=len(forge_hijacked),
                leak_count=len(leaks),
                routing_details="\n".join(routing_details) if routing_details else "No details available",
                traffic_anomaly=traffic_anomaly,
                traffic_count=traffic_count,
                percent_change=percent_change,
                anomaly_timestamps="\n".join(traffic_timestamps) if traffic_timestamps else "No details available",
                routing_time_range=routing_data.get("analysis_period", "unknown"),
                traffic_time_range=f"{traffic_data.get('start_time', 'unknown')} to {traffic_data.get('end_time', 'unknown')}",
                time_offset_minutes="unknown",
            )

            from agents.llm_wrapper import llm_complete
            response = llm_complete(
                self.llm,
                f"System: {self.SYSTEM_PROMPT}\n\nUser: {user_prompt}",
                run_id=run_id,
                agent_name="LLMTrafficCorrelator",
                json_mode=True,
                max_retries=2,
            )

            return self.parse_llm_response(response.text)

        except Exception as e:
            raise RuntimeError(
                f"LLMTrafficCorrelator: LLM call failed ({type(e).__name__}): {e}"
            ) from e

    def correlate_by_rule(
        self,
        routing_count: int,
        traffic_anomaly: bool,
        traffic_count: int,
        percent_change: float,
    ) -> Dict[str, Any]:
        """规则-based 关联评估（备用）"""
        if routing_count > 0 and traffic_anomaly:
            # 简单的时间/强度关联评估
            intensity = min(1.0, (routing_count / 5) * (abs(percent_change) / 50))
            
            return {
                "has_correlation": intensity >= 0.3,
                "confidence": 0.7 if intensity >= 0.5 else 0.5,
                "correlation_type": "direct" if intensity >= 0.5 else "indirect",
                "reasoning": f"Both routing and traffic anomalies detected",
                "temporal_alignment": 0.6,
                "intensity_correlation": intensity,
                "alternative_explanations": [],
                "source": "rule"
            }
        
        return {
            "has_correlation": False,
            "confidence": 0.5,
            "correlation_type": "none",
            "reasoning": "Unable to establish correlation",
            "temporal_alignment": 0.0,
            "intensity_correlation": 0.0,
            "alternative_explanations": [],
            "source": "rule"
        }

    def parse_llm_response(self, response: str) -> Dict[str, Any]:
        """解析 LLM 响应"""
        try:
            snippet = _extract_json_object(response)
            if snippet is not None:
                data = json.loads(snippet)

                return {
                    "has_correlation": data.get("has_correlation", False),
                    "confidence": float(data.get("confidence", 0.5)),
                    "correlation_type": data.get("correlation_type", "unclear"),
                    "reasoning": data.get("reasoning", ""),
                    "temporal_alignment": float(data.get("temporal_alignment", 0.5)),
                    "intensity_correlation": float(data.get("intensity_correlation", 0.5)),
                    "alternative_explanations": data.get("alternative_explanations", []),
                    "source": "llm"
                }
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"Failed to parse LLM correlation response: {e}")

        return {
            "has_correlation": False,
            "confidence": 0.3,
            "correlation_type": "unclear",
            "reasoning": "Failed to parse LLM response",
            "temporal_alignment": 0.5,
            "intensity_correlation": 0.5,
            "alternative_explanations": [],
            "source": "llm"
        }
