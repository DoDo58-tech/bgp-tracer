"""
辩论式多智能体验证系统
Multi-Agent Debate Verification System

创新点：
1. 检察官 Agent：收集攻击证据，质疑所有"无罪"解释
2. 辩护律师 Agent：寻找合理替代假设，质疑"有罪"证据
3. 法官 Agent：综合双方辩论，输出最终判决
4. 辩论轮次中 Agent 会主动寻找对方论点的漏洞

Author: BGP Tracer Team
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
from abc import ABC, abstractmethod
import asyncio
import logging
import sys
from pathlib import Path

logger = logging.getLogger("bgp_tracer")

# 添加父目录到路径以导入 core
sys.path.insert(0, str(Path(__file__).parent.parent))
try:
    from agents.core import TaskResult, Agent
except ImportError:
    # 如果 core 不存在，定义简单的 TaskResult
    @dataclass
    class TaskResult:
        success: bool = False
        data: dict = None
        error: str = ""
        agent: str = ""
        
        @classmethod
        def from_dict(cls, data: dict) -> 'TaskResult':
            return cls(
                success=data.get('success', False),
                data=data.get('data'),
                error=data.get('error', ''),
                agent=data.get('agent', ''),
            )


class AgentRole(Enum):
    """辩论中的角色"""
    PROSECUTOR = "prosecutor"       # 检察官
    DEFENSE = "defense"             # 辩护律师
    JUDGE = "judge"                 # 法官


@dataclass
class Argument:
    """辩论论点"""
    claim: str                      # 论点主张
    evidence: List[str] = field(default_factory=list)  # 证据列表
    counter_arguments: List[str] = field(default_factory=list)  # 反驳的论点
    strength: float = 0.5           # 论点强度 0-1
    agent: Optional[AgentRole] = None  # 提出论点的 Agent


@dataclass
class DebateRound:
    """辩论轮次"""
    round_number: int
    prosecutor_arguments: List[Argument] = field(default_factory=list)
    defense_arguments: List[Argument] = field(default_factory=list)
    cross_examinations: List[Dict] = field(default_factory=list)  # 交叉询问
    judge_notes: str = ""


@dataclass
class Verdict:
    """最终判决"""
    decision: str                   # 决定：有罪/无罪/需更多证据
    confidence: float              # 置信度
    primary_reason: str            # 主要理由
    evidence_summary: Dict[str, Any]  # 证据总结
    debate_summary: str = ""      # 辩论过程总结
    remaining_uncertainties: List[str] = field(default_factory=list)  # 剩余不确定性
    recommended_actions: List[str] = field(default_factory=list)  # 建议行动


@dataclass
class EventContext:
    """事件上下文"""
    event_id: str
    asn: str
    time_window: str
    routing_evidence: Dict = field(default_factory=dict)
    traffic_evidence: Dict = field(default_factory=dict)
    historical_context: Dict = field(default_factory=dict)
    ground_truth_type: str = ""    # 用于评估（可选）


class BaseDebateAgent(ABC):
    """辩论 Agent 基类"""
    
    def __init__(self, name: str, role: AgentRole):
        self.name = name
        self.role = role
    
    @abstractmethod
    async def make_argument(self, context: EventContext, debate_history: List[DebateRound]) -> List[Argument]:
        """提出论点"""
        pass
    
    @abstractmethod
    async def cross_examine(self, opponent_arguments: List[Argument], context: EventContext) -> List[Dict]:
        """交叉询问"""
        pass


class ProsecutorAgent(BaseDebateAgent):
    """
    检察官 Agent
    
    职责：
    1. 收集所有指向"有罪"的证据
    2. 质疑被告的所有"无罪"论点
    3. 强调事件的影响和严重性
    """
    
    def __init__(self):
        super().__init__("检察官", AgentRole.PROSECUTOR)
    
    async def make_argument(self, context: EventContext, debate_history: List[DebateRound]) -> List[Argument]:
        """提出控方论点"""
        arguments = []
        
        # 1. 路由异常论点
        if context.routing_evidence:
            routing_args = self.analyze_routing_evidence(context)
            arguments.extend(routing_args)
        
        # 2. 流量异常论点
        if context.traffic_evidence:
            traffic_args = self.analyze_traffic_evidence(context)
            arguments.extend(traffic_args)
        
        # 3. 时序一致性论点
        temporal_args = self.analyze_temporal_consistency(context)
        arguments.extend(temporal_args)
        
        # 4. 影响严重性论点
        impact_args = self.analyze_impact(context)
        arguments.extend(impact_args)
        
        return arguments
    
    async def cross_examine(self, opponent_arguments: List[Argument], context: EventContext) -> List[Dict]:
        """交叉询问辩护方论点"""
        cross_examinations = []
        
        for arg in opponent_arguments:
            # 寻找论点的弱点
            weakness = self.find_weakness(arg, context)
            if weakness:
                cross_examinations.append({
                    'target_claim': arg.claim,
                    'question': weakness['question'],
                    'challenge': weakness['challenge'],
                    'strength': weakness['strength']
                })
        
        return cross_examinations
    
    def analyze_routing_evidence(self, context: EventContext) -> List[Argument]:
        """分析路由证据"""
        args = []
        evidence = context.routing_evidence
        
        # 劫持证据
        hijack_detected = evidence.get('origin_hijacked') or evidence.get('origin_hijacking')
        if hijack_detected:
            hijack_count = evidence.get('hijack_count', 0)
            args.append(Argument(
                claim=f"检测到 {hijack_count} 次 BGP 劫持事件",
                evidence=[
                    f"前缀被 {evidence.get('hijacker_as', '未知')} 错误宣告",
                    f"AS-Path 异常: {evidence.get('sample_as_path', '')}",
                ],
                strength=min(hijack_count / 100, 1.0) * 0.8,
                agent=self.role
            ))
        
        # 撤回证据
        withdrawal_count = evidence.get('withdrawal_count', 0)
        if withdrawal_count > 100:
            args.append(Argument(
                claim=f"检测到 {withdrawal_count} 次路由撤回，呈现撤回激增",
                evidence=[
                    "大规模撤回可能表示主动断网",
                    "撤回的 IP 空间从全球路由表消失",
                ],
                strength=min(withdrawal_count / 1000, 1.0) * 0.9,
                agent=self.role
            ))
        
        return args
    
    def analyze_traffic_evidence(self, context: EventContext) -> List[Argument]:
        """分析流量证据"""
        args = []
        evidence = context.traffic_evidence
        
        if evidence.get('traffic_drop'):
            drop_ratio = evidence.get('traffic_drop_ratio', 0)
            args.append(Argument(
                claim=f"流量下降 {drop_ratio:.1%}，存在显著影响",
                evidence=[
                    f"Z-score: {evidence.get('z_score', 0):.1f}",
                    "流量下降与路由异常时序一致",
                ],
                strength=drop_ratio * 0.9,
                agent=self.role
            ))
        
        if evidence.get('sustained_outage'):
            args.append(Argument(
                claim="检测到持续断网，影响持续存在",
                evidence=[
                    f"断网持续时间: {evidence.get('outage_duration_minutes', 0)} 分钟",
                    "断网与路由撤回同步发生",
                ],
                strength=0.85,
                agent=self.role
            ))
        
        return args
    
    def analyze_temporal_consistency(self, context: EventContext) -> List[Argument]:
        """分析时序一致性"""
        args = []
        
        # 检查路由和流量变化是否同步
        routing_time = context.routing_evidence.get('first_anomaly_time', '')
        traffic_time = context.traffic_evidence.get('first_anomaly_time', '')
        
        if routing_time and traffic_time:
            args.append(Argument(
                claim="路由异常和流量异常时序一致，存在因果关系",
                evidence=[
                    f"路由异常时间: {routing_time}",
                    f"流量异常时间: {traffic_time}",
                    "时序一致性强化因果推断",
                ],
                strength=0.7,
                agent=self.role
            ))
        
        return args
    
    def analyze_impact(self, context: EventContext) -> List[Argument]:
        """分析影响严重性"""
        args = []
        
        # 检查是否影响多个 AS
        affected_as_count = context.routing_evidence.get('affected_as_count', 0)
        if affected_as_count > 1:
            args.append(Argument(
                claim=f"事件影响 {affected_as_count} 个 AS，可能具有国家级规模",
                evidence=[
                    "多 AS 同时受影响表示大规模事件",
                    "排除单一设备故障的可能",
                ],
                strength=min(affected_as_count / 10, 1.0) * 0.6,
                agent=self.role
            ))
        
        return args
    
    def find_weakness(self, arg: Argument, context: EventContext) -> Optional[Dict]:
        """寻找论点弱点"""
        # 检查证据充分性
        if len(arg.evidence) == 0:
            return {
                'question': '你的论点有什么证据支持？',
                'challenge': '缺乏证据的论点不应被采纳',
                'strength': 0.8
            }
        
        # 检查是否考虑了替代解释
        if '可能' in arg.claim or '也许' in arg.claim:
            return {
                'question': '你是否考虑了其他可能的解释？',
                'challenge': '论点存在不确定性，需要更多证据',
                'strength': 0.5
            }
        
        return None


class DefenseAgent(BaseDebateAgent):
    """
    辩护律师 Agent
    
    职责：
    1. 提出合理的替代假设
    2. 质疑控方证据的充分性
    3. 强调不确定性因素
    """
    
    def __init__(self):
        super().__init__("辩护律师", AgentRole.DEFENSE)
    
    async def make_argument(self, context: EventContext, debate_history: List[DebateRound]) -> List[Argument]:
        """提出辩护论点"""
        arguments = []
        
        # 1. 数据质量问题
        data_quality_args = self.analyze_data_quality(context)
        arguments.extend(data_quality_args)
        
        # 2. 替代假设
        alternative_args = self.generate_alternative_hypotheses(context)
        arguments.extend(alternative_args)
        
        # 3. 不确定性论点
        uncertainty_args = self.analyze_uncertainties(context)
        arguments.extend(uncertainty_args)
        
        # 4. 历史行为论点
        historical_args = self.analyze_historical_context(context)
        arguments.extend(historical_args)
        
        return arguments
    
    async def cross_examine(self, opponent_arguments: List[Argument], context: EventContext) -> List[Dict]:
        """交叉询问控方论点"""
        cross_examinations = []
        
        for arg in opponent_arguments:
            # 质疑证据来源
            question = self.challenge_evidence_source(arg, context)
            if question:
                cross_examinations.append(question)
            
            # 质疑因果关系
            causation = self.challenge_causation(arg, context)
            if causation:
                cross_examinations.append(causation)
        
        return cross_examinations
    
    def analyze_data_quality(self, context: EventContext) -> List[Argument]:
        """分析数据质量问题"""
        args = []
        
        # 检查数据覆盖范围
        routing_coverage = context.routing_evidence.get('data_coverage', 1.0)
        if routing_coverage < 0.5:
            args.append(Argument(
                claim="路由数据覆盖不完整，可能遗漏关键信息",
                evidence=[
                    f"数据覆盖率: {routing_coverage:.1%}",
                    "RIPE RIS 监测点有限，可能无法检测到所有路由变化",
                ],
                strength=(1 - routing_coverage) * 0.7,
                agent=self.role
            ))
        
        # 检查数据延迟
        data_delay = context.routing_evidence.get('data_delay_minutes', 0)
        if data_delay > 60:
            args.append(Argument(
                claim="数据存在延迟，可能影响时序分析准确性",
                evidence=[f"数据延迟: {data_delay} 分钟"],
                strength=min(data_delay / 240, 1.0) * 0.5,
                agent=self.role
            ))
        
        return args
    
    def generate_alternative_hypotheses(self, context: EventContext) -> List[Argument]:
        """生成替代假设"""
        args = []
        
        # 误报假设
        args.append(Argument(
            claim="检测可能为误报：异常可能是数据噪音",
            evidence=[
                "BGP 监测数据存在固有的噪音",
                "部分异常可能属于正常路由波动",
            ],
            strength=0.4,
            agent=self.role
        ))
        
        # 维护假设
        if context.historical_context.get('has_maintenance_history'):
            args.append(Argument(
                claim="可能是计划内维护，而非恶意事件",
                evidence=[
                    "该 AS 有维护历史",
                    "维护窗口与事件时间吻合",
                ],
                strength=0.5,
                agent=self.role
            ))
        
        # 数据源问题假设
        args.append(Argument(
            claim="异常可能源于数据源配置问题，而非真实路由变化",
            evidence=[
                "部分 RIPE RIS 监测点可能存在配置错误",
                "数据处理流程中可能引入伪影",
            ],
            strength=0.3,
            agent=self.role
        ))
        
        return args
    
    def analyze_uncertainties(self, context: EventContext) -> List[Argument]:
        """分析不确定性"""
        args = []
        
        # 时序不确定
        args.append(Argument(
            claim="路由和流量变化的因果方向存在不确定性",
            evidence=[
                "因果推断需要更多时序数据支持",
                "可能存在混杂变量",
            ],
            strength=0.5,
            agent=self.role
        ))
        
        return args
    
    def analyze_historical_context(self, context: EventContext) -> List[Argument]:
        """分析历史上下文"""
        args = []
        
        if context.historical_context.get('similar_events_resolved_as_normal'):
            args.append(Argument(
                claim="类似历史事件最终被证实为正常行为",
                evidence=[
                    "该 AS 过去有类似检测但最终确认正常",
                    "应谨慎对待重复出现的模式",
                ],
                strength=0.4,
                agent=self.role
            ))
        
        return args
    
    def challenge_evidence_source(self, arg: Argument, context: EventContext) -> Optional[Dict]:
        """质疑证据来源"""
        # 检查证据是否来自单一来源
        if len(set(arg.evidence)) < len(arg.evidence):
            return {
                'target_claim': arg.claim,
                'question': '你的证据是否经过交叉验证？',
                'challenge': '单一来源的证据可信度有限',
                'strength': 0.6
            }
        return None
    
    def challenge_causation(self, arg, context):
        """质疑因果关系"""
        if '因果' in arg.claim or '导致' in arg.claim:
            return {
                'target_claim': arg.claim,
                'question': '你能排除这是巧合的可能性吗？',
                'challenge': '相关性不等于因果性',
                'strength': 0.7
            }
        return None


class JudgeAgent:
    """
    法官 Agent
    
    职责：
    1. 记录辩论过程
    2. 评估双方论点强度
    3. 综合所有证据给出最终判决
    """
    
    def __init__(self):
        self.name = "法官"
        self.role = AgentRole.JUDGE
    
    async def adjudicate(
        self,
        prosecution: List[Argument],
        defense: List[Argument],
        cross_examinations: List[Dict],
        context: EventContext
    ) -> Verdict:
        """进行裁决"""
        
        # 1. 评估控方论点
        prosecution_strength = self.evaluate_arguments(prosecution)
        
        # 2. 评估辩护论点
        defense_strength = self.evaluate_arguments(defense)
        
        # 3. 评估交叉询问结果
        cross_exam_impact = self.evaluate_cross_examinations(cross_examinations)
        
        # 4. 计算综合得分
        net_strength = prosecution_strength - defense_strength + cross_exam_impact
        
        # 5. 生成判决
        verdict = self.make_verdict(
            net_strength,
            prosecution,
            defense,
            context
        )
        
        return verdict
    
    def evaluate_arguments(self, arguments: List[Argument]) -> float:
        """评估论点总分"""
        if not arguments:
            return 0.0
        
        # 加权求和（考虑论点数量的边际递减）
        total = 0.0
        for i, arg in enumerate(sorted(arguments, key=lambda x: x.strength, reverse=True)):
            # 权重递减
            weight = 1.0 / (1 + i * 0.2)
            total += arg.strength * weight
        
        return min(total, 1.0)
    
    def evaluate_cross_examinations(self, cross_exams: List[Dict]) -> float:
        """评估交叉询问的影响"""
        if not cross_exams:
            return 0.0
        
        # 正值表示控方成功削弱辩护论点，负值表示辩护成功
        impact = 0.0
        for exam in cross_exams:
            if exam.get('strength', 0) > 0.5:
                # 检查是控方还是辩护方的交叉询问
                # 这里简化处理
                impact += exam['strength'] * 0.1
        
        return impact
    
    def make_verdict(
        self,
        net_strength: float,
        prosecution: List[Argument],
        defense: List[Argument],
        context: EventContext
    ) -> Verdict:
        """生成判决"""
        
        # 决定
        if net_strength > 0.6:
            decision = "有罪"
            confidence = min(net_strength, 1.0)
            primary_reason = self.summarize_prosecution(prosecution)
        if net_strength < -0.3:
            decision = "无罪"
            confidence = min(abs(net_strength), 1.0)
            primary_reason = self.summarize_defense(defense)
        else:
            decision = "需更多证据"
            confidence = 0.5
            primary_reason = "证据不足以做出明确判断"
        
        # 证据总结
        evidence_summary = {
            'prosecution_strength': self.evaluate_arguments(prosecution),
            'defense_strength': self.evaluate_arguments(defense),
            'prosecution_arguments': [a.claim for a in prosecution],
            'defense_arguments': [a.claim for a in defense],
            'net_verdict_score': net_strength,
        }
        
        # 剩余不确定性
        uncertainties = []
        if confidence < 0.8:
            uncertainties.append("置信度未达到高置信度阈值")
        if len(prosecution) < 3:
            uncertainties.append("控方论点数量有限")
        
        # 建议行动
        recommended = []
        if decision == "需更多证据":
            recommended.append("收集更多时间范围的路由数据")
            recommended.append("进行实地调查或联系相关 AS")
        if confidence < 0.7:
            recommended.append("标记为待观察事件")
        
        return Verdict(
            decision=decision,
            confidence=confidence,
            primary_reason=primary_reason,
            evidence_summary=evidence_summary,
            debate_summary=f"控方得分 {evidence_summary['prosecution_strength']:.2f}，辩护方得分 {evidence_summary['defense_strength']:.2f}",
            remaining_uncertainties=uncertainties,
            recommended_actions=recommended
        )
    
    def summarize_prosecution(self, prosecution: List[Argument]) -> str:
        """总结控方论点"""
        if not prosecution:
            return "无明确控方论点"
        
        top_args = sorted(prosecution, key=lambda x: x.strength, reverse=True)[:2]
        return "；".join([a.claim for a in top_args])
    
    def summarize_defense(self, defense: List[Argument]) -> str:
        """总结辩护论点"""
        if not defense:
            return "无明确辩护论点"
        
        top_args = sorted(defense, key=lambda x: x.strength, reverse=True)[:2]
        return "；".join([a.claim for a in top_args])


class MultiAgentDebateSystem:
    """
    辩论式多智能体系统
    
    协调检察官、辩护律师和法官进行辩论验证
    """
    
    def __init__(self, debate_rounds: int = 3):
        self.debate_rounds = debate_rounds
        self.prosecutor = ProsecutorAgent()
        self.defense = DefenseAgent()
        self.judge = JudgeAgent()
    
    async def debate(self, context: EventContext) -> Verdict:
        """
        执行辩论流程
        
        Args:
            context: 事件上下文
            
        Returns:
            Verdict: 最终判决
        """
        debate_history = []
        
        for round_num in range(self.debate_rounds):
            # 1. 检察官提出论点
            pros_args = await self.prosecutor.make_argument(context, debate_history)
            
            # 2. 辩护律师提出论点
            def_args = await self.defense.make_argument(context, debate_history)
            
            # 3. 交叉询问
            pros_cross = await self.prosecutor.cross_examine(def_args, context)
            def_cross = await self.defense.cross_examine(pros_args, context)
            
            # 记录辩论轮次
            round_record = DebateRound(
                round_number=round_num + 1,
                prosecutor_arguments=pros_args,
                defense_arguments=def_args,
                cross_examinations=pros_cross + def_cross,
            )
            debate_history.append(round_record)
            
            # 检查是否已达成明确结论
            if round_num > 0:
                interim_verdict = await self.judge.adjudicate(
                    pros_args, def_args, pros_cross + def_cross, context
                )
                if interim_verdict.confidence > 0.85:
                    return interim_verdict
        
        # 最终裁决
        final_pros = [arg for r in debate_history for arg in r.prosecutor_arguments]
        final_def = [arg for r in debate_history for arg in r.defense_arguments]
        final_cross = [ex for r in debate_history for ex in r.cross_examinations]
        
        return await self.judge.adjudicate(
            final_pros, final_def, final_cross, context
        )
    
    def debate_sync(self, context: EventContext) -> Verdict:
        """同步辩论接口"""
        return asyncio.run(self.debate(context))


# 便捷函数
async def run_debate(
    asn: str,
    time_window: str,
    routing_evidence: Dict = None,
    traffic_evidence: Dict = None
) -> Verdict:
    """
    运行辩论验证
    """
    context = EventContext(
        event_id=f"debate_{asn}_{time_window}",
        asn=asn,
        time_window=time_window,
        routing_evidence=routing_evidence or {},
        traffic_evidence=traffic_evidence or {},
    )
    
    system = MultiAgentDebateSystem(debate_rounds=3)
    return await system.debate(context)


def run_debate_sync(
    asn: str,
    time_window: str,
    routing_evidence: Dict = None,
    traffic_evidence: Dict = None
) -> Verdict:
    """同步辩论接口"""
    return asyncio.run(run_debate(asn, time_window, routing_evidence, traffic_evidence))


# 兼容原有接口的包装类
@dataclass
class DebateResult:
    """辩论结果（兼容原有接口）"""
    verdict: str
    confidence: float
    prosecution_strength: float = 0.0
    defense_strength: float = 0.0
    arguments: List[Argument] = field(default_factory=list)


class DebateModerator:
    """辩论主持人（兼容原有接口）"""
    
    def __init__(self):
        self.debate_system = MultiAgentDebateSystem(debate_rounds=3)
    
    async def run_debate(self, context: EventContext) -> DebateResult:
        verdict = await self.debate_system.debate(context)
        return DebateResult(
            verdict=verdict.decision,
            confidence=verdict.confidence,
            prosecution_strength=verdict.evidence_summary.get('prosecution_strength', 0),
            defense_strength=verdict.evidence_summary.get('defense_strength', 0),
        )
    
    def run_debate_sync(self, context: EventContext) -> DebateResult:
        return asyncio.run(self.run_debate(context))


class LLMDebateAgent:
    """
    LLM 驱动的辩论 Agent（修复接口以兼容 workflow_engine）
    
    修复内容：
    1. 接受 bb (blackboard) 和 max_rounds 参数
    2. 实现 async step() 方法返回 TaskResult
    3. 实现 consume_budget() 方法
    """
    
    def __init__(self, bb=None, max_rounds: int = 2):
        self.bb = bb
        self.max_rounds = max_rounds
        self.prosecutor = ProsecutorAgent()
        self.defense = DefenseAgent()
        self.debate_rounds = max_rounds
        self.budget_consumed = 0
        self.role = "neutral"

    async def step(self) -> TaskResult:
        """
        执行辩论步骤（workflow_engine 调用的接口）
        
        Returns:
            TaskResult with debate_results in data
        """
        try:
            # 从 blackboard 获取上下文
            context_data = {}
            if self.bb:
                routing = await self.bb.read("routing", "result", {})
                traffic = await self.bb.read("traffic", "result", {})
                # claims 实际由 ReasoningAgent 写入 evidence section
                # (bb.write("evidence", "claims", payload)) 而非 diagnosis.claims
                claims = (
                    await self.bb.read("diagnosis", "claims", []) or []
                )
                if not claims:
                    ev_section = await self.bb.read_section("evidence") or {}
                    claims = ev_section.get("claims", []) or []
                # 如果 evidence.claims 还是空，进一步从 diagnosis section 读 result
                if not claims:
                    diagnosis_result = await self.bb.read("diagnosis", "result", {}) or {}
                    if isinstance(diagnosis_result, dict):
                        claims = diagnosis_result.get("claims", []) or []
                        if not claims:
                            final_claim = diagnosis_result.get("final_claim", {})
                            if isinstance(final_claim, dict) and final_claim:
                                claims = [final_claim]
                # 最终兜底：从 reasoning section 读 reasoning_result
                if not claims:
                    reasoning_section = await self.bb.read_section("reasoning") or {}
                    if isinstance(reasoning_section, dict):
                        reasoning_result = reasoning_section.get("result", {})
                        if isinstance(reasoning_result, dict):
                            claims = (
                                reasoning_result.get("claims", [])
                                or reasoning_result.get("diagnosis_claims", [])
                                or []
                            )

                # 从 routing/traffic dict 中提取 asn / time_window 字段
                extracted_asn = ""
                extracted_time_window = ""
                if isinstance(routing, dict):
                    extracted_asn = str(
                        routing.get("asn")
                        or routing.get("target_as")
                        or routing.get("investigation_plan", {}).get("asn", "")
                    )
                    if extracted_time_window == "":
                        # 路由结果里通常含 start_time/end_time 或 _time_window
                        extracted_time_window = (
                            f"{routing.get('start_time', '')} - {routing.get('end_time', '')}"
                        ).strip(" -")
                if isinstance(traffic, dict):
                    extracted_asn = extracted_asn or str(traffic.get("asn", ""))
                    if extracted_time_window == "":
                        extracted_time_window = (
                            f"{traffic.get('start_time', '')} - {traffic.get('end_time', '')}"
                        ).strip(" -")
                # 从 blackboard config section 兜底（workflow_engine 会写）
                if self.bb:
                    cfg = await self.bb.read_section("config")
                    extracted_asn = extracted_asn or str(cfg.get("asn", ""))
                    if extracted_time_window == "":
                        sw = cfg.get("start_time", "")
                        ew = cfg.get("end_time", "")
                        if sw and ew:
                            extracted_time_window = f"{sw} - {ew}"

                context_data = {
                    "asn": extracted_asn,
                    "time_window": extracted_time_window,
                    "start_time": extracted_time_window.split(" - ")[0] if " - " in extracted_time_window else "",
                    "end_time": extracted_time_window.split(" - ")[-1] if " - " in extracted_time_window else "",
                    "routing": routing,
                    "traffic": traffic,
                    "claims": claims,
                }
                logger.info(
                    f"[DebateAgent] extracted asn={extracted_asn!r}, "
                    f"time_window={extracted_time_window!r}"
                )

            # 构建事件上下文 — 字段名严格对齐 EventContext dataclass
            event_context = EventContext(
                event_id=str(context_data.get("asn", "")),
                asn=str(context_data.get("asn", "")),
                time_window=str(context_data.get("time_window", "")),
                routing_evidence=context_data.get("routing", {}),
                traffic_evidence=context_data.get("traffic", {}),
                historical_context={"claims": context_data.get("claims", [])},
                ground_truth_type=str(context_data.get("ground_truth_type", "")),
            )
            
            # 运行辩论
            debate_results = []
            claims = context_data.get("claims", [])

            if not claims:
                debate_results.append({
                    "original_claim": "No routing anomalies detected",
                    "prosecution_strength": 0.0,
                    "defense_strength": 0.0,
                    "winner": "neutral",
                    "conclusion": "Insufficient evidence for definitive conclusion",
                    "final_confidence": 0.5,
                    "debate_rounds": 0,
                })
            else:
                # 对每个 claim 运行辩论
                for claim in claims[:5]:
                    pros_args = await self.prosecutor.make_argument(event_context, [])
                    pros_strength = sum(arg.strength for arg in pros_args) / max(len(pros_args), 1)
                    def_args = await self.defense.make_argument(event_context, [])
                    def_strength = sum(arg.strength for arg in def_args) / max(len(def_args), 1)
                    if pros_strength > def_strength * 1.2:
                        winner = "prosecution"
                    elif def_strength > pros_strength * 1.2:
                        winner = "defense"
                    else:
                        winner = "neutral"
                    final_conf = max(0.1, min(0.95, 0.5 + (pros_strength - def_strength) * 0.3))
                    
                    debate_results.append({
                        "original_claim": claim if isinstance(claim, str) else str(claim),
                        "prosecution_strength": pros_strength,
                        "defense_strength": def_strength,
                        "winner": winner,
                        "conclusion": f"{winner.capitalize()} arguments were more compelling" if winner != "neutral" else "Arguments were equally compelling",
                        "final_confidence": final_conf,
                        "debate_rounds": self.debate_rounds,
                    })
            
            # 消费预算
            self.consume_budget(len(debate_results))
            
            return TaskResult(
                success=True,
                data={"debate_results": debate_results},
                error=None,
                agent="LLMDebateAgent"
            )
            
        except Exception as e:
            return TaskResult(
                success=False,
                data=None,
                error=f"Debate failed: {str(e)}",
                agent="LLMDebateAgent"
            )
    
    def consume_budget(self, amount: int = 1):
        """消费辩论预算"""
        self.budget_consumed += amount
    
    async def argue(self, context: EventContext, debate_history: List[DebateRound]) -> Argument:
        """保持原有接口兼容"""
        if self.role == "prosecutor":
            args = await self.prosecutor.make_argument(context, debate_history)
        else:
            args = await self.defense.make_argument(context, debate_history)
        return args[0] if args else Argument(claim="无论点")


class MultiClaimDebateOrchestrator:
    """多主张辩论编排器"""
    
    def __init__(self):
        self.debate_system = MultiAgentDebateSystem(debate_rounds=2)
    
    async def orchestrate(self, claims: List[str], context: EventContext) -> List[DebateResult]:
        results = []
        for claim in claims:
            # 为每个主张运行辩论
            result = await self.debate_system.debate(context)
            results.append(DebateResult(
                verdict=result.decision,
                confidence=result.confidence,
            ))
        return results


class ExternalValidator:
    """外部验证器"""
    
    @staticmethod
    def validate_routing_evidence(routing_data: Dict) -> bool:
        """验证路由证据的有效性"""
        return bool(
            routing_data.get('origin_hijacked') or
            routing_data.get('origin_hijacking') or
            routing_data.get('route_leaks') or
            routing_data.get('withdrawal_surge')
        )
    
    @staticmethod
    def validate_traffic_evidence(traffic_data: Dict) -> bool:
        """验证流量证据的有效性"""
        return bool(
            traffic_data.get('anomalies_detected') or
            traffic_data.get('traffic_drop')
        )
