"""
Enhanced Mode Components.

Activated by workflow_engine._init_enhanced_components. Provides the multi-agent
coordination layer on top of the core workflow agents in agents/.

Contents:
- AgentMessageBus / Topic / BlackboardMessageBridge  : pub/sub backbone
- QualityEvaluator / OnlineEvaluationAgent          : per-stage quality gate
- ReactiveDecisionEngine / ReactiveDecision          : stage transition control
- LLMDebateAgent                                    : prosecutor/defense/judge debate
- MultiAgentReportAgent                             : specialist-validated report pipeline
"""

from agents.enhanced.message_bus import (
    AgentMessageBus,
    MessageEnvelope,
    Topic,
    BlackboardMessageBridge,
)
from agents.enhanced.debate_agent import LLMDebateAgent
from agents.enhanced.evaluation_loop import (
    QualityMetrics,
    QualityEvaluator,
    OnlineEvaluationAgent,
    StageQualityGate,
)
from agents.enhanced.multi_report import MultiAgentReportAgent
from agents.enhanced.reactive_decision import ReactiveDecision, ReactiveDecisionEngine

__all__ = [
    "AgentMessageBus", "MessageEnvelope", "Topic", "BlackboardMessageBridge",
    "LLMDebateAgent",
    "QualityMetrics", "QualityEvaluator", "OnlineEvaluationAgent", "StageQualityGate",
    "ReactiveDecision", "ReactiveDecisionEngine",
    "MultiAgentReportAgent",
]