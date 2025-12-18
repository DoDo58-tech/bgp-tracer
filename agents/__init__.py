"""Lazy-loading proxy module for agent utilities."""

__all__ = [
    "run_traffic_agent",
    "run_traffic_agent_async",
    "LLMEnhancedTrafficAgent",
    "run_routing_agent",
    "run_routing_agent_async",
    "run_routing_agent_with_llm",
    "LLMEnhancedRoutingAgent",
    "run_reasoning_agent",
    "ReasoningAgent",
    "run_analysis_agent",
]

_EXPORTS = {}


def __getattr__(name):
    if name in _EXPORTS:
        return _EXPORTS[name]
    
    if name in {"run_traffic_agent", "run_traffic_agent_async", "LLMEnhancedTrafficAgent"}:
        from .traffic_agent import (
            run_traffic_agent,
            run_traffic_agent_async,
            LLMEnhancedTrafficAgent,
        )
        _EXPORTS.update(
            {
                "run_traffic_agent": run_traffic_agent,
                "run_traffic_agent_async": run_traffic_agent_async,
                "LLMEnhancedTrafficAgent": LLMEnhancedTrafficAgent,
            }
        )
    elif name in {
        "run_routing_agent",
        "run_routing_agent_async",
        "run_routing_agent_with_llm",
        "LLMEnhancedRoutingAgent",
    }:
        from .routing_agent import (
            run_routing_agent,
            run_routing_agent_async,
            run_routing_agent_with_llm,
            LLMEnhancedRoutingAgent,
        )
        _EXPORTS.update(
            {
                "run_routing_agent": run_routing_agent,
                "run_routing_agent_async": run_routing_agent_async,
                "run_routing_agent_with_llm": run_routing_agent_with_llm,
                "LLMEnhancedRoutingAgent": LLMEnhancedRoutingAgent,
            }
        )
    elif name in {"run_reasoning_agent", "ReasoningAgent"}:
        from .reasoning_agent import run_reasoning_agent, ReasoningAgent
        _EXPORTS.update(
            {"run_reasoning_agent": run_reasoning_agent, "ReasoningAgent": ReasoningAgent}
        )
    elif name == "run_analysis_agent":
        from .analysis_agent import run_analysis_agent
        _EXPORTS["run_analysis_agent"] = run_analysis_agent
    else:
        raise AttributeError(f"module 'agents' has no attribute '{name}'")
    
    return _EXPORTS[name]
