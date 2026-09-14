"""Lazy-loading proxy module for supported runtime agents."""

__all__ = [
    "run_traffic_agent",
    "run_traffic_agent_async",
    "run_routing_agent",
    "run_routing_agent_async",
    "run_reasoning_agent",
    "ReasoningAgent",
    "TrafficAgent",
    "RoutingAgent",
    "HypothesisAgent",
    "ReportAgent",
    "ReactAgent",
    "create_react_agent",
]

_EXPORTS = {}


def __getattr__(name):
    if name in _EXPORTS:
        return _EXPORTS[name]

    if name in {"run_traffic_agent", "run_traffic_agent_async", "TrafficAgent"}:
        from .traffic_agent import run_traffic_agent, run_traffic_agent_async, TrafficAgent
        _EXPORTS.update({
            "run_traffic_agent": run_traffic_agent,
            "run_traffic_agent_async": run_traffic_agent_async,
            "TrafficAgent": TrafficAgent,
        })
    elif name in {"run_routing_agent", "run_routing_agent_async", "RoutingAgent"}:
        from .routing_agent import run_routing_agent, run_routing_agent_async, RoutingAgent
        _EXPORTS.update({
            "run_routing_agent": run_routing_agent,
            "run_routing_agent_async": run_routing_agent_async,
            "RoutingAgent": RoutingAgent,
        })
    elif name in {"run_reasoning_agent", "ReasoningAgent"}:
        from .reasoning_agent import run_reasoning_agent, ReasoningAgent
        _EXPORTS.update({
            "run_reasoning_agent": run_reasoning_agent,
            "ReasoningAgent": ReasoningAgent,
        })
    elif name == "HypothesisAgent":
        from .hypothesis_manager import HypothesisAgent
        _EXPORTS["HypothesisAgent"] = HypothesisAgent
    elif name == "ReportAgent":
        from .report_agent import ReportAgent
        _EXPORTS["ReportAgent"] = ReportAgent
    elif name in {"ReactAgent", "create_react_agent"}:
        from .react_agent import ReactAgent, create_react_agent
        _EXPORTS["ReactAgent"] = ReactAgent
        _EXPORTS["create_react_agent"] = create_react_agent
    else:
        raise AttributeError(f"module 'agents' has no attribute '{name}'")

    return _EXPORTS[name]