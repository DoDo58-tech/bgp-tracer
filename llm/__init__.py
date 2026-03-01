"""
LLM (Large Language Model) utilities for BGP Tracer.

This package provides LLM integration for intelligent network analysis,
including DeepSeek reasoning models and OpenAI-compatible APIs.
"""

__version__ = "1.0.0"

# Export main functions for easy access
from .llm_factory import setup_llm_settings, create_llm, build_token_counter
from .prompt import build_react_system_prompt, build_multi_agent_coordination_prompt, get_reasoning_laws

__all__ = [
    "setup_llm_settings",
    "create_llm",
    "build_token_counter",
    "build_react_system_prompt",
    "build_multi_agent_coordination_prompt",
    "get_reasoning_laws",
]
