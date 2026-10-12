"""
BGP Multi-Agent Tools Package
=============================

Exports:
    ToolRegistry  — REGISTRY singleton + register_tool decorator
    SessionManager — conversation history + evidence store
    RouterAgent  — LLM-driven tool router + conversation manager
    ChatInterface — conversational REPL entry point
    tool_implementations — registers all built-in tools on import

Quick start:
    from tools import ChatInterface
    ChatInterface().run()

    # Or programmatically:
    from tools import RouterAgent, SessionManager
    router = RouterAgent()
    session = SessionManager()
    response = await router.step("analyze AS135826 from 2025-06-21 00:30 to 2025-06-21 01:46", session)
"""

from tools.tool_registry import REGISTRY, Tool, ToolResult, ToolParameter, tool, register_tool
from tools.session_manager import SessionManager
from tools.router_agent import RouterAgent

# Import this module to register all built-in tools
from tools import tool_implementations  # noqa: F401

# Import additional enhanced tools (each self-registers on import)
from tools import rpki_validation   # noqa: F401
from tools import as_topology      # noqa: F401
from tools import long_term_baseline  # noqa: F401
from tools import as_business_profile  # noqa: F401

# Import new auxiliary tools (each self-registers on import)
from tools import threat_intelligence  # noqa: F401
from tools import news_context        # noqa: F401
from tools import irr_registry       # noqa: F401
from tools import historical_behavior  # noqa: F401

__all__ = [
    "REGISTRY",
    "Tool",
    "ToolResult",
    "ToolParameter",
    "tool",
    "register_tool",
    "SessionManager",
    "RouterAgent",
]
