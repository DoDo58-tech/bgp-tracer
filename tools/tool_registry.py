"""
Tool Registry — dynamic tool registration and invocation.
========================================================

All analysis capabilities are exposed as "tools" that the RouterAgent
can call.  Tools are registered at startup and are called by name.

Tool schema (per tool):
    name        str         — unique identifier, e.g. "analyze_traffic"
    description str         — one-line human-readable description
    parameters  list[dict] — JSON-schema-like parameter list
    handler     callable   — async function(tool_input, session) → ToolResult

RouterAgent decides which tools to call based on the conversation context
and passes the tool's raw output back to the LLM for interpretation.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional
from utils.logger import logger


@dataclass
class ToolParameter:
    name: str
    description: str
    type: str = "string"
    required: bool = True
    default: Any = None


@dataclass
class Tool:
    """A callable tool registered in the ToolRegistry."""

    name: str
    description: str
    parameters: List[ToolParameter] = field(default_factory=list)
    handler: Optional[Callable] = None  # async def(tool_input: dict, session) -> dict
    enabled: bool = True

    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "parameters": [
                {
                    "name": p.name,
                    "description": p.description,
                    "type": p.type,
                    "required": p.required,
                    "default": p.default,
                }
                for p in self.parameters
            ],
        }


@dataclass
class ToolResult:
    """Result returned by a tool after execution."""

    tool_name: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: str = ""
    observation: str = ""  # Human-readable summary for the LLM

    def to_llm_dict(self):
        """Format suitable for injection into the LLM prompt."""
        return {
            "tool": self.tool_name,
            "success": self.success,
            "data": self.data,
            "observation": self.observation,
            "error": self.error,
        }

    def get(self, key, default=None):
        """Allow dict-like access to data fields for backward compatibility."""
        return self.data.get(key, default)


class ToolRegistry:
    """
    Central registry of all available tools.

    Usage:
        registry = ToolRegistry()
        registry.register(my_tool)
        result = await registry.call("analyze_traffic", {"asn": "135826", ...}, session)
    """

    def __init__(self):
        self._tools: Dict[str, Tool] = {}

    def register(self, tool):
        if tool.name in self._tools:
            logger.warning(f"Tool '{tool.name}' already registered — overwriting")
        self._tools[tool.name] = tool
        logger.info(f"[ToolRegistry] Registered: {tool.name}")

    def unregister(self, name):
        return self._tools.pop(name, None) is not None

    def get(self, name):
        return self._tools.get(name)

    def list_tools(self) -> List[dict]:
        return [t.to_dict() for t in self._tools.values() if t.enabled]

    def list_names(self) -> List[str]:
        return [t.name for t in self._tools.values() if t.enabled]

    async def call(
        self,
        tool_name: str,
        tool_input: Dict[str, Any],
        session,
    ) -> ToolResult:
        """Execute a tool by name and return a ToolResult."""
        tool = self._tools.get(tool_name)
        if not tool:
            return ToolResult(
                tool_name=tool_name,
                success=False,
                error=f"Unknown tool: {tool_name}",
            )
        if not tool.enabled:
            return ToolResult(
                tool_name=tool_name,
                success=False,
                error=f"Tool '{tool_name}' is disabled",
            )
        if tool.handler is None:
            return ToolResult(
                tool_name=tool_name,
                success=False,
                error=f"Tool '{tool_name}' has no handler registered",
            )

        try:
            logger.info(f"[ToolRegistry] Calling: {tool_name}({tool_input})")
            data = await tool.handler(tool_input, session)
            if isinstance(data, ToolResult):
                return data
            # Handler returned a plain dict — extract fields if present
            obs = data.get("observation") if isinstance(data, dict) else None
            return ToolResult(
                tool_name=tool_name,
                success=data.get("success", True) if isinstance(data, dict) else True,
                data=data if isinstance(data, dict) else {},
                observation=obs or f"Tool '{tool_name}' returned successfully.",
                error=data.get("error", "") if isinstance(data, dict) else "",
            )
        except Exception as e:
            logger.error(f"[ToolRegistry] {tool_name} failed: {e}")
            return ToolResult(
                tool_name=tool_name,
                success=False,
                error=str(e),
            )

    async def call_sequence(
        self,
        calls: List[Dict[str, Any]],
        session,
    ) -> List[ToolResult]:
        """Execute a sequence of tool calls, returning all results."""
        results = []
        for call in calls:
            name = call.get("name") or call.get("tool_name")
            inp = call.get("input") or call.get("parameters") or {}
            result = await self.call(name, inp, session)
            results.append(result)
        return results


# ── Global registry (singleton) ──────────────────────────────────────────────

REGISTRY = ToolRegistry()


def tool(
    name: str,
    description: str,
    parameters: Optional[List[ToolParameter]] = None,
):
    """
    Decorator to register a coroutine as a tool handler.

    Usage:
        @tool(name="analyze_traffic", description="...", parameters=[...])
        async def my_handler(tool_input, session):
            ...
    """

    def decorator(func):
        t = Tool(
            name=name,
            description=description,
            parameters=parameters or [],
            handler=func,
        )
        REGISTRY.register(t)
        return func

    return decorator


def register_tool(
    name: str,
    description: str,
    parameters: Optional[List[ToolParameter]] = None,
    handler: Optional[Callable] = None,
):
    """Functional tool registration (alternative to decorator)."""
    t = Tool(
        name=name,
        description=description,
        parameters=parameters or [],
        handler=handler,
    )
    REGISTRY.register(t)
    return t
