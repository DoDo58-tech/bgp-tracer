"""Tool Registry — dynamic tool registration and invocation.
========================================================"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from utils.logger import logger
import asyncio
import json
import httpx
from datetime import datetime


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
    """Central registry of all available tools."""

    def __init__(self):
        self._tools: Dict[str, Tool] = {}

    def register(self, tool):
        if tool.name in self._tools:
            logger.warning(f"Tool '{tool.name}' already registered — overwriting")
        self._tools[tool.name] = tool
        logger.info(f"[ToolRegistry] Registered: {tool.name}")

    def list_tools(self) -> List[dict]:
        return [t.to_dict() for t in self._tools.values() if t.enabled]

    async def call(
        self,
        tool_name: str,
        tool_input: Dict[str, Any],
        session,
    ) -> ToolResult:
        """Execute a tool by name and return a ToolResult."""
        entry = self._tools.get(tool_name)
        if not entry:
            return ToolResult(
                tool_name=tool_name,
                success=False,
                error=f"Unknown tool: {tool_name}",
            )
        if not entry.enabled:
            return ToolResult(
                tool_name=tool_name,
                success=False,
                error=f"Tool '{tool_name}' is disabled",
            )
        if entry.handler is None:
            return ToolResult(
                tool_name=tool_name,
                success=False,
                error=f"Tool '{tool_name}' has no handler registered",
            )

        try:
            logger.info(f"[ToolRegistry] Calling: {tool_name}({tool_input})")
            data = await entry.handler(tool_input, session)
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
        except (httpx.HTTPError, OSError, ValueError, KeyError,
                AttributeError, TypeError) as e:
            # A tool is an *optional* source of evidence.  An unreachable
            # upstream (DNS failure, connection reset, a JSON body that
            # changed shape) must cost the agent that one observation, not
            # the whole analysis: the previous narrow AttributeError
            # handler let a bgpview.io DNS failure propagate out of the
            # ReAct loop and abort the event entirely.
            logger.error(f"[ToolRegistry] {tool_name} failed: {e}")
            return ToolResult(
                tool_name=tool_name,
                success=False,
                error=str(e),
                observation=f"Tool '{tool_name}' unavailable: {e}",
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


def register_tool(
    name: str,
    description: str,
    parameters: Optional[List[ToolParameter]] = None,
    handler: Optional[Callable] = None,
):
    """Register a tool handler under ``name``."""
    t = Tool(
        name=name,
        description=description,
        parameters=parameters or [],
        handler=handler,
    )
    REGISTRY.register(t)
    return t