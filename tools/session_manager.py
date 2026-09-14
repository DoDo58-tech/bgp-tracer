"""
Session Manager — conversation history and evidence store.
=====================================================

Each chat session has its own:
  - conversation history (list of user/agent/tool turns)
  - collected evidence (traffic, routing, AS info results)
  - session context (current AS, time window, etc.)
  - tool call history (for the RouterAgent to decide next steps)
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class Turn:
    """A single turn in the conversation."""

    role: str  # "user" | "agent" | "tool"
    content: str
    tool_name: str = ""
    tool_input: Dict[str, Any] = field(default_factory=dict)
    tool_result: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat(timespec="seconds")

    def to_dict(self) -> dict:
        d = {
            "role": self.role,
            "content": self.content,
            "timestamp": self.timestamp,
        }
        if self.tool_name:
            d["tool_name"] = self.tool_name
            d["tool_input"] = self.tool_input
            d["tool_result"] = self.tool_result
        return d


class SessionManager:
    """
    Manages the state for a single chat session.

    Usage:
        session = SessionManager("AS135826", "2025-06-21 00:30", "2025-06-21 01:46")
        session.add_user_turn("analyze AS135826 ...")
        session.add_tool_turn("analyze_traffic", input, result)
        session.add_agent_turn("Found traffic anomaly, now checking routing...")
        history = session.get_history_for_llm()
    """

    def __init__(
        self,
        asn: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        session_id: Optional[str] = None,
    ):
        self.session_id = session_id or str(uuid.uuid4())[:8]
        self.asn = asn
        self.start_time = start_time
        self.end_time = end_time
        self.turns: List[Turn] = []
        self.evidence: Dict[str, Any] = {}  # key: tool_name, value: result dict
        self.tool_calls: List[Dict[str, Any]] = []  # ordered list of tool calls
        self.completed_tools: set = set()
        self.pending_tools: set = set()
        self.report_path: Optional[str] = None
        self._started_at = datetime.now()

    # ── Turn management ────────────────────────────────────────────────────────

    def add_user_turn(self, content: str) -> None:
        self.turns.append(Turn(role="user", content=content))

    def add_agent_turn(self, content: str) -> None:
        self.turns.append(Turn(role="agent", content=content))

    def add_tool_turn(
        self,
        tool_name: str,
        tool_input: Dict[str, Any],
        tool_result: Dict[str, Any],
    ) -> None:
        turn = Turn(
            role="tool",
            content=f"Called tool: {tool_name}",
            tool_name=tool_name,
            tool_input=tool_input,
            tool_result=tool_result,
        )
        self.turns.append(turn)
        self.tool_calls.append({
            "tool_name": tool_name,
            "input": tool_input,
            "result": tool_result,
            "timestamp": turn.timestamp,
        })
        if tool_result.get("success", False):
            self.completed_tools.add(tool_name)
            self.evidence[tool_name] = tool_result
        else:
            self.pending_tools.discard(tool_name)

    def add_event(self, event_type: str, agent: str, payload: Dict[str, Any]) -> None:
        self.turns.append(Turn(
            role="agent",
            content=f"Event: {event_type}",
            tool_name=agent,
            tool_result={"event_type": event_type, "payload": payload},
        ))

    def add_pending_tool(self, tool_name: str) -> None:
        self.pending_tools.add(tool_name)

    # ── Accessors ─────────────────────────────────────────────────────────────

    def get_history_for_llm(self) -> List[dict]:
        """Return the full conversation history formatted for injection into LLM prompts."""
        return [t.to_dict() for t in self.turns]

    def get_evidence(self, tool_name: str) -> Optional[dict]:
        return self.evidence.get(tool_name)

    def get_all_evidence(self) -> Dict[str, dict]:
        return dict(self.evidence)

    def set_time_window(self, start: str, end: str) -> None:
        self.start_time = start
        self.end_time = end

    def set_asn(self, asn: str) -> None:
        self.asn = asn

    def get_context_summary(self) -> dict:
        return {
            "session_id": self.session_id,
            "asn": self.asn,
            "time_window": f"{self.start_time} → {self.end_time}" if self.start_time else "unknown",
            "completed_tools": sorted(self.completed_tools),
            "pending_tools": sorted(self.pending_tools),
            "total_turns": len(self.turns),
            "elapsed_seconds": (datetime.now() - self._started_at).total_seconds(),
        }

    # ── Serialization ────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "asn": self.asn,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "turns": [t.to_dict() for t in self.turns],
            "tool_calls": self.tool_calls,
            "evidence": self.evidence,
            "completed_tools": sorted(self.completed_tools),
            "report_path": self.report_path,
            "started_at": self._started_at.isoformat(),
        }

    def save(self, path: Optional[Path] = None) -> Path:
        if path is None:
            path = Path("results") / "sessions" / f"session_{self.session_id}.json"
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False))
        return path

    @classmethod
    def load(cls, path: Path) -> "SessionManager":
        data = json.loads(path.read_text())
        session = cls(
            asn=data.get("asn"),
            start_time=data.get("start_time"),
            end_time=data.get("end_time"),
            session_id=data.get("session_id"),
        )
        session.turns = [Turn(**t) for t in data.get("turns", [])]
        session.tool_calls = data.get("tool_calls", [])
        session.evidence = data.get("evidence", {})
        session.completed_tools = set(data.get("completed_tools", []))
        return session

    # ── Convenience ───────────────────────────────────────────────────────────

    def has_traffic(self) -> bool:
        return "analyze_traffic" in self.completed_tools and self.evidence.get("analyze_traffic", {}).get("success")

    def has_routing(self) -> bool:
        return "analyze_routing" in self.completed_tools and self.evidence.get("analyze_routing", {}).get("success")

    def has_correlation(self) -> bool:
        return "check_traffic_routing_correlation" in self.completed_tools

    def has_asn_info(self) -> bool:
        return "query_as_info" in self.completed_tools

    def has_classification(self) -> bool:
        return "reason_and_classify" in self.completed_tools

    def has_report(self) -> bool:
        p = self.evidence.get("generate_report", {}).get("report_path")
        if p:
            self.report_path = p
        return bool(p)
