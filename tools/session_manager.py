"""Session Manager — conversation history and evidence store.
====================================================="""

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

    def to_dict(self):
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
    """Manages the state for a single chat session."""

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

    def add_user_turn(self, content):
        self.turns.append(Turn(role="user", content=content))

    def add_agent_turn(self, content):
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

    def get_evidence(self, tool_name):
        return self.evidence.get(tool_name)

    def get_all_evidence(self) -> Dict[str, dict]:
        return dict(self.evidence)

    def set_time_window(self, start, end):
        self.start_time = start
        self.end_time = end

    def set_asn(self, asn):
        self.asn = asn

    def get_context_summary(self):
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

    def to_dict(self):
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

    def save(self, path=None):
        if path is None:
            path = Path("results") / "sessions" / f"session_{self.session_id}.json"
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False))
        return path

    @classmethod
    def load(cls, path) -> "SessionManager":
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
