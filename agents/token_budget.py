"""Per-run LLM token accounting."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass
class AgentTokenUsage:
    agent: str
    prompt_tokens: int
    completion_tokens: int
    requests: int = 1
    timestamp: str = ""


class TokenBudget:
    """Accumulates token usage per run, keyed by ``run_id``."""

    _instances: dict[str, "TokenBudget"] = {}

    def __init__(self, run_id):
        self.run_id = run_id
        self._records: list[AgentTokenUsage] = []
        self._total_prompt: int = 0
        self._total_completion: int = 0

    @classmethod
    def get_instance(cls, run_id) -> "TokenBudget":
        if run_id not in cls._instances:
            cls._instances[run_id] = cls(run_id)
        return cls._instances[run_id]

    @classmethod
    def clear_instance(cls, run_id):
        cls._instances.pop(run_id, None)

    def add(self, agent, prompt_tokens, completion_tokens):
        self._records.append(AgentTokenUsage(
            agent=agent,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            timestamp=datetime.now().isoformat(),
        ))
        self._total_prompt += prompt_tokens
        self._total_completion += completion_tokens

    def total(self) -> tuple[int, int]:
        return self._total_prompt, self._total_completion

    def by_agent(self) -> dict[str, tuple[int, int]]:
        result: dict[str, tuple[int, int]] = {}
        for rec in self._records:
            pt, ct = result.get(rec.agent, (0, 0))
            result[rec.agent] = (pt + rec.prompt_tokens, ct + rec.completion_tokens)
        return result

    def summary(self):
        pt, ct = self.total()
        return {
            "run_id": self.run_id,
            "total_prompt_tokens": pt,
            "total_completion_tokens": ct,
            "total_tokens": pt + ct,
            "total_requests": len(self._records),
            "by_agent": {
                agent: {
                    "prompt_tokens": agent_pt,
                    "completion_tokens": agent_ct,
                    "total_tokens": agent_pt + agent_ct,
                }
                for agent, (agent_pt, agent_ct) in self.by_agent().items()
            },
        }

    def __len__(self):
        return len(self._records)