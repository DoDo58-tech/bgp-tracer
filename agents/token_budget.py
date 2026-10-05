"""
 Token 
==================

： LLM  token ，
" token"。

：
    from agents.token_budget import TokenBudget
    tb = TokenBudget.get_instance("run_123")
    tb.add("routing_agent", 500, 200)
    tb.add("reasoning_agent", 1000, 400)
    total = tb.total()  # (1500, 600)
"""

from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime


@dataclass
class AgentTokenUsage:
    """ agent  token """
    agent: str
    prompt_tokens: int
    completion_tokens: int
    requests: int = 1
    timestamp: str = ""  # non-default after default is OK (requests=1 has default, then timestamp="" has default)


class TokenBudget:
    """
    ： run_id  token 。

     LLM  TokenBudget.add() ，
   chief_agent 。
    """

    _instances: dict[str, "TokenBudget"] = {}

    def __init__(self, run_id: str):
        self.run_id = run_id
        self._records: list[AgentTokenUsage] = []
        self._total_prompt: int = 0
        self._total_completion: int = 0

    @classmethod
    def get_instance(cls, run_id: str) -> "TokenBudget":
        if run_id not in cls._instances:
            cls._instances[run_id] = cls(run_id)
        return cls._instances[run_id]

    @classmethod
    def clear_instance(cls, run_id: str):
        if run_id in cls._instances:
            del cls._instances[run_id]

    def add(self, agent: str, prompt_tokens: int, completion_tokens: int):
        """
         LLM  token 。
        """
        record = AgentTokenUsage(
            agent=agent,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            requests=1,
            timestamp=datetime.now().isoformat(),
        )
        self._records.append(record)
        self._total_prompt += prompt_tokens
        self._total_completion += completion_tokens

    def add_from_response(self, agent: str, response, prompt_tokens: int = 0):
        """
         LLM  usage 。
         OpenAI-compatible : response.usage.prompt_tokens / completion_tokens
        """
        try:
            usage = getattr(response, "usage", None)
            if usage:
                pt = getattr(usage, "prompt_tokens", 0) or prompt_tokens
                ct = getattr(usage, "completion_tokens", 0)
                self.add(agent, pt, ct)
                return
        except Exception:
            pass
        # Fallback:  prompt_tokens
        if prompt_tokens > 0:
            self.add(agent, prompt_tokens, 0)

    def total(self) -> tuple[int, int]:
        """ (prompt_tokens, completion_tokens) """
        return self._total_prompt, self._total_completion

    def by_agent(self) -> dict[str, tuple[int, int]]:
        """ agent  token """
        result: dict[str, tuple[int, int]] = {}
        for rec in self._records:
            key = rec.agent
            if key not in result:
                result[key] = (0, 0)
            pt, ct = result[key]
            result[key] = (pt + rec.prompt_tokens, ct + rec.completion_tokens)
        return result

    def summary(self) -> dict:
        """"""
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

    def __len__(self) -> int:
        return len(self._records)
