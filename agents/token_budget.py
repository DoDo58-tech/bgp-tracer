"""
统一 Token 计数系统
==================

解决碎片化问题：每个 LLM 模块各自维护 token 计数，无法回答
"本次分析总共消耗了多少 token"。

用法：
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
    """单个 agent 的 token 消耗"""
    agent: str
    prompt_tokens: int
    completion_tokens: int
    requests: int = 1
    timestamp: str = ""  # non-default after default is OK (requests=1 has default, then timestamp="" has default)


class TokenBudget:
    """
    单例模式：每个 run_id 维护一个独立的 token 计数。

    所有 LLM 调用方应通过 TokenBudget.add() 记录消耗，
   chief_agent 最终输出总消耗。
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
        记录一次 LLM 调用的 token 消耗。
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
        从 LLM 响应对象中提取 usage 并记录。
        支持 OpenAI-compatible 格式: response.usage.prompt_tokens / completion_tokens
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
        # Fallback: 使用传入的 prompt_tokens
        if prompt_tokens > 0:
            self.add(agent, prompt_tokens, 0)

    def total(self) -> tuple[int, int]:
        """返回 (prompt_tokens, completion_tokens) 总计"""
        return self._total_prompt, self._total_completion

    def by_agent(self) -> dict[str, tuple[int, int]]:
        """返回每个 agent 的 token 消耗"""
        result: dict[str, tuple[int, int]] = {}
        for rec in self._records:
            key = rec.agent
            if key not in result:
                result[key] = (0, 0)
            pt, ct = result[key]
            result[key] = (pt + rec.prompt_tokens, ct + rec.completion_tokens)
        return result

    def summary(self) -> dict:
        """返回完整统计摘要"""
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
