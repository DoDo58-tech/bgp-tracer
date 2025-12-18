import os
from dataclasses import dataclass
from typing import Optional

from openai import OpenAI

try:
    from config import BASE_URL as DEFAULT_BASE_URL, API_KEY as DEFAULT_API_KEY, MODEL as DEFAULT_MODEL
except Exception:
    DEFAULT_BASE_URL = os.getenv("CSTCLOUD_BASE_URL", "https://uni-api.cstcloud.cn/v1")
    DEFAULT_API_KEY = os.getenv("CstCloudToken", "")
    DEFAULT_MODEL = os.getenv("CSTCLOUD_MODEL", "deepseek-v3:671b")


@dataclass
class LLMResult:
    answer: str
    thinking: str


class CstCloud:
    """Lightweight OpenAI-compatible client for CSTCloud unified API (DeepSeek models).

    This wrapper exposes a streaming call that returns both final answer and optional reasoning stream.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        default_model: Optional[str] = None,
    ) -> None:
        self.token = api_key or DEFAULT_API_KEY or os.getenv("CstCloudToken", "")
        self.base_url = base_url or DEFAULT_BASE_URL
        self.default_model = default_model or DEFAULT_MODEL
        self.model_alias = {
            "r1-0528": "deepseek-r1:671b-0528",
            "r1": "deepseek-r1:671b-64k",
            "v3": "deepseek-v3:671b",
        }

    def _resolve_model(self, model: Optional[str]) -> str:
        if not model:
            return self.default_model
        return self.model_alias.get(model, model)

    def call_by_openai_stream(
        self,
        sys_prompt: str,
        user_prompt: str,
        model: Optional[str] = None,
        debug: bool = False,
        enable_thinking: bool = True,
    ) -> LLMResult:
        resolved_model = self._resolve_model(model)
        client = OpenAI(api_key=self.token, base_url=self.base_url)

        chat_response = client.chat.completions.create(
            model = resolved_model,
            messages=[
                {"role": "system", "content": sys_prompt},
                {"role": "user", "content": user_prompt},
            ],
            stream=True,
            extra_body={
                "chat_template_kwargs": {
                    "enable_thinking": bool(enable_thinking)
                }
            },
        )

        answer_parts: list[str] = []
        thinking_parts: list[str] = []
        for chunk in chat_response:
            if not getattr(chunk, "choices", None):
                continue
            delta = chunk.choices[0].delta
            # content stream
            if getattr(delta, "content", None):
                if debug:
                    print(delta.content, end="", flush=True)
                answer_parts.append(delta.content)
            # reasoning stream (if enabled by server)
            if getattr(delta, "reasoning_content", None):
                if debug:
                    print(delta.reasoning_content, end="", flush=True)
                thinking_parts.append(delta.reasoning_content)

        return LLMResult(answer="".join(answer_parts), thinking="".join(thinking_parts))


__all__ = ["CstCloud", "LLMResult"]


