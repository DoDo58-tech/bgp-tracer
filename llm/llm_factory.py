import os
import tiktoken
from llama_index.core.callbacks import CallbackManager, TokenCountingHandler
from llama_index.core import Settings
from llama_index.core.llms import LLM, ChatMessage
from llama_index.core.base.llms.types import (
    CompletionResponse,
    CompletionResponseGen,
    ChatResponse,
    ChatResponseGen,
    MessageRole,
)

try:
    from llama_index.llms.openai import OpenAI as LIOpenAI
except ImportError:
    LIOpenAI = None

try:
    from llama_index.llms.azure_openai import AzureOpenAI
except ImportError:
    AzureOpenAI = None


def build_token_counter():
    try:
        enc = tiktoken.get_encoding("cl100k_base")
        return TokenCountingHandler(tokenizer=enc.encode)
    except Exception:
        return TokenCountingHandler(tokenizer=lambda s: list(s.encode("utf-8")))


class OpenAICompatibleLLM(LLM):
    """OpenAI-compatible LLM wrapper for DeepSeek, Qwen, and other compatible models."""

    model_config = {"arbitrary_types_allowed": True}

    def __init__(
        self,
        model,
        api_key,
        base_url,
        temperature=0.2,
        timeout=120.0,
        max_retries=2,
        max_tokens=None,
        callback_manager=None,
    ):
        super().__init__(callback_manager=callback_manager)
        object.__setattr__(self, '_model_name', model)
        object.__setattr__(self, 'api_key', api_key)
        object.__setattr__(self, 'base_url', base_url)
        object.__setattr__(self, 'temperature', temperature)
        object.__setattr__(self, 'timeout', timeout)
        object.__setattr__(self, 'max_retries', max_retries)
        object.__setattr__(self, 'max_tokens', max_tokens)
        object.__setattr__(self, '_client', None)

    @property
    def client(self):
        if self._client is None:
            from openai import OpenAI as OAI

            self._client = OAI(
                api_key=self.api_key,
                base_url=self.base_url,
                timeout=self.timeout,
                max_retries=self.max_retries,
            )
        return self._client

    @property
    def metadata(self):
        from llama_index.core.llms import LLMMetadata

        return LLMMetadata(
            context_window=128000,
            num_output=self.max_tokens or -1,
            is_chat_model=True,
            is_function_calling_model=False,
            model_name=self._model_name,
        )

    @classmethod
    def class_name(cls):
        return "OpenAICompatibleLLM"

    def _get_encoding(self):
        try:
            return tiktoken.get_encoding("cl100k_base")
        except Exception:
            try:
                return tiktoken.get_encoding("o200k_base")
            except Exception:
                return tiktoken.get_encoding("cl100k_base")

    def complete(self, prompt, formatted=False, **kwargs):
        enc = self._get_encoding()
        num_tokens = len(enc.encode(prompt))

        try:
            response = self.client.chat.completions.create(
                model=self._model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            text = response.choices[0].message.content or ""
            return CompletionResponse(
                text=text,
                raw=response,
                additional_kwargs={},
                logprobs=None,
            )
        except Exception as e:
            raise RuntimeError(f"LLM call failed: {e}") from e

    def stream_complete(self, prompt, formatted=False, **kwargs):
        try:
            stream = self.client.chat.completions.create(
                model=self._model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                stream=True,
            )
            text_acc = ""
            for chunk in stream:
                if not chunk.choices:
                    continue
                delta = chunk.choices[0].delta
                if delta and delta.content:
                    text_acc += delta.content
                    yield CompletionResponse(
                        text=text_acc,
                        delta=delta.content,
                        raw=chunk,
                        additional_kwargs={},
                    )
        except Exception as e:
            raise RuntimeError(f"LLM stream call failed: {e}") from e

    def chat(self, messages, **kwargs):
        try:
            openai_messages = []
            for msg in messages:
                role = msg.role.value if hasattr(msg.role, "value") else str(msg.role)
                openai_messages.append({"role": role, "content": msg.content or ""})

            response = self.client.chat.completions.create(
                model=self._model_name,
                messages=openai_messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            msg_content = response.choices[0].message.content or ""
            return ChatResponse(
                message=ChatMessage(
                    role=MessageRole.ASSISTANT,
                    content=msg_content,
                    additional_kwargs={},
                ),
                raw=response,
                additional_kwargs={},
            )
        except Exception as e:
            raise RuntimeError(f"LLM chat call failed: {e}") from e

    def stream_chat(self, messages, **kwargs):
        try:
            openai_messages = []
            for msg in messages:
                role = msg.role.value if hasattr(msg.role, "value") else str(msg.role)
                openai_messages.append({"role": role, "content": msg.content or ""})

            stream = self.client.chat.completions.create(
                model=self._model_name,
                messages=openai_messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                stream=True,
            )
            text_acc = ""
            for chunk in stream:
                if not chunk.choices:
                    continue
                delta = chunk.choices[0].delta
                if delta and delta.content:
                    text_acc += delta.content
                    yield ChatResponse(
                        message=ChatMessage(
                            role=MessageRole.ASSISTANT,
                            content=text_acc,
                            additional_kwargs={},
                        ),
                        delta=delta.content,
                        raw=chunk,
                    )
        except Exception as e:
            raise RuntimeError(f"LLM stream chat failed: {e}") from e

    def achat(self, messages, **kwargs):
        return self.chat(messages, **kwargs)

    def acomplete(self, prompt, formatted=False, **kwargs):
        return self.complete(prompt, formatted, **kwargs)

    def astream_chat(self, messages, **kwargs):
        return self.stream_chat(messages, **kwargs)

    def astream_complete(self, prompt, formatted=False, **kwargs):
        return self.stream_complete(prompt, formatted, **kwargs)


def create_llm(
    model,
    api_key,
    base_url,
    temperature=0.2,
    timeout=300.0,
    max_retries=2
):
    model_lower = model.lower()
    base_url_lower = base_url.lower()

    if "azure" in base_url_lower:
        if AzureOpenAI is None:
            raise ImportError("azure-openai package is required for Azure OpenAI")
        return AzureOpenAI(
            engine=model,
            model=model,
            azure_endpoint=base_url,
            api_key=api_key,
            api_version=os.environ.get("OPENAI_API_VERSION", "2024-03-01-preview"),
            timeout=timeout,
            max_retries=max_retries,
        )

    if any(x in model_lower for x in ["deepseek", "qwq", "qwen", "gpt", "claude"]):
        return OpenAICompatibleLLM(
            model=model,
            api_key=api_key,
            base_url=base_url,
            temperature=temperature,
            timeout=timeout,
            max_retries=max_retries,
        )

    return OpenAICompatibleLLM(
        model=model,
        api_key=api_key,
        base_url=base_url,
        temperature=temperature,
        timeout=timeout,
        max_retries=max_retries,
    )


def setup_llm_settings(
    model,
    api_key,
    base_url,
    temperature=0.2,
    timeout=300.0,
    max_retries=2
):
    llm = create_llm(
        model=model,
        api_key=api_key,
        base_url=base_url,
        temperature=temperature,
        timeout=timeout,
        max_retries=max_retries
    )

    token_counter = build_token_counter()

    Settings.llm = llm
    Settings.callback_manager = CallbackManager([token_counter])
    token_counter.reset_counts()

    return llm, token_counter
