import json as _json
import os
import time
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


# Temperature policy
# LLM temperature is task-specific. Hardcoding 1.0 across the board produces
# hallucination-heavy outputs and breaks reproducibility for a security tool.
#
#   * REASONING  (0.1) — multi-step analysis / causal inference / debate.
#                       Low randomness so reasoning chains stay coherent.
#   * REPORT     (0.2) — final user-facing HTML report. Slightly higher so the
#                       prose reads naturally, but still grounded.
#   * CLASSIFY   (0.0) — JSON classification (severity, event_type, role...).
#                       Deterministic so output schemas don't drift.
#
# Override any of these via env vars if needed (advanced users only).
DEFAULT_TEMP_REPORT = float(os.environ.get("LLM_TEMP_REPORT", "0.2"))
DEFAULT_TEMP_REASONING = float(os.environ.get("LLM_TEMP_REASONING", "0.1"))
DEFAULT_TEMP_CLASSIFY = float(os.environ.get("LLM_TEMP_CLASSIFY", "0.0"))

try:
    from llama_index.llms.openai import OpenAI as LIOpenAI
except ImportError:
    LIOpenAI = None

try:
    from llama_index.llms.azure_openai import AzureOpenAI
except ImportError:
    AzureOpenAI = None


# ── Thinking / reasoning-disable helper ─────────────────────────────────────
# Some API providers (GLM-5, Kimi) place assistant output in reasoning_content
# instead of content unless a vendor-specific extra_body flag is set.
# LLM_THINKING_DISABLE (env var) holds the JSON-serialized extra_body dict.
# We merge it with any caller-provided extra_body so both are honoured.
_extra_body_disable: dict | None = None  # lazily parsed, cached at module level

def _get_thinking_disable() -> dict | None:
    global _extra_body_disable
    if _extra_body_disable is not None:
        return _extra_body_disable
    raw = os.environ.get("LLM_THINKING_DISABLE", "").strip()
    if not raw:
        _extra_body_disable = None
        return None
    try:
        _extra_body_disable = _json.loads(raw)
    except Exception:
        _extra_body_disable = None
    return _extra_body_disable

def _merge_extra_body(caller_eb: dict | None) -> dict | None:
    """Merge caller extra_body with vendor thinking-disable dict."""
    disable = _get_thinking_disable()
    if not disable and not caller_eb:
        return None
    if not disable:
        return caller_eb
    if not caller_eb:
        return disable
    # shallow merge: caller keys win to allow per-call overrides
    merged = {**disable, **caller_eb}
    return merged

def _extract_message_text(message) -> str:
    """Extract the visible assistant output from a chat completion message.

    Some vendors (GLM-5, Kimi thinking mode) place reasoning output in
    `reasoning_content` and the visible answer in `content`. We prioritize
    `content` so callers don't receive CoT introspections as the final output.
    """
    content = (getattr(message, "content", "") or "")
    reasoning = (getattr(message, "reasoning_content", "") or "")
    if content.strip():
        return content
    if reasoning.strip():
        return reasoning
    return ""


def _extract_delta_text(delta) -> str:
    """Combine streamed `content` and `reasoning_content` deltas.

    Handles three cases gracefully:
    1. delta is a proper ChoiceDelta object with content/reasoning_content attrs
    2. delta is None or has no usable attributes
    3. response is entirely in reasoning_content (Kimi thinking mode fallback)
    """
    if delta is None:
        return ""
    chunk = ""
    # Primary field: content
    c = getattr(delta, "content", None)
    if c:
        chunk += str(c)
    # Fallback: reasoning_content (used by Kimi thinking, GLM-5)
    r = getattr(delta, "reasoning_content", None)
    if r:
        chunk += str(r)
    return chunk


def build_token_counter():
    try:
        enc = tiktoken.get_encoding("cl100k_base")
        handler = TokenCountingHandler(tokenizer=enc.encode)
    except Exception:
        handler = TokenCountingHandler(tokenizer=lambda s: list(s.encode("utf-8")))
    register_token_counter(handler)
    return handler


# ── Process-wide token counter (Bug fix: react path was reporting N/A) ─────
# TokenCountingHandler keeps per-handler totals in ``total_llm_token_count``.
# We aggregate every handler created via ``build_token_counter()`` into a
# module-level set so the chief agent can report a single ``Tokens: N`` line
# even on the ReAct code path (which builds its own LLM instance and does not
# thread the counter through to the result object).
_GLOBAL_TOKEN_HANDLERS: list = []


def register_token_counter(handler) -> None:
    """Register a TokenCountingHandler with the process-wide aggregator."""
    try:
        if handler is not None and handler not in _GLOBAL_TOKEN_HANDLERS:
            _GLOBAL_TOKEN_HANDLERS.append(handler)
    except Exception:
        pass


def get_global_token_counter() -> int:
    """Sum ``total_llm_token_count`` across every registered handler."""
    total = 0
    for h in list(_GLOBAL_TOKEN_HANDLERS):
        try:
            total += int(getattr(h, "total_llm_token_count", 0) or 0)
        except Exception:
            continue
    return total


def reset_global_token_counter() -> None:
    """Reset every registered handler's counter."""
    for h in list(_GLOBAL_TOKEN_HANDLERS):
        try:
            h.reset_counts()
        except Exception:
            continue


class OpenAICompatibleLLM(LLM):
    """OpenAI-compatible LLM wrapper for DeepSeek, Qwen, and other compatible models."""

    model_config = {"arbitrary_types_allowed": True}

    def __init__(
        self,
        model,
        api_key,
        base_url,
        temperature=DEFAULT_TEMP_REASONING,
        timeout=300.0,
        max_retries=3,
        max_tokens=8192,
        callback_manager=None,
    ):
        super().__init__(callback_manager=callback_manager)
        object.__setattr__(self, '_model_name', model)
        object.__setattr__(self, 'api_key', api_key)
        object.__setattr__(self, 'base_url', base_url)
        # Some endpoints (e.g. Kimi kimi-for-coding) only accept a single
        # fixed temperature (1.0). When we detect that family, force the
        # value the upstream expects instead of the requested default.
        model_lower = (model or "").lower()
        base_lower = (base_url or "").lower()
        is_kimi_coding = (
            "kimi" in model_lower
            or "api.kimi.com" in base_lower
            or "kimi-for-coding" in model_lower
        )
        # Allow per-model override so providers with non-1.0 constraints (e.g.
        # Kimi CSTCLOUD at 0.6) can pass their own value without forcing 1.0.
        _force_kimi_temp = os.environ.get("LLM_FORCE_KIMI_TEMP", "true").lower() == "true"
        effective_temp = 1.0 if (is_kimi_coding and _force_kimi_temp) else float(temperature)
        object.__setattr__(self, 'temperature', effective_temp)
        object.__setattr__(self, '_forced_temperature', is_kimi_coding)
        object.__setattr__(self, 'timeout', timeout)
        object.__setattr__(self, 'max_retries', max_retries)
        object.__setattr__(self, 'max_tokens', max_tokens)
        object.__setattr__(self, '_client', None)

    @property
    def client(self):
        if self._client is None:
            from openai import OpenAI as OAI
            import httpx

            request_timeout = float(self.timeout)
            # Read timeout is what matters most for LLM responses. The hard
            # 90s cap was originally below the orchestration timeout
            # (COORDINATION_TIMEOUT=900s) to avoid pipeline stalls, but it
            # becomes a bottleneck for slower endpoints (Kimi on CSTCLOUD,
            # GLM on sfkey) whose report-stream can take several minutes.
            # Bump it via env var to give these providers headroom while
            # keeping the default behaviour for fast endpoints.
            #
            # REPORT_LLM_TIMEOUT_S (default 180s) is the hard watchdog that
            # kills the whole report call. The httpx read timeout must be at
            # least that large, otherwise the HTTP layer times out first and
            # leaves us with a partial/incomplete stream that looks empty.
            report_llm_timeout = float(os.environ.get("REPORT_LLM_TIMEOUT_S", "180.0"))
            read_cap = float(os.environ.get("LLM_READ_TIMEOUT", "0"))  # 0 = no cap
            if read_cap <= 0:
                # No cap: use the larger of request_timeout and report timeout + 60s buffer.
                # This ensures the HTTP layer never cuts off a report call prematurely.
                effective_read = max(request_timeout, report_llm_timeout + 60.0)
            else:
                effective_read = max(min(request_timeout, read_cap), 30.0)
            timeout = httpx.Timeout(
                connect=min(10.0, request_timeout),
                read=effective_read,
                write=min(10.0, request_timeout),
                pool=min(10.0, request_timeout),
            )

            self._client = OAI(
                api_key=self.api_key,
                base_url=self.base_url,
                timeout=timeout,
                max_retries=self.max_retries,
            )
        return self._client

    @property
    def metadata(self):
        from llama_index.core.llms import LLMMetadata

        return LLMMetadata(
            context_window=256000,
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

    @staticmethod
    def _is_retryable(exc: Exception) -> bool:
        err_lower = str(exc).lower()
        non_retryable = [
            "unprocessable entity",
            "invalid request error",
            "bad request",
            "400",
            "401",
            "403",
            "404",
            "invalid request",
            "model not found",
            "incorrect api key",
        ]
        if any(k in err_lower for k in non_retryable):
            return False
        # OpenAI SDK errors carry the HTTP status code on the response attribute
        try:
            status = getattr(exc, "response", None)
            if status is not None:
                code = getattr(status, "status_code", None)
                if code in (400, 401, 403, 404, 422):
                    return False
                if code in (429, 500, 502, 503, 504):
                    return True
        except Exception:
            pass
        kw = [
            "rate limit", "429", "500", "502", "503", "504",
            "connection", "timeout", "timed out", "network",
            "temporarily unavailable", "service unavailable",
            "internal server error", "gateway timeout", "bad gateway",
            "upstream connect error", "socket timeout",
        ]
        return any(k in err_lower for k in kw)

    @staticmethod
    def _extract_json(text: str):
        """Extract first JSON object from text. Supports:
        1. ```json ... ``` markdown code blocks (most reliable)
        2. ``` ... ``` any fenced code block
        3. Bare { ... } with balanced depth tracking

        JSON is parsed with strict=False so the LLM can embed raw newlines /
        tabs inside string values (e.g. a full HTML report inside a JSON
        field) without triggering the "Invalid control character" error.
        """
        import json as _json

        if isinstance(text, (dict, list)):
            return text, True
        if not isinstance(text, str) or not text:
            return "", False

        # Strategy 1: fenced ```json``` code block (highest reliability)
        import re
        code_block_pattern = re.compile(r"```(?:json)?\s*\n?(.*?)\n?```", re.DOTALL)
        for m in code_block_pattern.finditer(text):
            candidate = m.group(1).strip()
            if candidate.startswith("{") or candidate.startswith("["):
                try:
                    return _json.loads(candidate, strict=False), True
                except _json.JSONDecodeError:
                    pass  # try next block

        # Strategy 2: fenced ```...``` (any language)
        for m in code_block_pattern.finditer(text):
            candidate = m.group(1).strip()
            if "{" in candidate or "[" in candidate:
                try:
                    return _json.loads(candidate, strict=False), True
                except _json.JSONDecodeError:
                    pass

        # Strategy 3: balanced-brace depth scan on raw text
        depth = 0
        start = -1
        for i, ch in enumerate(text):
            if ch == "{" and start < 0:
                start, depth = i, 1
            elif ch == "{" and start >= 0:
                depth += 1
            elif ch == "}" and start >= 0:
                depth -= 1
                if depth == 0:
                    try:
                        return _json.loads(text[start:i + 1], strict=False), True
                    except _json.JSONDecodeError:
                        start = -1  # try to find another block
        return "", False

    def complete(self, prompt, formatted=False, max_retries: int = 3,
                 base_delay: float = 2.0, json_mode: bool = False,
                 _retry_default=None, **kwargs):
        """
        Call the LLM with application-level exponential-backoff retry
        and optional JSON extraction.

        json_mode=True: prepends a strict JSON-only system instruction so the
        model knows it must output only JSON (not markdown prose or commentary).
        Extraction retries up to max_retries before raising RuntimeError.
        """
        from llama_index.core.base.llms.types import CompletionResponse

        last_exc: Exception = RuntimeError("sentinel")

        # ── JSON-mode guardrail ────────────────────────────────────────────
        # When json_mode=True we inject a concise system instruction so the
        # model produces clean JSON even if the upstream API does not support
        # the native json_object response_format.
        _JSON_GUARD = (
            "IMPORTANT: You must respond with ONLY valid JSON. "
            "Do NOT include any text before or after the JSON. "
            "Do NOT wrap it in markdown fences. "
            "Return a single JSON object or array."
        )
        if json_mode and not prompt.startswith("System:"):
            prompt = f"System: {_JSON_GUARD}\n\n{prompt}"

        for attempt in range(1, max_retries + 1):
            try:
                last_exc = None  # clear on successful entry
                # Allow caller to override max_tokens per-call (e.g. for
                # Kimi report generation which needs a smaller cap to stay
                # under the upstream API rate limit).
                call_max_tokens = kwargs.get("max_tokens", self.max_tokens)
                response = self.client.chat.completions.create(
                    model=self._model_name,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=self.temperature,
                    max_tokens=call_max_tokens,
                    stream=False,
                    extra_body=_merge_extra_body(kwargs.get("extra_body")),
                )
                text = _extract_message_text(response.choices[0].message)

                if not json_mode:
                    return CompletionResponse(
                        text=text,
                        raw=response,
                        additional_kwargs={},
                        logprobs=None,
                    )

                # JSON extraction attempt
                parsed_json, ok = self._extract_json(text)
                if ok:
                    return CompletionResponse(
                        text=_json.dumps(parsed_json, ensure_ascii=False),
                        raw=response,
                        additional_kwargs={"_parsed_json": parsed_json},
                        logprobs=None,
                    )

                # No JSON found in this attempt
                if attempt < max_retries:
                    delay = min(base_delay * (2 ** (attempt - 1)), 60.0)
                    from utils.logger import logger
                    logger.warning(
                        f"[llm.complete] JSON extraction failed (attempt {attempt}/{max_retries}). "
                        f"Preview ({len(text)} chars): {text[:150]!r}  Retrying in {delay:.1f}s..."
                    )
                    time.sleep(delay)
                    continue
                else:
                    from utils.logger import logger
                    logger.error(
                        f"[llm.complete] JSON extraction failed after {max_retries} attempts. "
                        f"Preview: {text[:300]!r}"
                    )
                    if _retry_default is not None:
                        return CompletionResponse(
                            text=_json.dumps(_retry_default),
                            raw=response,
                            additional_kwargs={"_parsed_json": _retry_default,
                                               "_json_extract_failed": True},
                            logprobs=None,
                        )
                    raise RuntimeError(
                        f"llm.complete json_mode=True: no parseable JSON after {max_retries} attempts. "
                        f"Response preview: {text[:200]!r}"
                    )

            except Exception as e:
                last_exc = e  # always preserve the actual error
                if not self._is_retryable(e):
                    from utils.logger import logger
                    logger.warning(f"[llm.complete] Non-retryable error: {e}")
                    raise

                if attempt < max_retries:
                    delay = min(base_delay * (2 ** (attempt - 1)), 60.0)
                    from utils.logger import logger
                    logger.warning(
                        f"[llm.complete] Attempt {attempt}/{max_retries} failed ({e}). "
                        f"Retrying in {delay:.1f}s..."
                    )
                    time.sleep(delay)
                # else: fall through to raise below

        # last_exc is now either the real exception or None (all attempts succeeded)
        if last_exc is not None:
            raise last_exc

    def stream_complete(self, prompt, formatted=False, **kwargs):
        try:
            stream = self.client.chat.completions.create(
                model=self._model_name,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                stream=True,
                extra_body=_merge_extra_body(kwargs.get("extra_body")),
            )
            text_acc = ""
            for chunk in stream:
                if not chunk.choices:
                    continue
                delta = chunk.choices[0].delta
                added = _extract_delta_text(delta)
                if added:
                    text_acc += added
                    yield CompletionResponse(
                        text=text_acc,
                        delta=added,
                        raw=chunk,
                        additional_kwargs={},
                    )
        except Exception as e:
            err_str = str(e)
            if "timeout" in err_str.lower() or "timed out" in err_str.lower():
                raise RuntimeError(f"LLM stream timed out (check network/API latency): {e}") from e
            raise RuntimeError(f"LLM stream call failed: {e}") from e

    def chat(self, messages, **kwargs):
        try:
            openai_messages = []
            for msg in messages:
                if isinstance(msg, dict):
                    role = msg.get("role", "user")
                    content = msg.get("content", "")
                else:
                    role = msg.role.value if hasattr(msg.role, "value") else str(msg.role)
                    content = msg.content or ""
                openai_messages.append({"role": role, "content": content})

            response = self.client.chat.completions.create(
                model=self._model_name,
                messages=openai_messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                stream=False,
                extra_body=_merge_extra_body(kwargs.get("extra_body")),
            )
            msg_content = _extract_message_text(response.choices[0].message)
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
            # Bug fix 2026-09-13 (BUG-R67): previously every chat()
            # error was re-raised as ``"LLM chat timed out..."``,
            # regardless of the actual cause. That hid e.g.
            # authentication failures, model-not-found, or rate-limit
            # errors behind a misleading "timed out" message, making
            # network diagnostics confusing. Now we keep the original
            # exception class and only rephrase the message if the
            # cause really is a timeout — otherwise we re-raise the
            # original exception.
            err_str = str(e).lower()
            is_timeout = (
                "timeout" in err_str
                or "timed out" in err_str
                or "read timed out" in err_str
                or isinstance(e, (TimeoutError,))
            )
            if is_timeout:
                raise RuntimeError(f"LLM chat timed out (check network/API latency): {e}") from e
            raise

    def stream_chat(self, messages, **kwargs):
        try:
            openai_messages = []
            for msg in messages:
                if isinstance(msg, dict):
                    role = msg.get("role", "user")
                    content = msg.get("content", "")
                else:
                    role = msg.role.value if hasattr(msg.role, "value") else str(msg.role)
                    content = msg.content or ""
                openai_messages.append({"role": role, "content": content})

            stream = self.client.chat.completions.create(
                model=self._model_name,
                messages=openai_messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                stream=True,
                extra_body=_merge_extra_body(kwargs.get("extra_body")),
            )
            text_acc = ""
            for chunk in stream:
                if not chunk.choices:
                    continue
                delta = chunk.choices[0].delta
                added = _extract_delta_text(delta)
                if added:
                    text_acc += added
                    yield ChatResponse(
                        message=ChatMessage(
                            role=MessageRole.ASSISTANT,
                            content=text_acc,
                            additional_kwargs={},
                        ),
                        delta=added,
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
    temperature=DEFAULT_TEMP_REASONING,
    timeout=600.0,
    max_retries=3,
    max_tokens=8192,
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
            max_tokens=max_tokens,
        )

    return OpenAICompatibleLLM(
        model=model,
        api_key=api_key,
        base_url=base_url,
        temperature=temperature,
        timeout=timeout,
        max_retries=max_retries,
        max_tokens=max_tokens,
    )


def setup_llm_settings(
    model,
    api_key,
    base_url,
    temperature=DEFAULT_TEMP_REASONING,
    timeout=600.0,
    max_retries=3,
    max_tokens=8192,
):
    llm = create_llm(
        model=model,
        api_key=api_key,
        base_url=base_url,
        temperature=temperature,
        timeout=timeout,
        max_retries=max_retries,
        max_tokens=max_tokens,
    )

    # Bug fix 2026-09-13 (BUG-R66): previously every call to
    # ``setup_llm_settings`` registered a fresh TokenCountingHandler
    # in ``_GLOBAL_TOKEN_HANDLERS`` (module-level list) and never
    # cleaned up the old ones. Over the lifetime of a long-running
    # batch driver (17+ call sites in this codebase), the list grew
    # unboundedly — each handler holds accumulated token counts in
    # llama-index's TokenCountingHandler, so ``get_global_token_counter()``
    # returned the *sum across all past runs*, not the current run.
    # The chief_agent summary line then printed e.g. ``Tokens: 854,000``
    # after one batch that actually consumed 12,000.
    #
    # We now cap the registry at ``_MAX_TOKEN_HANDLERS`` (default 16)
    # by dropping the oldest entries on overflow, which bounds both
    # the memory footprint and the historic-token accumulation.
    token_counter = build_token_counter()
    _GLOBAL_TOKEN_HANDLERS.append(token_counter)
    if len(_GLOBAL_TOKEN_HANDLERS) > _MAX_TOKEN_HANDLERS:
        # Drop oldest entries first (FIFO). The list is treated as
        # bounded: keep at most the last ``_MAX_TOKEN_HANDLERS``.
        del _GLOBAL_TOKEN_HANDLERS[:-_MAX_TOKEN_HANDLERS]

    Settings.llm = llm
    Settings.callback_manager = CallbackManager([token_counter])
    token_counter.reset_counts()

    return llm, token_counter


_MAX_TOKEN_HANDLERS = 16
