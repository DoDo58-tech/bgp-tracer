import json as _json
import os
import time
from pathlib import Path
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
    """Extract visible assistant output from a streamed choice delta.

    Always returns only the ``content`` field — the visible answer.

    ``reasoning_content`` (the model's internal thinking trace) is NEVER
    returned. This is essential for thinking models (S1-Base-Pro, Kimi
    with thinking enabled, GLM-5) where the API streams the reasoning
    trace and the visible answer as separate delta fields. The original
    behaviour of appending both caused the thinking process to leak into
    the visible HTML report output, which then triggered the deterministic
    fallback renderer (BUG-R128, observed 2026-09-16).

    For models that route everything through ``reasoning_content`` (rare
    Kimi configurations), the report caller should set
    ``LLM_THINKING_DISABLE`` to disable thinking mode so output flows
    through ``content`` instead.
    """
    if delta is None:
        return ""
    # Primary field: content (the visible answer).
    # Reasoning content is intentionally ignored.
    c = getattr(delta, "content", None)
    return str(c) if c else ""


def build_token_counter():
    try:
        enc = tiktoken.get_encoding("cl100k_base")
        handler = TokenCountingHandler(tokenizer=enc.encode)
    except Exception:
        handler = TokenCountingHandler(tokenizer=lambda s: list(s.encode("utf-8")))
    register_token_counter(handler)
    return handler


# ── Process-wide token counter (Bug fix: react path was reporting N/A) ─────
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


def _extract_usage_from_response(response) -> tuple[int, int]:
    """Best-effort extraction of (prompt_tokens, completion_tokens) from a
    raw OpenAI / OpenAI-compatible response object.

    OpenAI-compatible APIs always populate ``response.usage`` on
    non-streaming chat/completion calls. The OpenAI SDK exposes this as
    either:
      - response.usage.prompt_tokens / completion_tokens
      - response.usage.input_tokens / output_tokens (newer schema)
      - response.usage.total_tokens (fallback, minus completion)
    Returns (0, 0) when the field is missing or unreadable.
    """
    if response is None:
        return 0, 0
    usage = getattr(response, "usage", None)
    if usage is None:
        return 0, 0
    # Newer OpenAI schema (input/output tokens).
    try:
        pt = int(getattr(usage, "input_tokens", 0) or 0)
        ct = int(getattr(usage, "output_tokens", 0) or 0)
        if pt or ct:
            return pt, ct
    except Exception:
        pass
    # Standard schema (prompt/completion tokens).
    try:
        pt = int(getattr(usage, "prompt_tokens", 0) or 0)
        ct = int(getattr(usage, "completion_tokens", 0) or 0)
        if pt or ct:
            return pt, ct
    except Exception:
        pass
    # Fallback: total_tokens - completion when only totals reported.
    try:
        total = int(getattr(usage, "total_tokens", 0) or 0)
        ct = int(getattr(usage, "completion_tokens", 0) or 0)
        if total and ct:
            return total - ct, ct
    except Exception:
        pass
    return 0, 0


def _record_token_usage_to_budget(response, agent_name: str = "OpenAICompatibleLLM") -> None:
    """Record (prompt_tokens, completion_tokens) into every TokenBudget
    instance in ``_GLOBAL_TOKEN_HANDLERS``.

    The OpenAI client returns ``response.usage`` but LlamaIndex's
    TokenCountingHandler callbacks never fire for our ``chat``/
    ``complete`` wrappers because we go straight to ``self.client.``
    bypassing the callback pipeline. This function is the
    reconciliation step that keeps the global counter in sync.
    """
    pt, ct = _extract_usage_from_response(response)
    if not (pt or ct):
        return
    for h in list(_GLOBAL_TOKEN_HANDLERS):
        try:
            # TokenCountingEvent requires (prompt, completion) strings
            # plus (prompt_token_count, completion_token_count) ints.
            from llama_index.core.callbacks.token_counting import (
                TokenCountingEvent,
            )
            # Synthesize strings from token counts so the dataclass
            # accepts them; the token-count fields are what the handler
            # sums via ``total_llm_token_count``.
            event = TokenCountingEvent(
                prompt=" " * pt,
                completion=" " * ct,
                prompt_token_count=pt,
                completion_token_count=ct,
                total_token_count=pt + ct,
            )
            # The handler exposes ``llm_token_counts`` (a list) and
            # ``prompt_llm_token_count`` / ``completion_llm_token_count``
            # / ``total_llm_token_count`` properties that sum the list.
            if hasattr(h, "llm_token_counts"):
                h.llm_token_counts.append(event)
        except Exception:
            continue


def reset_global_token_counter() -> None:
    """Reset every registered handler's counter."""
    for h in list(_GLOBAL_TOKEN_HANDLERS):
        try:
            h.reset_counts()
        except Exception:
            continue


# ── 429 Rate-Limit Circuit Breaker ──────────────────────────────────────────
import threading
import collections


class LLMRateLimitedError(RuntimeError):
    """Raised when the rate-limit circuit breaker is open.

    Carries the original exception as ``__cause__`` and a structured
    ``breaker_info`` dict for the caller to log/fallback on.
    """

    def __init__(self, message: str, breaker_info: dict | None = None):
        super().__init__(message)
        self.breaker_info = breaker_info or {}


class _RateLimitBreaker:
    """Process-wide rolling-window circuit breaker for HTTP 429 responses."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # Deque of timestamps (monotonic seconds) at which a 429 was seen.
        self._hits: collections.deque[float] = collections.deque()
        # When the breaker tripped (0.0 means closed). Used by is_open()
        self._tripped_at: float = 0.0
        # Monotonic time at which the cool-off expires.
        self._cooldown_until: float = 0.0

    @staticmethod
    def _now() -> float:
        import time as _t
        return _t.monotonic()

    def record_hit(self) -> None:
        """Record a 429. Returns True if the breaker just tripped open.

        Two state transitions:
          - Hit count reaches ``threshold``: trip the breaker. New calls
            are blocked (``is_open() == True``) until cool-off elapses.
          - Hit count stays below ``threshold``: apply a short soft
            cool-off to throttle retries, but don't trip the breaker
            (callers can still attempt after a few seconds).
        """
        now = self._now()
        window = float(os.environ.get("LLM_429_BREAKER_WINDOW_S", "60"))
        base_cooldown = float(os.environ.get("LLM_429_COOLDOWN_S", "5.0"))
        threshold = int(os.environ.get("LLM_429_BREAKER_THRESHOLD", "3"))
        with self._lock:
            self._hits.append(now)
            # Drop hits outside the rolling window.
            cutoff = now - window
            while self._hits and self._hits[0] < cutoff:
                self._hits.popleft()
            if len(self._hits) >= threshold and self._tripped_at == 0.0:
                # Just-tripped: exponential cool-off based on overshoot
                cooldown = min(
                    base_cooldown * (2 ** (len(self._hits) - threshold)),
                    60.0,
                )
                self._tripped_at = now
                self._cooldown_until = now + cooldown
                return True
            # Below threshold or already tripped — apply soft throttle.
            self._cooldown_until = now + base_cooldown
            return False

    def is_open(self) -> tuple[bool, float]:
        """Return (open?, seconds_remaining_until_closed).

        Only True when the breaker has TRIPPED (not just throttled).
        """
        now = self._now()
        with self._lock:
            if self._tripped_at == 0.0 or now >= self._cooldown_until:
                # Auto-recover: tripped-but-cooldown-elapsed → reset trip flag.
                if self._tripped_at != 0.0 and now >= self._cooldown_until:
                    self._tripped_at = 0.0
                    self._hits.clear()
                return False, 0.0
            return True, self._cooldown_until - now

    def get_window_hits(self) -> int:
        now = self._now()
        window = float(os.environ.get("LLM_429_BREAKER_WINDOW_S", "60"))
        with self._lock:
            cutoff = now - window
            while self._hits and self._hits[0] < cutoff:
                self._hits.popleft()
            return len(self._hits)

    def reset(self) -> None:
        """Force-clear the breaker (test/admin helper)."""
        with self._lock:
            self._hits.clear()
            self._cooldown_until = 0.0


# Module-level singleton; shared across every OpenAICompatibleLLM instance
_RATE_LIMIT_BREAKER = _RateLimitBreaker()


class BudgetExhausted(Exception):
    """Raised when the LLM request budget (e.g. GLM-5 1000/5h) is exhausted.

    Unlike 429 (which means "back off and retry"), this means "you have
    used your allocation — stop requesting and report the failure to the caller."
    """
    pass


class _BudgetTracker:
    """Rolling-window request budget tracker for API providers with hard
    per-window quotas (e.g. GLM-5 on sfkey.cn: ~1000 requests / 5 hours).

    Strategy:
      1. Every LLM call (complete / chat) is recorded with its timestamp.
      2. Before making a new call, we check:
         - If window hits ≥ budget max → raise BudgetExhausted
         - If window hits ≥ budget *warning_fraction → log a WARNING
      3. Window is rolling (timestamps older than window are dropped).
      4. If BudgetExhausted is raised, the caller gets a clean failure
         instead of a useless 429 that wastes a request slot.

    Usage in the calling code::

        budget = get_budget_tracker()
        budget.check_and_record()
        # or
        budget.record_call()  # record after a successful call
        remaining, total = budget.remaining_budget()

    Tunable via env vars:
      LLM_BUDGET_MAX_CALLS  (default 950)   max calls in the window (5% headroom)
      LLM_BUDGET_WINDOW_S   (default 18000) rolling window = 5 hours
      LLM_BUDGET_WARN_AT    (default 0.80) warning threshold fraction
      LLM_BUDGET_SHARED_FILE (default empty) — path to a shared file that
                              persists call timestamps across subprocesses.
                              When set, the tracker appends new call
                              timestamps to the file and reads them back
                              on construction. Used by the 4-mode batch
                              driver so each chief_agent subprocess
                              respects the running total.

    Cross-process semantics with LLM_BUDGET_SHARED_FILE:
      - Each subprocess reads the file at construction (loads all
        timestamps into the deque).
      - Each subprocess appends to the file on every call (with flock
        so concurrent appends don't corrupt).
      - The deque and file stay in sync within one process; the
        budget check uses both, taking the larger used count as
        the source of truth.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()  # reentrant: _append_shared is
        # called from inside check_and_record which already holds _lock
        self._calls: collections.deque[float] = collections.deque()
        self._warned: bool = False  # only warn once per window
        self._now_mono = __import__("time").monotonic
        self._now_wall = __import__("time").time
        self._shared_path: str = os.environ.get("LLM_BUDGET_SHARED_FILE", "").strip()
        self._mono_to_wall_offset: float = self._now_wall() - self._now_mono()
        if self._shared_path:
            self._load_shared()

    def _load_shared(self) -> None:
        """Load historical call timestamps from the shared file.

        File format: one timestamp per line (wall-clock seconds).
        Convert to monotonic seconds so the deque comparison works
        against the local monotonic clock.
        """
        try:
            p = Path(self._shared_path)
            if not p.exists():
                p.parent.mkdir(parents=True, exist_ok=True)
                p.touch()
                return
            now_mono = self._now_mono()
            cutoff_wall = self._now_wall() - float(self._env("BUDGET_WINDOW_S", 18000, float))
            with open(p, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ts_wall = float(line)
                        if ts_wall < cutoff_wall:
                            continue  # outside window
                        # Convert wall-clock → monotonic for deque storage
                        ts_mono = now_mono - (self._now_wall() - ts_wall)
                        self._calls.append(ts_mono)
                    except ValueError:
                        pass
        except Exception:
            # Don't crash if file is unreadable; budget check will just
            # be conservative (only count in-process calls).
            self._calls.clear()

    def _append_shared(self, ts_mono: float) -> None:
        """Append a monotonic timestamp to the shared file as wall-clock.

        To prevent the file from growing unbounded, periodically rotate it:
        rewrite the file with only the timestamps inside the current window.
        Rotation happens on every Nth append (default N=50).
        """
        if not self._shared_path:
            return
        try:
            ts_wall = self._now_wall() - (self._now_mono() - ts_mono)
            with open(self._shared_path, "a") as f:
                f.write(f"{ts_wall:.6f}\n")

            # Rotate every N appends to bound file size. We use a file lock
            rotate_every = int(os.environ.get("LLM_BUDGET_ROTATE_EVERY", "50"))
            with self._lock:
                self._append_count = getattr(self, "_append_count", 0) + 1
                if self._append_count % rotate_every == 0:
                    self._rotate_shared()
        except Exception:
            # Don't fail the LLM call just because the budget file
            pass

    def _rotate_shared(self) -> None:
        """Rewrite the shared file to contain only timestamps in the window.

        Best-effort: on any failure, the file is left as-is and the next
        rotation will retry. We deliberately avoid touching the in-memory
        deque here — rotation is purely a file-side cleanup.
        """
        try:
            cutoff_wall = self._now_wall() - float(self._env("BUDGET_WINDOW_S", 18000, float))
            keep = []
            with open(self._shared_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ts = float(line)
                        if ts >= cutoff_wall:
                            keep.append(f"{ts:.6f}\n")
                    except ValueError:
                        pass
            # Atomic write: write to temp, then rename
            tmp = self._shared_path + ".tmp"
            with open(tmp, "w") as f:
                f.writelines(keep)
            os.replace(tmp, self._shared_path)
        except Exception:
            pass

    @staticmethod
    def _env(key: str, default: float | int, dtype=float) -> float | int:
        return dtype(os.environ.get(f"LLM_{key}", str(default)))

    def _window_len(self) -> int:
        now_mono = self._now_mono()
        window_s = float(self._env("BUDGET_WINDOW_S", 18000, float))
        cutoff = now_mono - window_s
        while self._calls and self._calls[0] < cutoff:
            self._calls.popleft()
        return len(self._calls)

    def remaining_budget(self) -> tuple[int, int]:
        """Return (remaining_calls, max_calls)."""
        used = self._window_len()
        max_calls = int(self._env("BUDGET_MAX_CALLS", 950, int))
        return max(0, max_calls - used), max_calls

    def check_and_record(self) -> None:
        """Check budget; if OK, record this call. Raises BudgetExhausted."""
        used = self._window_len()
        max_calls = int(self._env("BUDGET_MAX_CALLS", 950, int))
        warn_at = float(self._env("BUDGET_WARN_AT", 0.80, float))
        remaining = max(0, max_calls - used)

        if used >= max_calls:
            raise BudgetExhausted(
                f"LLM budget exhausted: {used}/{max_calls} calls used in the "
                f"{self._env('BUDGET_WINDOW_S', 18000, int)}s window. "
                f"Increase LLM_BUDGET_MAX_CALLS or wait for the window to rotate."
            )

        if not self._warned and used >= int(max_calls * warn_at):
            self._warned = True
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(
                f"LLM budget at {used}/{max_calls} calls "
                f"({100 * used / max_calls:.0f}% used, {remaining} remaining). "
                f"Current provider: GLM-5 / sfkey.cn (1000/5h). "
                f"Remaining capacity for ~{remaining} more LLM calls before BudgetExhausted."
            )

        # Record this call
        with self._lock:
            ts_mono = self._now_mono()
            self._calls.append(ts_mono)
            self._append_shared(ts_mono)
            self._warned = False  # reset warning flag when window rolls

    def record_call(self) -> None:
        """Record a call (for callers who want to call separately from check)."""
        with self._lock:
            ts_mono = self._now_mono()
            self._calls.append(ts_mono)
            self._append_shared(ts_mono)
            self._warned = False

    def reset(self) -> None:
        """Clear all records (admin / test helper)."""
        with self._lock:
            self._calls.clear()
            self._warned = False


_BUDGET_TRACKER = _BudgetTracker()


def get_budget_tracker() -> _BudgetTracker:
    """Return the process-wide budget tracker singleton."""
    return _BUDGET_TRACKER


def get_rate_limit_breaker() -> _RateLimitBreaker:
    """Return the process-wide rate-limit circuit breaker (for diagnostics)."""
    return _RATE_LIMIT_BREAKER


class OpenAICompatibleLLM(LLM):
    """OpenAI-compatible LLM wrapper for DeepSeek, Qwen, and other compatible models."""

    model_config = {"arbitrary_types_allowed": True}

    def __init__(
        self,
        model,
        api_key,
        base_url,
        temperature=DEFAULT_TEMP_REASONING,
        timeout=600.0,
        max_retries=3,
        max_tokens=8192,
        callback_manager=None,
    ):
        super().__init__(callback_manager=callback_manager)
        object.__setattr__(self, '_model_name', model)
        object.__setattr__(self, 'api_key', api_key)
        object.__setattr__(self, 'base_url', base_url)
        # Some endpoints (e.g. Kimi kimi-for-coding) only accept a single
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
            report_llm_timeout = float(os.environ.get("REPORT_LLM_TIMEOUT_S", "180.0"))
            read_cap = float(os.environ.get("LLM_READ_TIMEOUT", "0"))  # 0 = no cap
            if read_cap <= 0:
                # No cap: use the larger of request_timeout and report timeout + 60s buffer.
                effective_read = min(
                    max(request_timeout, report_llm_timeout + 60.0),
                    report_llm_timeout + 30.0,
                )
            else:
                effective_read = max(min(request_timeout, read_cap), 30.0)
            timeout = httpx.Timeout(
                connect=min(10.0, request_timeout),
                read=effective_read,
                write=min(10.0, request_timeout),
                pool=min(10.0, request_timeout),
            )

            # Bug fix 2026-09-14 (BUG-R200): the OpenAI SDK retries on
            sdk_max_retries = 0

            self._client = OAI(
                api_key=self.api_key,
                base_url=self.base_url,
                timeout=timeout,
                max_retries=sdk_max_retries,
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
                if code == 429:
                    # Bug fix 2026-09-14 (BUG-R200): previously 429 was
                    return False
                if code in (500, 502, 503, 504):
                    return True
        except Exception:
            pass
        kw = [
            "500", "502", "503", "504",
            "connection", "timeout", "timed out", "network",
            "temporarily unavailable", "service unavailable",
            "internal server error", "gateway timeout", "bad gateway",
            "upstream connect error", "socket timeout",
        ]
        # NOTE: "429" and "rate limit" are deliberately removed from the
        return any(k in err_lower for k in kw)

    @staticmethod
    def _is_rate_limit_error(exc: Exception) -> bool:
        """Return True iff this exception represents an upstream 429."""
        try:
            status = getattr(exc, "response", None)
            if status is not None and getattr(status, "status_code", None) == 429:
                return True
        except Exception:
            pass
        err_lower = str(exc).lower()
        return "429" in err_lower or "rate limit" in err_lower

    @staticmethod
    def _breaker_guard():
        """Raise ``LLMRateLimitedError`` immediately if the breaker is open.

        Returning a value (None) means "proceed with the call". Used at
        the top of every call site to short-circuit doomed requests.
        """
        is_open, remaining = _RATE_LIMIT_BREAKER.is_open()
        if is_open:
            raise LLMRateLimitedError(
                f"LLM rate-limit circuit breaker is open "
                f"({remaining:.1f}s remaining, "
                f"{_RATE_LIMIT_BREAKER.get_window_hits()} hits in window). "
                f"Failing fast so the caller can render the fallback report.",
                breaker_info={
                    "cooldown_remaining_s": round(remaining, 2),
                    "window_hits": _RATE_LIMIT_BREAKER.get_window_hits(),
                },
            )

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

        Bug fix 2026-09-14 (BUG-R200): HTTP 429 (rate limit) is no longer
        retried by the application layer. Instead, every 429 hit is
        recorded into a process-wide rate-limit circuit breaker, which
        short-circuits subsequent calls in the cool-off window with a
        dedicated ``LLMRateLimitedError``. The caller can then render the
        deterministic fallback HTML instead of hanging on a doomed retry
        chain that would otherwise drag the subprocess past the 900s
        orchestration timeout.
        """
        from llama_index.core.base.llms.types import CompletionResponse
        # ── Budget tracker guard (entry) ───────────────────────────────
        from llm.llm_factory import get_budget_tracker, BudgetExhausted
        try:
            get_budget_tracker().check_and_record()
        except BudgetExhausted:
            raise


        # ── Circuit breaker guard (entry) ─────────────────────────────────
        self._breaker_guard()

        last_exc: Exception = RuntimeError("sentinel")

        # ── JSON-mode guardrail ────────────────────────────────────────────
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
                call_max_tokens = kwargs.get("max_tokens", self.max_tokens)
                # Bug fix 2026-09-14 (BUG-R200 corollary): the OpenAI SDK
                response = self.client.chat.completions.create(
                    model=self._model_name,
                    messages=[{"role": "user", "content": prompt}],
                    temperature=self.temperature,
                    max_tokens=call_max_tokens,
                    stream=False,
                    extra_body=_merge_extra_body(kwargs.get("extra_body")),
                    # Disable SDK-level retries so we own the retry budget
                )
                text = _extract_message_text(response.choices[0].message)

                # Bug fix 2026-10-08 (TokenCount-not-firing): feed the
                # usage back into the global handler because we bypassed
                # LlamaIndex's callback pipeline.
                try:
                    _record_token_usage_to_budget(response, agent_name="llm.complete")
                except Exception:
                    pass

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
                # Rate-limit specific path: record into the breaker so
                if self._is_rate_limit_error(e):
                    tripped = _RATE_LIMIT_BREAKER.record_hit()
                    if tripped:
                        from utils.logger import logger
                        is_open, remaining = _RATE_LIMIT_BREAKER.is_open()
                        logger.error(
                            f"[llm.complete] Rate-limit circuit breaker TRIPPED "
                            f"({_RATE_LIMIT_BREAKER.get_window_hits()} 429s in window). "
                            f"Cooldown {remaining:.1f}s. Failing fast."
                        )
                    else:
                        from utils.logger import logger
                        logger.warning(
                            f"[llm.complete] 429 hit recorded "
                            f"({_RATE_LIMIT_BREAKER.get_window_hits()} in window). "
                            f"Raising immediately (no application-level retry)."
                        )
                    # Always raise on 429 — no application-level retry.
                    raise

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
        # Bug fix 2026-09-14 (BUG-R200): check the rate-limit circuit
        from llm.llm_factory import get_budget_tracker, BudgetExhausted
        try:
            get_budget_tracker().check_and_record()
        except BudgetExhausted:
            raise

        self._breaker_guard()
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
            if self._is_rate_limit_error(e):
                tripped = _RATE_LIMIT_BREAKER.record_hit()
                if tripped:
                    from utils.logger import logger
                    logger.error(
                        f"[llm.stream_complete] Rate-limit circuit breaker TRIPPED "
                        f"({_RATE_LIMIT_BREAKER.get_window_hits()} 429s in window)."
                    )
                raise LLMRateLimitedError(
                    f"LLM stream hit 429 rate limit: {e}",
                    breaker_info={
                        "window_hits": _RATE_LIMIT_BREAKER.get_window_hits(),
                    },
                ) from e
            err_str = str(e)
            if "timeout" in err_str.lower() or "timed out" in err_str.lower():
                raise RuntimeError(f"LLM stream timed out (check network/API latency): {e}") from e
            raise RuntimeError(f"LLM stream call failed: {e}") from e

    def chat(self, messages, **kwargs):
        # Bug fix 2026-09-14 (BUG-R200): check the rate-limit circuit
        from llm.llm_factory import get_budget_tracker, BudgetExhausted
        try:
            get_budget_tracker().check_and_record()
        except BudgetExhausted:
            raise

        self._breaker_guard()
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
            # Bug fix 2026-10-08 (TokenCount-not-firing): the OpenAI
            # wrapper bypasses LlamaIndex's callback pipeline so
            # TokenCountingHandler never sees the response. Feed the
            # usage back into the handler explicitly.
            try:
                _record_token_usage_to_budget(response, agent_name="llm.chat")
            except Exception:
                pass
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
            if self._is_rate_limit_error(e):
                tripped = _RATE_LIMIT_BREAKER.record_hit()
                if tripped:
                    from utils.logger import logger
                    logger.error(
                        f"[llm.chat] Rate-limit circuit breaker TRIPPED "
                        f"({_RATE_LIMIT_BREAKER.get_window_hits()} 429s in window)."
                    )
                raise LLMRateLimitedError(
                    f"LLM chat hit 429 rate limit: {e}",
                    breaker_info={
                        "window_hits": _RATE_LIMIT_BREAKER.get_window_hits(),
                    },
                ) from e
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
        # Budget tracker guard (entry) — check rolling-window budget
        from llm.llm_factory import get_budget_tracker, BudgetExhausted
        try:
            get_budget_tracker().check_and_record()
        except BudgetExhausted:
            raise

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

    if any(x in model_lower for x in ["deepseek", "qwq", "qwen", "gpt", "claude", "s1", "glm", "glm-4", "glm-5", "kimi"]):
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
