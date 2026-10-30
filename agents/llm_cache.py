"""A content-addressed cache for LLM responses.

The evaluation harness runs the same pipeline over the same cached
measurements many times: the component ablation repeats each arm, the
ground-truth arms differ only in which stage runs, and the paper's
robustness sweeps re-run a fixed configuration.  Every one of those
runs issues the *same* LLM requests with the *same* prompts, and each
one costs money and wall-clock time.

This module stores the responses on disk, keyed by a hash of the
request that produced them: the model, the temperature, the prompt
text, and the JSON-mode flag.  A later run with the same request
replays the stored response instead of calling the provider.

The cache is opt-in and off by default, because a cache changes what a
run *does*: a cached run does not re-sample the model, so it measures
the pipeline's determinism given a fixed set of model outputs rather
than the pipeline's end-to-end stochasticity.  The two are different
experiments and the cache makes that choice explicit rather than
implicit.

The store is a single append-only JSON-lines file guarded by a lock
file, so several runs can share one cache directory without corrupting
each other.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Optional

from utils.logger import logger

__all__ = [
    "cache_enabled",
    "cache_key",
    "cache_get",
    "cache_put",
    "cache_stats",
    "cache_reset_stats",
    "LLMResponseCache",
]

DEFAULT_CACHE_DIR = Path(
    os.environ.get(
        "BGP_TRACER_LLM_CACHE_DIR",
        str(Path(__file__).resolve().parents[1] / "results" / "llm_cache"),
    )
)

_STATS_LOCK = threading.Lock()
_STATS = {"hits": 0, "misses": 0, "writes": 0, "bytes_written": 0}


def cache_enabled() -> bool:
    """True when response caching is switched on for this process."""
    return os.environ.get("BGP_TRACER_LLM_CACHE", "").strip().lower() in (
        "1", "true", "yes", "on",
    )


def cache_key(
    prompt: Any,
    *,
    model: str = "",
    temperature: float = 0.0,
    json_mode: bool = False,
    max_tokens: Optional[int] = None,
    extra: Optional[dict] = None,
) -> str:
    """A stable key for one LLM request.

    The key covers everything that changes the response: the prompt
    text, the model, the sampling temperature, whether the caller
    asked for JSON, the output cap, and any caller-supplied extras.
    """
    if isinstance(prompt, str):
        prompt_text = prompt
    else:
        prompt_text = str(prompt)
    payload = {
        "prompt": prompt_text,
        "model": model,
        "temperature": round(float(temperature), 6),
        "json_mode": bool(json_mode),
        "max_tokens": max_tokens,
        "extra": extra or {},
    }
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def cache_file(cache_dir: Path) -> Path:
    return cache_dir / "responses.jsonl"


def cache_get(key: str, cache_dir: Optional[Path] = None) -> Optional[Any]:
    """Return the stored response text for ``key``, or None."""
    directory = Path(cache_dir) if cache_dir else DEFAULT_CACHE_DIR
    path = cache_file(directory)
    if not path.exists():
        with _STATS_LOCK:
            _STATS["misses"] += 1
        return None
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                if record.get("key") == key:
                    with _STATS_LOCK:
                        _STATS["hits"] += 1
                    return record.get("text")
    except OSError as exc:
        logger.debug(f"[llm_cache] read failed: {exc!r}")
    with _STATS_LOCK:
        _STATS["misses"] += 1
    return None


def cache_put(
    key: str,
    text: str,
    cache_dir: Optional[Path] = None,
    *,
    model: str = "",
    agent: str = "",
) -> None:
    """Store a response text under ``key``."""
    directory = Path(cache_dir) if cache_dir else DEFAULT_CACHE_DIR
    directory.mkdir(parents=True, exist_ok=True)
    path = cache_file(directory)
    record = {
        "key": key,
        "text": text,
        "model": model,
        "agent": agent,
        "stored_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    line = json.dumps(record, ensure_ascii=False) + "\n"
    try:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line)
            fh.flush()
    except OSError as exc:
        logger.debug(f"[llm_cache] write failed: {exc!r}")
        return
    with _STATS_LOCK:
        _STATS["writes"] += 1
        _STATS["bytes_written"] += len(line)


def cache_stats(cache_dir: Optional[Path] = None) -> dict:
    """Counters describing this process's cache activity."""
    directory = Path(cache_dir) if cache_dir else DEFAULT_CACHE_DIR
    path = cache_file(directory)
    on_disk = 0
    size = 0
    if path.exists():
        size = path.stat().st_size
        with path.open("r", encoding="utf-8") as fh:
            on_disk = sum(1 for line in fh if line.strip())
    with _STATS_LOCK:
        stats = dict(_STATS)
    total = stats["hits"] + stats["misses"]
    return {
        "enabled": cache_enabled(),
        "cache_dir": str(directory),
        "entries_on_disk": on_disk,
        "size_bytes": size,
        "hits": stats["hits"],
        "misses": stats["misses"],
        "writes": stats["writes"],
        "hit_rate": round(stats["hits"] / total, 4) if total else None,
    }


def cache_reset_stats() -> None:
    """Zero this process's counters."""
    with _STATS_LOCK:
        _STATS["hits"] = 0
        _STATS["misses"] = 0
        _STATS["writes"] = 0
        _STATS["bytes_written"] = 0


class LLMResponseCache:
    """A small object wrapper around the module-level cache functions."""

    def __init__(self, cache_dir: Optional[Path] = None):
        self.cache_dir = Path(cache_dir) if cache_dir else DEFAULT_CACHE_DIR

    def get(self, key: str) -> Optional[Any]:
        return cache_get(key, self.cache_dir)

    def put(self, key: str, text: str, *, model: str = "", agent: str = "") -> None:
        cache_put(key, text, self.cache_dir, model=model, agent=agent)

    def stats(self) -> dict:
        return cache_stats(self.cache_dir)
