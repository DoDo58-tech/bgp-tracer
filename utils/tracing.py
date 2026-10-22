"""Structured tracing + metrics for bgp_tracer.

Why this module exists
======================

Production debugging of multi-stage pipelines is hard when:
  - per-stage latency is buried in free-form log strings,
  - token/cost attribution is opaque (which LLM call spent what?),
  - failure root-causes are guesswork.

This module wraps every stage in a context manager that records
``start``, ``end``, ``elapsed_s``, ``tokens_in``, ``tokens_out``, and
emits a single line per stage. A ``MetricsRegistry`` collects every
event in-memory and exposes a ``to_dict()`` for serialisation next to
the report JSON.

Usage::

    from utils.tracing import stage, metrics

    with stage("workflow.run", event_asn=event.asn) as ctx:
        result = run_workflow(...)
        ctx.tokens_in += sum(call.tokens for call in llm_calls)

    metrics.save(Path("results/json/event_metrics.json"))
"""

from __future__ import annotations

import json
import os
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from utils.logger import logger

__all__ = ["stage", "metrics", "StageEvent", "MetricsRegistry"]


@dataclass
class StageEvent:
    """One executed stage. Serialises cleanly with ``dataclasses.asdict``."""

    name: str
    start_ts: float
    end_ts: float = 0.0
    elapsed_s: float = 0.0
    tokens_in: int = 0
    tokens_out: int = 0
    attrs: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    @property
    def is_error(self):
        return self.error is not None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "start_ts": self.start_ts,
            "end_ts": self.end_ts,
            "elapsed_s": round(self.elapsed_s, 4),
            "tokens_in": self.tokens_in,
            "tokens_out": self.tokens_out,
            "attrs": self.attrs,
            "error": self.error,
        }


class MetricsRegistry:
    """Thread-safe in-memory store of stage events."""

    def __init__(self):
        self._events: list[StageEvent] = []
        self._lock = threading.Lock()

    def record(self, event):
        with self._lock:
            self._events.append(event)

    def all(self) -> list[StageEvent]:
        with self._lock:
            return list(self._events)

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            events = [e.to_dict() for e in self._events]
        # Aggregate by stage name for one-glance dashboards.
        by_name: dict[str, dict[str, Any]] = {}
        total_in = total_out = 0
        for e in events:
            agg = by_name.setdefault(
                e["name"],
                {
                    "count": 0,
                    "errors": 0,
                    "elapsed_s_total": 0.0,
                    "elapsed_s_max": 0.0,
                    "tokens_in": 0,
                    "tokens_out": 0,
                },
            )
            agg["count"] += 1
            if e["error"]:
                agg["errors"] += 1
            agg["elapsed_s_total"] += e["elapsed_s"]
            agg["elapsed_s_max"] = max(agg["elapsed_s_max"], e["elapsed_s"])
            agg["tokens_in"] += e["tokens_in"]
            agg["tokens_out"] += e["tokens_out"]
            total_in += e["tokens_in"]
            total_out += e["tokens_out"]
        # Round once at the end.
        for agg in by_name.values():
            agg["elapsed_s_total"] = round(agg["elapsed_s_total"], 4)
            agg["elapsed_s_max"] = round(agg["elapsed_s_max"], 4)
        return {
            "event_count": len(events),
            "tokens_in_total": total_in,
            "tokens_out_total": total_out,
            "by_stage": by_name,
            "events": events,
        }

    def save(self, path):
        """Persist as JSON next to the report."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
        logger.info(f"[tracing] saved metrics to {path}")

    def reset(self):
        with self._lock:
            self._events.clear()


# ── Module-level singleton ────────────────────────────────────────────────
metrics = MetricsRegistry()


# ── Public context manager ────────────────────────────────────────────────
@contextmanager
def stage(name: str, **attrs: Any) -> Iterator["_StageHandle"]:
    """Wrap a block as a tracked stage.

    ``ctx.tokens_in`` and ``ctx.tokens_out`` may be mutated by the caller
    as additional LLM calls happen inside the stage.
    """
    started = time.monotonic()
    handle = _StageHandle(name=name, start_ts=started, attrs=dict(attrs))
    try:
        yield handle
    except Exception as exc:  # noqa: BLE001 — re-raise after recording.
        handle.error = repr(exc)
        raise
    finally:
        handle.end_ts = time.monotonic()
        handle.elapsed_s = handle.end_ts - handle.start_ts
        metrics.record(handle._to_event())
        # Single-line log per stage: ``stage=name elapsed=12.34s tokens_in=2000``
        log_line = (
            f"[tracing] stage={handle.name!s} "
            f"elapsed={handle.elapsed_s:.2f}s "
            f"tokens_in={handle.tokens_in} tokens_out={handle.tokens_out}"
        )
        if handle.error:
            log_line += f" ERROR={handle.error!r}"
            logger.error(log_line)
        else:
            logger.info(log_line)


class _StageHandle:
    """Lightweight handle passed to the ``with stage(...)`` block."""

    __slots__ = ("name", "start_ts", "end_ts", "elapsed_s",
                 "tokens_in", "tokens_out", "attrs", "error")

    def __init__(
        self,
        name: str,
        start_ts: float,
        attrs: dict[str, Any],
    ) -> None:
        self.name = name
        self.start_ts = start_ts
        self.end_ts = 0.0
        self.elapsed_s = 0.0
        self.tokens_in = 0
        self.tokens_out = 0
        self.attrs = attrs
        self.error: str | None = None

    def add_tokens(self, in_tok=0, out_tok=0):
        self.tokens_in += int(in_tok)
        self.tokens_out += int(out_tok)

    def _to_event(self):
        return StageEvent(
            name=self.name,
            start_ts=self.start_ts,
            end_ts=self.end_ts,
            elapsed_s=self.elapsed_s,
            tokens_in=self.tokens_in,
            tokens_out=self.tokens_out,
            attrs=self.attrs,
            error=self.error,
        )


# ── Auto-save on metrics registry flush ───────────────────────────────────
def maybe_autosave(directory, slug):
    """Write a metrics snapshot if the env var points at a directory."""
    if not directory:
        return None
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{slug}_metrics.json"
    metrics.save(path)
    return path


# ── Env hook for tests: paranoid mode records every stage to a temp file ─
if os.environ.get("BGP_TRACER_TRACING_PARANOID") == "1":
    PARANOID_DIR = Path(os.environ.get(
        "BGP_TRACER_TRACING_PARANOID_DIR",
        "/tmp/bgp_tracer_tracing",
    ))

    _orig_stage_fn = stage  # circular-safe reference would not work; re-imported below
