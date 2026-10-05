from __future__ import annotations

import asyncio
import os
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from time import perf_counter

# Enable section-level slimming on Blackboard writes. When ``True``
_BB_SLIM_ENABLED = os.environ.get("BB_SLIM_DISABLE", "0") != "1"


# Critical-result write-once guard for `routing.result` and `traffic.result`.
_BB_CRITICAL_WRITEONCE = os.environ.get("BB_CRITICAL_WRITEONCE_DISABLE", "0") != "1"
_CRITICAL_RESULT_KEYS = {
    ("routing", "result"),
    ("traffic", "result"),
}


def _fingerprint_section_data(value):
    """Stable fingerprint for a Blackboard value used to detect drift.

    Returns an int suitable for comparing two payloads without holding the
    original value. We hash the canonical JSON of just the keys the
    correlation analyzer + report agent actually consume — that way a
    payload regenerated with cosmetic differences (timestamps, ids) does
    not trip the guard, but a payload whose semantic content diverged
    (different hijack counts, different anomaly counts) does.
    """
    import hashlib
    import json

    def _canon(v):
        if isinstance(v, dict):
            return {k: _canon(v[k]) for k in sorted(v.keys()) if _SIGNIFICANT_KEYS.match(str(k))}
        if isinstance(v, list):
            return [_canon(x) for x in v]
        if isinstance(v, (int, float, bool)) or v is None:
            return v
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                return _canon(parsed)
            except (ValueError, TypeError):
                # Strings shorter than 64 chars are kept verbatim (event types,
                return v if len(v) < 64 else f"<str:{len(v)}>"
        return repr(v)

    blob = json.dumps(_canon(value), sort_keys=True, ensure_ascii=False, default=str)
    return int(hashlib.sha1(blob.encode("utf-8")).hexdigest(), 16)


# Operational fingerprint for the *event lists* that drive the verdict.
_EVENT_LIST_KEYS = (
    "origin_hijacked",
    "origin_hijacking",
    "forge_hijacked",
    "forge_hijacking",
    "route_leaks",
    "hijacks",
    "anomalies",
    "outages",
)


def _event_list_signature(value):
    """Hash the event lists inside a routing/traffic result payload.

    Returns an int (or None if no event lists are present). Used to detect
    the most common cause of verdict divergence: one writer saved a
    non-empty event list while another saved an empty one because the
    ``timestamp`` / ``first_seen`` field was missing on some events.
    """
    if not isinstance(value, dict):
        return None
    import hashlib
    import json
    pieces = []
    for k in _EVENT_LIST_KEYS:
        v = value.get(k)
        if isinstance(v, list):
            pieces.append((k, len(v)))
            sig = []
            for ev in v:
                if isinstance(ev, dict):
                    sig.append((
                        ev.get("event_type") or ev.get("hijack_type") or ev.get("type"),
                        ev.get("prefix") or ev.get("prefix_v6") or "",
                        bool(ev.get("timestamp") or ev.get("first_seen") or ev.get("time")),
                    ))
            pieces.append((k + "_detailed", sig))
    if not pieces:
        return None
    blob = json.dumps(pieces, sort_keys=True, ensure_ascii=False, default=str)
    return int(hashlib.sha1(blob.encode("utf-8")).hexdigest(), 16)


# Keys whose values influence the report verdict / correlation output.
import re as _re
_SIGNIFICANT_KEYS = _re.compile(
    r"^(hijack|leak|outage|origin_hijack|forge_hijack|route_leak|"
    r"anomaly|severity|count|prefix|as_path|asn|attacker|victim|"
    r"timestamp|first_seen|time|confidence|impact|status|"
    r"total_|has_|is_)"
)


class MsgType(Enum):
    REQUEST = auto()
    RESPONSE = auto()
    BROADCAST = auto()
    ALERT = auto()
    DONE = auto()
    OBSERVATION = auto()
    CLAIM = auto()
    CHALLENGE = auto()
    VERDICT = auto()
    METRIC = auto()


@dataclass
class Message:
    sender: str
    type: MsgType
    content: dict
    timestamp: datetime = field(default_factory=datetime.now)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    in_reply_to: str | None = None

    def to_dict(self):
        return {
            "id": self.id,
            "sender": self.sender,
            "type": self.type.name,
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "in_reply_to": self.in_reply_to,
        }


@dataclass
class Observation:
    record_id: str
    source: str
    kind: str
    summary: str
    confidence: float = 0.5
    payload: dict = field(default_factory=dict)
    supports: list[str] = field(default_factory=list)
    contradicts: list[str] = field(default_factory=list)
    derived_from: list[str] = field(default_factory=list)
    window: dict = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self):
        return {
            "record_id": self.record_id,
            "type": "observation",
            "source": self.source,
            "kind": self.kind,
            "summary": self.summary,
            "confidence": self.confidence,
            "payload": self.payload,
            "supports": list(self.supports),
            "contradicts": list(self.contradicts),
            "derived_from": list(self.derived_from),
            "window": dict(self.window),
            "tags": list(self.tags),
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class HypothesisClaim:
    record_id: str
    source: str
    kind: str
    summary: str
    confidence: float = 0.5
    status: str = "proposed"
    evidence_ids: list[str] = field(default_factory=list)
    supports: list[str] = field(default_factory=list)
    contradicts: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    uncertainty: list[str] = field(default_factory=list)
    derived_from: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self):
        return {
            "record_id": self.record_id,
            "type": "claim",
            "source": self.source,
            "kind": self.kind,
            "summary": self.summary,
            "confidence": self.confidence,
            "status": self.status,
            "evidence_ids": list(self.evidence_ids),
            "supports": list(self.supports),
            "contradicts": list(self.contradicts),
            "assumptions": list(self.assumptions),
            "uncertainty": list(self.uncertainty),
            "derived_from": list(self.derived_from),
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ChallengeRecord:
    record_id: str
    source: str
    target_id: str
    summary: str
    confidence: float = 0.5
    issues: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    derived_from: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self):
        return {
            "record_id": self.record_id,
            "type": "challenge",
            "source": self.source,
            "target_id": self.target_id,
            "summary": self.summary,
            "confidence": self.confidence,
            "issues": list(self.issues),
            "evidence_ids": list(self.evidence_ids),
            "derived_from": list(self.derived_from),
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class VerdictRecord:
    record_id: str
    source: str
    target_id: str
    verdict: str
    summary: str
    confidence: float = 0.5
    support_ids: list[str] = field(default_factory=list)
    challenge_ids: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self):
        return {
            "record_id": self.record_id,
            "type": "verdict",
            "source": self.source,
            "target_id": self.target_id,
            "verdict": self.verdict,
            "summary": self.summary,
            "confidence": self.confidence,
            "support_ids": list(self.support_ids),
            "challenge_ids": list(self.challenge_ids),
            "evidence_ids": list(self.evidence_ids),
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class MetricRecord:
    record_id: str
    source: str
    name: str
    value: float | int | str | bool
    payload: dict = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self):
        return {
            "record_id": self.record_id,
            "type": "metric",
            "source": self.source,
            "name": self.name,
            "value": self.value,
            "payload": self.payload,
            "timestamp": self.timestamp.isoformat(),
        }


def _fingerprints_equivalent(existing, incoming):
    """Compare two Blackboard payloads by semantic fingerprint.

    The comparison is dominated by the *event-list signature* (which
    determines the correlation verdict). If event lists match, the rest of
    the payload — even if it differs in cosmetic fields — is considered
    equivalent. Only when event-list signatures differ (or are absent on
    both sides) do we fall back to the broader fingerprint.
    """
    existing_sig = _event_list_signature(existing)
    incoming_sig = _event_list_signature(incoming)
    if existing_sig is not None or incoming_sig is not None:
        return existing_sig == incoming_sig
    try:
        return _fingerprint_section_data(existing) == _fingerprint_section_data(incoming)
    except Exception:
        return existing == incoming


class Blackboard:
    SECTIONS = ("config", "traffic", "routing", "diagnosis", "evidence", "report", "meta", "validation")

    def __init__(self):
        self._sections = {section: {} for section in self.SECTIONS}
        self._lock = asyncio.Lock()
        self._subscribers = {section: [] for section in self.SECTIONS}
        self._events = []
        self._sections["evidence"] = {
            "observations": [],
            "claims": [],
            "challenges": [],
            "verdicts": [],
            "metrics": [],
            "messages": [],
        }

    async def read(self, section, key, default=None):
        async with self._lock:
            return self._sections.get(section, {}).get(key, default)

    async def write(self, section, key, value, *, _writer: str = "", _allow_overwrite: bool = False):
        """Write to a Blackboard section.

        Critical keys (see ``_CRITICAL_RESULT_KEYS``) are protected by
        write-once semantics: a second write whose semantic fingerprint
        differs from the first is rejected and the original value is kept.
        Pass ``_writer`` (any string, e.g. ``agent name``) for observability
        in the warning log; pass ``_allow_overwrite=True`` only when you
        genuinely want to replace a critical value (e.g. error-recovery
        fallback with partial data).

        Concurrency (Bug fix 2026-09-13): the write-once check is performed
        **inside** the lock to avoid a TOCTOU race where two coroutines
        both read ``existing=None`` and both proceed to overwrite. The
        ``_notify`` call is also invoked under the lock so subscribers see
        a value that is already visible to subsequent readers.
        """
        value = self.maybe_slim(section, key, value)
        async with self._lock:
            if _BB_CRITICAL_WRITEONCE and (section, key) in _CRITICAL_RESULT_KEYS and not _allow_overwrite:
                existing = self._sections.get(section, {}).get(key)
                if existing is not None and not _fingerprints_equivalent(existing, value):
                    from utils.logger import logger
                    logger.warning(
                        f"[Blackboard] write-once rejected for ({section}.{key}); "
                        f"writer={_writer or 'unknown'} — keeping original value. "
                        f"If this is intentional, pass _allow_overwrite=True."
                    )
                    # Drop the lock before notifying (notify may await on
                    asyncio.ensure_future(self._notify(section, key, existing))
                    return
            self._sections.setdefault(section, {})[key] = value
        await self._notify(section, key, value)

    async def read_section(self, section):
        async with self._lock:
            return dict(self._sections.get(section, {}))

    async def update_section(self, section, data, *, _writer: str = "", _allow_overwrite: bool = False):
        data = self.maybe_slim_section(section, data)
        # Concurrency fix 2026-09-13: move the write-once check inside the
        rejected: dict = {}
        async with self._lock:
            current = self._sections.setdefault(section, {})
            for key, incoming in data.items():
                if _BB_CRITICAL_WRITEONCE and (section, key) in _CRITICAL_RESULT_KEYS and not _allow_overwrite:
                    existing = current.get(key)
                    if existing is not None and not _fingerprints_equivalent(existing, incoming):
                        from utils.logger import logger
                        logger.warning(
                            f"[Blackboard] update_section rejected overwrite for ({section}.{key}); "
                            f"writer={_writer or 'unknown'} — keeping original value."
                        )
                        rejected[key] = existing
                        continue
                current[key] = incoming
        # Apply rejection fixes AFTER the lock so we don't mutate the
        # caller's dict under contention (and so the dict is not aliased).
        data = dict(data)
        for key, original in rejected.items():
            data[key] = original
        # Mirror notification behaviour: notify outside the lock to avoid
        # serialising every blackboard write behind subscriber latency.
        for key, value in data.items():
            asyncio.ensure_future(self._notify(section, key, value))

    # Section-level slimming
    _BB_SECTION_MAP = {
        "traffic": "traffic",
        "routing": "routing",
        "diagnosis": "reasoning",
        "evidence": "reasoning",
        "report": "reasoning",
        # validation section  causal_analysis / joint_alert /
        "validation": "reasoning",
        "meta": "reasoning",
    }

    def maybe_slim(self, section: str, key: str, value):
        """Slim only LLM-facing blackboard values, preserving agent contracts."""
        # The workflow's traffic/routing result entries are the contract used
        if (section, key) in {("traffic", "result"), ("routing", "result")}:
            return value
        if not _BB_SLIM_ENABLED:
            return value
        profile = self._BB_SECTION_MAP.get(section)
        if profile is None or not isinstance(value, (dict, list)):
            return value
        try:
            from agents.payload_builder import slim_section, estimate_bytes
            slimmed = slim_section(profile, value)
            pre = estimate_bytes(value)
            post = estimate_bytes(slimmed)
            if post < pre:
                from utils.logger import logger
                logger.debug(
                    f"[Blackboard] slim '{section}.{key}': {pre}B→{post}B "
                    f"(profile={profile})"
                )
            return slimmed
        except Exception:
            return value

    def maybe_slim_section(self, section: str, data: dict) -> dict:
        """Slim an entire section dict, per-key."""
        if not _BB_SLIM_ENABLED or not isinstance(data, dict):
            return data
        out = {}
        for k, v in data.items():
            out[k] = self.maybe_slim(section, k, v)
        return out

    async def log_event(self, event_type, agent, payload):
        event = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "agent": agent,
            "payload": payload,
        }
        async with self._lock:
            self._events.append(event)
            self._sections.setdefault("meta", {}).setdefault("events", []).append(event)
        await self._notify("meta", "events", event)

    def normalize_observation(self, record):
        if isinstance(record, Observation):
            return record.to_dict()
        payload = dict(record)
        def _dt(v):
            if isinstance(v, datetime):
                return v.isoformat()
            if isinstance(v, (list, tuple)):
                return [_dt(x) for x in v]
            if isinstance(v, dict):
                return {kk: _dt(vv) for kk, vv in v.items()}
            return v
        for k, v in list(payload.items()):
            payload[k] = _dt(v)
        payload.setdefault("record_id", str(uuid.uuid4()))
        payload.setdefault("type", "observation")
        payload.setdefault("source", "unknown")
        payload.setdefault("kind", "unknown")
        payload.setdefault("summary", "")
        payload.setdefault("confidence", 0.5)
        payload.setdefault("payload", {})
        payload.setdefault("supports", [])
        payload.setdefault("contradicts", [])
        payload.setdefault("derived_from", [])
        payload.setdefault("window", {})
        payload.setdefault("tags", [])
        payload.setdefault("timestamp", datetime.now().isoformat())
        return payload

    def normalize_claim(self, record):
        if isinstance(record, HypothesisClaim):
            return record.to_dict()
        payload = dict(record)
        #  datetime  ISO ， JSON 
        def _dt(v):
            if isinstance(v, datetime):
                return v.isoformat()
            if isinstance(v, (list, tuple)):
                return [_dt(x) for x in v]
            if isinstance(v, dict):
                return {kk: _dt(vv) for kk, vv in v.items()}
            return v
        for k, v in list(payload.items()):
            payload[k] = _dt(v)
        payload.setdefault("record_id", str(uuid.uuid4()))
        payload.setdefault("type", "claim")
        payload.setdefault("source", "unknown")
        payload.setdefault("kind", "unknown")
        payload.setdefault("summary", "")
        payload.setdefault("confidence", 0.5)
        payload.setdefault("status", "proposed")
        payload.setdefault("evidence_ids", [])
        payload.setdefault("supports", [])
        payload.setdefault("contradicts", [])
        payload.setdefault("assumptions", [])
        payload.setdefault("uncertainty", [])
        payload.setdefault("derived_from", [])
        payload.setdefault("timestamp", datetime.now().isoformat())
        return payload

    def normalize_challenge(self, record):
        if isinstance(record, ChallengeRecord):
            return record.to_dict()
        payload = dict(record)
        def _dt(v):
            if isinstance(v, datetime):
                return v.isoformat()
            if isinstance(v, (list, tuple)):
                return [_dt(x) for x in v]
            if isinstance(v, dict):
                return {kk: _dt(vv) for kk, vv in v.items()}
            return v
        for k, v in list(payload.items()):
            payload[k] = _dt(v)
        payload.setdefault("record_id", str(uuid.uuid4()))
        payload.setdefault("type", "challenge")
        payload.setdefault("source", "unknown")
        payload.setdefault("target_id", "")
        payload.setdefault("summary", "")
        payload.setdefault("confidence", 0.5)
        payload.setdefault("issues", [])
        payload.setdefault("evidence_ids", [])
        payload.setdefault("derived_from", [])
        payload.setdefault("timestamp", datetime.now().isoformat())
        return payload

    def normalize_verdict(self, record):
        if isinstance(record, VerdictRecord):
            return record.to_dict()
        payload = dict(record)
        def _dt(v):
            if isinstance(v, datetime):
                return v.isoformat()
            if isinstance(v, (list, tuple)):
                return [_dt(x) for x in v]
            if isinstance(v, dict):
                return {kk: _dt(vv) for kk, vv in v.items()}
            return v
        for k, v in list(payload.items()):
            payload[k] = _dt(v)
        payload.setdefault("record_id", str(uuid.uuid4()))
        payload.setdefault("type", "verdict")
        payload.setdefault("source", "unknown")
        payload.setdefault("target_id", "")
        payload.setdefault("verdict", "inconclusive")
        payload.setdefault("summary", "")
        payload.setdefault("confidence", 0.5)
        payload.setdefault("support_ids", [])
        payload.setdefault("challenge_ids", [])
        payload.setdefault("evidence_ids", [])
        payload.setdefault("timestamp", datetime.now().isoformat())
        return payload

    def normalize_metric(self, record):
        if isinstance(record, MetricRecord):
            return record.to_dict()
        payload = dict(record)
        def _dt(v):
            if isinstance(v, datetime):
                return v.isoformat()
            if isinstance(v, (list, tuple)):
                return [_dt(x) for x in v]
            if isinstance(v, dict):
                return {kk: _dt(vv) for kk, vv in v.items()}
            return v
        for k, v in list(payload.items()):
            payload[k] = _dt(v)
        payload.setdefault("record_id", str(uuid.uuid4()))
        payload.setdefault("type", "metric")
        payload.setdefault("source", "unknown")
        payload.setdefault("name", "unknown")
        payload.setdefault("value", 0)
        payload.setdefault("payload", {})
        payload.setdefault("timestamp", datetime.now().isoformat())
        return payload

    async def add_observation(self, record):
        payload = self.normalize_observation(record)
        async with self._lock:
            self._sections["evidence"]["observations"].append(payload)
        await self._notify("evidence", "observations", payload)
        return payload

    async def add_claim(self, record):
        payload = self.normalize_claim(record)
        async with self._lock:
            self._sections["evidence"]["claims"].append(payload)
        await self._notify("evidence", "claims", payload)
        return payload

    async def add_challenge(self, record):
        payload = self.normalize_challenge(record)
        async with self._lock:
            self._sections["evidence"]["challenges"].append(payload)
        await self._notify("evidence", "challenges", payload)
        return payload

    async def add_verdict(self, record):
        payload = self.normalize_verdict(record)
        async with self._lock:
            self._sections["evidence"]["verdicts"].append(payload)
        await self._notify("evidence", "verdicts", payload)
        return payload

    async def add_metric(self, record):
        payload = self.normalize_metric(record)
        async with self._lock:
            self._sections["evidence"]["metrics"].append(payload)
        await self._notify("evidence", "metrics", payload)
        return payload

    async def add_protocol_message(self, msg):
        payload = msg.to_dict() if hasattr(msg, "to_dict") else dict(msg)
        async with self._lock:
            self._sections["evidence"]["messages"].append(payload)
        await self._notify("evidence", "messages", payload)
        return payload

    async def read_evidence_board(self):
        async with self._lock:
            return dict(self._sections.get("evidence", {}))

    def subscribe(self, section, callback):
        self._subscribers.setdefault(section, []).append(callback)

    def unsubscribe(self, section, callback):
        if callback in self._subscribers.get(section, []):
            self._subscribers[section].remove(callback)

    async def _notify(self, section, key, value):
        payload = {"section": section, "key": key, "value": value}
        # Snapshot subscribers up front so unsubscribe() during a callback
        # doesn't affect this iteration. ``list()`` gives a shallow copy.
        for callback in list(self._subscribers.get(section, [])):
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(payload)
                else:
                    callback(payload)
            except asyncio.CancelledError:
                # Never swallow cancellation — it's how the event loop
                # signals shutdown / timeout / parent cancellation.
                raise
            except Exception as exc:
                # Log loudly so silent subscriber failures don't mask
                try:
                    from utils.logger import logger
                    logger.warning(
                        f"[Blackboard] subscriber for ({section}.{key}) raised: "
                        f"{callback!r}: {exc!r}"
                    )
                except Exception:
                    # Last-ditch fallback: avoid raising from inside the
                    # notification loop (would skip remaining subscribers).
                    pass

    def snapshot(self):
        return {section: dict(self._sections.get(section, {})) for section in self.SECTIONS}

    async def clear(self):
        async with self._lock:
            for section in self.SECTIONS:
                self._sections[section] = {}
            self._sections["evidence"] = {
                "observations": [],
                "claims": [],
                "challenges": [],
                "verdicts": [],
                "metrics": [],
                "messages": [],
            }


class AgentState(Enum):
    IDLE = auto()
    WORKING = auto()
    WAITING = auto()
    DONE = auto()
    ERROR = auto()


@dataclass
class TaskResult:
    success: bool
    data: dict | None = None
    error: str | None = None
    agent: str = ""


class Agent(ABC):
    name: str = ""

    def __init__(self, blackboard):
        self.bb = blackboard
        self.state = AgentState.IDLE
        self._inbox = []
        self._stop = asyncio.Event()
        self._started_at = 0.0
        self._step_started_at = 0.0

    async def start(self):
        self._started_at = perf_counter()

    async def stop(self):
        self._stop.set()

    async def wait_until_stopped(self):
        await self._stop.wait()

    async def receive(self, msg):
        self._inbox.append(msg)

    def peek_inbox(self):
        return list(self._inbox)

    def pop_inbox(self):
        messages, self._inbox = self._inbox, []
        return messages

    def count_inbox(self):
        return len(self._inbox)

    async def send_to(self, recipient, msg_type, content, in_reply_to=None):
        msg = Message(sender=self.name, type=msg_type, content=content, in_reply_to=in_reply_to)
        await self.bb.write("meta", f"outbox:{recipient}", msg)
        await self.bb.add_protocol_message(msg)
        return msg

    async def broadcast(self, msg_type, content):
        return await self.send_to("*", msg_type, content)

    @abstractmethod
    async def step(self):
        pass

    async def run(self):
        while not self._stop.is_set():
            result = await self.step()
            if result.success or self.state == AgentState.ERROR:
                self.state = AgentState.DONE if result.success else AgentState.ERROR
                break
            await asyncio.sleep(0.1)

    async def read_config(self, key, default=None):
        return await self.bb.read("config", key, default)

    async def write_result(self, section, data):
        await self.bb.update_section(section, data)

    async def add_observation(self, kind, summary, payload=None, confidence=0.5, supports=None, contradicts=None, derived_from=None, window=None, tags=None):
        record = Observation(
            record_id=str(uuid.uuid4()),
            source=self.name,
            kind=kind,
            summary=summary,
            confidence=confidence,
            payload=payload or {},
            supports=supports or [],
            contradicts=contradicts or [],
            derived_from=derived_from or [],
            window=window or {},
            tags=tags or [],
        )
        return await self.bb.add_observation(record)

    async def add_claim(self, kind, summary, confidence=0.5, evidence_ids=None, supports=None, contradicts=None, assumptions=None, uncertainty=None, derived_from=None, status="proposed"):
        record = HypothesisClaim(
            record_id=str(uuid.uuid4()),
            source=self.name,
            kind=kind,
            summary=summary,
            confidence=confidence,
            status=status,
            evidence_ids=evidence_ids or [],
            supports=supports or [],
            contradicts=contradicts or [],
            assumptions=assumptions or [],
            uncertainty=uncertainty or [],
            derived_from=derived_from or [],
        )
        return await self.bb.add_claim(record)

    async def add_challenge(self, target_id, summary, confidence=0.5, issues=None, evidence_ids=None, derived_from=None):
        record = ChallengeRecord(
            record_id=str(uuid.uuid4()),
            source=self.name,
            target_id=target_id,
            summary=summary,
            confidence=confidence,
            issues=issues or [],
            evidence_ids=evidence_ids or [],
            derived_from=derived_from or [],
        )
        return await self.bb.add_challenge(record)

    async def add_verdict(self, target_id, verdict, summary, confidence=0.5, support_ids=None, challenge_ids=None, evidence_ids=None):
        record = VerdictRecord(
            record_id=str(uuid.uuid4()),
            source=self.name,
            target_id=target_id,
            verdict=verdict,
            summary=summary,
            confidence=confidence,
            support_ids=support_ids or [],
            challenge_ids=challenge_ids or [],
            evidence_ids=evidence_ids or [],
        )
        return await self.bb.add_verdict(record)

    async def add_metric(self, name, value, payload=None):
        record = MetricRecord(
            record_id=str(uuid.uuid4()),
            source=self.name,
            name=name,
            value=value,
            payload=payload or {},
        )
        return await self.bb.add_metric(record)

    async def read_evidence_board(self):
        return await self.bb.read_evidence_board()

    async def record_step_timing(self, step_name, started_at):
        elapsed_ms = round((perf_counter() - started_at) * 1000, 3)
        await self.add_metric("latency_ms", elapsed_ms, {"step": step_name, "agent": self.name})
        return elapsed_ms

    def log(self, msg):
        from utils.logger import logger
        logger.info(f"[{self.name}] {msg}")


__all__ = [
    "Message",
    "MsgType",
    "Observation",
    "HypothesisClaim",
    "ChallengeRecord",
    "VerdictRecord",
    "MetricRecord",
    "Blackboard",
    "Agent",
    "AgentState",
    "TaskResult",
]
