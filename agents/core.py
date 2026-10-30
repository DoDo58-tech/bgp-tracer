from __future__ import annotations

import asyncio
import os
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from time import perf_counter

from agents.ablation_switches import ablation_switches

# Enable section-level slimming on Blackboard writes. When ``True``
_BB_SLIM_ENABLED = os.environ.get("BB_SLIM_DISABLE", "0") != "1"


# Critical-result write-once guard for `routing.result` and `traffic.result`.
_BB_CRITICAL_WRITEONCE = os.environ.get("BB_CRITICAL_WRITEONCE_DISABLE", "0") != "1"
_CRITICAL_RESULT_KEYS = {
    ("routing", "result"),
    ("traffic", "result"),
}


def fingerprint_section_data(value):
    """Stable fingerprint for a Blackboard value used to detect drift.
    
    Returns an int suitable for comparing two payloads without holding the
    original value. We hash the canonical JSON of just the keys the
    correlation analyzer + report agent actually consume — that way a
    payload regenerated with cosmetic differences (timestamps, ids) does
    not trip the guard, but a payload whose semantic content diverged
    (different hijack counts, different anomaly counts) does."""
    import hashlib
    import json

    def canon(v):
        if isinstance(v, dict):
            return {k: canon(v[k]) for k in sorted(v.keys()) if _SIGNIFICANT_KEYS.match(str(k))}
        if isinstance(v, list):
            return [canon(x) for x in v]
        if isinstance(v, (int, float, bool)) or v is None:
            return v
        if isinstance(v, str):
            try:
                parsed = json.loads(v)
                return canon(parsed)
            except (ValueError, TypeError):
                # Strings shorter than 64 chars are kept verbatim (event types,
                return v if len(v) < 64 else f"<str:{len(v)}>"
        return repr(v)

    blob = json.dumps(canon(value), sort_keys=True, ensure_ascii=False, default=str)
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


def event_list_signature(value):
    """Hash the event lists inside a routing/traffic result payload."""
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
class AlternativeRecord:
    """An alternative explanation that the analysis considered and ruled out."""
    record_id: str
    source: str
    alternative: str
    summary: str = ""
    competes_with: str = ""
    rejected_because: str = ""
    confidence: float = 0.5
    evidence_ids: list[str] = field(default_factory=list)
    derived_from: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self):
        return {
            "record_id": self.record_id,
            "type": "alternative",
            "source": self.source,
            "alternative": self.alternative,
            "summary": self.summary,
            "competes_with": self.competes_with,
            "rejected_because": self.rejected_because,
            "confidence": self.confidence,
            "evidence_ids": list(self.evidence_ids),
            "derived_from": list(self.derived_from),
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class GapRecord:
    """An input that was missing, unavailable, or degraded."""
    record_id: str
    source: str
    kind: str
    summary: str = ""
    severity: str = "missing"
    impact: str = ""
    confidence: float = 0.5
    derived_from: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self):
        return {
            "record_id": self.record_id,
            "type": "gap",
            "source": self.source,
            "kind": self.kind,
            "summary": self.summary,
            "severity": self.severity,
            "impact": self.impact,
            "confidence": self.confidence,
            "derived_from": list(self.derived_from),
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


def fingerprints_equivalent(existing, incoming):
    """Compare two Blackboard payloads by semantic fingerprint."""
    existing_sig = event_list_signature(existing)
    incoming_sig = event_list_signature(incoming)
    if existing_sig is not None or incoming_sig is not None:
        return existing_sig == incoming_sig
    try:
        return fingerprint_section_data(existing) == fingerprint_section_data(incoming)
    except (ValueError):
        return existing == incoming


def is_content_destroyed(original, slimmed) -> bool:
    """True when slimming emptied a payload that had content."""
    if isinstance(original, dict):
        if not original:
            return False
        return isinstance(slimmed, dict) and not slimmed
    if isinstance(original, list):
        if not original:
            return False
        return isinstance(slimmed, list) and not slimmed
    return False


def section_keep_keys() -> dict:
    """Map each payload profile to the set of top-level keys it allows."""
    try:
        from agents.payload_builder import (
            _TRAFFIC_KEEP, _ROUTING_KEEP, _CORRELATION_KEEP, _REASONING_KEEP,
        )
    except (ValueError):  # pragma: no cover - defensive
        return {}
    return {
        "traffic": set(_TRAFFIC_KEEP),
        "routing": set(_ROUTING_KEEP),
        "correlation": set(_CORRELATION_KEEP),
        "reasoning": set(_REASONING_KEEP),
    }


_SECTION_KEEP_KEYS = section_keep_keys()


class Blackboard:
    SECTIONS = ("config", "traffic", "routing", "diagnosis", "evidence", "report", "meta", "validation")

    def __init__(self):
        self._sections = {section: {} for section in self.SECTIONS}
        self._lock = asyncio.Lock()
        self._events = []
        # Component-ablation switch. When enabled, the typed record surface
        # is off.  Read through the shared switch module so the board and
        # the workflow engine cannot disagree about whether the surface
        # is on -- a disagreement would mean one arm records an audit
        # trail and another does not, for reasons that have nothing to do
        # with the stage under test.
        self.record_surface_enabled = not ablation_switches()["evidence_board"]
        self._sections["evidence"] = {
            "observations": [],
            "claims": [],
            "challenges": [],
            "verdicts": [],
            "alternatives": [],
            "gaps": [],
            "metrics": [],
        }

    async def read(self, section, key, default=None):
        async with self._lock:
            return self._sections.get(section, {}).get(key, default)

    async def write(self, section, key, value, *, _writer="", _allow_overwrite=False):
        """Write to a Blackboard section."""
        value = self.maybe_slim(section, key, value)
        async with self._lock:
            if _BB_CRITICAL_WRITEONCE and (section, key) in _CRITICAL_RESULT_KEYS and not _allow_overwrite:
                existing = self._sections.get(section, {}).get(key)
                if existing is not None and not fingerprints_equivalent(existing, value):
                    from utils.logger import logger
                    logger.warning(
                        f"[Blackboard] write-once rejected for ({section}.{key}); "
                        f"writer={_writer or 'unknown'} — keeping original value. "
                        f"If this is intentional, pass _allow_overwrite=True."
                    )
                    return
            self._sections.setdefault(section, {})[key] = value

    async def read_section(self, section):
        async with self._lock:
            return dict(self._sections.get(section, {}))

    async def update_section(self, section, data, *, _writer="", _allow_overwrite=False):
        data = self.maybe_slim_section(section, data)
        # Concurrency fix 2026-09-13: move the write-once check inside the
        rejected: dict = {}
        async with self._lock:
            current = self._sections.setdefault(section, {})
            for key, incoming in data.items():
                if _BB_CRITICAL_WRITEONCE and (section, key) in _CRITICAL_RESULT_KEYS and not _allow_overwrite:
                    existing = current.get(key)
                    if existing is not None and not fingerprints_equivalent(existing, incoming):
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
    def maybe_slim(self, section, key, value):
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

            # (1) Only slim payloads that look like a whole section: their
            # top-level keys must overlap the profile's allow-list.
            if isinstance(value, dict) and value:
                keep = _SECTION_KEEP_KEYS.get(profile)
                if keep is not None and not (set(value.keys()) & keep):
                    return value

            slimmed = slim_section(profile, value)

            # (2) Never let slimming delete the content of a payload.
            if is_content_destroyed(value, slimmed):
                return value

            pre = estimate_bytes(value)
            post = estimate_bytes(slimmed)
            if post < pre:
                from utils.logger import logger
                logger.debug(
                    f"[Blackboard] slim '{section}.{key}': {pre}B→{post}B "
                    f"(profile={profile})"
                )
            return slimmed
        except (ValueError):
            return value

    def maybe_slim_section(self, section, data):
        """Slim an entire section dict, per-key."""
        if not _BB_SLIM_ENABLED or not isinstance(data, dict):
            return data
        out = {}
        for k, v in data.items():
            out[k] = self.maybe_slim(section, k, v)
        return out
    def normalize_observation(self, record):
        if isinstance(record, Observation):
            return record.to_dict()
        payload = dict(record)
        def dt(v):
            if isinstance(v, datetime):
                return v.isoformat()
            if isinstance(v, (list, tuple)):
                return [dt(x) for x in v]
            if isinstance(v, dict):
                return {kk: dt(vv) for kk, vv in v.items()}
            return v
        for k, v in list(payload.items()):
            payload[k] = dt(v)
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
        def dt(v):
            if isinstance(v, datetime):
                return v.isoformat()
            if isinstance(v, (list, tuple)):
                return [dt(x) for x in v]
            if isinstance(v, dict):
                return {kk: dt(vv) for kk, vv in v.items()}
            return v
        for k, v in list(payload.items()):
            payload[k] = dt(v)
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
        def dt(v):
            if isinstance(v, datetime):
                return v.isoformat()
            if isinstance(v, (list, tuple)):
                return [dt(x) for x in v]
            if isinstance(v, dict):
                return {kk: dt(vv) for kk, vv in v.items()}
            return v
        for k, v in list(payload.items()):
            payload[k] = dt(v)
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
        def dt(v):
            if isinstance(v, datetime):
                return v.isoformat()
            if isinstance(v, (list, tuple)):
                return [dt(x) for x in v]
            if isinstance(v, dict):
                return {kk: dt(vv) for kk, vv in v.items()}
            return v
        for k, v in list(payload.items()):
            payload[k] = dt(v)
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

    def normalize_alternative(self, record):
        if isinstance(record, AlternativeRecord):
            return record.to_dict()
        payload = dict(record)
        payload.setdefault("record_id", str(uuid.uuid4()))
        payload.setdefault("type", "alternative")
        payload.setdefault("source", "unknown")
        payload.setdefault("alternative", "")
        payload.setdefault("summary", "")
        payload.setdefault("competes_with", "")
        payload.setdefault("rejected_because", "")
        payload.setdefault("confidence", 0.5)
        payload.setdefault("evidence_ids", [])
        payload.setdefault("derived_from", [])
        payload.setdefault("timestamp", datetime.now().isoformat())
        return payload

    def normalize_gap(self, record):
        if isinstance(record, GapRecord):
            return record.to_dict()
        payload = dict(record)
        payload.setdefault("record_id", str(uuid.uuid4()))
        payload.setdefault("type", "gap")
        payload.setdefault("source", "unknown")
        payload.setdefault("kind", "unknown")
        payload.setdefault("summary", "")
        payload.setdefault("severity", "missing")
        payload.setdefault("impact", "")
        payload.setdefault("confidence", 0.5)
        payload.setdefault("derived_from", [])
        payload.setdefault("timestamp", datetime.now().isoformat())
        return payload

    def normalize_metric(self, record):
        if isinstance(record, MetricRecord):
            return record.to_dict()
        payload = dict(record)
        def dt(v):
            if isinstance(v, datetime):
                return v.isoformat()
            if isinstance(v, (list, tuple)):
                return [dt(x) for x in v]
            if isinstance(v, dict):
                return {kk: dt(vv) for kk, vv in v.items()}
            return v
        for k, v in list(payload.items()):
            payload[k] = dt(v)
        payload.setdefault("record_id", str(uuid.uuid4()))
        payload.setdefault("type", "metric")
        payload.setdefault("source", "unknown")
        payload.setdefault("name", "unknown")
        payload.setdefault("value", 0)
        payload.setdefault("payload", {})
        payload.setdefault("timestamp", datetime.now().isoformat())
        return payload

    def record_surface_off(self) -> bool:
        """True when the typed record surface is ablated for this run.
        
        When it is off, record writes are silently dropped: the pipeline
        still reaches the same decision, but the run leaves no audit
        trail. This is the "no Evidence Blackboard" arm of the component
        ablation."""
        return not getattr(self, "record_surface_enabled", True)

    async def add_observation(self, record):
        if self.record_surface_off():
            return {}
        payload = self.normalize_observation(record)
        async with self._lock:
            self._sections["evidence"]["observations"].append(payload)
        return payload

    async def add_claim(self, record):
        if self.record_surface_off():
            return {}
        payload = self.normalize_claim(record)
        async with self._lock:
            self._sections["evidence"]["claims"].append(payload)
        return payload

    async def add_challenge(self, record):
        if self.record_surface_off():
            return {}
        payload = self.normalize_challenge(record)
        async with self._lock:
            self._sections["evidence"]["challenges"].append(payload)
        return payload

    async def add_verdict(self, record):
        if self.record_surface_off():
            return {}
        payload = self.normalize_verdict(record)
        async with self._lock:
            self._sections["evidence"]["verdicts"].append(payload)
        return payload

    async def add_alternative(self, record):
        """Record an alternative explanation that the analysis ruled out."""
        payload = self.normalize_alternative(record)
        if self.record_surface_off():
            return {}
        async with self._lock:
            self._sections["evidence"].setdefault("alternatives", []).append(payload)
        return payload

    async def add_gap(self, record):
        """Record an input that was missing, unavailable, or degraded."""
        payload = self.normalize_gap(record)
        if self.record_surface_off():
            return {}
        async with self._lock:
            self._sections["evidence"].setdefault("gaps", []).append(payload)
        return payload

    async def merge_evidence(self, data: dict, *, _writer: str = "") -> dict:
        """Merge typed record lists into the evidence section.
        
        Returns the number of records actually appended per list."""
        appended: dict[str, int] = {}
        if self.record_surface_off():
            return appended
        async with self._lock:
            ev = self._sections.setdefault("evidence", {})
            for list_name, records in (data or {}).items():
                if not isinstance(records, list):
                    continue
                bucket = ev.setdefault(list_name, [])
                if not isinstance(bucket, list):
                    bucket = []
                    ev[list_name] = bucket
                before = len(bucket)
                bucket.extend(records)
                appended[list_name] = len(bucket) - before
        if _writer:
            from utils.logger import logger
            logger.debug(f"[Blackboard] merge_evidence by {_writer}: {appended}")
        return appended

    async def add_metric(self, record):
        payload = self.normalize_metric(record)
        async with self._lock:
            self._sections["evidence"]["metrics"].append(payload)
        return payload

    async def read_evidence_board(self):
        async with self._lock:
            return dict(self._sections.get("evidence", {}))
    async def clear(self):
        async with self._lock:
            for section in self.SECTIONS:
                self._sections[section] = {}
            self._sections["evidence"] = {
                "observations": [],
                "claims": [],
                "challenges": [],
                "verdicts": [],
                "alternatives": [],
                "gaps": [],
                "metrics": [],
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
        self._inbox_lock = asyncio.Lock()
        self.stop = asyncio.Event()
        self._started_at = 0.0
        self._step_started_at = 0.0

    async def start(self):
        self._started_at = perf_counter()

    async def stop(self):
        self.stop.set()

    @abstractmethod
    async def step(self):
        pass

    async def run(self):
        while not self.stop.is_set():
            result = await self.step()
            if result.success or self.state == AgentState.ERROR:
                self.state = AgentState.DONE if result.success else AgentState.ERROR
                break
            await asyncio.sleep(0.1)
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

    async def add_alternative(self, alternative, summary="", competes_with="",
                              rejected_because="", confidence=0.5,
                              evidence_ids=None, derived_from=None):
        """Record an alternative explanation this analysis ruled out."""
        record = AlternativeRecord(
            record_id=str(uuid.uuid4()),
            source=self.name,
            alternative=alternative,
            summary=summary,
            competes_with=competes_with,
            rejected_because=rejected_because,
            confidence=confidence,
            evidence_ids=evidence_ids or [],
            derived_from=derived_from or [],
        )
        return await self.bb.add_alternative(record)

    async def add_gap(self, kind, summary="", severity="missing", impact="",
                      confidence=0.5, derived_from=None):
        """Record a missing, unavailable, or degraded input."""
        record = GapRecord(
            record_id=str(uuid.uuid4()),
            source=self.name,
            kind=kind,
            summary=summary,
            severity=severity,
            impact=impact,
            confidence=confidence,
            derived_from=derived_from or [],
        )
        return await self.bb.add_gap(record)

    async def read_evidence_board(self):
        return await self.bb.read_evidence_board()
    def log(self, msg):
        from utils.logger import logger
        logger.info(f"[{self.name}] {msg}")


__all__ = [
    "Observation",
    "HypothesisClaim",
    "ChallengeRecord",
    "VerdictRecord",
    "AlternativeRecord",
    "GapRecord",
    "MetricRecord",
    "Blackboard",
    "Agent",
    "AgentState",
    "TaskResult",
]
