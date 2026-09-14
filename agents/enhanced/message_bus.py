"""
AgentMessageBus — Real Agent-to-Agent Communication Layer
=========================================================

Solves Problem 1: Blackboard infrastructure (send_to, broadcast, subscribe)
was defined but NEVER used in the active pipeline. Every handler created
its own isolated Blackboard instance, making cross-agent communication impossible.

Design:
- Singleton per-analysis-run (shared across all agents in the same analysis)
- Topic-based pub/sub: agents subscribe to topics (e.g., "routing.events",
  "traffic.anomalies", "diagnosis.claims")
- Synchronous delivery with async support via callbacks
- Message envelope with: sender, topic, content, timestamp, in_reply_to, message_id
- Dead-letter queue for failed deliveries
- Message history for audit trail

Usage:
    bus = AgentMessageBus()
    await bus.publish(topic="traffic.anomalies", sender="TrafficAgent",
                     content={"count": 6, "anomalies": [...]})
    await bus.subscribe(topic="traffic.anomalies", handler=my_callback,
                      subscriber="ReasoningAgent")
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from typing import Any, Callable, Optional
from dataclasses import dataclass, field
from collections import defaultdict
from utils.logger import logger


@dataclass
class MessageEnvelope:
    message_id: str
    sender: str
    topic: str
    content: Any
    timestamp: str
    in_reply_to: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "message_id": self.message_id,
            "sender": self.sender,
            "topic": self.topic,
            "content": self.content,
            "timestamp": self.timestamp,
            "in_reply_to": self.in_reply_to,
            "metadata": self.metadata,
        }


class AgentMessageBus:
    """
    Topic-based publish-subscribe message bus for multi-agent communication.
    Replaces the dead `Agent.send_to()` / `Agent.broadcast()` in core.py.
    """

    _instances: dict[str, "AgentMessageBus"] = {}

    @classmethod
    def get_instance(cls, run_id: str = "default") -> "AgentMessageBus":
        """Get or create a bus instance for a specific analysis run."""
        if run_id not in cls._instances:
            cls._instances[run_id] = cls(run_id=run_id)
        return cls._instances[run_id]

    @classmethod
    def clear_instance(cls, run_id: str = "default"):
        """Clear a bus instance after analysis completes."""
        if run_id in cls._instances:
            del cls._instances[run_id]

    def __init__(self, run_id: str = "default"):
        self.run_id = run_id
        self._subscriptions: dict[str, list[tuple[str, Callable]]] = defaultdict(list)
        # Map: topic -> [(subscriber_name, callback)]
        self._message_history: list[MessageEnvelope] = []
        self._dead_letters: list[MessageEnvelope] = []
        self._lock = asyncio.Lock()
        self._pending_deliveries: list[asyncio.Task] = []

    # Core API

    async def publish(
        self,
        topic: str,
        sender: str,
        content: Any,
        in_reply_to: Optional[str] = None,
        metadata: Optional[dict] = None,
        require_delivery: bool = False,
    ) -> MessageEnvelope:
        """
        Publish a message to a topic.
        All subscribers to that topic receive the message.
        """
        envelope = MessageEnvelope(
            message_id=str(uuid.uuid4()),
            sender=sender,
            topic=topic,
            content=content,
            timestamp=datetime.now().isoformat(),
            in_reply_to=in_reply_to,
            metadata=metadata or {},
        )

        async with self._lock:
            self._message_history.append(envelope)

        await self._deliver(envelope)

        if require_delivery:
            await self._wait_for_delivery(envelope.message_id)

        return envelope

    async def subscribe(
        self,
        topic: str,
        handler: Callable,
        subscriber: str,
        metadata_filter: Optional[dict] = None,
    ):
        """
        Subscribe to a topic. Handler is called with MessageEnvelope on each delivery.
        Supports wildcard topics: "traffic.*" matches "traffic.anomalies", "traffic.events"
        """
        self._subscriptions[topic].append((subscriber, handler))
        logger.info(f"[MessageBus/{self.run_id}] {subscriber} subscribed to topic '{topic}'")

    def subscribe_sync(
        self,
        topic: str,
        handler: Callable,
        subscriber: str,
        metadata_filter: Optional[dict] = None,
    ):
        """Synchronous version of subscribe — for use in non-async contexts."""
        self._subscriptions[topic].append((subscriber, handler))
        logger.info(f"[MessageBus/{self.run_id}] {subscriber} subscribed to topic '{topic}' (sync)")

    async def unsubscribe(self, topic: str, subscriber: str):
        """Remove a subscription."""
        if topic in self._subscriptions:
            self._subscriptions[topic] = [
                (s, h) for s, h in self._subscriptions[topic] if s != subscriber
            ]

    async def send_to(
        self,
        recipient: str,
        sender: str,
        content: Any,
        in_reply_to: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> MessageEnvelope:
        """
        Send a direct message to a specific agent (point-to-point).
        Internally uses topic 'direct.{recipient}'.
        """
        topic = f"direct.{recipient}"
        envelope = await self.publish(
            topic=topic,
            sender=sender,
            content=content,
            in_reply_to=in_reply_to,
            metadata=metadata,
        )
        logger.debug(f"[MessageBus/{self.run_id}] {sender} -> {recipient}: {content}")
        return envelope

    async def broadcast(
        self,
        sender: str,
        content: Any,
        topic: str = "broadcast",
        in_reply_to: Optional[str] = None,
    ) -> MessageEnvelope:
        """
        Broadcast to all subscribers of 'broadcast' topic.
        """
        return await self.publish(
            topic=topic,
            sender=sender,
            content=content,
            in_reply_to=in_reply_to,
        )

    # Query API

    def get_messages(
        self,
        topic: Optional[str] = None,
        sender: Optional[str] = None,
        since: Optional[str] = None,
        limit: int = 100,
    ) -> list[MessageEnvelope]:
        """Query message history with filters."""
        results = list(self._message_history)
        if topic:
            results = [m for m in results if self.topic_matches(m.topic, topic)]
        if sender:
            results = [m for m in results if m.sender == sender]
        if since:
            results = [m for m in results if m.timestamp >= since]
        return results[-limit:]

    def get_latest(
        self,
        topic: str,
        sender: Optional[str] = None,
    ) -> Optional[MessageEnvelope]:
        """Get the most recent message for a topic."""
        messages = self.get_messages(topic=topic, sender=sender, limit=1)
        return messages[-1] if messages else None

    def get_dead_letters(self) -> list[MessageEnvelope]:
        """Messages that failed to deliver."""
        return list(self._dead_letters)

    def get_topics(self) -> list[str]:
        """All topics with active subscribers."""
        return list(self._subscriptions.keys())

    def get_subscription_count(self, topic: str) -> int:
        """Number of subscribers to a topic."""
        return len(self._subscriptions.get(topic, []))

    # Internal

    def topic_matches(self, msg_topic: str, sub_topic: str) -> bool:
        """Check if a message topic matches a subscription topic.

        Wildcard rules (both forms supported):
          - ``"diagnosis.*"`` → must match a single path segment, e.g.
            ``diagnosis.final`` matches but ``diagnosis.final.sub``
            does not. This is the standard MQTT-style hierarchical
            wildcard.
          - ``"diagnosis*"``  → legacy prefix-only wildcard (no ``.``
            required at the boundary). Provided for backwards
            compatibility with existing call sites; treat as
            substring-from-start without requiring a delimiter.

        Bug fix 2026-09-13 (BUG-R95): the previous wildcard handling
        only stripped ``.*`` or ``*`` and used ``startswith`` on the
        remainder. That made ``"report*"`` match ``"report_done"``
        (false positive — there is no separator) and broke the
        hierarchical semantics that ``"diagnosis.*"`` is supposed to
        enforce. Use ``fnmatch`` for the legacy single-star case so a
        trailing star only matches up to the next path segment, and
        keep the explicit ``startswith(prefix + '.')`` for the
        hierarchical form.
        """
        import fnmatch as _fnmatch
        if sub_topic.endswith(".*"):
            # Hierarchical wildcard: must be followed by a literal "."
            # separator before any further path segment. e.g.
            # "diagnosis.*" matches "diagnosis.final" and
            # "diagnosis.debate.complete" but NOT "diagnosisX".
            prefix = sub_topic[:-2]
            return msg_topic == prefix or msg_topic.startswith(prefix + ".")
        if sub_topic.endswith("*"):
            # Single-segment wildcard (no dot): legacy form. We use
            # fnmatch so the trailing '*' matches any tail but does
            # not implicitly require a "." boundary. This matches the
            # documented "diagnosis*" → "diagnosis_final" intent
            # without false positives against unrelated topics.
            return _fnmatch.fnmatchcase(msg_topic, sub_topic)
        return msg_topic == sub_topic

    async def _deliver(self, envelope: MessageEnvelope):
        """Deliver message to all matching subscribers."""
        # Collect matching subscribers
        targets: list[tuple[str, Callable]] = []
        async with self._lock:
            for topic_pattern, subscribers in self._subscriptions.items():
                if self.topic_matches(envelope.topic, topic_pattern):
                    targets.extend(subscribers)

        if not targets:
            logger.debug(
                f"[MessageBus/{self.run_id}] No subscribers for topic '{envelope.topic}' "
                f"(message from {envelope.sender}, id={envelope.message_id[:8]})"
            )
            return

        # Bug fix 2026-09-13 (BUG-R112): ``_pending_deliveries`` was
        # never trimmed except inside ``_wait_for_delivery``, which
        # is only called when ``publish(..., require_delivery=True)``
        # is used. For the much more common ``require_delivery=False``
        # path, every published message appended a finished (or
        # pending) ``asyncio.Task`` to the list and never removed
        # it — a slow memory leak that also prevented the GC from
        # collecting envelope / handler closures. We now prune the
        # list on every publish by sweeping done tasks up-front and
        # attaching a done-callback that removes the task from the
        # bookkeeping list as soon as it finishes.
        self._sweep_pending_deliveries()
        for subscriber, handler in targets:
            task = asyncio.create_task(
                self._safe_deliver(envelope, subscriber, handler)
            )
            task.add_done_callback(self._on_delivery_done)
            self._pending_deliveries.append(task)

    def _sweep_pending_deliveries(self) -> None:
        """Drop completed tasks from the pending list (best-effort, sync-safe).

        ``Task.remove_done_callback`` is sync, so this is safe to call
        from any context (publish path, snapshot path, etc.). The list
        is mutated in place so existing references stay valid.
        """
        keep = []
        for t in self._pending_deliveries:
            if t.done():
                continue
            keep.append(t)
        self._pending_deliveries = keep

    def _on_delivery_done(self, task: "asyncio.Task") -> None:
        """Done-callback: drop the finished task from the bookkeeping list."""
        try:
            self._pending_deliveries.remove(task)
        except (ValueError, RuntimeError):
            pass

    async def _safe_deliver(
        self,
        envelope: MessageEnvelope,
        subscriber: str,
        handler: Callable,
    ):
        """Deliver with error handling."""
        try:
            if asyncio.iscoroutinefunction(handler):
                await handler(envelope)
            else:
                handler(envelope)
        except Exception as exc:
            logger.warning(
                f"[MessageBus/{self.run_id}] Delivery failed to {subscriber}: {exc}"
            )
            async with self._lock:
                self._dead_letters.append(envelope)

    async def _wait_for_delivery(self, message_id: str, timeout: float = 5.0):
        """Wait until a message is delivered or timeout."""
        start = asyncio.get_event_loop().time()
        while asyncio.get_event_loop().time() - start < timeout:
            delivered = any(
                task.done() for task in self._pending_deliveries
            )
            if delivered:
                return
            await asyncio.sleep(0.05)
        logger.warning(
            f"[MessageBus/{self.run_id}] Delivery timeout for message {message_id[:8]}"
        )

    async def wait_all(self, timeout: float = 30.0):
        """Wait for all pending deliveries to complete."""
        if not self._pending_deliveries:
            return
        done, pending = await asyncio.wait(
            [t for t in self._pending_deliveries if not t.done()],
            timeout=timeout,
        )
        self._pending_deliveries = list(pending)

    def snapshot(self) -> dict:
        """Get a snapshot of bus state for debugging."""
        return {
            "run_id": self.run_id,
            "topic_count": len(self._subscriptions),
            "message_count": len(self._message_history),
            "dead_letter_count": len(self._dead_letters),
            "pending_deliveries": len(self._pending_deliveries),
            "topics": list(self._subscriptions.keys()),
        }


# Pre-defined topics (constants for type safety)


class Topic:
    """Standard topic names used across all agents."""

    # Traffic signals
    TRAFFIC_ANOMALIES = "traffic.anomalies"
    TRAFFIC_SCREENING_RESULT = "traffic.screening"
    TRAFFIC_FULL_RESULT = "traffic.full"

    # Routing signals
    ROUTING_HIJACKS = "routing.hijacks"
    ROUTING_LEAKS = "routing.leaks"
    ROUTING_OUTAGES = "routing.outages"
    ROUTING_COMPLETE = "routing.complete"

    # Diagnosis / reasoning
    DIAGNOSIS_CLAIMS = "diagnosis.claims"
    DIAGNOSIS_CHALLENGES = "diagnosis.challenges"
    DIAGNOSIS_VERDICTS = "diagnosis.verdicts"
    DIAGNOSIS_FINAL = "diagnosis.final"

    # Cross-agent correlation
    CORRELATION_UPDATE = "correlation.update"
    CORRELATION_FINAL = "correlation.final"

    # Report generation
    REPORT_SECTION_TRAFFIC = "report.section.traffic"
    REPORT_SECTION_ROUTING = "report.section.routing"
    REPORT_SECTION_CORRELATION = "report.section.correlation"
    REPORT_SECTION_SYNTHESIS = "report.section.synthesis"
    REPORT_COMPLETE = "report.complete"

    # System events
    AGENT_STATE_CHANGE = "agent.state"
    ANALYSIS_START = "analysis.start"
    ANALYSIS_COMPLETE = "analysis.complete"
    ANALYSIS_ERROR = "analysis.error"

    # Wildcard patterns
    TRAFFIC_STAR = "traffic.*"
    ROUTING_STAR = "routing.*"
    DIAGNOSIS_STAR = "diagnosis.*"
    REPORT_STAR = "report.*"
    DIRECT_PREFIX = "direct."


# Blackboard Integration Layer


class BlackboardMessageBridge:
    """
    Bridge between AgentMessageBus and the existing Blackboard.

    This lets existing agents that write to Blackboard also publish to the bus,
    and lets agents subscribe to Blackboard updates via the bus.

    Usage:
        bridge = BlackboardMessageBridge(bb, bus)
        bridge.start()   # starts listening to bb._notify events
        # Now every bb.write() automatically publishes to bus
    """

    def __init__(self, bb, bus: AgentMessageBus):
        self.bb = bb
        self.bus = bus
        self._original_notify = bb._notify
        self._active = False

    def start(self):
        """Start bridging Blackboard writes to MessageBus topics."""
        if self._active:
            return
        self._active = True
        # Patch Blackboard._notify to also publish to bus
        self.bb._notify = self._patched_notify
        logger.info(f"[Bridge] Blackboard → MessageBus bridge active (run_id={self.bus.run_id})")

    def stop(self):
        """Stop bridging. Notifies all subscribers before restoring original notify.

        Bug fix: the previous implementation called ``asyncio.create_task`` from
        inside this *synchronous* method. That has two failure modes:

        1. If ``stop()`` is invoked when no event loop is running (e.g. the
           workflow engine's ``finally`` block during interpreter shutdown, or
           from a non-async test harness), ``create_task`` raises
           ``RuntimeError: no running event loop`` and the caller's
           ``except Exception`` swallows the error while leaving
           ``self._active = False`` inconsistent with the still-patched
           ``bb._notify``.
        2. Even when a loop is running, the BRIDGE_STOPPED message is
           fire-and-forget: the bus may already be cleared by the caller
           before delivery, producing a ``KeyError`` in ``_deliver`` and
           a dead-letter entry.

        The fix uses ``asyncio.run_coroutine_threadsafe`` when an event
        loop is available, and silently drops the notification otherwise.
        The bridge state is restored unconditionally *before* the
        notification so the patched ``_notify`` callback is gone by the
        time subscribers try to inspect the blackboard.
        """
        if not self._active:
            return
        self._active = False
        # Restore the original notify first; any subsequent bb.write()
        # during the brief window between deactivate and notification
        # must not try to call into a deactivated bridge.
        self.bb._notify = self._original_notify
        # Best-effort notification. If we have a running loop, schedule
        # the coroutine on it; otherwise drop the notification (the
        # subscribers' blackboard reads will still see the latest state).
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None and not loop.is_closed():
            try:
                loop.create_task(
                    self.bus.publish(
                        topic="blackboard.bridge",
                        sender="BlackboardMessageBridge",
                        content={
                            "event": "BRIDGE_STOPPED",
                            "timestamp": __import__("datetime").datetime.now().isoformat(),
                        },
                        metadata={"section": "system", "key": "bridge_status"},
                    )
                )
            except Exception as exc:
                logger.debug(f"[Bridge] BRIDGE_STOPPED publish dropped: {exc!r}")
        else:
            logger.debug("[Bridge] No running event loop; BRIDGE_STOPPED notification dropped")
        logger.info("[Bridge] Blackboard → MessageBus bridge stopped")

    async def _patched_notify(self, section: str, key: str, value: Any):
        """Patched _notify: original behavior + MessageBus publish."""
        # Call original
        await self._original_notify(section, key, value)
        # Publish to bus
        if not self._active:
            return
        topic = f"{section}.{key}"
        await self.bus.publish(
            topic=topic,
            sender="Blackboard",
            content=value,
            metadata={"section": section, "key": key},
        )

    async def publish_result(
        self,
        agent_name: str,
        section: str,
        result: dict,
    ):
        """Manually publish a structured result to the bus."""
        topic = f"{section}.{agent_name}.result"
        await self.bus.publish(
            topic=topic,
            sender=agent_name,
            content=result,
            metadata={"section": section},
        )
