"""A2A-style inter-agent messaging.

A lightweight, in-process, topic-based async message bus that lets agents in the pool
coordinate (e.g. a specialist signalling the coordinator that a high-severity finding
was produced, or sharing a discovered parameter). It intentionally implements the
*shape* of Agent-to-Agent messaging (typed envelopes, addressed/broadcast delivery,
async subscription) without a network transport; a network A2A endpoint can later back
the same `AgentMessage`/`MessageBus` contract.

Messages are data. Nothing received over the bus can widen authorization or scope —
consumers validate content against the deterministic policy layer exactly as with any
other untrusted input.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field


@dataclass
class AgentMessage:
    topic: str
    sender: str
    payload: dict
    recipient: str | None = None  # None => broadcast on topic
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    ts: float = field(default_factory=time.time)


class MessageBus:
    """Async pub/sub bus with bounded per-subscriber queues."""

    def __init__(self, max_queue: int = 1000):
        self._subscribers: dict[str, list[asyncio.Queue]] = {}
        self._history: list[AgentMessage] = []
        self._max_queue = max_queue
        self._lock = asyncio.Lock()

    async def subscribe(self, topic: str) -> asyncio.Queue:
        async with self._lock:
            q: asyncio.Queue = asyncio.Queue(maxsize=self._max_queue)
            self._subscribers.setdefault(topic, []).append(q)
            return q

    async def unsubscribe(self, topic: str, q: asyncio.Queue) -> None:
        async with self._lock:
            if topic in self._subscribers and q in self._subscribers[topic]:
                self._subscribers[topic].remove(q)

    async def publish(self, message: AgentMessage) -> int:
        """Deliver to subscribers of the topic. Returns delivery count."""
        delivered = 0
        async with self._lock:
            self._history.append(message)
            subs = list(self._subscribers.get(message.topic, []))
        for q in subs:
            try:
                q.put_nowait(message)
                delivered += 1
            except asyncio.QueueFull:
                pass  # backpressure: drop for a slow consumer rather than block the bus
        return delivered

    def history(self, topic: str | None = None) -> list[AgentMessage]:
        if topic is None:
            return list(self._history)
        return [m for m in self._history if m.topic == topic]


# A process-wide default bus for convenience; assessments may use their own instance.
default_bus = MessageBus()
