"""
Simple pub-sub event bus for SSE streaming.
"""
import asyncio
import time
from typing import Any


class EventBus:
    """Pub-sub bus: publishers call publish(), subscribers get queues."""

    def __init__(self):
        self._subscribers: list[asyncio.Queue] = []
        self._history: list[dict] = []

    async def publish(self, event_type: str, data: dict[str, Any]):
        event = {"type": event_type, "data": data, "ts": time.time()}
        self._history.append(event)
        for q in list(self._subscribers):
            q.put_nowait(event)

    def subscribe(self) -> asyncio.Queue:
        """Return a queue pre-loaded with history, and register for future events."""
        q: asyncio.Queue = asyncio.Queue()  # unbounded — prevents event drops and replay truncation
        for evt in self._history:
            q.put_nowait(evt)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        try:
            self._subscribers.remove(q)
        except ValueError:
            pass

    def reset(self):
        self._history.clear()
