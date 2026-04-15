"""Tests for server.event_bus.EventBus."""

import asyncio

import pytest

from server.event_bus import EventBus


@pytest.fixture
def bus():
    return EventBus()


class TestEventBus:
    @pytest.mark.asyncio
    async def test_publish_and_subscribe(self, bus):
        q = bus.subscribe()
        await bus.publish("log", {"text": "hello"})
        event = q.get_nowait()
        assert event["type"] == "log"
        assert event["data"]["text"] == "hello"
        assert "ts" in event

    @pytest.mark.asyncio
    async def test_history_replay(self, bus):
        await bus.publish("phase_start", {"phase": "recon"})
        await bus.publish("phase_complete", {"phase": "recon"})
        # New subscriber sees both events from history
        q = bus.subscribe()
        assert q.qsize() == 2
        e1 = q.get_nowait()
        e2 = q.get_nowait()
        assert e1["type"] == "phase_start"
        assert e2["type"] == "phase_complete"

    @pytest.mark.asyncio
    async def test_multiple_subscribers(self, bus):
        q1 = bus.subscribe()
        q2 = bus.subscribe()
        await bus.publish("log", {"text": "msg"})
        assert q1.qsize() == 1
        assert q2.qsize() == 1

    @pytest.mark.asyncio
    async def test_unsubscribe(self, bus):
        q = bus.subscribe()
        bus.unsubscribe(q)
        await bus.publish("log", {"text": "msg"})
        assert q.empty()

    @pytest.mark.asyncio
    async def test_unsubscribe_unknown_queue(self, bus):
        # Should not raise
        bus.unsubscribe(asyncio.Queue())

    @pytest.mark.asyncio
    async def test_reset_clears_history(self, bus):
        await bus.publish("log", {"text": "old"})
        bus.reset()
        q = bus.subscribe()
        assert q.empty()

