"""
SSE streaming endpoint — /api/events
"""
import asyncio
import json

from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse

from .. import run_state

router = APIRouter()

_SSE_HEADERS = {
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",
}


@router.get("/events")
async def events(request: Request, run: str = Query(default=None)):
    run_entry = run_state.active_runs.get(run) if run else None

    if not run_entry:
        # No matching run — send keepalive pings until the client reconnects.
        async def empty_gen():
            while True:
                if await request.is_disconnected():
                    break
                yield ": no-run\n\n"
                await asyncio.sleep(15)

        return StreamingResponse(empty_gen(), media_type="text/event-stream", headers=_SSE_HEADERS)

    bus = run_entry["bus"]
    q = bus.subscribe()

    async def generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(q.get(), timeout=15)
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            bus.unsubscribe(q)

    return StreamingResponse(generator(), media_type="text/event-stream", headers=_SSE_HEADERS)
