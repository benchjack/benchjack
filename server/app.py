"""
BenchJack web server — FastAPI application factory.

Route logic lives in server/routes/; shared state in server/run_state.py.
"""
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from . import run_state
from .constants import TOOLS_DIR, WEB_DIR
from .routes import audit as audit_routes
from .routes import events as events_routes
from .routes import runs as runs_routes
from .routes import static as static_routes


def create_app(
    *,
    ai_backend: str = "auto",
    ai_model: str | None = None,
    sandbox: bool = True,
) -> FastAPI:
    # Publish config to the shared state module before any requests arrive.
    run_state.ai_backend = ai_backend
    run_state.ai_model = ai_model
    run_state.use_sandbox = sandbox

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Pre-build the sandbox Docker image in the background so the server
        # starts accepting requests immediately.
        if run_state.use_sandbox:
            async def _prebuild():
                from .sandbox import Sandbox as _Sb
                sb = _Sb(str(TOOLS_DIR), enabled=True)
                if sb.enabled:
                    await sb.ensure_image()
                sb.cleanup()
            asyncio.create_task(_prebuild())

        yield

        # Teardown: cancel running tasks and clean up sandboxes.
        for run in run_state.active_runs.values():
            if run["task"] and not run["task"].done():
                run["task"].cancel()
            if run["sandbox"]:
                run["sandbox"].cleanup()

    app = FastAPI(title="BenchJack", lifespan=lifespan)

    # Serve JS modules from web/js/ at /js/*
    js_dir = WEB_DIR / "js"
    if js_dir.is_dir():
        app.mount("/js", StaticFiles(directory=js_dir), name="web_js")

    # Register route modules
    app.include_router(static_routes.router)
    app.include_router(events_routes.router, prefix="/api")
    app.include_router(audit_routes.router, prefix="/api")
    app.include_router(runs_routes.router, prefix="/api")

    return app
