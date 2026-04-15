"""
Static file routes — serves index.html, CSS, and legacy app.js.
The /js/* tree is mounted separately in app.py via StaticFiles.
"""
from fastapi import APIRouter
from fastapi.responses import FileResponse, HTMLResponse

from ..constants import WEB_DIR

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def index():
    return FileResponse(WEB_DIR / "index.html")


@router.get("/style.css")
async def style():
    return FileResponse(WEB_DIR / "style.css", media_type="text/css")


@router.get("/app.js")
async def script():
    return FileResponse(WEB_DIR / "app.js", media_type="application/javascript")
