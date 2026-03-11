"""
Static Frontend Routes
----------------------
Serves the vanilla HTML/CSS/JS frontend directly from FastAPI.
Place your HTML files in the `frontend/` directory next to main.py.

Directory layout expected:
  frontend/
  ├── index.html          ← chat UI       → GET /
  ├── dashboard.html      ← dashboard     → GET /dashboard
  └── static/
      └── loco.png        ← logo          → GET /static/loco.png

Routes:
  GET /          → frontend/index.html
  GET /dashboard → frontend/dashboard.html
  GET /static/*  → frontend/static/*
"""

from pathlib import Path
from fastapi import APIRouter
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

# Resolve frontend directory relative to this file
FRONTEND_DIR = Path(__file__).parent / "frontend"

router = APIRouter(tags=["Frontend"])


@router.get("/", response_class=FileResponse, include_in_schema=False)
async def serve_chat():
    """Serve the chat UI."""
    return FileResponse(FRONTEND_DIR / "index.html")


@router.get("/dashboard", response_class=FileResponse, include_in_schema=False)
async def serve_dashboard():
    """Serve the analytics dashboard."""
    return FileResponse(FRONTEND_DIR / "dashboard.html")


def mount_static(app):
    """
    Call this in main.py after creating the FastAPI app.
    Mounts /static for any extra assets (images, fonts, etc.)
    """
    static_dir = FRONTEND_DIR / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
