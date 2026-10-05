"""FastAPI entrypoint for Vulture AI."""
from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.config import PROJECT_ROOT, get_settings
from backend.db.session import init_db
from backend.routes.hosts import router as hosts_router
from backend.routes.scans import router as scans_router
from backend.routes.chat import router as chat_router


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
log = logging.getLogger("vulture-ai")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Vulture AI API",
        version="0.1.0",
        description="Vulnerability scanner & threat intelligence platform.",
    )

    # CORS configuration
    cors_origins = settings.cors_origins
    if "*" in cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    else:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    @app.on_event("startup")
    def _startup() -> None:
        init_db()
        log.info("vulture-ai API ready (cors origins=%s)", cors_origins)

    # ── Meta endpoints ────────────────────────────────────────────────────────
    @app.get("/health", tags=["meta"])
    def health() -> dict:
        return {"status": "ok"}

    # ── Include API routers under /api prefix ────────────────────────────────
    # scans_router has prefix="/scans" → becomes /api/scans
    # hosts_router has prefix="/hosts" → becomes /api/hosts
    # chat_router has prefix="" with explicit /api/chat paths
    app.include_router(scans_router, prefix="/api")
    app.include_router(hosts_router, prefix="/api")
    app.include_router(chat_router)

    # ── SPA static files serving ──────────────────────────────────────────────
    dist_candidates = [
        PROJECT_ROOT / "frontend" / "dist",
        PROJECT_ROOT / "dist",
        Path("/app/frontend/dist"),
        Path("/app/dist"),
    ]
    dist_dir = next((p for p in dist_candidates if p.is_dir()), None)

    if dist_dir:
        log.info("Serving frontend static assets from %s", dist_dir)
        assets_dir = dist_dir / "assets"
        if assets_dir.is_dir():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        async def serve_spa(request: Request, full_path: str):
            # Let real API routes through — never serve index.html for /api/ or /health
            if full_path.startswith("api/") or full_path == "api" or full_path == "health":
                return JSONResponse({"detail": "Not Found"}, status_code=404)
            file_path = dist_dir / full_path
            if file_path.is_file():
                return FileResponse(file_path)
            # All SPA routes (e.g. /app, /scans/5) fall back to index.html
            return FileResponse(dist_dir / "index.html")

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    uvicorn.run("backend.main:app", host=host, port=port, reload=False)
