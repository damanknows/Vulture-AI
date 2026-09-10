"""FastAPI entrypoint for Vulmap Pro."""
from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import get_settings
from backend.db.session import init_db
from backend.routes.hosts import router as hosts_router
from backend.routes.scans import router as scans_router


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
log = logging.getLogger("vulmap")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Vulmap Pro API",
        version="0.1.0",
        description="Vulnerability scanner — Nmap + NVD CVE matching.",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.on_event("startup")
    def _startup() -> None:
        init_db()
        log.info("vulmap-pro API ready (cors origins=%s)", settings.cors_origins)

    @app.get("/health", tags=["meta"])
    def health() -> dict:
        return {"status": "ok"}

    app.include_router(scans_router)
    app.include_router(hosts_router)
    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=False)
