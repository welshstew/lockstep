from __future__ import annotations

import logging
import sys
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .api import analyze, auth, compare, connections, expiry, sync
from .config import Settings, get_settings
from .session import SessionTooLarge

CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "lockstep"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _setup_audit_log() -> None:
    """Audit events go to stdout as one JSON object per line (collected by k8s logging)."""
    log = logging.getLogger("lockstep.audit")
    if not log.handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter("%(message)s"))
        log.addHandler(h)
        log.setLevel(logging.INFO)
        log.propagate = False


def create_app() -> FastAPI:
    settings = get_settings()
    _setup_audit_log()
    app = FastAPI(title="Lockstep", docs_url="/api/docs", openapi_url="/api/openapi.json")

    @app.middleware("http")
    async def csrf_guard(request: Request, call_next):
        # The session cookie is SameSite=Lax. As a second guard, every state-changing API
        # call must also send a custom header. A cross-site form can't set one, and a
        # cross-origin fetch would need a CORS preflight that we never approve.
        if (request.url.path.startswith("/api/") and request.method not in SAFE_METHODS
                and request.headers.get(CSRF_HEADER) != CSRF_VALUE):
            return JSONResponse({"detail": {"message": f"Missing {CSRF_HEADER} header"}}, status_code=403)
        response = await call_next(request)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"  # responses may contain secret values
        return response

    @app.exception_handler(SessionTooLarge)
    async def _too_large(_: Request, exc: SessionTooLarge):
        return JSONResponse({"detail": {"message": "Too many connections in this session; remove one"}},
                            status_code=400)

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    def readyz():
        return {"status": "ready"}

    @app.get("/api/config")
    def public_config(settings: Settings = Depends(get_settings)):
        return {
            "presets": [
                {"id": i, "name": c.name, "browser_url": c.browser_url, "namespace": c.namespace}
                for i, c in enumerate(settings.preset_connections)
            ],
            "allow_custom_connections": settings.allow_custom_connections,
            "demo_banner": settings.demo_banner,
            "k8s_auth": {
                "available": connections.k8s_available(settings),
                "mount": settings.k8s_auth_mount,
                "roles": settings.k8s_auth_roles,
                "service_account": connections.k8s_service_account(settings)
                if connections.k8s_available(settings) else None,
            },
        }

    @app.get("/api/profiles")
    def shared_profiles(settings: Settings = Depends(get_settings)):
        """Comparison profiles configured on the server (read-only in the UI)."""
        return [pr.model_dump() for pr in settings.profiles]

    app.include_router(connections.router)
    app.include_router(compare.router)
    app.include_router(sync.router)
    app.include_router(analyze.router)
    app.include_router(auth.router)
    app.include_router(expiry.router)

    if settings.static_dir and Path(settings.static_dir).is_dir():
        app.mount("/", StaticFiles(directory=settings.static_dir, html=True), name="spa")
    return app


app = create_app()
