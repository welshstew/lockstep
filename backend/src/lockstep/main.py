from __future__ import annotations

import logging
import secrets
import sys
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from .api import access, analyze, auth, authusers, configcopy, browse, compare, connections, destroy, expiry, database, exports, identity, leases, matrix, pki, plans, policies, roles, sync, transit, trypolicy, undo, vaultconfig
from . import logs, metrics, plansign
from .config import Settings, get_settings
from .ratelimit import RateLimiter, retry_after
from .session import SessionTooLarge

CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "lockstep"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
QUIET_PATHS = {"/healthz", "/readyz", "/metrics"}  # probes and scrapes: logged at debug only

# Browser hardening, the same as the demo's proxy sends, so a Helm or docker run install gets it too.
# The UI is self-contained (no inline scripts, nothing from other sites).
CSP = ("default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self'; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
# Swagger UI (/api/docs) loads its script and styles from jsDelivr and starts with an inline script
DOCS_CSP = ("default-src 'self'; img-src 'self' data: https://fastapi.tiangolo.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; connect-src 'self'; "
            "frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}

log = logging.getLogger("lockstep")
http_log = logging.getLogger("lockstep.http")


def _version() -> str:
    try:
        return version("lockstep")
    except PackageNotFoundError:
        return "dev"


def _log_startup(settings: Settings) -> None:
    on = lambda b: "on" if b else "off"  # noqa: E731
    log.info("Lockstep %s starting; log level %s, format %s", _version(), settings.log_level, settings.log_format)
    for i, p in enumerate(settings.preset_connections):
        log.info("preset Vault %d: %s at %s%s", i, p.name, p.url, f" (namespace {p.namespace})" if p.namespace else "")
    if not settings.preset_connections:
        log.info("no preset Vaults configured")
    rate = (f"{settings.rate_limit_per_minute}/min" if settings.rate_limit_per_minute > 0 else "off")
    log.info("custom connections %s; read-only %s; export %s; destroy %s; policy apply %s; user write %s; "
             "rate limit %s; TLS verify %s%s; %d shared profiles",
             on(settings.allow_custom_connections), on(settings.read_only), settings.export_mode,
             on(settings.allow_destroy), settings.policy_apply, settings.user_write, rate,
             on(settings.vault_tls_verify), " with a CA bundle" if settings.vault_ca_bundle else "",
             len(settings.profiles))


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
    logs.setup(settings.log_level, settings.log_format)
    _setup_audit_log()
    _log_startup(settings)
    docs = settings.api_docs == "on"
    app = FastAPI(title="Lockstep", docs_url="/api/docs" if docs else None,
                  openapi_url="/api/openapi.json" if docs else None, redoc_url=None)
    hsts = settings.public_url.lower().startswith("https://")

    limiter = (RateLimiter(settings.rate_limit_per_minute,
                           settings.rate_limit_burst or max(20, settings.rate_limit_per_minute // 4))
               if settings.rate_limit_per_minute > 0 else None)

    @app.middleware("http")
    async def csrf_guard(request: Request, call_next):
        # The session cookie is SameSite=Lax. As a second guard, every state-changing API
        # call must also send a custom header. A cross-site form can't set one, and a
        # cross-origin fetch would need a CORS preflight that we never approve.
        if (request.url.path.startswith("/api/") and request.method not in SAFE_METHODS
                and request.headers.get(CSRF_HEADER) != CSRF_VALUE):
            return JSONResponse({"detail": {"message": f"Missing {CSRF_HEADER} header"}}, status_code=403)
        if limiter and request.url.path.startswith("/api/"):
            wait = limiter.check(request.client.host if request.client else "unknown")
            if wait:
                secs = retry_after(wait)
                metrics.rate_limited("api")
                return JSONResponse({"detail": {"message": f"Too many requests from your address. Try again in "
                                                           f"{secs} second{'s' if secs != 1 else ''}."}},
                                    status_code=429, headers={"Retry-After": str(secs), "Cache-Control": "no-store"})
        response = await call_next(request)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"  # responses may contain secret values
        return response

    # Registered last, so it runs outermost: it also sees the guard's 403s and 429s.
    @app.middleware("http")
    async def request_log(request: Request, call_next):
        # One line per request, with a request ID on every log line it causes. A caller's
        # X-Request-ID (from a proxy) is kept if it looks sane, so lines can be matched up.
        rid = request.headers.get("x-request-id", "")
        if not (0 < len(rid) <= 64 and rid.replace("-", "").isalnum()):
            rid = secrets.token_hex(4)
        token = logs.request_id.set(rid)
        timer = logs.Timer()
        path = request.url.path
        client = request.client.host if request.client else "-"
        try:
            response = await call_next(request)
        except Exception:
            http_log.exception("%s %s failed after %dms (client %s)", request.method, path, timer.ms, client)
            response = JSONResponse({"detail": {"message": f"Internal error. Request ID {rid}: the server log has "
                                                           "the details."}}, status_code=500)
        finally:
            logs.request_id.reset(token)
        if metrics.enabled and path.startswith("/api/"):
            route = request.scope.get("route")
            template = getattr(route, "path", None) or "unmatched"  # a template, never the real path
            metrics.REQUESTS.inc(template, request.method, str(response.status_code))
            metrics.REQUEST_SECONDS.observe(timer.seconds, template, request.method)
        response.headers["X-Request-ID"] = rid
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        response.headers.setdefault("Content-Security-Policy", DOCS_CSP if path == "/api/docs" else CSP)
        if hsts:  # only over HTTPS: on plain HTTP it would be ignored, or lock out a dev setup
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        level = (logging.DEBUG if path in QUIET_PATHS or not path.startswith("/api/")
                 else logging.WARNING if response.status_code >= 500 else logging.INFO)
        if http_log.isEnabledFor(level):
            http_log.log(level, "%s %s %d %dms client %s", request.method, path, response.status_code, timer.ms,
                         client, extra={"request_id": rid, "fields": {
                             "method": request.method, "path": path, "status": response.status_code,
                             "ms": timer.ms, "client": client}})
        return response

    @app.exception_handler(SessionTooLarge)
    async def _too_large(_: Request, exc: SessionTooLarge):
        return JSONResponse({"detail": {"message": "Too many connections in this session; remove one"}},
                            status_code=400)

    metrics.enabled = settings.metrics == "on"
    if metrics.enabled:
        @app.get("/metrics", include_in_schema=False)
        def prometheus(request: Request):
            if settings.metrics_token and not secrets.compare_digest(
                    request.headers.get("authorization", "").encode(), f"Bearer {settings.metrics_token}".encode()):
                return JSONResponse({"detail": {"message": "Send Authorization: Bearer <LOCKSTEP_METRICS_TOKEN>"}},
                                    status_code=401, headers={"WWW-Authenticate": "Bearer"})
            return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4; charset=utf-8",
                                     headers={"Cache-Control": "no-store"})

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
            "export_mode": settings.export_mode,
            "export_teams": [{"name": t.name, "keys": len(t.recipients)} for t in settings.export_recipients],
            "export_protection": settings.export_protection or ["key", "passphrase", "age", "teams"],
            "allow_destroy": settings.allow_destroy and not settings.read_only,
            "read_only": settings.read_only,
            "policy_apply": settings.policy_apply == "on" and not settings.read_only,
            "allow_clipboard": settings.allow_clipboard,
            "user_write": settings.user_write == "on" and not settings.read_only,
            # Names a plan can be limited to (its audience): this server, and those whose plans it trusts
            "plan_servers": {"self": plansign.installation_name(settings),
                             "trusted": sorted({k.name for k in settings.plan_trusted_keys})},
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
    app.include_router(matrix.router)
    app.include_router(sync.router)
    app.include_router(analyze.router)
    app.include_router(auth.router)
    app.include_router(expiry.router)
    app.include_router(plans.router)
    app.include_router(undo.router)
    app.include_router(exports.router)
    app.include_router(destroy.router)
    app.include_router(policies.router)
    app.include_router(browse.router)
    app.include_router(roles.router)
    app.include_router(access.router)
    app.include_router(vaultconfig.router)
    app.include_router(identity.router)
    app.include_router(pki.router)
    app.include_router(leases.router)
    app.include_router(database.router)
    app.include_router(transit.router)
    app.include_router(trypolicy.router)
    app.include_router(authusers.router)
    app.include_router(configcopy.router)

    if settings.static_dir and Path(settings.static_dir).is_dir():
        app.mount("/", StaticFiles(directory=settings.static_dir, html=True), name="spa")
    return app


app = create_app()
