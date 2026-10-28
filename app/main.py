import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import audit, auth, patients
from .config import Settings
from .crypto import FieldCipher
from .db import Base, Database
from .gateway import Gateway, RateLimiter
from .policy import require_access
from .seed import seed

ROOT = Path(__file__).resolve().parent.parent


def create_app(settings=None):
    @asynccontextmanager
    async def lifespan(app):
        app.state.settings = settings or Settings.from_env()
        app.state.db = Database(app.state.settings.database_url)
        app.state.cipher = FieldCipher(app.state.settings.fernet_key)
        app.state.gateway_lock = asyncio.Lock()
        app.state.limiter = RateLimiter()
        Base.metadata.create_all(app.state.db.engine)
        with app.state.db.Session() as session:
            seed(session, app.state.cipher)
        yield
        app.state.db.engine.dispose()

    app = FastAPI(title="Zero Trust Medical · учебный MVP", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False)
    app.add_middleware(Gateway)

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        return response

    app.include_router(auth.router)
    app.include_router(patients.router)
    app.include_router(audit.router)

    @app.post("/api/demo/reset")
    async def reset(request: Request):
        user = require_access(getattr(request.state, "user", None), "demo.reset")
        with app.state.db.Session() as session:
            seed(session, app.state.cipher, reset=True, commit=False)
            event = audit.record_event(session, username=user["username"], role="admin",
                                       action="demo.reset", resource="POST /api/demo/reset", result="allow",
                                       status_code=200, reason="Демо восстановлено; прежние токены отозваны",
                                       request_id=request.state.request_id,
                                       simulated_night=request.state.simulated_night,
                                       app_timezone=app.state.settings.timezone)
            request.state.audit_id = event.id
        app.state.limiter.requests.clear()
        return {"detail": "Демо восстановлено. Выполните вход заново.", "audit_id": event.id}

    @app.get("/")
    async def index():
        return FileResponse(ROOT / "static" / "index.html")

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    app.mount("/static", StaticFiles(directory=ROOT / "static", check_dir=False), name="static")
    return app


app = create_app()
