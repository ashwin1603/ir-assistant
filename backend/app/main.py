import asyncio
import logging
import re
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from cryptography.fernet import Fernet
from sqlalchemy import text
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

logger = logging.getLogger("ir_assistant")

from app.ai.client import warm_up
from app.audit import initialize_audit_chain
from app.auth.permissions import authorize
from app.auth.routes import router as auth_router
from app.config import settings
from app.db import Base, SessionLocal, add_missing_columns, engine, ensure_indexes
from app.rate_limit import limiter
from app.routes.actions import router as actions_router
from app.routes.anomalies import router as anomalies_router
from app.routes.artifacts import router as artifacts_router
from app.routes.attack import router as attack_router
from app.routes.audit_log import router as audit_router
from app.routes.detections import router as detections_router
from app.routes.devices import router as devices_router
from app.routes.events import router as events_router
from app.routes.incidents import router as incidents_router
from app.routes.network import router as network_router
from app.routes.reports import router as reports_router
from app.routes.settings import router as settings_router
from app.routes.stream import router as stream_router
from app.routes.uploads import router as uploads_router
from app.detection.threat_intel import seed_demo_indicators
from app.seed import seed_admin_user

Base.metadata.create_all(bind=engine)
add_missing_columns()
ensure_indexes()
_chain_db = SessionLocal()
try:
    initialize_audit_chain(_chain_db)
finally:
    _chain_db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    db = SessionLocal()
    try:
        migrate_sensitive_storage()
        seed_admin_user(db)
        seed_demo_indicators(db)
    finally:
        db.close()
    # Fire-and-forget: don't block server startup on the model load.
    asyncio.create_task(asyncio.to_thread(warm_up, settings.llm_provider))
    yield


def migrate_sensitive_storage() -> None:
    """Encrypt legacy MFA values and leftover UUID-named upload files once configured."""
    if not settings.data_encryption_key:
        logger.warning("DATA_ENCRYPTION_KEY is missing; encrypted uploads and MFA updates are unavailable")
        return
    fernet = Fernet(settings.data_encryption_key.encode("ascii"))
    with engine.begin() as conn:
        for column in ("mfa_secret", "mfa_pending_secret"):
            rows = conn.execute(text(f"SELECT id, {column} FROM users WHERE {column} IS NOT NULL")).all()
            for user_id, value in rows:
                if not value.startswith("gAAAA"):
                    encrypted = fernet.encrypt(value.encode("utf-8")).decode("ascii")
                    conn.execute(text(f"UPDATE users SET {column} = :value WHERE id = :id"),
                                 {"value": encrypted, "id": user_id})
    upload_dir = Path(settings.upload_dir).resolve()
    if upload_dir.is_dir():
        for path in upload_dir.iterdir():
            if path.is_file() and re.fullmatch(r"[0-9a-f]{32}\.(evtx|json|csv)", path.name, re.I):
                content = path.read_bytes()
                if not content.startswith(b"gAAAA"):
                    path.write_bytes(fernet.encrypt(content))


# authorize runs before every route: role checks come from the one table in app/auth/permissions.py.
_docs_enabled = settings.app_env.lower() == "development"
app = FastAPI(title="IR Assistant API", lifespan=lifespan, dependencies=[Depends(authorize)],
              docs_url="/docs" if _docs_enabled else None,
              redoc_url="/redoc" if _docs_enabled else None,
              openapi_url="/openapi.json" if _docs_enabled else None)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Log the full error (may include offending field values) server-side only.
    logger.warning("validation error on %s: %s", request.url.path, exc.errors())
    sanitized = [{"loc": err["loc"], "type": err["type"], "msg": err["msg"]} for err in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": sanitized})

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.cors_origin],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Export-Rows", "X-Export-Truncated"],  # CSV export row count for the UI
)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response


app.include_router(auth_router)
app.include_router(audit_router)
app.include_router(events_router)
app.include_router(devices_router)
app.include_router(detections_router)
app.include_router(anomalies_router)
app.include_router(network_router)
app.include_router(attack_router)
app.include_router(incidents_router)
app.include_router(reports_router)
app.include_router(artifacts_router)
app.include_router(actions_router)
app.include_router(uploads_router)
app.include_router(settings_router)
app.include_router(stream_router)


@app.get("/api/health")
def health():
    return {"status": "ok", "env": settings.app_env}
