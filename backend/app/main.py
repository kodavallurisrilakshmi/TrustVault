import os
import uuid
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from app.storage.local_storage import get_vault_root

from app.core.config import settings
from app.core.database import get_db, engine
from app.api.v1.router import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Use the same resolved private vault path as the storage service.
    vault_root = get_vault_root()
    vault_root.mkdir(parents=True, exist_ok=True)
    yield
    await engine.dispose()



app = FastAPI(
    title=settings.APP_NAME,
    version="1.0.0",
    description="TrustVault Enterprise Document Vault API",
    lifespan=lifespan
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID"],
)


@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    """Ensure every incoming HTTP request has an X-Request-ID correlation header."""
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = request_id
    response: Response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


@app.get("/health", tags=["Health"])
async def health_check():
    """Basic liveness probe."""
    return {"status": "ok", "service": settings.APP_NAME}


@app.get("/health/ready", tags=["Health"])
async def readiness_check(db: AsyncSession = Depends(get_db)):
    """Check database connectivity and private vault accessibility."""
    db_status = "error"

    try:
        result = await db.execute(text("SELECT 1"))
        if result.scalar() == 1:
            db_status = "ok"
    except Exception:
        # Do not expose database credentials or internal exception details.
        db_status = "error"

    vault_root = get_vault_root()
    vault_status = (
        "ok"
        if vault_root.is_dir()
        else "missing"
    )

    is_ready = db_status == "ok" and vault_status == "ok"

    return {
        "status": "ready" if is_ready else "not_ready",
        "database": db_status,
        "vault": vault_status,
    } if is_ready else Response(
        content='{"status":"not_ready","database":"'
        + db_status
        + '","vault":"'
        + vault_status
        + '"}',
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        media_type="application/json",
    )


@app.get("/health/live", tags=["Health"])
async def liveness_check():
    """Confirm that the application process is responding."""
    return {"status": "alive"}


@app.get("/health/config", tags=["Health"])
async def config_check():
    """Return non-sensitive configuration parameters for deployment verification."""
    return {
        "app_name": settings.APP_NAME,
        "app_env": settings.APP_ENV,
        "access_token_expire_minutes": settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        "refresh_token_expire_days": settings.REFRESH_TOKEN_EXPIRE_DAYS,
        "max_upload_size_bytes": settings.MAX_UPLOAD_SIZE_BYTES,
        "allowed_extensions": settings.allowed_extensions_list,
    }


# Include V1 API Router
app.include_router(api_router, prefix="/api/v1")
