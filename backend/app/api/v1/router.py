from fastapi import APIRouter
from app.api.v1.endpoints import auth, users, audit,documents

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(audit.router, prefix="/audit", tags=["Audit"])
api_router.include_router(
    documents.router,
    prefix="/documents",
    tags=["Documents"],
)