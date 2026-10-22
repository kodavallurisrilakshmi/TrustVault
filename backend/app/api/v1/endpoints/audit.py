import uuid
from datetime import datetime
from typing import List, Optional, Any
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.user import User
from app.models.audit_log import AuditLog
from app.schemas.audit import AuditLogResponse, AuditChainVerificationResult
from app.api.deps import require_admin_user
from app.services.audit_service import AuditService

router = APIRouter()


@router.get("/logs", response_model=List[AuditLogResponse])
async def get_audit_logs(
    actor_id: Optional[uuid.UUID] = Query(None, description="Filter by actor user ID"),
    action: Optional[str] = Query(None, description="Filter by action code"),
    target_type: Optional[str] = Query(None, description="Filter by target type"),
    target_id: Optional[str] = Query(None, description="Filter by target resource ID"),
    result: Optional[str] = Query(None, description="Filter by outcome: SUCCESS, DENIED, ERROR"),
    from_date: Optional[datetime] = Query(None, description="Filter records starting from timestamp"),
    to_date: Optional[datetime] = Query(None, description="Filter records up to timestamp"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    admin_user: User = Depends(require_admin_user)
) -> Any:
    """Administrator-only: query immutable audit log records with comprehensive filters."""
    query = select(AuditLog).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())

    if actor_id:
        query = query.where(AuditLog.actor_id == actor_id)
    if action:
        query = query.where(AuditLog.action == action)
    if target_type:
        query = query.where(AuditLog.target_type == target_type)
    if target_id:
        query = query.where(AuditLog.target_id == target_id)
    if result:
        query = query.where(AuditLog.result == result)
    if from_date:
        query = query.where(AuditLog.timestamp >= from_date)
    if to_date:
        query = query.where(AuditLog.timestamp <= to_date)

    query = query.limit(limit).offset(offset)
    res = await db.execute(query)
    return list(res.scalars().all())


@router.get("/verify", response_model=AuditChainVerificationResult)
async def verify_audit_chain(
    db: AsyncSession = Depends(get_db),
    admin_user: User = Depends(require_admin_user)
) -> Any:
    """
    Administrator-only: execute complete cryptographic verification of the audit hash chain.
    Validates sequential continuity from genesis and recalculates all hashes to detect any tampering.
    """
    return await AuditService.verify_chain(db)
