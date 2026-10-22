import uuid
from typing import List, Any
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.user import User
from app.schemas.user import UserResponse, UserStatusUpdate, UserRoleUpdate
from app.api.deps import require_admin_user, get_request_id
from app.services.audit_service import AuditService

router = APIRouter()


@router.get("", response_model=List[UserResponse])
async def list_users(
    db: AsyncSession = Depends(get_db),
    admin_user: User = Depends(require_admin_user)
) -> Any:
    """Administrator-only: list all platform users."""
    stmt = select(User).order_by(User.created_at.desc())
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.patch("/{user_id}/status", response_model=UserResponse)
async def update_user_status(
    user_id: uuid.UUID,
    status_update: UserStatusUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin_user: User = Depends(require_admin_user),
    request_id: str = Depends(get_request_id)
) -> Any:
    """
    Administrator-only: activate or deactivate user account.
    Deactivating increments token_version to immediately revoke all outstanding sessions.
    """
    actor_ip = request.client.host if request.client else "127.0.0.1"

    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    target_user = result.scalar_one_or_none()

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Prevent admin from deactivating their own account
    if target_user.id == admin_user.id and not status_update.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot deactivate their own account"
        )

    target_user.is_active = status_update.is_active
    if not status_update.is_active:
        # Immediate session invalidation across all devices
        target_user.token_version += 1

    await AuditService.log_event(
        db=db,
        request_id=request_id,
        actor_ip=actor_ip,
        action="USER_STATUS_UPDATE",
        target_type="user",
        target_id=str(target_user.id),
        result="SUCCESS",
        actor_id=admin_user.id,
        actor_email=admin_user.email,
        metadata_json={
            "target_email": target_user.email,
            "is_active": target_user.is_active,
            "new_token_version": target_user.token_version
        }
    )
    await db.commit()
    await db.refresh(target_user)
    return target_user


@router.patch("/{user_id}/role", response_model=UserResponse)
async def update_user_role(
    user_id: uuid.UUID,
    role_update: UserRoleUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin_user: User = Depends(require_admin_user),
    request_id: str = Depends(get_request_id)
) -> Any:
    """Administrator-only: update user role."""
    actor_ip = request.client.host if request.client else "127.0.0.1"

    stmt = select(User).where(User.id == user_id)
    result = await db.execute(stmt)
    target_user = result.scalar_one_or_none()

    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    old_role = target_user.role
    target_user.role = role_update.role
    target_user.token_version += 1  # Invalidate current session to force role refresh

    await AuditService.log_event(
        db=db,
        request_id=request_id,
        actor_ip=actor_ip,
        action="USER_ROLE_UPDATE",
        target_type="user",
        target_id=str(target_user.id),
        result="SUCCESS",
        actor_id=admin_user.id,
        actor_email=admin_user.email,
        metadata_json={
            "target_email": target_user.email,
            "old_role": old_role,
            "new_role": target_user.role
        }
    )
    await db.commit()
    await db.refresh(target_user)
    return target_user
