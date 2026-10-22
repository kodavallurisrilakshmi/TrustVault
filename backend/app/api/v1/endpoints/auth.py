import uuid
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Request, status
import jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token
)
from app.models.user import User
from app.schemas.user import UserCreate, UserLogin, UserResponse
from app.schemas.token import Token, TokenRefreshRequest
from app.services.audit_service import AuditService
from app.api.deps import get_current_user, get_request_id

router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_in: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    request_id: str = Depends(get_request_id)
) -> Any:
    """Register a new user account with Argon2id password hashing."""
    actor_ip = request.client.host if request.client else "127.0.0.1"

    # Check if email is already registered
    stmt = select(User).where(User.email == user_in.email)
    existing = await db.execute(stmt)
    if existing.scalar_one_or_none():
        await AuditService.log_autonomous_denied(
            request_id=request_id,
            actor_ip=actor_ip,
            action="AUTH_REGISTER",
            target_type="user",
            denial_reason="EMAIL_ALREADY_EXISTS",
            metadata_json={"email": user_in.email}
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists"
        )

    user = User(
        email=user_in.email,
        hashed_password=hash_password(user_in.password),
        full_name=user_in.full_name,
        # Public registration never honors a client-supplied role.
        role="user",
        token_version=1,
        is_active=True
    )
    db.add(user)
    await db.flush()

    # Log successful registration within transaction
    await AuditService.log_event(
        db=db,
        request_id=request_id,
        actor_ip=actor_ip,
        action="AUTH_REGISTER",
        target_type="user",
        target_id=str(user.id),
        result="SUCCESS",
        actor_id=user.id,
        actor_email=user.email,
        metadata_json={"role": user.role}
    )
    await db.commit()
    await db.refresh(user)
    return user


@router.post("/login", response_model=Token)
async def login(
    login_data: UserLogin,
    request: Request,
    db: AsyncSession = Depends(get_db),
    request_id: str = Depends(get_request_id)
) -> Any:
    """Authenticate credentials and issue short-lived JWT access and refresh tokens."""
    actor_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent")

    stmt = select(User).where(User.email == login_data.email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not verify_password(login_data.password, user.hashed_password):
        await AuditService.log_autonomous_denied(
            request_id=request_id,
            actor_ip=actor_ip,
            user_agent=user_agent,
            action="AUTH_LOGIN",
            target_type="user",
            target_id=str(user.id) if user else None,
            actor_id=user.id if user else None,
            actor_email=login_data.email,
            denial_reason="INVALID_CREDENTIALS"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        await AuditService.log_autonomous_denied(
            request_id=request_id,
            actor_ip=actor_ip,
            user_agent=user_agent,
            action="AUTH_LOGIN",
            target_type="user",
            target_id=str(user.id),
            actor_id=user.id,
            actor_email=user.email,
            denial_reason="ACCOUNT_DEACTIVATED"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is deactivated. Contact an administrator.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        user_id=str(user.id),
        role=user.role,
        token_version=user.token_version
    )
    refresh_token = create_refresh_token(
        user_id=str(user.id),
        token_version=user.token_version
    )

    await AuditService.log_event(
        db=db,
        request_id=request_id,
        actor_ip=actor_ip,
        user_agent=user_agent,
        action="AUTH_LOGIN",
        target_type="user",
        target_id=str(user.id),
        result="SUCCESS",
        actor_id=user.id,
        actor_email=user.email,
        metadata_json={"token_version": user.token_version}
    )
    await db.commit()

    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )


@router.post("/refresh", response_model=Token)
async def refresh_token(
    refresh_in: TokenRefreshRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    request_id: str = Depends(get_request_id)
) -> Any:
    """Exchange valid refresh token for new access and refresh tokens."""
    actor_ip = request.client.host if request.client else "127.0.0.1"

    try:
        payload = decode_token(refresh_in.refresh_token)
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )

    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type"
        )

    user_id_str = payload.get("sub")
    token_version = payload.get("token_version")

    stmt = select(User).where(User.id == uuid.UUID(user_id_str))
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not user.is_active or user.token_version != token_version:
        await AuditService.log_autonomous_denied(
            request_id=request_id,
            actor_ip=actor_ip,
            action="AUTH_REFRESH",
            target_type="user",
            actor_id=user.id if user else None,
            denial_reason="TOKEN_VERSION_REVOKED"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token revoked or invalid"
        )

    new_access_token = create_access_token(
        user_id=str(user.id),
        role=user.role,
        token_version=user.token_version
    )
    new_refresh_token = create_refresh_token(
        user_id=str(user.id),
        token_version=user.token_version
    )
    return Token(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer"
    )


@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    request_id: str = Depends(get_request_id)
) -> Any:
    """
    Log out user and immediately invalidate all outstanding JWT tokens.
    Increments users.token_version so any token previously issued becomes invalid immediately.
    """
    actor_ip = request.client.host if request.client else "127.0.0.1"

    current_user.token_version += 1
    await AuditService.log_event(
        db=db,
        request_id=request_id,
        actor_ip=actor_ip,
        action="AUTH_LOGOUT",
        target_type="user",
        target_id=str(current_user.id),
        result="SUCCESS",
        actor_id=current_user.id,
        actor_email=current_user.email,
        metadata_json={"new_token_version": current_user.token_version}
    )
    await db.commit()
    return {"message": "Successfully logged out. All active sessions invalidated."}


@router.get("/me", response_model=UserResponse)
async def get_me(
    current_user: User = Depends(get_current_user)
) -> Any:
    """Return currently authenticated user profile."""
    return current_user
