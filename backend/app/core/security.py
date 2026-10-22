import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from app.core.config import settings

# Initialize Argon2id password hasher with secure enterprise parameters
# time_cost: 3 iterations
# memory_cost: 64 MB (65536 KiB)
# parallelism: 4 lanes
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16
)


def hash_password(password: str) -> str:
    """Hash password using Argon2id with recommended parameters."""
    return _hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify plain password against stored Argon2id hash."""
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def create_access_token(
    user_id: str,
    role: str,
    token_version: int,
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Generate short-lived JWT access token.
    Claims contain user ID, role, session token_version, and unique jti.
    CRITICAL: Document permissions are NEVER included in the JWT.
    """
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "role": role,
        "token_version": token_version,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "nbf": now,
        "exp": expire,
        "type": "access",
    }
    encoded_jwt = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def create_refresh_token(
    user_id: str,
    token_version: int,
    expires_delta: Optional[timedelta] = None
) -> str:
    """Generate longer-lived JWT refresh token."""
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    payload: Dict[str, Any] = {
        "sub": str(user_id),
        "token_version": token_version,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "nbf": now,
        "exp": expire,
        "type": "refresh",
    }
    encoded_jwt = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> Dict[str, Any]:
    """
    Decode and cryptographically verify a JWT.
    Raises jwt.PyJWTError subclasses on failure.
    """
    return jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM],
        options={"require": ["sub", "exp", "token_version", "type"]}
    )
