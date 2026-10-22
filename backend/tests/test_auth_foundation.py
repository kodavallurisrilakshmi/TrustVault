import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password, verify_password, create_access_token
from app.models.user import User


def test_argon2id_password_hashing():
    """Verify passwords are authenticated with Argon2id and mismatches are rejected."""
    raw_password = "SuperSecurePassword987!"
    hashed = hash_password(raw_password)

    # Hash must start with $argon2id$
    assert hashed.startswith("$argon2id$")
    assert verify_password(raw_password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


@pytest.mark.asyncio
async def test_user_registration_and_login_flow(client: AsyncClient, db_session: AsyncSession):
    """Test full registration, login, and profile retrieval flow."""
    unique_email = f"test_{uuid.uuid4().hex[:8]}@example.com"
    reg_payload = {
        "email": unique_email,
        "password": "Password123!Secure",
        "full_name": "Test Engineer"
    }

    # 1. Register
    reg_res = await client.post("/api/v1/auth/register", json=reg_payload)
    assert reg_res.status_code == 201
    user_data = reg_res.json()
    assert user_data["email"] == unique_email
    assert user_data["role"] == "user"
    assert user_data["token_version"] == 1
    assert "hashed_password" not in user_data

    # 2. Duplicate registration rejected
    dup_res = await client.post("/api/v1/auth/register", json=reg_payload)
    assert dup_res.status_code == 400
    assert "already exists" in dup_res.json()["detail"]

    # 3. Login with correct credentials
    login_res = await client.post("/api/v1/auth/login", json={
        "email": unique_email,
        "password": "Password123!Secure"
    })
    assert login_res.status_code == 200
    token_data = login_res.json()
    assert "access_token" in token_data
    assert "refresh_token" in token_data
    assert token_data["token_type"] == "bearer"

    # 4. Access /me endpoint
    access_token = token_data["access_token"]
    me_res = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    assert me_res.status_code == 200
    assert me_res.json()["email"] == unique_email


@pytest.mark.asyncio
async def test_ordinary_registration_creates_non_admin_user(
    client: AsyncClient,
    db_session: AsyncSession
):
    """Ordinary public registration still succeeds and always yields role=user."""
    unique_email = f"ordinary_{uuid.uuid4().hex[:8]}@example.com"
    res = await client.post("/api/v1/auth/register", json={
        "email": unique_email,
        "password": "Password123!Secure",
        "full_name": "Ordinary Registrant"
    })
    assert res.status_code == 201
    body = res.json()
    assert body["email"] == unique_email
    assert body["role"] == "user"
    assert body["role"] != "admin"
    assert "hashed_password" not in body

    stored = await db_session.execute(select(User).where(User.email == unique_email))
    user = stored.scalar_one()
    assert user.role == "user"


@pytest.mark.asyncio
async def test_registration_ignores_client_supplied_admin_role(
    client: AsyncClient,
    db_session: AsyncSession
):
    """Submitting role=admin on the public register endpoint must not create an administrator."""
    unique_email = f"escalation_{uuid.uuid4().hex[:8]}@example.com"
    res = await client.post("/api/v1/auth/register", json={
        "email": unique_email,
        "password": "Password123!Secure",
        "full_name": "Would Be Admin",
        "role": "admin"
    })
    assert res.status_code == 201
    body = res.json()
    assert body["email"] == unique_email
    assert body["role"] == "user"
    assert body["role"] != "admin"

    stored = await db_session.execute(select(User).where(User.email == unique_email))
    user = stored.scalar_one()
    assert user.role == "user"
    assert user.role != "admin"


@pytest.mark.asyncio
async def test_invalid_credentials_rejected(client: AsyncClient):
    """Test that invalid credentials return 401 without timing or enumeration leaks."""
    res = await client.post("/api/v1/auth/login", json={
        "email": "nonexistent@example.com",
        "password": "WrongPassword123!"
    })
    assert res.status_code == 401
    assert "Incorrect email or password" in res.json()["detail"]


@pytest.mark.asyncio
async def test_tampered_jwt_signature_rejected(client: AsyncClient, user_a_headers: dict):
    """Test that a tampered JWT token payload or signature is strictly rejected."""
    valid_token = user_a_headers["Authorization"].split(" ")[1]
    # Tamper with the signature portion
    tampered_token = valid_token[:-4] + "xxxx"

    res = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {tampered_token}"}
    )
    assert res.status_code == 401
    assert "Invalid or malformed authentication token" in res.json()["detail"]


@pytest.mark.asyncio
async def test_token_version_immediate_revocation(
    client: AsyncClient,
    test_user_a: User,
    user_a_headers: dict,
    db_session: AsyncSession
):
    """
    Test that logout increments token_version and immediately revokes active token.
    On subsequent requests, the revoked token must be rejected with 401.
    """
    # 1. Request succeeds with current token
    before_res = await client.get("/api/v1/auth/me", headers=user_a_headers)
    assert before_res.status_code == 200

    # 2. Call logout endpoint
    logout_res = await client.post("/api/v1/auth/logout", headers=user_a_headers)
    assert logout_res.status_code == 200

    # 3. Attempt subsequent request with the old token -> MUST BE REJECTED IMMEDIATELY
    after_res = await client.get("/api/v1/auth/me", headers=user_a_headers)
    assert after_res.status_code == 401
    assert "Session has been revoked" in after_res.json()["detail"]


@pytest.mark.asyncio
async def test_deactivated_account_immediate_revocation(
    client: AsyncClient,
    test_user_a: User,
    user_a_headers: dict,
    admin_headers: dict,
    db_session: AsyncSession
):
    """
    Test that when an administrator deactivates an account,
    token_version is incremented and active user requests are blocked immediately.
    """
    # 1. Active user succeeds
    pre_res = await client.get("/api/v1/auth/me", headers=user_a_headers)
    assert pre_res.status_code == 200

    # 2. Admin deactivates User A
    deactivate_res = await client.patch(
        f"/api/v1/users/{test_user_a.id}/status",
        headers=admin_headers,
        json={"is_active": False}
    )
    assert deactivate_res.status_code == 200
    assert deactivate_res.json()["is_active"] is False

    # 3. User A makes subsequent request -> MUST BE REJECTED IMMEDIATELY
    post_res = await client.get("/api/v1/auth/me", headers=user_a_headers)
    assert post_res.status_code == 401


@pytest.mark.asyncio
async def test_expired_jwt_is_rejected(client, test_user_a):
    """An expired access token must not authenticate a request."""
    from datetime import timedelta
    from app.core.security import create_access_token

    expired_token = create_access_token(
        user_id=str(test_user_a.id),
        role=test_user_a.role,
        token_version=test_user_a.token_version,
        expires_delta=timedelta(seconds=-60),
    )

    response = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )

    assert response.status_code == 401
