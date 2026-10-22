
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_regular_user_cannot_verify_audit_chain(
    client: AsyncClient,
    user_b_headers: dict,
):
    response = await client.get(
        "/api/v1/audit/verify",
        headers=user_b_headers,
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Administrative privileges required"


@pytest.mark.asyncio
async def test_admin_can_verify_audit_chain(
    client: AsyncClient,
    admin_headers: dict,
):
    response = await client.get(
        "/api/v1/audit/verify",
        headers=admin_headers,
    )

    assert response.status_code == 200

    body = response.json()
    assert body["is_valid"] is True



@pytest.mark.asyncio
async def test_regular_user_cannot_read_audit_logs(
    client: AsyncClient,
    user_b_headers: dict,
):
    response = await client.get(
        "/api/v1/audit/logs",
        headers=user_b_headers,
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_unauthenticated_clients_cannot_access_audit_endpoints(
    client: AsyncClient,
):
    logs_response = await client.get("/api/v1/audit/logs")
    verify_response = await client.get("/api/v1/audit/verify")

    assert logs_response.status_code == 401
    assert verify_response.status_code == 401


@pytest.mark.asyncio
async def test_regular_user_cannot_list_platform_users(
    client: AsyncClient,
    user_b_headers: dict,
):
    response = await client.get(
        "/api/v1/users",
        headers=user_b_headers,
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_regular_user_cannot_change_another_users_role(
    client: AsyncClient,
    test_user_a,
    user_b_headers: dict,
):
    response = await client.patch(
        f"/api/v1/users/{test_user_a.id}/role",
        headers=user_b_headers,
        json={"role": "admin"},
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_regular_user_cannot_change_another_users_status(
    client: AsyncClient,
    test_user_a,
    user_b_headers: dict,
):
    response = await client.patch(
        f"/api/v1/users/{test_user_a.id}/status",
        headers=user_b_headers,
        json={"is_active": False},
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_role_change_revokes_old_access_token(
    client: AsyncClient,
    test_admin_user,
    test_user_a,
    admin_headers: dict,
    user_a_headers: dict,
):
    # Confirm the user's existing token initially works.
    before_response = await client.get(
        "/api/v1/auth/me",
        headers=user_a_headers,
    )
    assert before_response.status_code == 200

    # Change the user's role as an administrator.
    role_response = await client.patch(
        f"/api/v1/users/{test_user_a.id}/role",
        headers=admin_headers,
        json={"role": "admin"},
    )
    assert role_response.status_code == 200
    assert role_response.json()["role"] == "admin"

    # The previous token must now be rejected.
    after_response = await client.get(
        "/api/v1/auth/me",
        headers=user_a_headers,
    )
    assert after_response.status_code == 401
