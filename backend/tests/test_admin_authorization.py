
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
