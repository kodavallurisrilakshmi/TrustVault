
import uuid

import pytest
from sqlalchemy import select

from app.models.document import Document
from app.models.permission import DocumentPermission


@pytest.mark.asyncio
async def test_owner_can_grant_view_permission(
    client,
    db_session,
    test_user_a,
    test_user_b,
    user_a_headers,
):
    document = Document(
        id=uuid.uuid4(),
        title="Shared Contract",
        description=None,
        category="legal",
        owner_id=test_user_a.id,
        storage_key=f"test/{uuid.uuid4().hex}",
        original_filename="contract.pdf",
        file_size_bytes=100,
        mime_type="application/pdf",
        content_sha256="a" * 64,
    )
    db_session.add(document)
    await db_session.commit()

    response = await client.post(
        f"/api/v1/documents/{document.id}/permissions",
        headers=user_a_headers,
        json={
            "user_id": str(test_user_b.id),
            "permission_level": "view",
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["document_id"] == str(document.id)
    assert body["user_id"] == str(test_user_b.id)
    assert body["permission_level"] == "view"
    assert body["granted_by"] == str(test_user_a.id)

    result = await db_session.execute(
        select(DocumentPermission).where(
            DocumentPermission.document_id == document.id,
            DocumentPermission.user_id == test_user_b.id,
        )
    )
    assert result.scalar_one_or_none() is not None


@pytest.mark.asyncio
async def test_non_owner_cannot_grant_permission(
    client,
    db_session,
    test_user_a,
    test_user_b,
    test_admin_user,
    user_b_headers,
):
    document = Document(
        id=uuid.uuid4(),
        title="Private Contract",
        description=None,
        category="legal",
        owner_id=test_user_a.id,
        storage_key=f"test/{uuid.uuid4().hex}",
        original_filename="private.pdf",
        file_size_bytes=100,
        mime_type="application/pdf",
        content_sha256="b" * 64,
    )
    db_session.add(document)
    await db_session.commit()

    response = await client.post(
        f"/api/v1/documents/{document.id}/permissions",
        headers=user_b_headers,
        json={
            "user_id": str(test_admin_user.id),
            "permission_level": "view",
        },
    )

    assert response.status_code == 404


@pytest.mark.asyncio
async def test_duplicate_permission_grant_is_rejected(
    client,
    db_session,
    test_user_a,
    test_user_b,
    user_a_headers,
):
    document = Document(
        id=uuid.uuid4(),
        title="Shared Contract",
        description=None,
        category="legal",
        owner_id=test_user_a.id,
        storage_key=f"test/{uuid.uuid4().hex}",
        original_filename="shared.pdf",
        file_size_bytes=100,
        mime_type="application/pdf",
        content_sha256="c" * 64,
    )
    db_session.add(document)
    await db_session.commit()

    payload = {
        "user_id": str(test_user_b.id),
        "permission_level": "view",
    }
    url = f"/api/v1/documents/{document.id}/permissions"

    first = await client.post(url, headers=user_a_headers, json=payload)
    assert first.status_code == 201

    second = await client.post(url, headers=user_a_headers, json=payload)
    assert second.status_code == 409


@pytest.mark.asyncio
async def test_invalid_permission_level_is_rejected(
    client,
    db_session,
    test_user_a,
    test_user_b,
    user_a_headers,
):
    document = Document(
        id=uuid.uuid4(),
        title="Permission Test",
        description=None,
        category="general",
        owner_id=test_user_a.id,
        storage_key=f"test/{uuid.uuid4().hex}",
        original_filename="test.pdf",
        file_size_bytes=100,
        mime_type="application/pdf",
        content_sha256="d" * 64,
    )
    db_session.add(document)
    await db_session.commit()

    response = await client.post(
        f"/api/v1/documents/{document.id}/permissions",
        headers=user_a_headers,
        json={
            "user_id": str(test_user_b.id),
            "permission_level": "admin",
        },
    )

    assert response.status_code == 422
