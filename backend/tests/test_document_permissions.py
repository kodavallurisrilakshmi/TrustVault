
import uuid

import pytest
from sqlalchemy import select

from app.models.document import Document
from app.models.permission import DocumentPermission
from app.models.audit_log import AuditLog


@pytest.mark.asyncio
async def test_owner_can_grant_view_permission(
    client,
    db_session,
    test_user_a,
    test_user_b,
    user_a_headers,
):
    document_id = uuid.uuid4()

    document = Document(
        id=document_id,
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
        f"/api/v1/documents/{document_id}/permissions",
        headers=user_a_headers,
        json={
            "user_id": str(test_user_b.id),
            "permission_level": "view",
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["document_id"] == str(document_id)
    assert body["user_id"] == str(test_user_b.id)
    assert body["permission_level"] == "view"
    assert body["granted_by"] == str(test_user_a.id)

    result = await db_session.execute(
        select(DocumentPermission).where(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == test_user_b.id,
        )
    )
    assert result.scalar_one_or_none() is not None

    audit_result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "DOCUMENT_PERMISSION_GRANTED",
            AuditLog.target_id == str(document_id),
            AuditLog.actor_id == test_user_a.id,
        )
    )
    audit_entry = audit_result.scalar_one_or_none()

    assert audit_entry is not None
    assert audit_entry.result == "SUCCESS"
    assert audit_entry.metadata_json["recipient_user_id"] == str(test_user_b.id)
    assert audit_entry.record_hash


@pytest.mark.asyncio
async def test_non_owner_cannot_grant_permission(
    client,
    db_session,
    test_user_a,
    test_user_b,
    test_admin_user,
    user_b_headers,
):
    document_id = uuid.uuid4()

    document = Document(
        id=document_id,
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
        f"/api/v1/documents/{document_id}/permissions",
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
    document_id = uuid.uuid4()

    document = Document(
        id=document_id,
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
    url = f"/api/v1/documents/{document_id}/permissions"

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
    document_id = uuid.uuid4()

    document = Document(
        id=document_id,
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
        f"/api/v1/documents/{document_id}/permissions",
        headers=user_a_headers,
        json={
            "user_id": str(test_user_b.id),
            "permission_level": "admin",
        },
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_document_list_is_isolated_between_users(
    client,
    db_session,
    test_user_a,
    test_user_b,
    user_a_headers,
    user_b_headers,
):
    private_document_id = uuid.uuid4()
    shared_document_id = uuid.uuid4()

    private_document = Document(
        id=private_document_id,
        title="Alice Private Document",
        description=None,
        category="legal",
        owner_id=test_user_a.id,
        storage_key=f"test/{uuid.uuid4().hex}",
        original_filename="private.pdf",
        file_size_bytes=100,
        mime_type="application/pdf",
        content_sha256="e" * 64,
    )

    shared_document = Document(
        id=shared_document_id,
        title="Alice Shared Document",
        description=None,
        category="legal",
        owner_id=test_user_a.id,
        storage_key=f"test/{uuid.uuid4().hex}",
        original_filename="shared.pdf",
        file_size_bytes=100,
        mime_type="application/pdf",
        content_sha256="f" * 64,
    )

    db_session.add_all([private_document, shared_document])
    await db_session.flush()

    permission = DocumentPermission(
        id=uuid.uuid4(),
        document_id=shared_document_id,
        user_id=test_user_b.id,
        permission_level="view",
        granted_by=test_user_a.id,
    )
    db_session.add(permission)
    await db_session.commit()

    response_a = await client.get(
        "/api/v1/documents",
        headers=user_a_headers,
    )
    assert response_a.status_code == 200

    ids_a = {item["id"] for item in response_a.json()}
    assert str(private_document_id) in ids_a
    assert str(shared_document_id) in ids_a

    response_b = await client.get(
        "/api/v1/documents",
        headers=user_b_headers,
    )
    assert response_b.status_code == 200

    ids_b = {item["id"] for item in response_b.json()}
    assert str(shared_document_id) in ids_b
    assert str(private_document_id) not in ids_b


@pytest.mark.asyncio
async def test_revoked_viewer_loses_document_list_access(
    client,
    db_session,
    test_user_a,
    test_user_b,
    user_a_headers,
    user_b_headers,
):
    document_id = uuid.uuid4()

    document = Document(
        id=document_id,
        title="Revocation Security Test",
        description=None,
        category="legal",
        owner_id=test_user_a.id,
        storage_key=f"test/{uuid.uuid4().hex}",
        original_filename="revocation.pdf",
        file_size_bytes=100,
        mime_type="application/pdf",
        content_sha256="9" * 64,
    )
    db_session.add(document)
    await db_session.flush()

    permission = DocumentPermission(
        id=uuid.uuid4(),
        document_id=document_id,
        user_id=test_user_b.id,
        permission_level="view",
        granted_by=test_user_a.id,
    )
    db_session.add(permission)
    await db_session.commit()

    before = await client.get(
        "/api/v1/documents",
        headers=user_b_headers,
    )
    assert before.status_code == 200
    assert str(document_id) in {item["id"] for item in before.json()}

    revoke = await client.delete(
        f"/api/v1/documents/{document_id}/permissions/{test_user_b.id}",
        headers=user_a_headers,
    )
    assert revoke.status_code == 200
    assert revoke.json()["message"] == "Document access revoked successfully"

    after = await client.get(
        "/api/v1/documents",
        headers=user_b_headers,
    )
    assert after.status_code == 200
    assert str(document_id) not in {item["id"] for item in after.json()}

    audit_result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "DOCUMENT_PERMISSION_REVOKED",
            AuditLog.target_id == str(document_id),
            AuditLog.actor_id == test_user_a.id,
        )
    )
    audit_entry = audit_result.scalar_one_or_none()

    assert audit_entry is not None
    assert audit_entry.result == "SUCCESS"
    assert audit_entry.metadata_json["recipient_user_id"] == str(test_user_b.id)
    assert audit_entry.record_hash


@pytest.mark.asyncio
async def test_revoked_viewer_cannot_download_document(
    client,
    db_session,
    test_user_a,
    test_user_b,
    user_a_headers,
    user_b_headers,
    monkeypatch,
):
    from app.api.v1.endpoints.documents import LocalStorageService

    document_id = uuid.uuid4()

    document = Document(
        id=document_id,
        title="Download Revocation Test",
        description=None,
        category="legal",
        owner_id=test_user_a.id,
        storage_key=f"test/{uuid.uuid4().hex}",
        original_filename="revocation.pdf",
        file_size_bytes=12,
        mime_type="application/pdf",
        content_sha256="a" * 64,
    )
    db_session.add(document)
    await db_session.flush()

    permission = DocumentPermission(
        id=uuid.uuid4(),
        document_id=document_id,
        user_id=test_user_b.id,
        permission_level="view",
        granted_by=test_user_a.id,
    )
    db_session.add(permission)
    await db_session.commit()

    monkeypatch.setattr(
        LocalStorageService,
        "read_file",
        lambda self, storage_key: b"test file data",
    )

    download_url = f"/api/v1/documents/{document_id}/download"

    before = await client.get(download_url, headers=user_b_headers)
    assert before.status_code == 200
    assert before.content == b"test file data"

    revoke = await client.delete(
        f"/api/v1/documents/{document_id}/permissions/{test_user_b.id}",
        headers=user_a_headers,
    )
    assert revoke.status_code == 200
    assert revoke.json()["message"] == "Document access revoked successfully"

    after = await client.get(download_url, headers=user_b_headers)
    assert after.status_code == 404
    assert after.json()["detail"] == "Document not found"


@pytest.mark.asyncio
async def test_admin_cannot_download_private_document_without_permission(
    client,
    db_session,
    test_user_a,
    test_admin_user,
    admin_headers,
    monkeypatch,
):
    from app.api.v1.endpoints.documents import LocalStorageService

    document_id = uuid.uuid4()

    document = Document(
        id=document_id,
        title="Administrator Isolation Test",
        description=None,
        category="legal",
        owner_id=test_user_a.id,
        storage_key=f"test/{uuid.uuid4().hex}",
        original_filename="private.txt",
        file_size_bytes=11,
        mime_type="text/plain",
        content_sha256="a" * 64,
    )
    db_session.add(document)
    await db_session.commit()

    def fail_if_file_is_read(self, storage_key):
        pytest.fail("Storage must not be read before authorization")

    monkeypatch.setattr(
        LocalStorageService,
        "read_file",
        fail_if_file_is_read,
    )

    response = await client.get(
        f"/api/v1/documents/{document_id}/download",
        headers=admin_headers,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Document not found"

    audit_result = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "DOCUMENT_ACCESS_DENIED",
            AuditLog.target_id == str(document_id),
            AuditLog.actor_id == test_admin_user.id,
        )
    )
    audit_entry = audit_result.scalar_one_or_none()

    assert audit_entry is not None
    assert audit_entry.result == "DENIED"
    assert audit_entry.denial_reason == "NO_CURRENT_PERMISSION"
    assert audit_entry.record_hash


@pytest.mark.asyncio
async def test_permission_grant_rolls_back_when_audit_fails(
    client,
    db_session,
    test_user_a,
    test_user_b,
    user_a_headers,
    monkeypatch,
):
    from app.api.v1.endpoints import documents

    document_id = uuid.uuid4()
    user_b_id = test_user_b.id

    document = Document(
        id=document_id,
        title="Audit Failure Grant Test",
        description=None,
        category="general",
        owner_id=test_user_a.id,
        storage_key=f"test/{uuid.uuid4().hex}",
        original_filename="grant-test.txt",
        file_size_bytes=10,
        mime_type="text/plain",
        content_sha256="a" * 64,
    )
    db_session.add(document)
    await db_session.commit()

    async def fail_audit(**kwargs):
        raise RuntimeError("Simulated audit failure")

    monkeypatch.setattr(documents.AuditService, "log_event", fail_audit)

    response = await client.post(
        f"/api/v1/documents/{document_id}/permissions",
        headers=user_a_headers,
        json={
            "user_id": str(user_b_id),
            "permission_level": "view",
        },
    )

    assert response.status_code == 500

    result = await db_session.execute(
        select(DocumentPermission).where(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == user_b_id,
        )
    )
    assert result.scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_permission_revoke_rolls_back_when_audit_fails(
    client,
    db_session,
    test_user_a,
    test_user_b,
    user_a_headers,
    monkeypatch,
):
    from app.api.v1.endpoints import documents

    document_id = uuid.uuid4()
    user_b_id = test_user_b.id

    document = Document(
        id=document_id,
        title="Audit Failure Revoke Test",
        description=None,
        category="general",
        owner_id=test_user_a.id,
        storage_key=f"test/{uuid.uuid4().hex}",
        original_filename="revoke-test.txt",
        file_size_bytes=10,
        mime_type="text/plain",
        content_sha256="b" * 64,
    )
    db_session.add(document)
    await db_session.flush()

    permission = DocumentPermission(
        id=uuid.uuid4(),
        document_id=document_id,
        user_id=user_b_id,
        permission_level="view",
        granted_by=test_user_a.id,
    )
    db_session.add(permission)
    await db_session.commit()

    async def fail_audit(**kwargs):
        raise RuntimeError("Simulated audit failure")

    monkeypatch.setattr(documents.AuditService, "log_event", fail_audit)

    response = await client.delete(
        f"/api/v1/documents/{document_id}/permissions/{user_b_id}",
        headers=user_a_headers,
    )

    assert response.status_code == 500

    result = await db_session.execute(
        select(DocumentPermission).where(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == user_b_id,
        )
    )
    remaining_permission = result.scalar_one_or_none()

    assert remaining_permission is not None
    assert remaining_permission.permission_level == "view"
