
import uuid

import pytest
from fastapi import HTTPException

from app.models.document import Document
from app.models.permission import DocumentPermission
from app.services.document_access_service import DocumentAccessService


@pytest.mark.asyncio
async def test_owner_can_access_own_document(
    db_session, test_user_a
):
    document = Document(
        id=uuid.uuid4(),
        title="Private Contract",
        description="Confidential document",
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

    result = await DocumentAccessService.get_document_for_user(
        db_session, document.id, test_user_a
    )

    assert result.id == document.id


@pytest.mark.asyncio
async def test_unpermitted_user_cannot_access_document(
    db_session, test_user_a, test_user_b
):
    document = Document(
        id=uuid.uuid4(),
        title="Private Contract",
        description=None,
        category="legal",
        owner_id=test_user_a.id,
        storage_key=f"test/{uuid.uuid4().hex}",
        original_filename="contract.pdf",
        file_size_bytes=100,
        mime_type="application/pdf",
        content_sha256="b" * 64,
    )
    db_session.add(document)
    await db_session.commit()

    with pytest.raises(HTTPException) as exc:
        await DocumentAccessService.get_document_for_user(
            db_session, document.id, test_user_b
        )

    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_view_permission_does_not_allow_edit(
    db_session, test_user_a, test_user_b
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
    await db_session.flush()

    permission = DocumentPermission(
        id=uuid.uuid4(),
        document_id=document.id,
        user_id=test_user_b.id,
        permission_level="view",
        granted_by=test_user_a.id,
    )
    db_session.add(permission)
    await db_session.commit()

    # Viewing is allowed.
    result = await DocumentAccessService.get_document_for_user(
        db_session, document.id, test_user_b, required_level="view"
    )
    assert result.id == document.id

    # Editing is denied.
    with pytest.raises(HTTPException) as exc:
        await DocumentAccessService.get_document_for_user(
            db_session, document.id, test_user_b, required_level="edit"
        )

    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_deleted_document_is_not_accessible(
    db_session, test_user_a
):
    document = Document(
        id=uuid.uuid4(),
        title="Deleted Contract",
        description=None,
        category="legal",
        owner_id=test_user_a.id,
        storage_key=f"test/{uuid.uuid4().hex}",
        original_filename="deleted.pdf",
        file_size_bytes=100,
        mime_type="application/pdf",
        content_sha256="d" * 64,
        is_deleted=True,
    )
    db_session.add(document)
    await db_session.commit()

    with pytest.raises(HTTPException) as exc:
        await DocumentAccessService.get_document_for_user(
            db_session, document.id, test_user_a
        )

    assert exc.value.status_code == 404
