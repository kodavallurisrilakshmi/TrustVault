
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import ProgrammingError, InternalError, DBAPIError

from app.services.audit_service import AuditService


@pytest.mark.asyncio
async def test_audit_logs_immutability_trigger_blocks_update(
    db_session: AsyncSession,
):
    """Verify the audit-log trigger blocks UPDATE operations."""
    req_id = str(uuid.uuid4())
    entry = await AuditService.log_event(
        db=db_session,
        request_id=req_id,
        actor_ip="127.0.0.1",
        action="TEST_ACTION",
        target_type="document",
        result="SUCCESS",
    )
    await db_session.commit()
    entry_id = entry.id

    try:
        await db_session.execute(
            text("UPDATE audit_logs SET result = 'ALTERED' WHERE id = :id"),
            {"id": entry_id},
        )
        await db_session.commit()

        if db_session.get_bind().dialect.name == "postgresql":
            pytest.fail(
                "UPDATE on audit_logs succeeded but should have been blocked!"
            )

    except (DBAPIError, InternalError, ProgrammingError) as exc:
        assert (
            "Audit logs are immutable" in str(exc)
            or "prohibited" in str(exc).lower()
            or "permission denied" in str(exc).lower()
        )
        await db_session.rollback()

    original_entry = await db_session.get(type(entry), entry_id)
    assert original_entry is not None
    assert original_entry.result == "SUCCESS"


@pytest.mark.asyncio
async def test_audit_logs_immutability_trigger_blocks_delete(
    db_session: AsyncSession,
):
    """Verify the audit-log trigger blocks DELETE operations."""
    req_id = str(uuid.uuid4())
    entry = await AuditService.log_event(
        db=db_session,
        request_id=req_id,
        actor_ip="127.0.0.1",
        action="TEST_ACTION_DELETE",
        target_type="document",
        result="SUCCESS",
    )
    await db_session.commit()
    entry_id = entry.id

    try:
        await db_session.execute(
            text("DELETE FROM audit_logs WHERE id = :id"),
            {"id": entry_id},
        )
        await db_session.commit()

        if db_session.get_bind().dialect.name == "postgresql":
            pytest.fail(
                "DELETE on audit_logs succeeded but should have been blocked!"
            )

    except (DBAPIError, InternalError, ProgrammingError) as exc:
        assert (
            "Audit logs are immutable" in str(exc)
            or "prohibited" in str(exc).lower()
            or "permission denied" in str(exc).lower()
        )
        await db_session.rollback()

    original_entry = await db_session.get(type(entry), entry_id)
    assert original_entry is not None
    assert original_entry.action == "TEST_ACTION_DELETE"
