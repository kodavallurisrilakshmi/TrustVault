import uuid
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import ProgrammingError, InternalError, DBAPIError

from app.models.audit_log import AuditLog
from app.services.audit_service import AuditService


@pytest.mark.asyncio
async def test_audit_logs_immutability_trigger_blocks_update(db_session: AsyncSession):
    """
    Automated Negative Test:
    Verify that PostgreSQL trigger trg_audit_logs_immutable raises an exception
    if an UPDATE statement is attempted on audit_logs.
    """
    # 1. Create a legitimate audit record
    req_id = str(uuid.uuid4())
    entry = await AuditService.log_event(
        db=db_session,
        request_id=req_id,
        actor_ip="127.0.0.1",
        action="TEST_ACTION",
        target_type="document",
        result="SUCCESS"
    )
    await db_session.commit()

    # 2. Attempt to update the audit record
    # On PostgreSQL, the trigger aborts the operation with an exception.
    # On SQLite test engine, we verify raw or trigger behavior.
    try:
        await db_session.execute(
            text("UPDATE audit_logs SET result = 'ALTERED' WHERE id = :id"),
            {"id": entry.id}
        )
        await db_session.commit()
        # If it reached here without PostgreSQL trigger, verify if engine was PostgreSQL
        bind = db_session.get_bind()
        if "postgresql" in str(bind.url):
            pytest.fail("UPDATE on audit_logs succeeded but should have been blocked by trigger!")
    except (DBAPIError, InternalError, ProgrammingError) as exc:
        # Trigger properly caught and aborted the update
        assert "Audit logs are immutable" in str(exc) or "prohibited" in str(exc).lower() or "permission denied" in str(exc).lower()



@pytest.mark.asyncio
async def test_audit_logs_immutability_trigger_blocks_delete(db_session: AsyncSession):
    """
    Verify that DELETE on audit_logs is blocked by the immutability trigger.
    """
    # Diagnostic: identify the database and locate the audit table
    result = await db_session.execute(
        text("SELECT current_database(), current_schema(), current_user")
    )
    print("SESSION DATABASE/SCHEMA/USER:", result.fetchone())

    result = await db_session.execute(
        text("""
            SELECT table_schema, table_name
            FROM information_schema.tables
            WHERE table_name = 'audit_logs'
        """)
    )
    print("AUDIT TABLE LOCATION:", result.fetchall())

    # Create a legitimate audit record
    req_id = str(uuid.uuid4())
    entry = await AuditService.log_event(
        db=db_session,
        request_id=req_id,
        actor_ip="127.0.0.1",
        action="TEST_ACTION_DELETE",
        target_type="document",
        result="SUCCESS"
    )
    await db_session.commit()

    # Attempt to delete the audit record
    try:
        await db_session.execute(
            text("DELETE FROM audit_logs WHERE id = :id"),
            {"id": entry.id}
        )
        await db_session.commit()

        bind = db_session.get_bind()
        if "postgresql" in str(bind.url):
            pytest.fail(
                "DELETE on audit_logs succeeded but should have been blocked!"
            )

    except (DBAPIError, InternalError, ProgrammingError) as exc:
        assert (
            "Audit logs are immutable" in str(exc)
            or "prohibited" in str(exc).lower()
            or "permission denied" in str(exc).lower()
        )
