import uuid
import asyncio
from datetime import datetime, timezone
import pytest
from httpx import AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.models.user import User
from app.services.audit_service import AuditService


@pytest.mark.asyncio
async def test_audit_event_logged_on_successful_login(
    client: AsyncClient,
    test_user_a: User,
    db_session: AsyncSession
):
    """Verify that successful authentication writes an immutable audit record."""
    request_id = str(uuid.uuid4())
    res = await client.post(
        "/api/v1/auth/login",
        json={"email": test_user_a.email, "password": "UserASecurePassword123!"},
        headers={"X-Request-ID": request_id}
    )
    assert res.status_code == 200

    stmt = select(AuditLog).where(AuditLog.request_id == request_id)
    audit_res = await db_session.execute(stmt)
    entry = audit_res.scalar_one_or_none()

    assert entry is not None
    assert entry.action == "AUTH_LOGIN"
    assert entry.result == "SUCCESS"
    assert entry.actor_id == test_user_a.id
    assert entry.actor_email == test_user_a.email
    assert entry.record_hash is not None


@pytest.mark.asyncio
async def test_autonomous_audit_logging_on_denied_attempt(
    client: AsyncClient,
    db_session: AsyncSession
):
    """Verify that rejected access generates an autonomous audit record with DENIED status."""
    request_id = str(uuid.uuid4())
    res = await client.post(
        "/api/v1/auth/login",
        json={"email": "attacker@example.com", "password": "BadPassword123!"},
        headers={"X-Request-ID": request_id}
    )
    assert res.status_code == 401

    stmt = select(AuditLog).where(AuditLog.request_id == request_id)
    audit_res = await db_session.execute(stmt)
    entry = audit_res.scalar_one_or_none()

    assert entry is not None
    assert entry.action == "AUTH_LOGIN"
    assert entry.result == "DENIED"
    assert entry.denial_reason == "INVALID_CREDENTIALS"




@pytest.mark.asyncio
async def test_audit_chain_tamper_detection(
    db_session: AsyncSession
):
    """
    Verify that tampering with an audit record is detected,
    then restore the original record for subsequent tests.
    """
    req1 = str(uuid.uuid4())
    req2 = str(uuid.uuid4())
    req3 = str(uuid.uuid4())

    entry1 = await AuditService.log_event(
        db=db_session,
        request_id=req1,
        actor_ip="127.0.0.1",
        action="TEST_ACTION_1",
        target_type="document",
        result="SUCCESS"
    )
    await db_session.commit()

    entry2 = await AuditService.log_event(
        db=db_session,
        request_id=req2,
        actor_ip="127.0.0.1",
        action="TEST_ACTION_2",
        target_type="document",
        result="SUCCESS"
    )
    await db_session.commit()

    entry3 = await AuditService.log_event(
        db=db_session,
        request_id=req3,
        actor_ip="127.0.0.1",
        action="TEST_ACTION_3",
        target_type="document",
        result="SUCCESS"
    )
    await db_session.commit()

    # Confirm the chain is initially valid.
    initial_verification = await AuditService.verify_chain(db_session)
    assert initial_verification.is_valid is True

    # Simulate tampering in the isolated test database.
    await db_session.execute(
        text(
            "ALTER TABLE audit_logs "
            "DISABLE TRIGGER trg_audit_logs_immutable"
        )
    )

    try:
        await db_session.execute(
            text(
                "UPDATE audit_logs "
                "SET action = 'TAMPERED_ACTION' "
                "WHERE id = :record_id"
            ),
            {"record_id": entry2.id}
        )
        await db_session.commit()
    finally:
        await db_session.execute(
            text(
                "ALTER TABLE audit_logs "
                "ENABLE TRIGGER trg_audit_logs_immutable"
            )
        )
        await db_session.commit()

    # Confirm that tampering is detected.
    tampered_verification = await AuditService.verify_chain(db_session)
    assert tampered_verification.is_valid is False
    assert tampered_verification.broken_record_id == entry2.id
    assert "Tampered record content detected" in tampered_verification.message

    # Restore the original action in the isolated test database.
    await db_session.execute(
        text(
            "ALTER TABLE audit_logs "
            "DISABLE TRIGGER trg_audit_logs_immutable"
        )
    )

    try:
        await db_session.execute(
            text(
                "UPDATE audit_logs "
                "SET action = 'TEST_ACTION_2' "
                "WHERE id = :record_id"
            ),
            {"record_id": entry2.id}
        )
        await db_session.commit()
    finally:
        await db_session.execute(
            text(
                "ALTER TABLE audit_logs "
                "ENABLE TRIGGER trg_audit_logs_immutable"
            )
        )
        await db_session.commit()

    # Confirm restoration makes the chain valid again.
    restored_verification = await AuditService.verify_chain(db_session)
    assert restored_verification.is_valid is True




@pytest.mark.asyncio
async def test_audit_chain_concurrency_continuity():
    """
    Verify concurrent audit writes preserve a valid hash chain.
    Each task gets its own database session.
    """
    from app.services.audit_service import async_session_factory

    async def write_log(idx: int):
        async with async_session_factory() as session:
            await AuditService.log_event(
                db=session,
                request_id=f"concurrent-req-{idx}-{uuid.uuid4()}",
                actor_ip="10.0.0.1",
                action=f"CONCURRENT_ACTION_{idx}",
                target_type="document",
                result="SUCCESS",
            )
            await session.commit()

    await asyncio.gather(*(write_log(i) for i in range(5)))

    async with async_session_factory() as session:
        verification = await AuditService.verify_chain(session)

    assert verification.is_valid is True
