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
from unittest.mock import AsyncMock, MagicMock


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




@pytest.mark.asyncio
async def test_autonomous_denied_audit_failure_is_logged(monkeypatch, caplog):
    """Verify that denied-audit persistence failures are logged."""
    import logging
    from unittest.mock import AsyncMock, MagicMock

    from app.services import audit_service

    mock_session = MagicMock()
    mock_session.__aenter__ = AsyncMock(return_value=mock_session)
    mock_session.__aexit__ = AsyncMock(return_value=False)
    mock_session.rollback = AsyncMock()

    monkeypatch.setattr(
        audit_service,
        "async_session_factory",
        lambda: mock_session,
    )
    monkeypatch.setattr(
        AuditService,
        "log_event",
        AsyncMock(side_effect=RuntimeError("simulated audit failure")),
    )

    with caplog.at_level(logging.ERROR, logger="app.services.audit_service"):
        await AuditService.log_autonomous_denied(
            request_id="audit-failure-test",
            actor_ip="127.0.0.1",
            action="TEST_DENIED_ACTION",
            target_type="document",
        )

    mock_session.rollback.assert_awaited_once()
    assert "Failed to persist denied audit event" in caplog.text
    assert "audit-failure-test" in caplog.text
    assert "simulated audit failure" in caplog.text


@pytest.mark.asyncio
async def test_audit_chain_detects_broken_previous_hash(
    db_session: AsyncSession,
    monkeypatch,
):
    """Verify that the audit verifier detects a broken previous-hash link."""
    for action in ("LINK_TEST_1", "LINK_TEST_2"):
        await AuditService.log_event(
            db=db_session,
            request_id=str(uuid.uuid4()),
            actor_ip="127.0.0.1",
            action=action,
            target_type="document",
            result="SUCCESS",
        )
        await db_session.commit()

    initial = await AuditService.verify_chain(db_session)
    assert initial.is_valid is True

    # Load the actual records, then simulate a corrupted link in memory.
    result = await db_session.execute(
        select(AuditLog).order_by(AuditLog.timestamp.asc(), AuditLog.id.asc())
    )
    records = list(result.scalars().all())

    assert len(records) >= 2

    second = next(
        record for record in records
        if record.action == "LINK_TEST_2"
    )
    original_prev_hash = second.prev_hash
    second.prev_hash = "f" * 64

    # Return the simulated records directly so the database cannot refresh
    # and overwrite the in-memory corruption during verification.
    mocked_result = MagicMock()
    mocked_result.scalars.return_value.all.return_value = records

    monkeypatch.setattr(
        db_session,
        "execute",
        AsyncMock(return_value=mocked_result),
    )

    try:
        tampered = await AuditService.verify_chain(db_session)

        assert tampered.is_valid is False
        assert tampered.broken_record_id == second.id
        assert "Broken prev_hash chain link" in tampered.message
    finally:
        second.prev_hash = original_prev_hash
        monkeypatch.undo()
        await db_session.rollback()

    restored = await AuditService.verify_chain(db_session)
    assert restored.is_valid is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field_name", "tampered_value"),
    [
        ("actor_email", "tampered@example.com"),
        ("actor_ip", "203.0.113.99"),
        ("user_agent", "Tampered-Test-Agent"),
    ],
)
async def test_audit_chain_detects_actor_metadata_tampering(
    db_session: AsyncSession,
    monkeypatch,
    field_name: str,
    tampered_value: str,
):
    """Verify actor email, IP, and user-agent changes invalidate new audit hashes."""
    request_id = str(uuid.uuid4())

    await AuditService.log_event(
        db=db_session,
        request_id=request_id,
        actor_email="original@example.com",
        actor_ip="127.0.0.1",
        user_agent="Original-Test-Agent",
        action="ACTOR_METADATA_TAMPER_TEST",
        target_type="document",
        result="SUCCESS",
    )
    await db_session.commit()

    initial = await AuditService.verify_chain(db_session)
    assert initial.is_valid is True

    result = await db_session.execute(
        select(AuditLog).order_by(
            AuditLog.timestamp.asc(),
            AuditLog.id.asc(),
        )
    )
    records = list(result.scalars().all())

    target = next(
        record for record in records
        if record.request_id == request_id
    )

    original_value = getattr(target, field_name)
    setattr(target, field_name, tampered_value)

    mocked_result = MagicMock()
    mocked_result.scalars.return_value.all.return_value = records

    monkeypatch.setattr(
        db_session,
        "execute",
        AsyncMock(return_value=mocked_result),
    )

    try:
        verification = await AuditService.verify_chain(db_session)

        assert verification.is_valid is False
        assert verification.broken_record_id == target.id
        assert "Tampered record content detected" in verification.message
    finally:
        setattr(target, field_name, original_value)
        monkeypatch.undo()
        await db_session.rollback()

    restored = await AuditService.verify_chain(db_session)
    assert restored.is_valid is True

def test_legacy_audit_hash_preserves_unicode_metadata_serialization():
    """Legacy hashes must retain the original ASCII-escaped JSON format."""
    import hashlib
    import json

    timestamp = datetime(
        2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc
    )
    metadata = {"document_title": "Résumé 📄"}
    request_id = "legacy-unicode-test"

    legacy_preimage = (
        "GENESIS|"
        f"{timestamp.isoformat()}|"
        f"{request_id}|"
        "ANONYMOUS|"
        "TEST_ACTION|"
        "document|"
        "doc-1|"
        "SUCCESS|"
        "|"
        + json.dumps(
            metadata,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    expected_hash = hashlib.sha256(
        legacy_preimage.encode("utf-8")
    ).hexdigest()

    actual_hash = AuditLog.calculate_record_hash(
        prev_hash=None,
        timestamp=timestamp,
        request_id=request_id,
        actor_id=None,
        action="TEST_ACTION",
        target_type="document",
        target_id="doc-1",
        result="SUCCESS",
        denial_reason=None,
        metadata_json=metadata,
    )

    assert actual_hash == expected_hash


@pytest.mark.asyncio
async def test_audit_chain_verifies_mixed_legacy_and_new_hash_formats(
    db_session: AsyncSession,
):
    """Verify a legacy-format record can precede a new-format record."""
    legacy_timestamp = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    legacy_request_id = f"legacy-{uuid.uuid4()}"

    # Create a genuine legacy-format hash by omitting actor metadata.
    legacy_hash = AuditLog.calculate_record_hash(
        prev_hash=None,
        timestamp=legacy_timestamp,
        request_id=legacy_request_id,
        actor_id=None,
        action="LEGACY_TEST_EVENT",
        target_type="document",
        target_id="legacy-doc",
        result="SUCCESS",
        denial_reason=None,
        metadata_json={"format": "legacy"},
    )

    legacy_record = AuditLog(
        request_id=legacy_request_id,
        actor_id=None,
        actor_email=None,
        actor_ip="127.0.0.1",
        user_agent=None,
        action="LEGACY_TEST_EVENT",
        target_type="document",
        target_id="legacy-doc",
        result="SUCCESS",
        denial_reason=None,
        metadata_json={"format": "legacy"},
        prev_hash=None,
        record_hash=legacy_hash,
        timestamp=legacy_timestamp,
        hash_version=1,
    )
    db_session.add(legacy_record)
    await db_session.flush()

    # Create a new-format record whose previous hash links to the legacy one.
    new_timestamp = datetime(2026, 1, 1, 12, 1, 0, tzinfo=timezone.utc)
    new_request_id = f"new-{uuid.uuid4()}"
    new_actor_ip = "127.0.0.1"
    new_user_agent = "Mixed-Format-Test"

    new_hash = AuditLog.calculate_record_hash(
        prev_hash=legacy_hash,
        timestamp=new_timestamp,
        request_id=new_request_id,
        actor_id=None,
        action="NEW_TEST_EVENT",
        target_type="document",
        target_id="new-doc",
        result="SUCCESS",
        denial_reason=None,
        metadata_json={"format": "new"},
        actor_email="tester@example.com",
        actor_ip=new_actor_ip,
        user_agent=new_user_agent,
    )

    new_record = AuditLog(
        request_id=new_request_id,
        actor_id=None,
        actor_email="tester@example.com",
        actor_ip=new_actor_ip,
        user_agent=new_user_agent,
        action="NEW_TEST_EVENT",
        target_type="document",
        target_id="new-doc",
        result="SUCCESS",
        denial_reason=None,
        metadata_json={"format": "new"},
        prev_hash=legacy_hash,
        record_hash=new_hash,
        timestamp=new_timestamp,
        hash_version=2,
    )
    db_session.add(new_record)
    await db_session.commit()

    # Verify this test's two records independently of other test data.
    from unittest.mock import AsyncMock, MagicMock

    mocked_result = MagicMock()
    mocked_result.scalars.return_value.all.return_value = [
        legacy_record,
        new_record,
    ]

    original_execute = db_session.execute
    try:
        db_session.execute = AsyncMock(return_value=mocked_result)

        verification = await AuditService.verify_chain(db_session)

        assert verification.is_valid is True
        assert verification.total_records == 2
    finally:
        db_session.execute = original_execute



@pytest.mark.asyncio
async def test_audit_chain_rejects_unsupported_hash_version(
    db_session: AsyncSession,
):
    """Reject records whose hash version is not explicitly supported."""
    timestamp = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    request_id = f"unsupported-{uuid.uuid4()}"

    # The hash is deliberately irrelevant: version 99 must be rejected
    # before the verifier attempts to validate the record hash.
    record = AuditLog(
        request_id=request_id,
        actor_id=None,
        actor_email="tester@example.com",
        actor_ip="127.0.0.1",
        user_agent="Unsupported-Version-Test",
        action="UNSUPPORTED_VERSION_TEST",
        target_type="document",
        target_id="unsupported-doc",
        result="SUCCESS",
        denial_reason=None,
        metadata_json={},
        prev_hash=None,
        record_hash="0" * 64,
        hash_version=99,
        timestamp=timestamp,
    )

    mocked_result = MagicMock()
    mocked_result.scalars.return_value.all.return_value = [record]

    original_execute = db_session.execute
    try:
        db_session.execute = AsyncMock(return_value=mocked_result)

        verification = await AuditService.verify_chain(db_session)

        assert verification.is_valid is False
        assert verification.total_records == 1
        assert verification.broken_record_id == record.id
        assert "Unsupported audit hash version 99" in verification.message
    finally:
        db_session.execute = original_execute
