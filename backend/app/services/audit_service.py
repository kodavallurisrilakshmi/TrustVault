
import uuid
from datetime import datetime, timezone
from typing import Optional, Any, Dict, List

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog
from app.schemas.audit import AuditChainVerificationResult
from app.core.database import async_session_factory


# Global advisory lock ID for serializing audit-chain writes in PostgreSQL.
AUDIT_CHAIN_ADVISORY_LOCK_ID = 748192837


class AuditService:
    @staticmethod
    async def log_event(
        db: AsyncSession,
        request_id: str,
        actor_ip: str,
        action: str,
        target_type: str,
        result: str,
        actor_id: Optional[uuid.UUID] = None,
        actor_email: Optional[str] = None,
        user_agent: Optional[str] = None,
        target_id: Optional[str] = None,
        denial_reason: Optional[str] = None,
        metadata_json: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """
        Record an audit event in the provided database transaction.

        PostgreSQL advisory transaction locking serializes hash-chain writes.
        The lock remains held until the surrounding transaction commits or
        rolls back. Lock failures are not silently ignored.
        """
        # Require PostgreSQL because the audit chain relies on its
        # transaction-level advisory lock for concurrent-write safety.
        dialect_name = db.get_bind().dialect.name

        if dialect_name != "postgresql":
            raise RuntimeError(
                "Audit hash-chain writes require PostgreSQL advisory locking."
            )

        # 1. Acquire the transaction-level advisory lock.
        await db.execute(
            text("SELECT pg_advisory_xact_lock(:lock_id)"),
            {"lock_id": AUDIT_CHAIN_ADVISORY_LOCK_ID},
        )

        # 2. Generate the timestamp after acquiring the lock so the
        # timestamp reflects the serialized write order more closely.
        now = datetime.now(timezone.utc)
        safe_metadata = metadata_json or {}

        # 3. Read the latest record's hash while holding the lock.
        stmt = (
            select(AuditLog.record_hash)
            .order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
            .limit(1)
        )
        prev_hash_res = await db.execute(stmt)
        prev_hash = prev_hash_res.scalar_one_or_none()

        # 4. Calculate the deterministic record hash.
        record_hash = AuditLog.calculate_record_hash(
            prev_hash=prev_hash,
            timestamp=now,
            request_id=request_id,
            actor_id=actor_id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            result=result,
            denial_reason=denial_reason,
            metadata_json=safe_metadata,
        )

        # 5. Construct the audit record.
        audit_entry = AuditLog(
            request_id=request_id,
            actor_id=actor_id,
            actor_email=actor_email,
            actor_ip=actor_ip,
            user_agent=user_agent,
            action=action,
            target_type=target_type,
            target_id=target_id,
            result=result,
            denial_reason=denial_reason,
            metadata_json=safe_metadata,
            prev_hash=prev_hash,
            record_hash=record_hash,
            timestamp=now,
        )

        db.add(audit_entry)
        return audit_entry

    @classmethod
    async def log_autonomous_denied(
        cls,
        request_id: str,
        actor_ip: str,
        action: str,
        target_type: str,
        actor_id: Optional[uuid.UUID] = None,
        actor_email: Optional[str] = None,
        user_agent: Optional[str] = None,
        target_id: Optional[str] = None,
        denial_reason: Optional[str] = None,
        metadata_json: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Record a denied or forbidden event in an independent session.

        This allows unauthorized attempts to be recorded independently of
        the main business transaction.
        """
        async with async_session_factory() as session:
            try:
                await cls.log_event(
                    db=session,
                    request_id=request_id,
                    actor_ip=actor_ip,
                    action=action,
                    target_type=target_type,
                    result="DENIED",
                    actor_id=actor_id,
                    actor_email=actor_email,
                    user_agent=user_agent,
                    target_id=target_id,
                    denial_reason=denial_reason,
                    metadata_json=metadata_json,
                )
                await session.commit()
            except Exception:
                await session.rollback()
                # Do not expose internal audit errors to the caller.
                # A production deployment should separately monitor and
                # alert on audit-write failures.
                pass

    @staticmethod
    async def verify_chain(
        db: AsyncSession,
    ) -> AuditChainVerificationResult:
        """
        Verify audit records in chronological order.

        Detects broken previous-hash links and modified record contents.
        """
        stmt = select(AuditLog).order_by(
            AuditLog.timestamp.asc(),
            AuditLog.id.asc(),
        )

        result = await db.execute(
            stmt.execution_options(populate_existing=True)
        )
        records: List[AuditLog] = list(result.scalars().all())

        if not records:
            return AuditChainVerificationResult(
                is_valid=True,
                total_records=0,
                message="Audit log is empty. Genesis state valid.",
            )

        expected_prev_hash: Optional[str] = None

        for idx, record in enumerate(records):
            # Check the link to the preceding record.
            if record.prev_hash != expected_prev_hash:
                return AuditChainVerificationResult(
                    is_valid=False,
                    total_records=len(records),
                    broken_record_id=record.id,
                    expected_hash=expected_prev_hash,
                    actual_hash=record.prev_hash,
                    message=(
                        f"Broken prev_hash chain link at index {idx} "
                        f"(record {record.id})"
                    ),
                )

            # Recompute the record hash from its stored contents.
            recomputed = AuditLog.calculate_record_hash(
                prev_hash=record.prev_hash,
                timestamp=record.timestamp,
                request_id=record.request_id,
                actor_id=record.actor_id,
                action=record.action,
                target_type=record.target_type,
                target_id=record.target_id,
                result=record.result,
                denial_reason=record.denial_reason,
                metadata_json=record.metadata_json,
            )

            if record.record_hash != recomputed:
                return AuditChainVerificationResult(
                    is_valid=False,
                    total_records=len(records),
                    broken_record_id=record.id,
                    expected_hash=recomputed,
                    actual_hash=record.record_hash,
                    message=(
                        f"Tampered record content detected at index {idx} "
                        f"(record {record.id})"
                    ),
                )

            expected_prev_hash = record.record_hash

        return AuditChainVerificationResult(
            is_valid=True,
            total_records=len(records),
            message=(
                "Cryptographic audit chain fully verified "
                f"({len(records)} records)."
            ),
        )
