
import uuid
import hashlib
import json
from datetime import datetime, timezone
from typing import Optional, Any, Dict

from sqlalchemy import String, DateTime
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    request_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    actor_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
        index=True,
    )
    actor_email: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    actor_ip: Mapped[str] = mapped_column(
        String(45),
        nullable=False,
    )
    user_agent: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
    )
    action: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    target_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    target_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )
    result: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        index=True,
    )
    denial_reason: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True,
    )
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
    )
    prev_hash: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
    )
    hash_version: Mapped[int] = mapped_column(
        nullable=False,
        default=2,
        server_default="2",
    )
    record_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    @staticmethod
    def calculate_record_hash(
        prev_hash: Optional[str],
        timestamp: datetime,
        request_id: str,
        actor_id: Optional[uuid.UUID],
        action: str,
        target_type: str,
        target_id: Optional[str],
        result: str,
        denial_reason: Optional[str],
        metadata_json: Dict[str, Any],
        actor_email: Optional[str] = None,
        actor_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> str:
        """
        Calculate a deterministic SHA-256 audit hash.

        Calls that omit all three actor details retain the legacy
        format. New audit writes must include actor details.
        """
        canonical_metadata = json.dumps(
            metadata_json or {},
            sort_keys=True,
            separators=(",", ":"),
        )

        # Use a consistent UTC representation regardless of the
        # timezone offset returned by the database.
        if timestamp.tzinfo is not None:
            timestamp = timestamp.astimezone(timezone.utc)

        timestamp_str = timestamp.isoformat()
        previous = prev_hash or "GENESIS"
        actor = str(actor_id) if actor_id else "ANONYMOUS"

        # Preserve the original preimage structure for legacy records.
        if (
            actor_email is None
            and actor_ip is None
            and user_agent is None
        ):
            preimage = (
                f"{previous}|"
                f"{timestamp_str}|"
                f"{request_id}|"
                f"{actor}|"
                f"{action}|"
                f"{target_type}|"
                f"{target_id or ''}|"
                f"{result}|"
                f"{denial_reason or ''}|"
                f"{canonical_metadata}"
            )
        else:
            payload = {
                "hash_version": 2,
                "prev_hash": previous,
                "timestamp": timestamp_str,
                "request_id": request_id,
                "actor_id": actor,
                "actor_email": actor_email,
                "actor_ip": actor_ip,
                "user_agent": user_agent,
                "action": action,
                "target_type": target_type,
                "target_id": target_id,
                "result": result,
                "denial_reason": denial_reason,
                "metadata": metadata_json or {},
            }
            preimage = json.dumps(
                payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )

        return hashlib.sha256(
            preimage.encode("utf-8")
        ).hexdigest()
