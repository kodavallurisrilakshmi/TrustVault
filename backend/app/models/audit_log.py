import uuid
import hashlib
import json
from datetime import datetime, timezone
from typing import Optional, Any, Dict
from sqlalchemy import String, DateTime, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    request_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True
    )
    actor_id: Mapped[Optional[uuid.UUID]] = mapped_column(
    UUID(as_uuid=True),
    nullable=True,
    index=True
    )
    actor_email: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True
    )
    actor_ip: Mapped[str] = mapped_column(
        String(45),
        nullable=False
    )
    user_agent: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True
    )
    action: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True
    )
    target_type: Mapped[str] = mapped_column(
        String(32),
        nullable=False
    )
    target_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True,
        index=True
    )
    result: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        index=True
    )  # 'SUCCESS', 'DENIED', 'ERROR'
    denial_reason: Mapped[Optional[str]] = mapped_column(
        String(128),
        nullable=True
    )
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict
    )
    prev_hash: Mapped[Optional[str]] = mapped_column(
        String(64),
        nullable=True
    )
    record_hash: Mapped[str] = mapped_column(
        String(64),
        nullable=False
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True
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
        metadata_json: Dict[str, Any]
    ) -> str:
        """
        Compute SHA-256 hash chaining link.
        Canonicalizes fields into a deterministic preimage string.
        """
        canonical_metadata = json.dumps(metadata_json or {}, sort_keys=True, separators=(",", ":"))
        timestamp_str = timestamp.isoformat()
        preimage = (
            f"{prev_hash or 'GENESIS'}|"
            f"{timestamp_str}|"
            f"{request_id}|"
            f"{str(actor_id) if actor_id else 'ANONYMOUS'}|"
            f"{action}|"
            f"{target_type}|"
            f"{target_id or ''}|"
            f"{result}|"
            f"{denial_reason or ''}|"
            f"{canonical_metadata}"
        )
        return hashlib.sha256(preimage.encode("utf-8")).hexdigest()
