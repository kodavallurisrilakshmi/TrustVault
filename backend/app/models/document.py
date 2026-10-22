import uuid
from typing import List, Optional, TYPE_CHECKING
from sqlalchemy import String, Text, BigInteger, Boolean, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.permission import DocumentPermission


class Document(Base, TimestampMixin):
    __tablename__ = "documents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    title: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True
    )
    category: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        default="general",
        index=True
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    storage_key: Mapped[str] = mapped_column(
        String(128),
        unique=True,
        nullable=False,
        index=True
    )
    original_filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )
    file_size_bytes: Mapped[int] = mapped_column(
        BigInteger,
        nullable=False
    )
    mime_type: Mapped[str] = mapped_column(
        String(128),
        nullable=False
    )
    content_sha256: Mapped[str] = mapped_column(
        String(64),
        nullable=False
    )
    is_deleted: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False
    )

    # Relationships
    owner: Mapped["User"] = relationship(
        "User",
        back_populates="owned_documents",
        foreign_keys=[owner_id]
    )
    permissions: Mapped[List["DocumentPermission"]] = relationship(
        "DocumentPermission",
        back_populates="document",
        cascade="all, delete-orphan"
    )
