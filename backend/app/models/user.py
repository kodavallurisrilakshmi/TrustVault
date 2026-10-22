import uuid
from typing import List, TYPE_CHECKING
from sqlalchemy import String, Boolean, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin

if TYPE_CHECKING:
    from app.models.document import Document
    from app.models.permission import DocumentPermission


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        index=True,
        nullable=False
    )
    hashed_password: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )
    full_name: Mapped[str] = mapped_column(
        String(255),
        nullable=False
    )
    role: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="user"
    )
    token_version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True
    )

    # Relationships
    owned_documents: Mapped[List["Document"]] = relationship(
        "Document",
        back_populates="owner",
        cascade="all, delete-orphan",
        foreign_keys="Document.owner_id"
    )
    permissions: Mapped[List["DocumentPermission"]] = relationship(
        "DocumentPermission",
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="DocumentPermission.user_id"
    )
