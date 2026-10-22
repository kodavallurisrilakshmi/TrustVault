
import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.document import Document
from app.models.permission import DocumentPermission
from app.models.user import User


class DocumentAccessService:
    """Centralized server-side authorization for document access."""

    @staticmethod
    async def get_document_for_user(
        db: AsyncSession,
        document_id: uuid.UUID,
        current_user: User,
        required_level: str = "view",
    ) -> Document:
        """
        Return a document only if the user owns it or has sufficient
        explicit permission. Admin status alone grants no content access.
        """
        if required_level not in {"view", "edit"}:
            raise ValueError("required_level must be 'view' or 'edit'")

        result = await db.execute(
            select(Document).where(
                Document.id == document_id,
                Document.is_deleted.is_(False),
            )
        )
        document = result.scalar_one_or_none()

        # Use the same response for missing and inaccessible documents
        # to reduce document-ID enumeration.
        if document is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Document not found",
            )

        if document.owner_id == current_user.id:
            return document

        permission_result = await db.execute(
            select(DocumentPermission.permission_level).where(
                DocumentPermission.document_id == document.id,
                DocumentPermission.user_id == current_user.id,
            )
        )
        permission_level = permission_result.scalar_one_or_none()

        allowed = (
            permission_level == "edit"
            or (
                required_level == "view"
                and permission_level == "view"
            )
        )

        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Document not found",
            )

        return document
