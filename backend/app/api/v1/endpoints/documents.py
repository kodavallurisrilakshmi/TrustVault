
import uuid
import re
import hashlib
from pathlib import Path

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    Response,
    status,
    File,
    Form,
    UploadFile,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_request_id
from app.core.config import settings
from app.core.database import get_db
from app.models.document import Document
from app.models.permission import DocumentPermission
from app.models.user import User
from app.schemas.document import DocumentResponse
from app.schemas.permission import PermissionGrantRequest, PermissionResponse
from app.services.audit_service import AuditService
from app.storage.local_storage import LocalStorageService

router = APIRouter()


@router.get("", response_model=list[DocumentResponse])
async def list_documents(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List documents owned by or shared with the authenticated user."""

    from sqlalchemy import or_

    result = await db.execute(
        select(Document)
        .outerjoin(
            DocumentPermission,
            DocumentPermission.document_id == Document.id,
        )
        .where(
            Document.is_deleted.is_(False),
            or_(
                Document.owner_id == current_user.id,
                (
                    (DocumentPermission.user_id == current_user.id)
                    & DocumentPermission.permission_level.in_(["view", "edit"])
                ),
            ),
        )
        .distinct()
        .order_by(Document.updated_at.desc())
    )

    return result.scalars().all()



@router.post(
    "",
    response_model=DocumentResponse,
    status_code=status.HTTP_201_CREATED,
)
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    title: str | None = Form(default=None),
    description: str | None = Form(default=None),
    category: str = Form(default="general"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    request_id: str = Depends(get_request_id),
):
    """Upload a private document and record its metadata and audit event."""

    supplied_name = (file.filename or "").replace("\\", "/")
    filename = supplied_name.rsplit("/", 1)[-1].strip()

    if not filename or filename in {".", ".."}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A valid filename is required",
        )

    if any(ord(char) < 32 or ord(char) == 127 for char in filename):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename contains invalid characters",
        )

    if len(filename) > 255:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename must not exceed 255 characters",
        )

    extension = Path(filename).suffix.lower().lstrip(".")

    if extension not in settings.allowed_extensions_list:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="File extension is not allowed",
        )

    document_title = (title or Path(filename).stem).strip()

    if not document_title or len(document_title) > 255:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Title must contain 1 to 255 characters",
        )

    if len(category) > 64 or not category.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Category must contain 1 to 64 characters",
        )

    if description is not None and len(description) > 10000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Description must not exceed 10000 characters",
        )

    max_size = settings.MAX_UPLOAD_SIZE_BYTES
    storage = LocalStorageService()
    storage_key = None
    total_size = 0
    digest = hashlib.sha256()

    try:
        storage_key, file_path = storage.create_file()

        # Stream in chunks rather than loading the complete upload into memory.
        with file_path.open("wb") as destination:
            while True:
                chunk = await file.read(1024 * 1024)

                if not chunk:
                    break

                total_size += len(chunk)

                if total_size > max_size:
                    raise HTTPException(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        detail="File exceeds the maximum upload size",
                    )

                digest.update(chunk)
                destination.write(chunk)

        if total_size == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Empty files are not allowed",
            )

        document = Document(
            id=uuid.uuid4(),
            title=document_title,
            description=description,
            category=category.strip(),
            owner_id=current_user.id,
            storage_key=storage_key,
            original_filename=filename,
            file_size_bytes=total_size,
            mime_type=file.content_type or "application/octet-stream",
            content_sha256=digest.hexdigest(),
            is_deleted=False,
        )

        db.add(document)

        actor_ip = request.client.host if request.client else "127.0.0.1"

        await AuditService.log_event(
            db=db,
            request_id=request_id,
            actor_ip=actor_ip,
            action="DOCUMENT_UPLOADED",
            target_type="document",
            target_id=str(document.id),
            result="SUCCESS",
            actor_id=current_user.id,
            actor_email=current_user.email,
            user_agent=request.headers.get("user-agent"),
            metadata_json={
                "filename": filename,
                "file_size_bytes": total_size,
                "content_sha256": digest.hexdigest(),
            },
        )

        await db.commit()
        await db.refresh(document)

        return document

    except Exception:
        await db.rollback()

        if storage_key is not None:
            storage.delete_file(storage_key)

        raise

    finally:
        await file.close()


@router.post(
    "/{document_id}/permissions",
    response_model=PermissionResponse,
    status_code=status.HTTP_201_CREATED,
)
async def grant_document_permission(
    document_id: uuid.UUID,
    payload: PermissionGrantRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    request_id: str = Depends(get_request_id),
):
    """Allow document owners to grant view or edit access."""

    result = await db.execute(
        select(Document).where(
            Document.id == document_id,
            Document.is_deleted.is_(False),
        )
    )
    document = result.scalar_one_or_none()

    if document is None or document.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    if payload.user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You already own this document",
        )

    target_result = await db.execute(
        select(User).where(
            User.id == payload.user_id,
            User.is_active.is_(True),
        )
    )
    target_user = target_result.scalar_one_or_none()

    if target_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    existing_result = await db.execute(
        select(DocumentPermission).where(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == payload.user_id,
        )
    )

    if existing_result.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Permission already exists",
        )

    permission = DocumentPermission(
        id=uuid.uuid4(),
        document_id=document_id,
        user_id=payload.user_id,
        permission_level=payload.permission_level,
        granted_by=current_user.id,
    )
    db.add(permission)

    actor_ip = request.client.host if request.client else "127.0.0.1"

    await AuditService.log_event(
        db=db,
        request_id=request_id,
        actor_ip=actor_ip,
        action="DOCUMENT_PERMISSION_GRANTED",
        target_type="document",
        target_id=str(document_id),
        result="SUCCESS",
        actor_id=current_user.id,
        actor_email=current_user.email,
        user_agent=request.headers.get("user-agent"),
        metadata_json={
            "recipient_user_id": str(target_user.id),
            "permission_level": payload.permission_level,
        },
    )

    await db.commit()
    await db.refresh(permission)

    return permission


@router.delete("/{document_id}/permissions/{user_id}")
async def revoke_document_permission(
    document_id: uuid.UUID,
    user_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    request_id: str = Depends(get_request_id),
):
    """Allow document owners to revoke a user's access immediately."""

    result = await db.execute(
        select(Document).where(
            Document.id == document_id,
            Document.is_deleted.is_(False),
        )
    )
    document = result.scalar_one_or_none()

    if document is None or document.owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    permission_result = await db.execute(
        select(DocumentPermission).where(
            DocumentPermission.document_id == document_id,
            DocumentPermission.user_id == user_id,
        )
    )
    permission = permission_result.scalar_one_or_none()

    if permission is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found",
        )

    old_level = permission.permission_level
    await db.delete(permission)

    actor_ip = request.client.host if request.client else "127.0.0.1"

    await AuditService.log_event(
        db=db,
        request_id=request_id,
        actor_ip=actor_ip,
        action="DOCUMENT_PERMISSION_REVOKED",
        target_type="document",
        target_id=str(document_id),
        result="SUCCESS",
        actor_id=current_user.id,
        actor_email=current_user.email,
        user_agent=request.headers.get("user-agent"),
        metadata_json={
            "recipient_user_id": str(user_id),
            "revoked_permission_level": old_level,
        },
    )

    await db.commit()

    return {
        "message": "Document access revoked successfully",
        "document_id": str(document_id),
        "user_id": str(user_id),
    }


@router.get("/{document_id}/download")
async def download_document(
    document_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    request_id: str = Depends(get_request_id),
):
    """Download a document only after checking current database permissions."""

    # Find a document that has not been deleted.
    result = await db.execute(
        select(Document).where(
            Document.id == document_id,
            Document.is_deleted.is_(False),
        )
    )
    document = result.scalar_one_or_none()

    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    # The owner always has access to their own document.
    is_owner = document.owner_id == current_user.id

    # Check the viewer's current permission in PostgreSQL.
    permission = None

    if not is_owner:
        permission_result = await db.execute(
            select(DocumentPermission).where(
                DocumentPermission.document_id == document.id,
                DocumentPermission.user_id == current_user.id,
            )
        )
        permission = permission_result.scalar_one_or_none()

    # Do not disclose the document to unauthorized users.
    if not is_owner and (
        permission is None
        or permission.permission_level not in ("view", "edit")
    ):
        actor_ip = request.client.host if request.client else "127.0.0.1"

        await AuditService.log_event(
            db=db,
            request_id=request_id,
            actor_ip=actor_ip,
            actor_id=current_user.id,
            actor_email=current_user.email,
            user_agent=request.headers.get("user-agent"),
            action="DOCUMENT_ACCESS_DENIED",
            target_type="document",
            target_id=str(document.id),
            result="DENIED",
            denial_reason="NO_CURRENT_PERMISSION",
            metadata_json={},
        )
        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    # Only read the private file after authorization succeeds.
    storage = LocalStorageService()

    try:
        content = storage.read_file(document.storage_key)
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document file not found",
        )

    # Record successful access without recording file contents.
    actor_ip = request.client.host if request.client else "127.0.0.1"

    await AuditService.log_event(
        db=db,
        request_id=request_id,
        actor_ip=actor_ip,
        actor_id=current_user.id,
        actor_email=current_user.email,
        user_agent=request.headers.get("user-agent"),
        action="DOCUMENT_DOWNLOADED",
        target_type="document",
        target_id=str(document.id),
        result="SUCCESS",
        metadata_json={
            "filename": document.original_filename,
            "file_size_bytes": document.file_size_bytes,
            "content_sha256": document.content_sha256,
        },
    )
    await db.commit()

    # Prevent filename characters from injecting response headers.
    safe_filename = re.sub(
        r"[^A-Za-z0-9._-]",
        "_",
        document.original_filename,
    )[:200] or "document"

    return Response(
        content=content,
        media_type=document.mime_type,
        headers={
            "Content-Disposition": f'attachment; filename="{safe_filename}"',
            "X-Content-Type-Options": "nosniff",
        },
    )
