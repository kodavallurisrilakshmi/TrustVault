import uuid
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, ConfigDict


class DocumentBase(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    description: Optional[str] = None
    category: str = Field(default="general", max_length=64)


class DocumentCreate(DocumentBase):
    pass


class DocumentMetadataUpdate(BaseModel):
    title: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = None
    category: Optional[str] = Field(default=None, max_length=64)


class DocumentResponse(DocumentBase):
    id: uuid.UUID
    owner_id: uuid.UUID
    original_filename: str
    file_size_bytes: int
    mime_type: str
    content_sha256: str
    is_deleted: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OwnershipTransferRequest(BaseModel):
    destination_user_id: uuid.UUID
    reason: str = Field(min_length=5, max_length=500, description="Audit justification for administrative ownership transfer")
