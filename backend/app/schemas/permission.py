import uuid
from datetime import datetime
from pydantic import BaseModel, Field


class PermissionGrantRequest(BaseModel):
    user_id: uuid.UUID
    permission_level: str = Field(pattern="^(view|edit)$")


class PermissionResponse(BaseModel):
    id: uuid.UUID
    document_id: uuid.UUID
    user_id: uuid.UUID
    permission_level: str
    granted_by: uuid.UUID
    created_at: datetime

    class Config:
        from_attributes = True
