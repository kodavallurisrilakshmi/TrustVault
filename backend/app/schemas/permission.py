import uuid
from datetime import datetime
from pydantic import BaseModel, Field
from pydantic import ConfigDict

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

    model_config = ConfigDict(from_attributes=True)
