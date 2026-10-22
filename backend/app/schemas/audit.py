import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel


class AuditLogResponse(BaseModel):
    id: uuid.UUID
    request_id: str
    actor_id: Optional[uuid.UUID]
    actor_email: Optional[str]
    actor_ip: str
    user_agent: Optional[str]
    action: str
    target_type: str
    target_id: Optional[str]
    result: str
    denial_reason: Optional[str]
    metadata_json: Dict[str, Any]
    prev_hash: Optional[str]
    record_hash: str
    timestamp: datetime

    class Config:
        from_attributes = True


class AuditChainVerificationResult(BaseModel):
    is_valid: bool
    total_records: int
    broken_record_id: Optional[uuid.UUID] = None
    expected_hash: Optional[str] = None
    actual_hash: Optional[str] = None
    message: str
