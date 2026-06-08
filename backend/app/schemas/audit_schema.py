from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AuditLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    actor_id: int | None
    actor_email: str | None = None
    actor_role: str | None = None
    action: str
    target_type: str | None
    target_id: str | None
    timestamp: datetime
    details: dict | None = None


class AuditLogListResponse(BaseModel):
    logs: list[AuditLogRead]
    total: int = 0
