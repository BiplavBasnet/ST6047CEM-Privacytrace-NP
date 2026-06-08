from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.services import permission_service
from app.schemas.audit_schema import AuditLogListResponse, AuditLogRead
from app.services import audit_service, organisation_access_service as org_access

router = APIRouter(prefix="/audit-logs", tags=["audit"])


@router.get("", response_model=AuditLogListResponse)
def list_audit_logs(
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_AUDIT_READ))
    ],
    db: Session = Depends(get_db_session),
    incident_id: str | None = Query(default=None),
    action: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
):
    membership = org_access.get_active_membership(db, _user)
    rows = audit_service.list_audit_logs(
        db,
        incident_id=incident_id,
        action=action,
        limit=limit,
        organisation_id=membership.organisation_id if membership else None,
    )
    items = [
        AuditLogRead.model_validate(audit_service.audit_log_to_safe_read(r))
        for r in rows
    ]
    return AuditLogListResponse(logs=items, total=len(items))
