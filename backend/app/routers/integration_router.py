"""Phase 11.8 universal SIEM/SOC integration HTTP endpoints.

This router exposes:

* ``POST /integrations/events`` – ingest a single safe/masked event
* ``POST /integrations/events/batch`` – ingest a batch (max 100 items)
* ``GET  /integrations/events/{integration_event_id}`` – safe metadata view
* ``GET  /integrations/formats`` – list supported formats
* ``GET  /integrations/incidents/{incident_id}/formats`` – per-incident
  supported export formats
* ``GET  /integrations/incidents/{incident_id}/export`` – safe SOC export

Authentication is JWT-only (standard PrivacyTrace-NP bearer). The
underlying services enforce safety validation; the router translates
service-layer exceptions into safe HTTP responses without echoing the
unsafe input.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.schemas.integration_schema import (
    IntegrationEventSafeRead,
    IntegrationFormatsResponse,
    IntegrationIncidentExportResponse,
)
from app.services import integrity_ledger_service, integration_service, permission_service, siem_export_service
from app.services.report_safety_service import ReportSafetyError
from app.services.report_service import IncidentNotFoundError
from app.services.siem_export_service import UnsupportedExportFormatError

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.get("/formats", response_model=IntegrationFormatsResponse)
def list_integration_formats(
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INTEGRATION_READ))
    ],
) -> IntegrationFormatsResponse:
    return integration_service.list_formats()


@router.get(
    "/events/{integration_event_id}",
    response_model=IntegrationEventSafeRead,
)
def get_integration_event(
    integration_event_id: Annotated[str, Path(min_length=4, max_length=64)],
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INTEGRATION_READ))
    ],
    db: Annotated[Session, Depends(get_db_session)],
) -> IntegrationEventSafeRead:
    record = integration_service.get_event_metadata(db, integration_event_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Integration event not found: {integration_event_id}",
        )
    return record


@router.get(
    "/incidents/{incident_id}/formats",
    response_model=IntegrationFormatsResponse,
)
def get_incident_export_formats(
    incident_id: Annotated[str, Path(min_length=1, max_length=64)],
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INTEGRATION_READ))
    ],
) -> IntegrationFormatsResponse:
    return integration_service.list_formats()


@router.get(
    "/incidents/{incident_id}/export",
    response_model=IntegrationIncidentExportResponse,
)
def export_incident_for_soc(
    incident_id: Annotated[str, Path(min_length=1, max_length=64)],
    current_user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_INTEGRATION_EXPORT)),
    ],
    fmt: Annotated[str, Query(alias="format", min_length=1, max_length=64)] = "privacytrace_json",
    db: Session = Depends(get_db_session),
) -> IntegrationIncidentExportResponse:
    try:
        integrity_ledger_service.assert_export_allowed(
            db, scope_type="incident", scope_id=incident_id, executed_by=current_user.id
        )
        export = siem_export_service.export_incident(db, incident_id=incident_id, fmt=fmt)
    except integrity_ledger_service.IntegrityExportBlockedError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except UnsupportedExportFormatError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except IncidentNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except ReportSafetyError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc

    # Audit the export so SOC operators have a paper trail.
    from app.services import audit_service

    audit_service.log_action(
        db,
        action="integration_incident_exported",
        actor_id=current_user.id,
        actor_email=current_user.email,
        actor_role=current_user.role.value,
        target_type="incident",
        target_id=incident_id,
        details={
            "format": export.format,
            "content_type": export.content_type,
            "incident_id": incident_id,
        },
    )
    db.commit()

    return IntegrationIncidentExportResponse(
        incident_id=export.incident_id,
        format=export.format,
        content_type=export.content_type,
        export_body=export.body,
        generated_at=export.generated_at,
    )
