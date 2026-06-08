"""Versioned connector receiver. Reuses Integration Gateway auth and ingest."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from app.dependencies import get_db_session
from app.dependencies.integration_auth_dependencies import (
    IntegrationPrincipal,
    require_integration_ingest_principal,
)
from app.schemas.connector_schema import (
    CONNECTOR_PRIVACY_REJECTED,
    ConnectorEventEnvelope,
    ConnectorIngestResponse,
)
from app.services import connector_ingest_service
from app.services.live_monitor_service import LiveMonitorNotRunningError

router = APIRouter(prefix="/integrations/connector/v1", tags=["connector"])


@router.post("/events", response_model=ConnectorIngestResponse)
def ingest_connector_event(
    body: ConnectorEventEnvelope,
    principal: Annotated[
        IntegrationPrincipal, Depends(require_integration_ingest_principal)
    ],
    response: Response,
    db: Session = Depends(get_db_session),
) -> ConnectorIngestResponse:
    try:
        result = connector_ingest_service.ingest_connector_event(
            db, body, principal=principal
        )
    except LiveMonitorNotRunningError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    if result.status == "rejected":
        response.status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
        if result.reason == CONNECTOR_PRIVACY_REJECTED:
            return ConnectorIngestResponse(
                status="rejected",
                reason=CONNECTOR_PRIVACY_REJECTED,
            )
    return result
