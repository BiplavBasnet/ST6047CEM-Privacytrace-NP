"""Universal Integration Gateway HTTP endpoints."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Body, Depends, HTTPException, Path, Response, status
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.config import synthetic_demo_actions_allowed
from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.dependencies.integration_auth_dependencies import (
    IntegrationPrincipal,
    require_integration_ingest_principal,
)
from app.models.user import User
from app.schemas.integration_schema import (
    IntegrationBatchItemResult,
    IntegrationBatchResponse,
    IntegrationEventIngestRequest,
    IntegrationEventIngestResponse,
    IntegrationGatewayStatusResponse,
    IntegrationSchemaResponse,
    IntegrationSnippetsResponse,
    IntegrationTokenCreateRequest,
    IntegrationTokenCreatedResponse,
    IntegrationTokenListResponse,
    IntegrationTokenRead,
    IntegrationTokenRevokeResponse,
    IntegrationValidationResponse,
)
from app.services import (
    integration_gateway_service,
    integration_service,
    integration_token_service,
    organisation_access_service as org_access,
    permission_service,
    siem_import_service,
)
from app.services.integration_mapping_service import UnsupportedSourceFormatError
from app.services.live_monitor_service import LiveMonitorNotRunningError

router = APIRouter(prefix="/integrations", tags=["integration-gateway"])


def _missing_fields(exc: ValidationError, body: dict[str, Any]) -> list[str]:
    fields = {
        str(error["loc"][-1])
        for error in exc.errors()
        if error.get("loc") and error.get("type") in {"missing", "value_error"}
    }
    fields.discard("__root__")
    source_name = body.get("source_name") or body.get("source_tool")
    if not isinstance(source_name, str) or not source_name.strip():
        fields.add("source_name")
    message = body.get("message")
    if (not isinstance(message, str) or not message.strip()) and not isinstance(
        body.get("payload"), dict
    ):
        fields.add("message")
    return sorted(fields)


def _parse_event(body: dict[str, Any]) -> IntegrationEventIngestRequest:
    try:
        return IntegrationEventIngestRequest.model_validate(body)
    except ValidationError as exc:
        missing = _missing_fields(exc, body)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "message": "Integration event validation failed.",
                "required_fields_missing": missing,
            },
        ) from exc


@router.get("/status", response_model=IntegrationGatewayStatusResponse)
def gateway_status(
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INTEGRATION_READ))
    ],
    db: Session = Depends(get_db_session),
) -> IntegrationGatewayStatusResponse:
    return integration_gateway_service.get_status(db)


@router.get("/schema", response_model=IntegrationSchemaResponse)
def gateway_schema(
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INTEGRATION_READ))
    ],
) -> IntegrationSchemaResponse:
    return integration_gateway_service.get_schema()


@router.get("/snippets", response_model=IntegrationSnippetsResponse)
def gateway_snippets(
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_INTEGRATION_READ))
    ],
) -> IntegrationSnippetsResponse:
    return integration_gateway_service.get_snippets()


@router.post("/events", response_model=IntegrationEventIngestResponse)
def ingest_event(
    body: Annotated[dict[str, Any], Body()],
    principal: Annotated[
        IntegrationPrincipal, Depends(require_integration_ingest_principal)
    ],
    response: Response,
    db: Session = Depends(get_db_session),
) -> IntegrationEventIngestResponse:
    event = _parse_event(body)
    try:
        result = integration_service.ingest_single_event(
            db,
            event,
            actor_id=principal.actor_id,
            actor_email=principal.actor_email,
            actor_role=principal.actor_role,
            source_name_override=principal.source_name,
        )
    except UnsupportedSourceFormatError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported source_format. Use a format listed by /integrations/schema.",
        ) from exc
    except LiveMonitorNotRunningError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    if result.status == "rejected":
        response.status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    return result


@router.post("/events/batch", response_model=IntegrationBatchResponse)
def ingest_event_batch(
    body: Annotated[dict[str, Any], Body()],
    principal: Annotated[
        IntegrationPrincipal, Depends(require_integration_ingest_principal)
    ],
    db: Session = Depends(get_db_session),
) -> IntegrationBatchResponse:
    raw_events = body.get("events")
    if not isinstance(raw_events, list) or not raw_events:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="events must be a non-empty list.",
        )
    if len(raw_events) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Batch size exceeds limit of 100 events per request.",
        )

    results: list[IntegrationBatchItemResult] = []
    accepted = 0
    rejected = 0
    for index, raw_event in enumerate(raw_events):
        if not isinstance(raw_event, dict):
            rejected += 1
            results.append(
                IntegrationBatchItemResult(
                    index=index,
                    status="rejected",
                    safety_status="rejected",
                    reason="Event validation failed.",
                )
            )
            continue
        try:
            event = _parse_event(raw_event)
            outcome = integration_service.ingest_single_event(
                db,
                event,
                actor_id=principal.actor_id,
                actor_email=principal.actor_email,
                actor_role=principal.actor_role,
                source_name_override=principal.source_name,
            )
        except HTTPException:
            rejected += 1
            results.append(
                IntegrationBatchItemResult(
                    index=index,
                    status="rejected",
                    safety_status="rejected",
                    reason="Event validation failed.",
                )
            )
            continue
        except UnsupportedSourceFormatError:
            rejected += 1
            results.append(
                IntegrationBatchItemResult(
                    index=index,
                    status="rejected",
                    safety_status="rejected",
                    reason="Unsupported source_format.",
                )
            )
            continue
        except LiveMonitorNotRunningError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        if outcome.status == "accepted":
            accepted += 1
        else:
            rejected += 1
        results.append(
            IntegrationBatchItemResult(
                index=index,
                status=outcome.status,
                integration_event_id=outcome.integration_event_id,
                safety_status=outcome.safety_status,
                reason=outcome.reason,
                external_alert_id=event.external_alert_id,
                alert_created=outcome.alert_created,
                alert_id=outcome.alert_id,
            )
        )
    return IntegrationBatchResponse(
        total=len(raw_events),
        accepted=accepted,
        rejected=rejected,
        results=results,
    )


@router.post("/validate", response_model=IntegrationValidationResponse)
def validate_event(
    body: Annotated[dict[str, Any], Body()],
    principal: Annotated[
        IntegrationPrincipal, Depends(require_integration_ingest_principal)
    ],
) -> IntegrationValidationResponse:
    try:
        event = IntegrationEventIngestRequest.model_validate(body)
    except ValidationError as exc:
        missing = [
            field
            for field in ("source_name", "message")
            if not isinstance(body.get(field), str) or not body.get(field, "").strip()
        ]
        return IntegrationValidationResponse(
            valid=False,
            detected_source_type="custom",
            required_fields_missing=missing or _missing_fields(exc, body),
            safety_status="rejected",
            would_create_alert=False,
            reason="Integration event validation failed.",
        )
    try:
        preview = siem_import_service.preview_event(
            event,
            source_name_override=principal.source_name,
        )
    except UnsupportedSourceFormatError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported source_format. Use a format listed by /integrations/schema.",
        ) from exc
    return IntegrationValidationResponse(**preview)


@router.post("/test-event", response_model=IntegrationEventIngestResponse)
def test_event(
    principal: Annotated[
        IntegrationPrincipal, Depends(require_integration_ingest_principal)
    ],
    db: Session = Depends(get_db_session),
) -> IntegrationEventIngestResponse:
    if not synthetic_demo_actions_allowed():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Synthetic integration events are available only in demo environments.",
        )
    phone = "984" + "1234" + "567"
    event = IntegrationEventIngestRequest(
        source_name="integration-hub-test",
        source_type="api_log",
        source_format="generic_json",
        service_name="wallet-service",
        endpoint="/wallet/transfer",
        environment="demo",
        severity="info",
        message=f"Synthetic integration check phone={phone}",
        metadata={
            "deployment_version": "v1.4.2",
            "trace_id": "trace-demo-001",
        },
    )
    try:
        return integration_service.ingest_single_event(
            db,
            event,
            actor_id=principal.actor_id,
            actor_email=principal.actor_email,
            actor_role=principal.actor_role,
            source_name_override=principal.source_name,
        )
    except LiveMonitorNotRunningError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc


@router.post("/tokens", response_model=IntegrationTokenCreatedResponse)
def create_integration_token(
    body: IntegrationTokenCreateRequest,
    current_user: Annotated[
        User,
        Depends(
            require_permission(
                permission_service.PERMISSION_INTEGRATION_TOKEN_MANAGE
            )
        ),
    ],
    db: Session = Depends(get_db_session),
) -> IntegrationTokenCreatedResponse:
    record, raw_token = integration_token_service.create_token(
        db,
        name=body.name,
        source_name=body.source_name,
        created_by_user_id=current_user.id,
        actor_email=current_user.email,
        actor_role=current_user.role.value,
        organisation_id=org_access.require_active_membership(db, current_user).organisation_id,
    )
    return IntegrationTokenCreatedResponse(
        **IntegrationTokenRead.model_validate(record).model_dump(),
        token=raw_token,
    )


@router.get("/tokens", response_model=IntegrationTokenListResponse)
def list_integration_tokens(
    _user: Annotated[
        User,
        Depends(
            require_permission(
                permission_service.PERMISSION_INTEGRATION_TOKEN_MANAGE
            )
        ),
    ],
    db: Session = Depends(get_db_session),
) -> IntegrationTokenListResponse:
    rows = integration_token_service.list_tokens(
        db,
        organisation_id=org_access.require_active_membership(db, _user).organisation_id,
    )
    return IntegrationTokenListResponse(
        tokens=[IntegrationTokenRead.model_validate(row) for row in rows],
        total=len(rows),
    )


@router.delete(
    "/tokens/{token_id}",
    response_model=IntegrationTokenRevokeResponse,
)
def revoke_integration_token(
    token_id: Annotated[str, Path(min_length=4, max_length=64)],
    current_user: Annotated[
        User,
        Depends(
            require_permission(
                permission_service.PERMISSION_INTEGRATION_TOKEN_MANAGE
            )
        ),
    ],
    db: Session = Depends(get_db_session),
) -> IntegrationTokenRevokeResponse:
    try:
        record = integration_token_service.revoke_token(
            db,
            token_id=token_id,
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_role=current_user.role.value,
        )
    except integration_token_service.IntegrationTokenNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    return IntegrationTokenRevokeResponse(
        token_id=record.token_id,
        is_active=record.is_active,
        message="Integration token revoked.",
    )
