"""Phase 11.85 ScannerBridge-NP HTTP endpoints."""

from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from sqlalchemy.orm import Session

from app.config import get_settings
from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.schemas.scanner_evidence_schema import (
    ScannerCorrelationResponse,
    ScannerEvidenceSafeRead,
    ScannerImportBody,
    ScannerImportResponse,
    ScannerLinkRequest,
    ScannerPreviewResponse,
    SUPPORTED_SOURCE_FORMATS,
)
from app.services import permission_service, scanner_bridge_service
from app.services.report_service import IncidentNotFoundError
from app.services.scanner_adapter_service import (
    ScannerParseError,
    UnsupportedSourceFormatError,
)

router = APIRouter(prefix="/scanner-bridge", tags=["scanner-bridge"])


@router.post("/preview", response_model=ScannerPreviewResponse)
def preview_scanner_json(
    body: ScannerImportBody,
    _user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_SCANNER_BRIDGE_IMPORT)),
    ],
) -> ScannerPreviewResponse:
    raw, fmt = _body_to_bytes(body)
    try:
        return scanner_bridge_service.preview_scanner_payload(raw, source_format=fmt)
    except (UnsupportedSourceFormatError, ScannerParseError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/preview/upload", response_model=ScannerPreviewResponse)
def preview_scanner_upload(
    _user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_SCANNER_BRIDGE_IMPORT)),
    ],
    source_format: str = Form(...),
    file: UploadFile = File(...),
) -> ScannerPreviewResponse:
    raw = _read_scanner_upload(file)
    try:
        return scanner_bridge_service.preview_scanner_payload(raw, source_format=source_format)
    except (UnsupportedSourceFormatError, ScannerParseError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.post("/import", response_model=ScannerImportResponse)
def import_scanner_json(
    body: ScannerImportBody,
    current_user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_SCANNER_BRIDGE_IMPORT)),
    ],
    db: Session = Depends(get_db_session),
) -> ScannerImportResponse:
    raw, fmt = _body_to_bytes(body)
    return _run_import(
        db,
        raw,
        fmt,
        linked_incident_id=body.linked_incident_id,
        source_system=body.source_system,
        service_hint=body.service_hint,
        endpoint_hint=body.endpoint_hint,
        release_version_hint=body.release_version_hint,
        actor_id=current_user.id,
        actor_email=current_user.email,
        actor_role=current_user.role.value,
    )


@router.post("/import/upload", response_model=ScannerImportResponse)
def import_scanner_upload(
    current_user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_SCANNER_BRIDGE_IMPORT)),
    ],
    db: Session = Depends(get_db_session),
    source_format: str = Form(...),
    file: UploadFile = File(...),
    linked_incident_id: str | None = Form(None),
    source_system: str | None = Form(None),
    service_hint: str | None = Form(None),
    endpoint_hint: str | None = Form(None),
    release_version_hint: str | None = Form(None),
) -> ScannerImportResponse:
    raw = _read_scanner_upload(file)
    return _run_import(
        db,
        raw,
        source_format,
        linked_incident_id=linked_incident_id,
        source_system=source_system,
        service_hint=service_hint,
        endpoint_hint=endpoint_hint,
        release_version_hint=release_version_hint,
        actor_id=current_user.id,
        actor_email=current_user.email,
        actor_role=current_user.role.value,
    )


@router.get("/evidence", response_model=list[ScannerEvidenceSafeRead])
def list_scanner_evidence(
    _user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_SCANNER_BRIDGE_READ)),
    ],
    db: Session = Depends(get_db_session),
    linked_incident_id: str | None = Query(None),
    source_format: str | None = Query(None),
    severity: str | None = Query(None),
    limit: int = Query(default=50, ge=1, le=200),
) -> list[ScannerEvidenceSafeRead]:
    return scanner_bridge_service.list_scanner_evidence(
        db,
        linked_incident_id=linked_incident_id,
        source_format=source_format,
        severity=severity,
        limit=limit,
    )


@router.get("/evidence/{scanner_evidence_id}", response_model=ScannerEvidenceSafeRead)
def get_scanner_evidence(
    scanner_evidence_id: str,
    _user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_SCANNER_BRIDGE_READ)),
    ],
    db: Session = Depends(get_db_session),
) -> ScannerEvidenceSafeRead:
    record = scanner_bridge_service.get_scanner_evidence(db, scanner_evidence_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scanner evidence not found")
    return record


@router.post("/evidence/{scanner_evidence_id}/link", response_model=ScannerEvidenceSafeRead)
def link_scanner_evidence(
    scanner_evidence_id: str,
    body: ScannerLinkRequest,
    current_user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_SCANNER_BRIDGE_IMPORT)),
    ],
    db: Session = Depends(get_db_session),
) -> ScannerEvidenceSafeRead:
    try:
        record = scanner_bridge_service.link_scanner_evidence(
            db,
            scanner_evidence_id,
            body.incident_id,
            actor_id=current_user.id,
            actor_email=current_user.email,
            actor_role=current_user.role.value,
        )
        db.commit()
    except IncidentNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scanner evidence not found")
    return record


@router.get(
    "/incidents/{incident_id}/scanner-evidence",
    response_model=list[ScannerEvidenceSafeRead],
)
def incident_scanner_evidence(
    incident_id: str,
    _user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_INCIDENT_READ)),
    ],
    db: Session = Depends(get_db_session),
) -> list[ScannerEvidenceSafeRead]:
    return scanner_bridge_service.list_incident_scanner_evidence(db, incident_id)


@router.post(
    "/incidents/{incident_id}/correlate",
    response_model=ScannerCorrelationResponse,
)
def correlate_scanner_evidence(
    incident_id: str,
    current_user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_SCANNER_BRIDGE_READ)),
    ],
    db: Session = Depends(get_db_session),
) -> ScannerCorrelationResponse:
    result = scanner_bridge_service.correlate_incident_scanner(
        db,
        incident_id,
        actor_id=current_user.id,
        actor_email=current_user.email,
        actor_role=current_user.role.value,
    )
    db.commit()
    return result


def _read_scanner_upload(file: UploadFile) -> bytes:
    max_bytes = get_settings().max_upload_bytes
    raw = file.file.read(max_bytes + 1)
    if not raw:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty scanner payload")
    if len(raw) > max_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Uploaded scanner payload exceeds the configured size limit",
        )
    return raw


def _body_to_bytes(body: ScannerImportBody) -> tuple[bytes, str]:
    if isinstance(body.payload, str):
        raw = body.payload.encode("utf-8")
    else:
        raw = json.dumps(body.payload).encode("utf-8")
    if len(raw) > get_settings().max_upload_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Scanner payload exceeds the configured size limit",
        )
    return raw, body.source_format


def _run_import(
    db: Session,
    raw: bytes,
    source_format: str,
    *,
    linked_incident_id: str | None,
    source_system: str | None,
    service_hint: str | None,
    endpoint_hint: str | None,
    release_version_hint: str | None,
    actor_id: int | None,
    actor_email: str | None,
    actor_role: str | None,
) -> ScannerImportResponse:
    if source_format not in SUPPORTED_SOURCE_FORMATS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported source_format. Use one of: {', '.join(SUPPORTED_SOURCE_FORMATS)}",
        )
    try:
        result = scanner_bridge_service.import_scanner_payload(
            db,
            raw,
            source_format=source_format,
            linked_incident_id=linked_incident_id,
            source_system=source_system,
            service_hint=service_hint,
            endpoint_hint=endpoint_hint,
            release_version_hint=release_version_hint,
            actor_id=actor_id,
            actor_email=actor_email,
            actor_role=actor_role,
        )
        db.commit()
        return result
    except IncidentNotFoundError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except (UnsupportedSourceFormatError, ScannerParseError) as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
