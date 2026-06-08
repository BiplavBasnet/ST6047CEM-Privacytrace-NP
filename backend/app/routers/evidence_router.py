from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.dependencies import get_db_session
from app.dependencies.auth_dependencies import require_permission
from app.models.user import User
from app.models.evidence_file import EvidenceFile
from app.models.evidence_provenance import EvidenceProvenance
from app.services import permission_service
from app.models.enums import EvidenceType, ParsingStatus
from app.schemas.detection_schema import DetectionRead
from app.schemas.evidence_schema import (
    DetectAllResponse,
    DetectEvidenceResponse,
    EvidenceFileRead,
    EvidenceUploadResponse,
    LoadSampleRequest,
    LoadSampleResponse,
    ParseAllResponse,
    ParseEvidenceResponse,
)
from app.schemas.event_schema import NormalizedEventRead
from app.services import detection_service, ingestion_service, normalization_service

router = APIRouter(prefix="/evidence", tags=["evidence"])


def _reads_with_collector(db: Session, records: list[EvidenceFile]) -> list[EvidenceFileRead]:
    if not records:
        return []
    ids = [item.evidence_id for item in records]
    names = dict(
        db.execute(
            select(EvidenceProvenance.evidence_id, EvidenceProvenance.collector_name).where(
                EvidenceProvenance.evidence_id.in_(ids)
            )
        ).all()
    )
    return [
        EvidenceFileRead.model_validate(item).model_copy(
            update={"collector_name": names.get(item.evidence_id)}
        )
        for item in records
    ]


@router.post("/upload", response_model=EvidenceUploadResponse, status_code=status.HTTP_201_CREATED)
async def upload_evidence(
    current_user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_EVIDENCE_UPLOAD))
    ],
    db: Session = Depends(get_db_session),
    file: UploadFile = File(...),
    evidence_type: EvidenceType = Form(...),
    source_system: str | None = Form(None),
    linked_incident_id: str | None = Form(None),
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")

    try:
        ingestion_service.validate_upload_extension(file.filename)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    max_bytes = get_settings().max_upload_bytes
    content = await file.read(max_bytes + 1)
    if not content:
        raise HTTPException(status_code=400, detail="Empty file")
    if len(content) > max_bytes:
        raise HTTPException(status_code=413, detail="Uploaded evidence file exceeds the configured size limit")

    try:
        record = ingestion_service.ingest_file(
            db,
            content=content,
            file_name=file.filename,
            evidence_type=evidence_type,
            source_system=source_system,
            linked_incident_id=linked_incident_id,
            uploaded_by=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    return EvidenceUploadResponse(
        message="Evidence uploaded successfully",
        evidence=EvidenceFileRead.model_validate(record),
    )


@router.post("/load-sample", response_model=LoadSampleResponse)
def load_sample_evidence(
    body: LoadSampleRequest,
    current_user: Annotated[
        User,
        Depends(require_permission(permission_service.PERMISSION_EVIDENCE_LOAD_SAMPLE)),
    ],
    db: Session = Depends(get_db_session),
):
    try:
        result = ingestion_service.load_sample_scenario(
            db,
            scenario=body.scenario,
            uploaded_by=current_user.id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return LoadSampleResponse(scenario=body.scenario, **result)


@router.post("/parse-all", response_model=ParseAllResponse)
def parse_all_evidence(
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_WORKFLOW_PARSE))
    ],
    db: Session = Depends(get_db_session),
    linked_incident_id: str | None = None,
    include_failed: bool = False,
):
    batch = normalization_service.parse_all_pending(
        db,
        linked_incident_id=linked_incident_id,
        include_failed=include_failed,
    )
    return ParseAllResponse(
        parsed=[
            ParseEvidenceResponse(
                evidence_id=item.evidence_id,
                status=item.status,
                event_count=item.event_count,
                skipped=item.skipped,
                error=item.error,
            )
            for item in batch.parsed
        ],
        total_events=batch.total_events,
    )


@router.post("/detect-all", response_model=DetectAllResponse)
def detect_all_evidence(
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_WORKFLOW_DETECT))
    ],
    db: Session = Depends(get_db_session),
    linked_incident_id: str | None = None,
):
    batch = detection_service.detect_all_parsed(
        db,
        linked_incident_id=linked_incident_id,
    )
    return DetectAllResponse(
        detected=[
            DetectEvidenceResponse(
                evidence_id=item.evidence_id,
                status=item.status,
                detection_count=item.detection_count,
                skipped=item.skipped,
                error=item.error,
                warnings=item.warnings,
            )
            for item in batch.results
        ],
        total_detections=batch.total_detections,
    )


@router.get("", response_model=list[EvidenceFileRead])
def list_evidence_files(
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_EVIDENCE_READ))
    ],
    db: Session = Depends(get_db_session),
    linked_incident_id: str | None = None,
):
    records = ingestion_service.list_evidence(db, linked_incident_id=linked_incident_id)
    return _reads_with_collector(db, records)


@router.post("/{evidence_id}/parse", response_model=ParseEvidenceResponse)
def parse_single_evidence(
    evidence_id: str,
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_WORKFLOW_PARSE))
    ],
    db: Session = Depends(get_db_session),
    force: bool = Query(False),
):
    try:
        result = normalization_service.parse_evidence(db, evidence_id, force=force)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    if result.status == ParsingStatus.FAILED.value and result.error:
        raise HTTPException(
            status_code=422,
            detail={"evidence_id": evidence_id, "error": result.error},
        )

    return ParseEvidenceResponse(
        evidence_id=result.evidence_id,
        status=result.status,
        event_count=result.event_count,
        skipped=result.skipped,
        error=result.error,
    )


@router.get("/{evidence_id}/events", response_model=list[NormalizedEventRead])
def list_evidence_events(
    evidence_id: str,
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_EVIDENCE_READ))
    ],
    db: Session = Depends(get_db_session),
):
    record = ingestion_service.get_evidence(db, evidence_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Evidence not found: {evidence_id}")
    events = normalization_service.list_normalized_events(db, evidence_id)
    return [NormalizedEventRead.model_validate(e) for e in events]


@router.post("/{evidence_id}/detect", response_model=DetectEvidenceResponse)
def detect_single_evidence(
    evidence_id: str,
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_WORKFLOW_DETECT))
    ],
    db: Session = Depends(get_db_session),
    force: bool = Query(False),
):
    try:
        result = detection_service.detect_evidence(db, evidence_id, force=force)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    if result.status == "failed" and result.error:
        raise HTTPException(
            status_code=422,
            detail={"evidence_id": evidence_id, "error": result.error},
        )

    return DetectEvidenceResponse(
        evidence_id=result.evidence_id,
        status=result.status,
        detection_count=result.detection_count,
        skipped=result.skipped,
        error=result.error,
        warnings=result.warnings,
    )


@router.get("/{evidence_id}/detections", response_model=list[DetectionRead])
def list_evidence_detections(
    evidence_id: str,
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_EVIDENCE_READ))
    ],
    db: Session = Depends(get_db_session),
):
    record = ingestion_service.get_evidence(db, evidence_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Evidence not found: {evidence_id}")
    detections = detection_service.list_detections(db, evidence_id)
    return [DetectionRead.model_validate(d) for d in detections]


@router.get("/{evidence_id}", response_model=EvidenceFileRead)
def get_evidence_file(
    evidence_id: str,
    _user: Annotated[
        User, Depends(require_permission(permission_service.PERMISSION_EVIDENCE_READ))
    ],
    db: Session = Depends(get_db_session),
):
    record = ingestion_service.get_evidence(db, evidence_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Evidence not found: {evidence_id}")
    return _reads_with_collector(db, [record])[0]

