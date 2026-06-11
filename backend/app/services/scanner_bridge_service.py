"""ScannerBridge-NP orchestration: preview, import, list, link, correlate."""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.enums import EvidenceType, ParsingStatus, Severity
from app.models.evidence_file import EvidenceFile
from app.models.incident import Incident
from app.models.sast_finding import SastFinding
from app.models.scanner_evidence_record import ScannerEvidenceRecord
from app.models.secret_finding import SecretFinding
from app.schemas.scanner_evidence_schema import (
    ScannerCorrelationResponse,
    ScannerEvidenceSafeRead,
    ScannerImportResponse,
    ScannerPreviewFinding,
    ScannerPreviewResponse,
)
from app.services import (
    audit_service,
    causality_engine,
    scanner_adapter_service,
    scanner_correlation_service,
    scanner_mapping_service,
    scanner_safety_service,
    scanner_validation_service,
)
from app.services.report_service import IncidentNotFoundError


def _hash_payload(payload: Any) -> str:
    serialized = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _payload_from_bytes(raw: bytes) -> Any:
    text = raw.decode("utf-8", errors="replace").strip()
    if text.startswith("[") or text.startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text
    return text


def preview_scanner_payload(
    raw: bytes,
    *,
    source_format: str | None,
) -> ScannerPreviewResponse:
    payload = _payload_from_bytes(raw)
    safety = scanner_safety_service.sanitize_payload(payload)
    if not safety.safe:
        return ScannerPreviewResponse(
            detected_format=source_format or "unknown",
            safe_preview_findings=[],
            unsafe_item_count=1,
            warnings=[safety.reason or scanner_safety_service.GENERIC_REJECT],
            import_allowed=False,
        )

    clean = safety.sanitised_payload
    parse_bytes = json.dumps(clean).encode("utf-8")
    fmt, drafts = scanner_adapter_service.parse_payload_bytes(parse_bytes, source_format)

    safe_findings: list[ScannerPreviewFinding] = []
    unsafe_count = 0
    warnings: list[str] = []

    for draft in drafts:
        mapped = scanner_mapping_service.map_draft_to_record_fields(
            draft,
            source_format=fmt,
            raw_payload_hash=_hash_payload(clean),
            import_evidence_id="PREVIEW",
            linked_incident_id=None,
            service_hint=None,
            endpoint_hint=None,
            release_version_hint=None,
        )
        val = scanner_validation_service.validate_finding_dict(mapped)
        if not val.safe:
            unsafe_count += 1
            warnings.append(val.reason or "unsafe finding")
            continue
        sev = mapped.get("severity")
        safe_findings.append(
            ScannerPreviewFinding(
                detector_name=mapped.get("detector_name"),
                finding_type=mapped.get("finding_type"),
                masked_value=mapped.get("masked_value"),
                source_file=mapped.get("source_file"),
                line_number=mapped.get("line_number"),
                severity=sev.value if hasattr(sev, "value") else None,
                confidence=mapped.get("confidence"),
                verification_status=mapped.get("verification_status"),
                safety_status="safe",
                repository=mapped.get("repository"),
                commit_id=mapped.get("commit_id"),
            )
        )

    return ScannerPreviewResponse(
        detected_format=fmt,
        safe_preview_findings=safe_findings,
        unsafe_item_count=unsafe_count,
        warnings=warnings,
        import_allowed=unsafe_count == 0 and len(safe_findings) > 0,
    )


def import_scanner_payload(
    db: Session,
    raw: bytes,
    *,
    source_format: str,
    linked_incident_id: str | None,
    source_system: str | None,
    service_hint: str | None,
    endpoint_hint: str | None,
    release_version_hint: str | None,
    actor_id: int | None,
    actor_email: str | None,
    actor_role: str | None,
) -> ScannerImportResponse:
    payload = _payload_from_bytes(raw)
    safety = scanner_safety_service.sanitize_payload(payload)
    if not safety.safe:
        audit_service.log_action(
            db,
            action=audit_service.ACTION_SCANNER_BRIDGE_REJECTED,
            actor_id=actor_id,
            actor_email=actor_email,
            actor_role=actor_role,
            target_type="scanner_bridge",
            target_id=None,
            details={
                "violation_codes": scanner_validation_service.audit_safe_violation_codes(
                    safety.violation_codes
                ),
                "source_format": source_format,
            },
        )
        return ScannerImportResponse(
            status="rejected",
            imported_count=0,
            rejected_count=1,
            linked_incident_id=linked_incident_id,
            safety_warnings=[safety.reason or scanner_safety_service.GENERIC_REJECT],
            message="Import rejected due to unsafe scanner payload.",
        )

    clean = safety.sanitised_payload
    parse_bytes = json.dumps(clean).encode("utf-8")
    fmt, drafts = scanner_adapter_service.parse_payload_bytes(parse_bytes, source_format)
    payload_hash = _hash_payload(clean)

    if linked_incident_id:
        inc = db.scalar(select(Incident).where(Incident.incident_id == linked_incident_id))
        if inc is None:
            raise IncidentNotFoundError(f"Incident not found: {linked_incident_id}")

    import_evidence_id = f"EVD-SCN-{uuid.uuid4().hex[:12].upper()}"
    db.add(
        EvidenceFile(
            evidence_id=import_evidence_id,
            file_name=f"scanner-bridge-{fmt}-{import_evidence_id[:12]}",
            evidence_type=EvidenceType.SCANNER_BRIDGE_IMPORT,
            source_system=(source_system or "scanner_bridge")[:255],
            file_hash=payload_hash,
            uploaded_by=actor_id,
            parsing_status=ParsingStatus.PARSED,
            linked_incident_id=linked_incident_id,
        )
    )
    db.flush()
    from app.services import evidence_provenance_service
    evidence_provenance_service.record_system_provenance(
        db,
        import_evidence_id,
        source_system=source_system or "scanner_bridge",
        source_format=fmt,
        collector_name="scanner_bridge",
        parser_name=f"{fmt}_adapter",
        parser_version="1",
        commit=False,
        append_integrity=True,
    )
    from app.services import privacy_ingestion_pipeline_service

    privacy_ingestion_pipeline_service.classify_and_persist(
        db,
        clean,
        source_context={
            "scanner_label": fmt,
            "source_service": service_hint or source_system or "scanner_bridge",
            "endpoint": endpoint_hint or "",
        },
        allow_fingerprint=False,
        incident_id=linked_incident_id,
        evidence_id=import_evidence_id,
        actor_id=actor_id,
    )
    privacy_ingestion_pipeline_service.refresh_exposure_profiles(
        db,
        linked_incident_id,
        actor_id=actor_id,
    )

    imported_ids: list[str] = []
    rejected = 0
    warnings: list[str] = []

    for draft in drafts:
        fields = scanner_mapping_service.map_draft_to_record_fields(
            draft,
            source_format=fmt,
            raw_payload_hash=payload_hash,
            import_evidence_id=import_evidence_id,
            linked_incident_id=linked_incident_id,
            service_hint=service_hint,
            endpoint_hint=endpoint_hint,
            release_version_hint=release_version_hint,
        )
        val = scanner_validation_service.validate_finding_dict(fields)
        if not val.safe:
            rejected += 1
            audit_service.log_action(
                db,
                action=audit_service.ACTION_SCANNER_BRIDGE_REJECTED,
                actor_id=actor_id,
                actor_email=actor_email,
                actor_role=actor_role,
                target_type="scanner_evidence",
                target_id=None,
                details={
                    "violation_codes": val.violation_codes,
                    "import_evidence_id": import_evidence_id,
                },
            )
            continue

        existing = db.scalar(
            select(ScannerEvidenceRecord).where(
                ScannerEvidenceRecord.finding_fingerprint == fields["finding_fingerprint"],
                ScannerEvidenceRecord.raw_payload_hash == payload_hash,
            )
        )
        if existing:
            warnings.append(f"duplicate_skipped:{existing.scanner_evidence_id}")
            continue

        record = ScannerEvidenceRecord(**fields)
        if linked_incident_id:
            inc = db.scalar(select(Incident).where(Incident.incident_id == linked_incident_id))
            record.causal_relevance_score = scanner_correlation_service.compute_causal_relevance(
                record, inc
            )
            causality_engine.mark_stale(
                db,
                linked_incident_id,
                "Scanner evidence was imported and linked since the last root-cause analysis.",
            )
        db.add(record)
        db.flush()
        _dual_write_finding(db, record, fmt)
        imported_ids.append(record.scanner_evidence_id)

    audit_service.log_action(
        db,
        action=audit_service.ACTION_SCANNER_BRIDGE_IMPORT,
        actor_id=actor_id,
        actor_email=actor_email,
        actor_role=actor_role,
        target_type="scanner_bridge",
        target_id=import_evidence_id,
        details={
            "imported_count": len(imported_ids),
            "rejected_count": rejected,
            "source_format": fmt,
            "linked_incident_id": linked_incident_id,
        },
    )

    return ScannerImportResponse(
        status="accepted" if imported_ids else "partial",
        imported_count=len(imported_ids),
        rejected_count=rejected,
        scanner_evidence_ids=imported_ids,
        linked_incident_id=linked_incident_id,
        import_evidence_id=import_evidence_id,
        safety_warnings=warnings,
        message=(
            f"Imported {len(imported_ids)} safe scanner evidence record(s). "
            "Findings are supporting evidence only; human review is required."
        ),
    )


def _dual_write_finding(db: Session, record: ScannerEvidenceRecord, fmt: str) -> None:
    category = record.scanner_category or ""
    if fmt in ("semgrep_sarif", "semgrep_json") or category == "sast":
        db.add(
            SastFinding(
                evidence_id=record.import_evidence_id,
                rule_id=record.detector_name,
                file_path=record.source_file,
                line_number=record.line_number,
                finding_type=record.finding_type,
                message=record.explanation,
                severity=record.severity,
                endpoint_hint=record.endpoint_hint,
            )
        )
    elif record.masked_value:
        db.add(
            SecretFinding(
                evidence_id=record.import_evidence_id,
                secret_type=record.detector_name,
                file_path=record.source_file,
                masked_secret=record.masked_value,
                severity=record.severity or Severity.MEDIUM,
                confidence=record.confidence,
            )
        )


def list_scanner_evidence(
    db: Session,
    *,
    linked_incident_id: str | None = None,
    source_format: str | None = None,
    severity: str | None = None,
    limit: int = 50,
) -> list[ScannerEvidenceSafeRead]:
    stmt = select(ScannerEvidenceRecord)
    if linked_incident_id:
        stmt = stmt.where(ScannerEvidenceRecord.linked_incident_id == linked_incident_id)
    if source_format:
        stmt = stmt.where(ScannerEvidenceRecord.source_format == source_format)
    if severity:
        stmt = stmt.where(ScannerEvidenceRecord.severity == severity)
    bounded_limit = max(1, min(int(limit or 50), 200))
    records = db.scalars(
        stmt.order_by(ScannerEvidenceRecord.imported_at.desc()).limit(bounded_limit)
    ).all()
    return [_to_safe_read(r) for r in records]


def get_scanner_evidence(db: Session, scanner_evidence_id: str) -> ScannerEvidenceSafeRead | None:
    record = db.scalar(
        select(ScannerEvidenceRecord).where(
            ScannerEvidenceRecord.scanner_evidence_id == scanner_evidence_id
        )
    )
    if not record:
        return None
    return _to_safe_read(record)


def link_scanner_evidence(
    db: Session,
    scanner_evidence_id: str,
    incident_id: str,
    *,
    actor_id: int | None,
    actor_email: str | None,
    actor_role: str | None,
) -> ScannerEvidenceSafeRead | None:
    record = db.scalar(
        select(ScannerEvidenceRecord).where(
            ScannerEvidenceRecord.scanner_evidence_id == scanner_evidence_id
        )
    )
    if not record:
        return None
    inc = db.scalar(select(Incident).where(Incident.incident_id == incident_id))
    if not inc:
        raise IncidentNotFoundError(f"Incident not found: {incident_id}")
    record.linked_incident_id = incident_id
    record.causal_relevance_score = scanner_correlation_service.compute_causal_relevance(
        record, inc
    )
    # Phase N: new scanner evidence invalidates any existing root-cause
    # analysis ranking for this incident until it is re-run.
    causality_engine.mark_stale(
        db, incident_id, "Scanner evidence was linked since the last root-cause analysis."
    )
    db.flush()
    audit_service.log_action(
        db,
        action=audit_service.ACTION_SCANNER_BRIDGE_LINKED,
        actor_id=actor_id,
        actor_email=actor_email,
        actor_role=actor_role,
        target_type="scanner_evidence",
        target_id=scanner_evidence_id,
        details={"incident_id": incident_id},
    )
    return _to_safe_read(record)


def list_incident_scanner_evidence(db: Session, incident_id: str) -> list[ScannerEvidenceSafeRead]:
    return list_scanner_evidence(db, linked_incident_id=incident_id)


def correlate_incident_scanner(
    db: Session,
    incident_id: str,
    *,
    actor_id: int | None,
    actor_email: str | None,
    actor_role: str | None,
) -> ScannerCorrelationResponse:
    result = scanner_correlation_service.correlate_incident(db, incident_id)
    audit_service.log_action(
        db,
        action=audit_service.ACTION_SCANNER_BRIDGE_CORRELATED,
        actor_id=actor_id,
        actor_email=actor_email,
        actor_role=actor_role,
        target_type="incident",
        target_id=incident_id,
        details={"scanner_evidence_count": result.scanner_evidence_count},
    )
    return result


def _to_safe_read(record: ScannerEvidenceRecord) -> ScannerEvidenceSafeRead:
    tags = record.tags if isinstance(record.tags, list) else []
    return ScannerEvidenceSafeRead(
        scanner_evidence_id=record.scanner_evidence_id,
        source_format=record.source_format,
        scanner_category=record.scanner_category,
        finding_type=record.finding_type,
        detector_name=record.detector_name,
        verification_status=record.verification_status,
        severity=record.severity.value if record.severity else None,
        confidence=record.confidence,
        causal_relevance_score=record.causal_relevance_score,
        repository=record.repository,
        source_file=record.source_file,
        line_number=record.line_number,
        commit_id=record.commit_id,
        branch=record.branch,
        masked_value=record.masked_value,
        evidence_reference=record.evidence_reference,
        linked_evidence_id=record.linked_evidence_id,
        linked_incident_id=record.linked_incident_id,
        service_hint=record.service_hint,
        endpoint_hint=record.endpoint_hint,
        release_version_hint=record.release_version_hint,
        detected_at=record.detected_at,
        imported_at=record.imported_at,
        safety_status=record.safety_status,
        raw_payload_hash=record.raw_payload_hash,
        tags=[str(t) for t in tags],
        explanation=record.explanation,
        import_evidence_id=record.import_evidence_id,
    )
