"""Evidence normalisation: parse files into normalized_events (Phase 4)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

import tempfile

from app.config import resolve_upload_dir
from app.models import EvidenceFile, NormalizedEvent
from app.models.enums import ParsingStatus
from app.parsers.registry import parse_evidence_file
from app.services import file_encryption_service


@dataclass
class ParseEvidenceResult:
    evidence_id: str
    status: str
    event_count: int = 0
    skipped: bool = False
    error: str | None = None


@dataclass
class ParseAllResult:
    parsed: list[ParseEvidenceResult] = field(default_factory=list)
    total_events: int = 0


def safe_parse_error(exc: Exception) -> str:
    """Return a parser error that cannot echo uploaded evidence content."""

    if isinstance(exc, FileNotFoundError):
        return "Stored evidence file is unavailable."
    return "Evidence could not be parsed. Check file format, timestamp fields, and supported evidence type."


def resolve_stored_evidence_path(
    evidence_id: str,
    *,
    record: EvidenceFile | None = None,
) -> Path:
    if record and record.is_encrypted and record.encrypted_file_path:
        content = file_encryption_service.read_encrypted_evidence(
            encrypted_relative_path=record.encrypted_file_path,
            file_crypto_metadata=record.file_crypto_metadata or {},
        )
        suffix = Path(record.file_name).suffix or ".tmp"
        with tempfile.NamedTemporaryFile(
            prefix=f"privacytrace_{evidence_id}_",
            suffix=suffix,
            delete=False,
        ) as tmp_file:
            tmp_file.write(content)
            return Path(tmp_file.name)

    upload_dir = resolve_upload_dir()
    matches = sorted(upload_dir.glob(f"{evidence_id}_*"))
    if not matches:
        raise FileNotFoundError(
            f"Stored file not found for evidence {evidence_id} in {upload_dir}"
        )
    return matches[0]


def list_normalized_events(db: Session, evidence_id: str) -> list[NormalizedEvent]:
    stmt = (
        select(NormalizedEvent)
        .where(NormalizedEvent.evidence_id == evidence_id)
        .order_by(NormalizedEvent.timestamp, NormalizedEvent.id)
    )
    return list(db.scalars(stmt).all())


def _drafts_to_models(drafts) -> list[NormalizedEvent]:
    return [
        NormalizedEvent(
            event_id=d.event_id,
            evidence_id=d.evidence_id,
            timestamp=d.timestamp,
            source_type=d.source_type,
            service_name=d.service_name,
            endpoint=d.endpoint,
            release_version=d.release_version,
            event_type=d.event_type,
            raw_reference=d.raw_reference,
            masked_message=d.masked_message,
            severity=d.severity,
            linked_incident_id=d.linked_incident_id,
        )
        for d in drafts
    ]


def parse_evidence(
    db: Session,
    evidence_id: str,
    *,
    force: bool = False,
) -> ParseEvidenceResult:
    record = db.scalar(
        select(EvidenceFile).where(EvidenceFile.evidence_id == evidence_id)
    )
    if not record:
        raise KeyError(f"Evidence not found: {evidence_id}")

    if record.parsing_status == ParsingStatus.PARSED and not force:
        count = len(list_normalized_events(db, evidence_id))
        return ParseEvidenceResult(
            evidence_id=evidence_id,
            status=ParsingStatus.PARSED.value,
            event_count=count,
            skipped=True,
        )

    record.parsing_status = ParsingStatus.PARSING
    db.commit()

    decrypted_temp_path: Path | None = None

    try:
        if force:
            db.execute(
                delete(NormalizedEvent).where(
                    NormalizedEvent.evidence_id == evidence_id
                )
            )
            db.commit()

        path = resolve_stored_evidence_path(evidence_id, record=record)
        if record.is_encrypted:
            decrypted_temp_path = path
        drafts = parse_evidence_file(
            path,
            evidence_id=record.evidence_id,
            evidence_type=record.evidence_type,
            linked_incident_id=record.linked_incident_id,
        )
        models = _drafts_to_models(drafts)
        db.add_all(models)
        record.parsing_status = ParsingStatus.PARSED
        db.commit()
        db.refresh(record)
        return ParseEvidenceResult(
            evidence_id=evidence_id,
            status=ParsingStatus.PARSED.value,
            event_count=len(models),
            skipped=False,
        )
    except Exception as exc:
        db.rollback()
        record = db.scalar(
            select(EvidenceFile).where(EvidenceFile.evidence_id == evidence_id)
        )
        if record:
            record.parsing_status = ParsingStatus.FAILED
            db.commit()
        return ParseEvidenceResult(
            evidence_id=evidence_id,
            status=ParsingStatus.FAILED.value,
            event_count=0,
            skipped=False,
            error=safe_parse_error(exc),
        )
    finally:
        if decrypted_temp_path is not None:
            try:
                decrypted_temp_path.unlink(missing_ok=True)
            except OSError:
                pass


def parse_all_pending(
    db: Session,
    *,
    linked_incident_id: str | None = None,
    include_failed: bool = False,
) -> ParseAllResult:
    statuses = [ParsingStatus.PENDING]
    if include_failed:
        statuses.append(ParsingStatus.FAILED)

    stmt = select(EvidenceFile).where(EvidenceFile.parsing_status.in_(statuses))
    if linked_incident_id:
        stmt = stmt.where(EvidenceFile.linked_incident_id == linked_incident_id)
    stmt = stmt.order_by(EvidenceFile.id)

    records = list(db.scalars(stmt).all())
    result = ParseAllResult()
    for record in records:
        item = parse_evidence(db, record.evidence_id, force=False)
        result.parsed.append(item)
        if item.status == ParsingStatus.PARSED.value and not item.skipped:
            result.total_events += item.event_count
    return result
